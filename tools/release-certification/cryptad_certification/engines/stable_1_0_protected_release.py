"""Side-effect-free Stable 1.0 protected execution preflight and closeout."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
import subprocess
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable
from urllib.parse import urlsplit
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ..envelope import validate_envelope
from ..io import read_json, read_json_bytes, write_json, write_text
from ..redaction import scan_value
from ..schema_validation import validate_schema
from .release_certification_core import (
    stable_dependency_vulnerability_phase_errors,
)
from .stable_1_0_ga_core import (
    canonical_artifact_base_uri,
    canonical_public_https_uri,
    is_public_https_uri,
    is_supported_artifact_base_uri,
    is_supported_catalog_publication_uri,
    public_audit_redaction_findings,
)
from .stable_1_0_independent_closeout import (
    independent_receipt_semantic_errors as _independent_receipt_semantic_errors,
)
from .stable_1_0_rc_core import placeholder_findings
from .stable_1_0_rc_freeze import freeze_content_digest
from .stable_1_0_public_observation import (
    PublicObservationTransportError,
    catalog_signature_uri,
)
from .stable_1_0_supply_chain_archive import inspect_archive_safety
from .stable_1_0_supply_chain_core import semantic_digest as supply_chain_semantic_digest

CONTRACT_SCHEMA = "stable-1.0-protected-release-execution-v1.schema.json"
SUMMARY_SCHEMA = "stable-1.0-protected-release-execution-summary-v1.schema.json"
OBSERVATION_SCHEMA = "stable-1.0-protected-release-public-observation-v1.schema.json"
EVIDENCE_ENVELOPE_SCHEMA = "evidence-envelope-v2.schema.json"
GA_AUTHORIZATION_SCHEMA = "stable-1.0-ga-authorization-v1.schema.json"
GA_VALIDATION_SCHEMA = "stable-1.0-ga-validation-v1.schema.json"
GA_VALIDATION_IDENTITY_SCHEMA = (
    "stable-1.0-ga-validation-authorization-identity-v1.schema.json"
)
GA_PUBLICATION_PLAN_SCHEMA = "stable-1.0-ga-publication-plan-v1.schema.json"
GA_PUBLICATION_RECEIPT_SCHEMA = "stable-1.0-ga-publication-receipt-v1.schema.json"
RC_LINEAGE_SCHEMA = "stable-1.0-rc-lineage-v1.schema.json"
RC_FREEZE_SCHEMA = "stable-1.0-rc-freeze-v1.schema.json"
RC_VALIDATION_SCHEMA = "stable-1.0-rc-validation-v1.schema.json"
REPRODUCIBILITY_SCHEMA = "stable-1.0-reproducibility-result-v1.schema.json"
REPRODUCIBILITY_PLAN_SCHEMA = "stable-1.0-rebuild-comparison-plan-v1.schema.json"
SUPPLY_CHAIN_SUMMARY_SCHEMA = "stable-1.0-supply-chain-promotion-summary-v1.schema.json"
INDEPENDENT_SUMMARY_SCHEMA = "stable-1.0-independent-reproducibility-summary-v1.schema.json"
INDEPENDENT_BUILDER_SCHEMA = "stable-1.0-independent-builder-receipt-v2.schema.json"
INDEPENDENT_AUTHORITY_SCHEMA = "stable-1.0-independent-authority-attestation-v1.schema.json"
INDEPENDENT_OUTPUT_SCHEMA = "stable-1.0-independent-output-manifest-v1.schema.json"
INDEPENDENT_POLICY_FILE = "stable-1.0-independent-reproducibility-policy.json"
POLICY_FILE = "stable-1.0-protected-release-policy.json"
SUPPLY_CHAIN_POLICY_FILE = "stable-1.0-supply-chain-policy.json"
SUPPLY_CHAIN_POLICY_SCHEMA = "stable-1.0-supply-chain-policy-v1.schema.json"
SUMMARY_FILE = "stable-1.0-protected-release-execution-summary.json"
REPORT_FILE = "stable-1.0-protected-release-execution-report.md"
REDACTION_FILE = "redaction-report.json"
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
RELEASE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
BUILD_RE = re.compile(r"[1-9][0-9]{0,9}")
REMOTE_ACTION_RE = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}$"
)
PLACEHOLDER_RE = re.compile(
    r"(?i)(?:replace[_-]?me|replace[_-]?with|placeholder|example\.invalid|\.invalid(?:/|$))"
)


def _digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return "sha256:" + hasher.hexdigest()


def _semantic_digest(value: Any) -> str:
    import json

    raw = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _bytes_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _github_api_json(path: str, token: str) -> dict[str, Any]:
    request = Request(
        f"https://api.github.com{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "cryptad-stable-protected-release-closeout",
        },
    )
    with urlopen(request, timeout=30) as response:  # noqa: S310 - fixed GitHub API origin
        value = json.loads(response.read())
    if not isinstance(value, dict):
        raise ValueError("GitHub API response is not an object")
    return value


def _github_actions_coordinate_errors(
    coordinate: dict[str, Any] | None,
    *,
    label: str,
    required_job_name: str | None = None,
    required_job_steps: tuple[str, ...] = (),
) -> list[str]:
    """Authenticate one asserted workflow artifact against GitHub's read-only API."""

    if coordinate is None:
        return [f"{label} has no GitHub workflow coordinates"]
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        return [f"{label} cannot authenticate GitHub metadata because GH_TOKEN is absent"]
    repository = coordinate.get("repository")
    run_id = coordinate.get("runId")
    attempt = coordinate.get("runAttempt")
    try:
        user = _github_api_json("/user", token)
        run = _github_api_json(
            f"/repos/{repository}/actions/runs/{run_id}/attempts/{attempt}", token
        )
        artifacts = _github_api_json(
            f"/repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100",
            token,
        )
        jobs = (
            _github_api_json(
                f"/repos/{repository}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100",
                token,
            )
            if required_job_name is not None
            else None
        )
    except (HTTPError, URLError, OSError, TimeoutError, ValueError, json.JSONDecodeError):
        return [f"{label} GitHub metadata could not be authenticated"]
    errors: list[str] = []
    if user.get("login") != "leumor":
        errors.append(f"{label} GitHub metadata was not queried as leumor")
    run_repository = (
        run.get("repository") if isinstance(run.get("repository"), dict) else {}
    )
    run_path = str(run.get("path", "")).split("@", 1)[0]
    if (
        str(run.get("id")) != str(run_id)
        or str(run.get("run_attempt")) != str(attempt)
        or run.get("head_sha") != coordinate.get("workflowCommit")
        or run_path != coordinate.get("workflowPath")
        or run.get("event") != "workflow_dispatch"
        or run.get("conclusion") != "success"
        or run_repository.get("full_name") != repository
    ):
        errors.append(
            f"{label} GitHub run differs from the repository, workflow, commit, attempt, or conclusion"
        )
    actor = run.get("actor") if isinstance(run.get("actor"), dict) else {}
    triggering_actor = (
        run.get("triggering_actor")
        if isinstance(run.get("triggering_actor"), dict)
        else {}
    )
    if actor.get("login") != "leumor" or triggering_actor.get("login") != "leumor":
        errors.append(f"{label} GitHub workflow operation was not performed by leumor")
    rows = artifacts.get("artifacts")
    rows = rows if isinstance(rows, list) else []
    if artifacts.get("total_count", len(rows)) > len(rows):
        errors.append(f"{label} GitHub artifact result is incomplete or ambiguous")
    matches = [
        row
        for row in rows
        if isinstance(row, dict)
        and row.get("name") == coordinate.get("artifactName")
        and row.get("digest") == coordinate.get("artifactDigest")
        and row.get("expired") is False
    ]
    if len(matches) != 1:
        errors.append(
            f"{label} GitHub artifact name and digest are missing, expired, or ambiguous"
        )
    if required_job_name is not None:
        job_rows = jobs.get("jobs") if isinstance(jobs, dict) else None
        job_rows = job_rows if isinstance(job_rows, list) else []
        if not isinstance(jobs, dict) or jobs.get("total_count", len(job_rows)) > len(job_rows):
            errors.append(f"{label} GitHub job result is incomplete or ambiguous")
        job_matches = [
            row
            for row in job_rows
            if isinstance(row, dict)
            and row.get("name") == required_job_name
            and str(row.get("run_id")) == str(run_id)
            and row.get("head_sha") == coordinate.get("workflowCommit")
            and row.get("status") == "completed"
            and row.get("conclusion") == "success"
        ]
        if len(job_matches) != 1:
            errors.append(
                f"{label} required protected workflow job did not complete successfully"
            )
        else:
            step_rows = job_matches[0].get("steps")
            step_rows = step_rows if isinstance(step_rows, list) else []
            for required_step in required_job_steps:
                step_matches = [
                    step
                    for step in step_rows
                    if isinstance(step, dict)
                    and step.get("name") == required_step
                    and step.get("status") == "completed"
                    and step.get("conclusion") == "success"
                ]
                if len(step_matches) != 1:
                    errors.append(
                        f"{label} required protected workflow step did not complete successfully"
                    )
    return errors


def _plan_digest(contract: dict[str, Any]) -> str:
    """Digest immutable dispatch inputs without circular closeout state."""
    planned = copy.deepcopy(contract)
    planned["workflowCoordinates"] = {
        "rc": None,
        "gaValidation": None,
        "gaEvidenceApproval": None,
        "gaPublication": None,
        "publicObservation": None,
    }
    operation_evidence = {
        "preflight": None,
        "rcPreflight": None,
        "rcFreeze": None,
        "rcFreezeRecord": None,
        "rcFreezeArtifact": None,
        "gaValidation": None,
        "gaValidationIdentity": None,
        "gaValidationArtifact": None,
        "gaPromotionPlan": None,
        "gaPublication": None,
        "gaPublicationArtifact": None,
        "publicObservation": None,
        "publicObservationArtifact": None,
        "independentReproducibility": None,
        "independentReproducibilityArtifact": None,
    }
    supplied_evidence = contract.get("operationEvidence")
    if isinstance(supplied_evidence, dict) and (
        "independentReproducibilityCoordinate" in supplied_evidence
    ):
        operation_evidence["independentReproducibilityCoordinate"] = None
    planned["operationEvidence"] = operation_evidence
    planned["lifecycleState"] = "planned"
    planned["evidenceClassification"] = {
        "repositoryImplementation": "present",
        "offlineVerification": "pending",
        "protectedOperation": "not-performed",
        "publicObservation": "not-performed",
    }
    planned["blockedReason"] = None
    return _semantic_digest(planned)


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _evaluation_clock_errors(
    contract: dict[str, Any],
    policy: dict[str, Any],
    observed_time: datetime,
) -> list[str]:
    maximum_skew = policy.get("maximumPreflightClockSkewSeconds")
    if type(maximum_skew) is not int or maximum_skew < 0 or maximum_skew > 3600:
        return ["protected release policy has an invalid preflight clock-skew bound"]
    try:
        declared = _timestamp(contract["evaluationTime"])
    except (KeyError, TypeError, ValueError):
        return ["execution evaluation time is missing or malformed"]
    if abs((observed_time - declared).total_seconds()) > maximum_skew:
        return [
            "execution evaluation time differs from current runner UTC beyond policy skew"
        ]
    return []


def _dispatch_clock_errors(
    contract: dict[str, Any],
    policy: dict[str, Any],
    observed_time: datetime,
) -> list[str]:
    """Reject a future preflight clock without turning review time into a dispatch TTL."""

    maximum_skew = policy.get("maximumPreflightClockSkewSeconds")
    if type(maximum_skew) is not int or maximum_skew < 0 or maximum_skew > 3600:
        return ["protected release policy has an invalid preflight clock-skew bound"]
    try:
        declared = _timestamp(contract["evaluationTime"])
    except (KeyError, TypeError, ValueError):
        return ["execution evaluation time is missing or malformed"]
    if (declared - observed_time).total_seconds() > maximum_skew:
        return ["execution evaluation time is future-dated beyond policy skew"]
    return []


def _confined_file(workspace: Path, relative: str, label: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{label} path is not repository-relative")
    current = workspace
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"{label} path contains a symbolic link")
    resolved = current.resolve()
    try:
        resolved.relative_to(workspace.resolve())
    except ValueError as exc:
        raise ValueError(f"{label} path escapes the repository") from exc
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError(f"{label} is missing or is not a regular file")
    return resolved


def _confined_output_directory(workspace: Path, output: Path) -> Path:
    resolved_workspace = workspace.resolve()
    if ".." in output.parts:
        raise ValueError("protected release output contains traversal")
    lexical_output = output if output.is_absolute() else resolved_workspace / output
    try:
        relative = lexical_output.relative_to(resolved_workspace)
    except ValueError as exc:
        raise ValueError("protected release output must remain inside the workspace") from exc

    def validate_components() -> None:
        current = resolved_workspace
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError(
                    "protected release output contains a symbolic-link component"
                )
            if current.exists() and not current.is_dir():
                raise ValueError(
                    "protected release output contains a non-directory component"
                )

    validate_components()
    lexical_output.mkdir(parents=True, exist_ok=True)
    validate_components()
    resolved_output = lexical_output.resolve()
    try:
        resolved_output.relative_to(resolved_workspace)
    except ValueError as exc:
        raise ValueError("protected release output must remain inside the workspace") from exc
    if resolved_output.is_symlink() or not resolved_output.is_dir():
        raise ValueError("protected release output directory is unsafe")
    return resolved_output


def _bound_input_paths(
    workspace: Path,
    contract: dict[str, Any],
    contract_path: Path,
    rc_input_map_path: Path | None,
) -> set[Path]:
    """Collect immutable local inputs that command output must never replace."""

    resolved_workspace = workspace.resolve()
    paths = {contract_path.resolve()}
    if rc_input_map_path is not None:
        paths.add(rc_input_map_path.resolve())

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            relative = value.get("path")
            if isinstance(relative, str):
                candidate = Path(relative)
                if not candidate.is_absolute() and ".." not in candidate.parts:
                    resolved = (resolved_workspace / candidate).resolve(strict=False)
                    try:
                        resolved.relative_to(resolved_workspace)
                    except ValueError:
                        pass
                    else:
                        paths.add(resolved)
            for child in value.values():
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)

    collect(contract)
    return paths


def _reject_output_input_collisions(
    workspace: Path,
    output: Path,
    contract: dict[str, Any],
    contract_path: Path,
    rc_input_map_path: Path | None,
) -> None:
    """Fail before writing when an output target aliases immutable input evidence."""

    inputs = _bound_input_paths(
        workspace,
        contract,
        contract_path,
        rc_input_map_path,
    )
    targets = {
        (output / SUMMARY_FILE).resolve(strict=False),
        (output / REPORT_FILE).resolve(strict=False),
        (output / REDACTION_FILE).resolve(strict=False),
    }
    if targets & inputs:
        raise ValueError("protected release output would overwrite immutable input evidence")


def _run_git(workspace: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=workspace,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return completed.stdout.strip()


def _all_values(value: Any, names: set[str]) -> list[Any]:
    found: list[Any] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key in names:
                found.append(child)
            found.extend(_all_values(child, names))
    elif isinstance(value, list):
        for child in value:
            found.extend(_all_values(child, names))
    return found


def _contains_expected(value: Any, names: Iterable[str], expected: Any) -> bool:
    return expected in _all_values(value, set(names))


def _unsafe_evidence_classification(value: Any) -> list[str]:
    errors: list[str] = []
    checks = {
        "fixture evidence": ({"fixture", "fixtureOnly", "fixtureEvidence"}, True),
        "simulated-only evidence": ({"simulatedOnly"}, True),
        "non-release evidence": ({"nonRelease", "nonProduction"}, True),
        "test signing": ({"testSigning", "testSigningUsed"}, True),
    }
    for label, (names, unsafe) in checks.items():
        if unsafe in _all_values(value, names):
            errors.append(f"evidence contains {label}")
    signing_labels = _all_values(
        value,
        {
            "signingKeyId",
            "catalogSigningKeyId",
            "reviewerKeyId",
            "appSigningKeyId",
            "reviewPolicyId",
            "reviewPolicyVersion",
        },
    )
    if any(
        isinstance(label, str) and re.search(r"(?i)(?:fixture|test|example|developer)", label)
        for label in signing_labels
    ):
        errors.append("evidence uses a fixture or test signing identity")
    return errors


def _public_https(value: str, *, base: bool = False) -> str | None:
    if PLACEHOLDER_RE.search(value):
        return "contains a placeholder or example authority"
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        return "contains an invalid port"
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.query
        or parsed.fragment
    ):
        return "must be credential-free public HTTPS on port 443 without query or fragment"
    hostname = parsed.hostname.lower().rstrip(".")
    if hostname in {"localhost", "127.0.0.1", "::1"} or hostname.endswith(".localhost"):
        return "uses a local authority"
    if not is_public_https_uri(value):
        return "does not resolve exclusively to globally routable addresses"
    if base and not parsed.path.endswith("/"):
        return "artifact base URI must end with a slash"
    if not base and parsed.path.endswith("/"):
        return "catalog URI must identify one concrete object"
    if "//" in parsed.path or "/../" in parsed.path or "/./" in parsed.path or "\\" in parsed.path:
        return "contains an ambiguous path"
    return None


def _canonical_publication_targets(contract: dict[str, Any]) -> dict[str, Any]:
    """Build the exact timestamp-free target identity used by Stable GA authorization."""

    release = contract["release"]
    targets = contract["publicTargets"]
    return {
        "expectedTag": f"v{release['integerBuild']}",
        "expectedReleaseBranch": f"release/{release['integerBuild']}",
        "artifactBaseUri": canonical_artifact_base_uri(
            canonical_public_https_uri(targets["artifactBaseUri"])
        ),
        "catalog": {
            "channel": "stable",
            "primaryUri": canonical_public_https_uri(targets["catalogPrimaryUri"]),
            "mirrorUris": [
                canonical_public_https_uri(uri)
                for uri in targets["catalogMirrorUris"]
            ],
            "rollbackUri": canonical_public_https_uri(
                targets["catalogRollbackUri"]
            ),
        },
    }


def _workflow_action_errors(path: Path) -> list[str]:
    errors: list[str] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = re.search(r"\buses:\s*([^\s#]+)", line)
        if match is None:
            continue
        reference = match.group(1)
        if reference.startswith("./"):
            continue
        if REMOTE_ACTION_RE.fullmatch(reference) is None:
            errors.append(
                f"{path.name}:{line_number} remote action is not pinned to a full commit"
            )
    return errors


def _workflow_job_block(workflow: str, job_id: str) -> str | None:
    """Return one top-level Actions job block without parsing untrusted YAML."""

    marker = re.search(rf"^  {re.escape(job_id)}:\s*$", workflow, re.MULTILINE)
    if marker is None:
        return None
    next_job = re.search(r"^  [A-Za-z0-9_-]+:\s*$", workflow[marker.end() :], re.MULTILINE)
    end = marker.end() + next_job.start() if next_job is not None else len(workflow)
    return workflow[marker.start() : end]


def _toolchain_errors(workspace: Path, policy: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    toolchain = policy["toolchain"]
    wrapper = workspace / "gradle/wrapper/gradle-wrapper.properties"
    expected_gradle = f"gradle-{toolchain['gradleVersion']}-bin.zip"
    wrapper_text = wrapper.read_text(encoding="utf-8") if wrapper.is_file() else ""
    if (
        expected_gradle not in wrapper_text
        or f"distributionSha256Sum={toolchain['gradleDistributionSha256']}"
        not in wrapper_text
        or "validateDistributionUrl=true" not in wrapper_text
    ):
        errors.append("Gradle wrapper version differs from protected release policy")
    build_logic = workspace / "build-logic/build.gradle.kts"
    build_logic_text = build_logic.read_text(encoding="utf-8") if build_logic.is_file() else ""
    if "JavaLanguageVersion.of(25)" not in build_logic_text or "jvmToolchain(25)" not in build_logic_text:
        errors.append("build-logic does not retain the Java 25 toolchain contract")
    try:
        completed = subprocess.run(
            ["java", "-XshowSettings:properties", "-version"],
            cwd=workspace,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        settings = completed.stdout + "\n" + completed.stderr
        version_match = re.search(r"^\s*java\.version\s*=\s*(\S+)\s*$", settings, re.MULTILINE)
        vendor_match = re.search(r"^\s*java\.vendor\s*=\s*(.+?)\s*$", settings, re.MULTILINE)
        expected_version = toolchain["setupJavaVersion"].split("+")[0]
        if version_match is None or version_match.group(1) != expected_version:
            errors.append("observable Java runtime differs from the pinned protected JDK build")
        if vendor_match is None or "adoptium" not in vendor_match.group(1).lower():
            errors.append("observable Java runtime is not the protected Temurin distribution")
    except (OSError, subprocess.SubprocessError, IndexError):
        errors.append("observable Java runtime could not be authenticated")
    return errors


def _project_build(workspace: Path) -> str | None:
    path = workspace / "build.gradle.kts"
    if not path.is_file():
        return None
    match = re.search(r'^version\s*=\s*["\']([1-9][0-9]*)["\']\s*$', path.read_text(encoding="utf-8"), re.MULTILINE)
    return match.group(1) if match else None


def _source_errors(workspace: Path, contract: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    repository = contract["repository"]
    release = contract["release"]
    candidate = repository["candidateCommit"]
    expected_ref = f"refs/heads/release/{release['integerBuild']}"
    if repository["sourceRef"] != expected_ref:
        errors.append("source ref does not match release/<integer-build>")
    try:
        if _run_git(workspace, "rev-parse", "HEAD") != candidate:
            errors.append("candidate commit differs from checked-out HEAD")
        release_ref_commits: list[str] = []
        for release_ref in (
            expected_ref,
            f"refs/remotes/origin/release/{release['integerBuild']}",
        ):
            try:
                release_ref_commits.append(
                    _run_git(
                        workspace,
                        "rev-parse",
                        "--verify",
                        "--quiet",
                        f"{release_ref}^{{commit}}",
                    )
                )
            except subprocess.CalledProcessError:
                continue
        if not release_ref_commits:
            errors.append("candidate source ref is unavailable in the checkout")
        elif any(commit != candidate for commit in release_ref_commits):
            errors.append("candidate source ref does not resolve to the exact candidate commit")
        root = Path(_run_git(workspace, "rev-parse", "--show-toplevel")).resolve()
        if root != workspace.resolve():
            errors.append("workspace root is not the repository root")
        if repository["requireCleanWorkspace"] and _run_git(
            workspace, "status", "--porcelain=v1", "--untracked-files=all"
        ):
            errors.append("candidate workspace is dirty")
    except (OSError, subprocess.SubprocessError):
        errors.append("candidate Git identity is unavailable or ambiguous")
    project_build = _project_build(workspace)
    if project_build != release["integerBuild"]:
        errors.append("project build does not match the protected execution integer build")
    return errors


def _file_binding_errors(
    workspace: Path,
    binding: dict[str, Any],
    label: str,
    *,
    scan_public: bool = True,
) -> tuple[Path | None, dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    try:
        path = _confined_file(workspace, binding["path"], label)
    except (OSError, ValueError) as exc:
        return None, None, [str(exc)]
    if _digest(path) != binding["sha256"]:
        errors.append(f"{label} digest differs from the execution contract")
    value: dict[str, Any] | None = None
    if path.suffix == ".json":
        try:
            loaded = read_json(path)
            if not isinstance(loaded, dict):
                errors.append(f"{label} is not a JSON object")
            else:
                value = loaded
        except (OSError, UnicodeDecodeError, ValueError):
            errors.append(f"{label} is malformed or ambiguous JSON")
        schema = binding.get("schema")
        if value is not None and isinstance(schema, str):
            errors.extend(f"{label}: {error}" for error in validate_schema(value, schema))
        if value is not None and scan_public:
            errors.extend(
                f"{label}: {finding['summary']}" for finding in scan_value(value)
            )
    return path, value, errors


def _evidence_errors(
    workspace: Path,
    contract: dict[str, Any],
    policy: dict[str, Any],
    evaluation_time: datetime | None = None,
) -> list[str]:
    errors: list[str] = []
    canonical_values: dict[str, tuple[dict[str, Any], Path, str]] = {}
    evidence = contract["upstreamEvidence"]
    ids = [row["id"] for row in evidence]
    required = policy["requiredEvidenceIds"]
    if ids != sorted(set(ids)):
        errors.append("upstream evidence IDs must be unique and sorted")
    if set(ids) != set(required):
        errors.append("upstream evidence does not contain the exact required policy identity set")
    release_id = contract["release"]["id"]
    build = contract["release"]["integerBuild"]
    commit = contract["repository"]["candidateCommit"]
    evaluation_time = evaluation_time or _timestamp(contract["evaluationTime"])
    evidence_contracts = policy.get("requiredEvidenceContracts")
    if not isinstance(evidence_contracts, dict) or set(evidence_contracts) != set(required):
        return [*errors, "protected release policy lacks the exact evidence contract map"]
    for row in evidence:
        label = f"upstream evidence {row['id']}"
        expected_contract = evidence_contracts.get(row["id"])
        if not isinstance(expected_contract, dict):
            errors.append(f"{label} has no canonical producer contract in repository policy")
            continue
        expected_schema = expected_contract.get("schema")
        expected_kind = expected_contract.get("kind")
        if row["kind"] != expected_kind:
            errors.append(f"{label} kind differs from repository policy")
        if row["file"].get("schema") != expected_schema:
            errors.append(f"{label} schema differs from repository policy")
        if row["releaseId"] != release_id or row["buildVersion"] != build:
            errors.append(f"{label} contract binding uses the wrong release or build")
        if row["candidateCommit"] != commit:
            errors.append(f"{label} contract binding uses the wrong candidate commit")
        authority_class = expected_contract.get("authorityClass")
        if row.get("authorityClass") != authority_class:
            errors.append(f"{label} authority class differs from repository policy")
        protected_producer = authority_class == "protected-producer"
        expected_classification = (
            "protected-operation" if protected_producer else "offline-prerequisite"
        )
        if row.get("classification") != expected_classification:
            errors.append(f"{label} evidence classification differs from its authority class")
        producer = row.get("producer")
        if protected_producer:
            if not isinstance(producer, dict):
                errors.append(f"{label} omits its protected producer coordinates")
            else:
                if producer.get("workflowCommit") != commit:
                    errors.append(f"{label} producer workflow commit differs from the candidate")
                expected_workflow = expected_contract.get("workflowPath")
                if producer.get("workflowPath") != expected_workflow:
                    errors.append(f"{label} producer workflow differs from repository policy")
                expected_environment = expected_contract.get("environment")
                if producer.get("environment") != expected_environment:
                    errors.append(f"{label} producer environment differs from repository policy")
                expected_artifact_name = {
                    "stable-supply-chain": (
                        f"stable-1.0-supply-chain-{release_id}-comparison"
                    ),
                    "stable-dependency-vulnerability": (
                        f"stable-1.0-dependency-vulnerability-{release_id}-evaluation"
                    ),
                    "stable-vulnerability": (
                        "stable-1.0-vulnerability-protected-ledger-wide-"
                        f"{producer.get('runId')}-{producer.get('runAttempt')}"
                    ),
                }.get(row["id"])
                if producer.get("artifactName") != expected_artifact_name:
                    errors.append(f"{label} producer artifact name is not canonical")
        elif producer is not None:
            errors.append(f"{label} must not claim a protected producer authority")
        if authority_class == "exact-dispatch-input":
            if row["file"].get("path") != expected_contract.get("rcInputPath"):
                errors.append(f"{label} RC input path differs from repository policy")
        elif authority_class == "rc-generated-prerequisite":
            generated_ids = policy.get("requiredRcGeneratedEvidenceIds", [])
            if row["id"] not in generated_ids:
                errors.append(f"{label} is not a repository-authorized RC-generated gate")
        try:
            if _timestamp(row["validUntil"]) <= evaluation_time:
                errors.append(f"{label} is stale at the execution evaluation time")
        except ValueError:
            errors.append(f"{label} validity timestamp is malformed")
        file_binding = row["file"]
        if expected_schema == EVIDENCE_ENVELOPE_SCHEMA:
            # The shared envelope schema contains conditional constraints that the
            # repository's deliberately small JSON-schema reader does not implement.
            # validate_envelope() is the canonical closed semantic validator.
            file_binding = {**file_binding, "schema": None}
        path, value, file_errors = _file_binding_errors(workspace, file_binding, label)
        errors.extend(file_errors)
        if value is None:
            continue
        if value.get("kind") != expected_kind:
            errors.append(f"{label} document kind differs from repository policy")
        if expected_schema == EVIDENCE_ENVELOPE_SCHEMA:
            try:
                validate_envelope(value, str(expected_kind), release_id)
            except ValueError:
                errors.append(f"{label} violates the canonical evidence-envelope semantics")
            try:
                _timestamp(str(value.get("generatedAt")))
            except ValueError:
                errors.append(f"{label} envelope generatedAt is malformed")
            subject = value.get("subject") if isinstance(value.get("subject"), dict) else {}
            result = value.get("result") if isinstance(value.get("result"), dict) else {}
            if (
                subject.get("releaseId") != release_id
                or str(subject.get("version")) != build
                or subject.get("profile") != "stable-review"
                or subject.get("component") != expected_contract.get("component")
            ):
                errors.append(f"{label} envelope subject differs from the exact Stable candidate")
            if (
                result.get("status") != "pass"
                or result.get("promotionReady") is not True
                or result.get("exitCode") != 0
            ):
                errors.append(f"{label} envelope is not promotion-ready")
            required_evidence_id = expected_contract.get("requiredEvidenceId")
            if isinstance(required_evidence_id, str):
                rows = [
                    item
                    for item in value.get("evidence", [])
                    if isinstance(item, dict)
                    and item.get("id") == required_evidence_id
                    and item.get("status") == "pass"
                ]
                if len(rows) != 1:
                    errors.append(
                        f"{label} omits or duplicates passing {required_evidence_id} evidence"
                    )
            payload = value.get("payload") if isinstance(value.get("payload"), dict) else {}
            legacy = payload.get("legacy") if isinstance(payload.get("legacy"), dict) else None
            if legacy is None:
                errors.append(f"{label} omits its canonical producer payload")
            elif path is not None:
                canonical_values[row["id"]] = (legacy, path, row["file"]["sha256"])
        else:
            if value.get("releaseId") != release_id:
                errors.append(f"{label} document does not bind the exact release ID")
            if str(value.get("buildVersion")) != build:
                errors.append(f"{label} document does not bind the exact integer build")
            candidate_value = value.get("candidateSourceCommit", value.get("sourceCommit"))
            if candidate_value is not None and candidate_value != commit:
                errors.append(f"{label} document binds a different candidate commit")
            if value.get("status") != "pass":
                errors.append(f"{label} document is not passing")
            if "promotionReady" in value and value.get("promotionReady") is not True:
                errors.append(f"{label} document is not promotion-ready")
            if row["id"] == "stable-supply-chain":
                from .stable_1_0_supply_chain import evaluated_promotion_summary_errors
                from .stable_1_0_supply_chain_reproducibility import promotion_summary_errors

                release_identity = {
                    "releaseId": release_id,
                    "buildVersion": int(build),
                    "sourceCommit": commit,
                    "tag": f"v{build}",
                    "sourceRef": f"commit:{commit}",
                    "policyDigest": expected_contract.get("policyDigest"),
                }
                errors.extend(
                    f"{label}: {error}"
                    for error in promotion_summary_errors(value, release_identity)
                )
                errors.extend(
                    f"{label}: {error}"
                    for error in evaluated_promotion_summary_errors(value)
                )
            elif row["id"] == "stable-dependency-vulnerability":
                from .stable_1_0_dependency_vulnerability_core import self_digest_errors

                errors.extend(
                    f"{label}: {error}"
                    for error in self_digest_errors(
                        value, "summaryDigest", "dependency-vulnerability summary"
                    )
                )
                errors.extend(
                    f"{label}: {error}"
                    for error in stable_dependency_vulnerability_phase_errors(
                        value,
                        "prepublication-evaluation",
                    )
                )
                if value.get("validUntil") != row["validUntil"]:
                    errors.append(
                        f"{label} validity differs from its protected execution binding"
                    )
            elif row["id"] == "stable-vulnerability" and path is not None:
                from ..stable_vulnerability_handoff import summary_errors

                errors.extend(
                    f"{label}: {error}"
                    for error in summary_errors(
                        value,
                        path.read_bytes(),
                        workspace,
                        evaluation_time,
                        release_id,
                        build,
                    )
                    )
            if path is not None:
                canonical_values[row["id"]] = (value, path, row["file"]["sha256"])
        errors.extend(f"{label}: {error}" for error in _unsafe_evidence_classification(value))
    for identities in (
        ("app-platform", "sandbox-provider"),
        ("hyphanet-interop", "performance", "release-certification"),
    ):
        bindings = {
            row["file"]["sha256"]
            for row in evidence
            if row["id"] in identities
        }
        if len(bindings) != 1:
            errors.append(
                "upstream evidence aggregate identities do not bind the same canonical bytes"
            )
    required_native = {
        "app-platform",
        "catalog-operations",
        "live-network",
        "multi-node",
        "network-scale",
        "previous-candidate",
        "release-certification",
        "release-history",
        "sandbox-provider",
        "security-drills",
        "stable-readiness",
        "third-party-intake",
    }
    if required_native.issubset(canonical_values):
        from .stable_1_0_rc_core import (
            LoadedInput,
            ValidationState,
            release_certification_is_promotable,
            stable_release_authority_governance_errors,
            stable_vulnerability_governance_errors,
            validate_catalog_operations,
            validate_live_inputs,
            validate_stable_readiness,
        )

        def loaded(key: str, evidence_id: str) -> LoadedInput:
            native, native_path, native_digest = canonical_values[evidence_id]
            return LoadedInput(key, native_path, native, native_digest)

        rc_inputs = {
            "appPlatform": loaded("appPlatform", "sandbox-provider"),
            "liveNetwork": loaded("liveNetwork", "live-network"),
            "multiNodeSoak": loaded("multiNodeSoak", "multi-node"),
            "networkScaleSoak": loaded("networkScaleSoak", "network-scale"),
            "previousCandidate": loaded("previousCandidate", "previous-candidate"),
            "releaseHistory": loaded("releaseHistory", "release-history"),
            "securityDrills": loaded("securityDrills", "security-drills"),
            "stableReadiness": loaded("stableReadiness", "stable-readiness"),
            "thirdPartyIntake": loaded("thirdPartyIntake", "third-party-intake"),
        }
        state = ValidationState()
        try:
            validate_live_inputs(rc_inputs, release_id, build, evaluation_time, state)
            validate_stable_readiness(
                rc_inputs["stableReadiness"].value,
                release_id,
                evaluation_time,
                rc_inputs,
                state,
            )
            validate_catalog_operations(
                canonical_values["catalog-operations"][0],
                release_id,
                build,
                evaluation_time,
                state,
            )
        except (KeyError, TypeError, ValueError):
            errors.append("canonical Stable RC producer validation could not authenticate evidence")
        certification = canonical_values["release-certification"][0]
        if not release_certification_is_promotable(certification):
            errors.append("release-certification evidence is not canonically promotable")
        errors.extend(stable_vulnerability_governance_errors(certification))
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
            errors.extend(
                stable_release_authority_governance_errors(
                    certification,
                    evidence_id=evidence_id,
                    gate_id=gate_id,
                    label=authority,
                )
            )
        errors.extend(
            f"canonical Stable RC producer rejected {row['id']}"
            for row in state.blockers
        )
    return errors


def _archive_errors(workspace: Path, contract: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    ids = [row["id"] for row in contract["archives"]]
    if ids != sorted(set(ids)):
        errors.append("archive IDs must be unique and sorted")
    for row in contract["archives"]:
        label = f"archive {row['id']}"
        try:
            path = _confined_file(workspace, row["path"], label)
            if _digest(path) != row["sha256"]:
                errors.append(f"{label} digest differs from the execution contract")
                continue
            inspect_archive_safety(
                path,
                maximum_entries=row["maximumEntries"],
                maximum_expanded_bytes=row["maximumExpandedBytes"],
                reject_links=True,
                reject_nested_archives=True,
            )
        except (OSError, ValueError) as exc:
            errors.append(f"{label} is unsafe or malformed: {type(exc).__name__}")
    return errors


def _contract_redaction_errors(contract: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    import json

    serialized = json.dumps(contract, ensure_ascii=False, sort_keys=True)
    forbidden = (
        re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
        re.compile(r"\b(?:SSK|USK)@[A-Za-z0-9~_-]+,[A-Za-z0-9~_-]+,AQECAAE/"),
        re.compile(r"(?i)authorization\s*:\s*(?:bearer|basic)\s+\S+"),
        re.compile(r"(?i)(?:password|passphrase|token|secret)\s*[:=]\s*[^<\s][^\s,;]{2,}"),
        re.compile(r"(?<![A-Za-z0-9:])/(?:home|work|tmp|Users|private|var)/[^\s\"']+"),
        re.compile(r"(?i)(?<![A-Za-z0-9])[A-Z]:[\\/][^\s\"']+"),
    )
    if any(pattern.search(serialized) for pattern in forbidden):
        errors.append("execution contract contains secret, private URI, or absolute path material")
    return errors


def _policy_errors(workspace: Path, contract: dict[str, Any], policy: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if contract["repository"]["identity"] != policy["repositoryIdentity"]:
        errors.append("repository identity differs from protected release policy")
    environments = contract["authorities"]["protectedEnvironments"]
    if environments != policy["requiredProtectedEnvironments"]:
        errors.append("protected environment names or ordering differ from repository policy")
    if contract["authorities"]["workflowPaths"] != policy["requiredWorkflowPaths"]:
        errors.append("workflow paths differ from repository policy")
    evidence_contracts = policy.get("requiredEvidenceContracts")
    required_ids = policy.get("requiredEvidenceIds")
    generated_ids = policy.get("requiredRcGeneratedEvidenceIds")
    if not isinstance(evidence_contracts, dict) or set(evidence_contracts) != set(required_ids):
        errors.append("protected release policy lacks the exact evidence contract map")
    elif not isinstance(generated_ids, list) or generated_ids != sorted(
        evidence_id
        for evidence_id, evidence_contract in evidence_contracts.items()
        if evidence_contract.get("authorityClass") == "rc-generated-prerequisite"
    ):
        errors.append("protected release policy has an inconsistent RC-generated evidence set")
    else:
        for evidence_id, evidence_contract in evidence_contracts.items():
            authority_class = evidence_contract.get("authorityClass")
            if authority_class == "protected-producer":
                if not isinstance(evidence_contract.get("workflowPath"), str) or not isinstance(
                    evidence_contract.get("environment"), str
                ):
                    errors.append(
                        f"protected producer {evidence_id} lacks a workflow or environment authority"
                    )
            elif authority_class == "exact-dispatch-input":
                if not isinstance(evidence_contract.get("rcInputPath"), str):
                    errors.append(
                        f"exact RC dispatch input {evidence_id} lacks a canonical materialized path"
                    )
            elif authority_class != "rc-generated-prerequisite":
                errors.append(f"evidence {evidence_id} has an unknown authority class")
    supply_chain_policy_path = (
        workspace / "tools/release-certification" / SUPPLY_CHAIN_POLICY_FILE
    )
    try:
        if supply_chain_policy_path.is_symlink() or not supply_chain_policy_path.is_file():
            raise OSError("canonical policy path is missing or unsafe")
        supply_chain_policy = read_json(supply_chain_policy_path)
    except (OSError, ValueError):
        supply_chain_policy = None
    if not isinstance(supply_chain_policy, dict):
        errors.append("canonical Stable supply-chain policy is missing or malformed")
    else:
        errors.extend(
            f"canonical Stable supply-chain policy: {error}"
            for error in validate_schema(
                supply_chain_policy,
                SUPPLY_CHAIN_POLICY_SCHEMA,
            )
        )
        canonical_supply_chain_digest = supply_chain_policy.get("policyDigest")
        if canonical_supply_chain_digest != supply_chain_semantic_digest(
            supply_chain_policy,
            "policyDigest",
        ):
            errors.append("canonical Stable supply-chain policy self-digest is invalid")
        protected_supply_chain_digest = (
            policy.get("requiredEvidenceContracts", {})
            .get("stable-supply-chain", {})
            .get("policyDigest")
        )
        if protected_supply_chain_digest != canonical_supply_chain_digest:
            errors.append(
                "protected release supply-chain identity differs from the canonical policy"
            )
    for role, relative in policy["requiredWorkflowPaths"].items():
        try:
            path = _confined_file(workspace, relative, f"{role} workflow")
        except ValueError as exc:
            errors.append(str(exc))
            continue
        errors.extend(_workflow_action_errors(path))
        text = path.read_text(encoding="utf-8")
        environment_key = {
            "rc": "rcEnvironment",
            "ga": "gaPublicationEnvironment",
            "publicObservation": "publicObservationEnvironment",
        }[role]
        expected_environment = policy["workflowPolicy"][environment_key]
        if f"environment: {expected_environment}" not in text:
            errors.append(f"{role} workflow does not use the required protected environment")
        if "cancel-in-progress: false" not in text or policy["workflowPolicy"]["releaseConcurrencyPrefix"] not in text:
            errors.append(f"{role} workflow does not retain the protected release concurrency contract")
        if role in {"rc", "ga"} and (
            f"java-version: '{policy['toolchain']['setupJavaVersion']}'" not in text
            or f"distribution: {policy['toolchain']['javaDistribution']}" not in text
        ):
            errors.append(f"{role} workflow does not retain the pinned protected JDK setup")
    rc_text = (workspace / policy["requiredWorkflowPaths"]["rc"]).read_text(encoding="utf-8")
    if rc_text.count("certify.py stable-rc --manifest") != 1:
        errors.append("RC workflow does not retain stable-rc as its single freeze authority")
    if (
        rc_text.count("protected_execution_contract:") != 1
        or rc_text.count("--mode rc-dispatch") != 1
        or rc_text.count("--rc-input-map") != 1
    ):
        errors.append("RC workflow does not bind the reviewed execution contract before freeze")
    ga_path = workspace / policy["requiredWorkflowPaths"]["ga"]
    ga_text = ga_path.read_text(encoding="utf-8")
    if f"environment: {policy['workflowPolicy']['gaEvidenceEnvironment']}" not in ga_text:
        errors.append("GA workflow omits the separate protected evidence environment")
    attestation_job = _workflow_job_block(ga_text, "attest-evidence")
    attestation_contract = (
        "name: Attest protected Stable GA evidence bytes",
        "if: inputs.publish == false",
        "needs: validate",
        f"environment: {policy['workflowPolicy']['gaEvidenceEnvironment']}",
        "name: Verify the exact protected attestation subjects",
        "name: Attest exact validation, authorization, and publication-target identity",
    )
    if attestation_job is None or any(
        requirement not in attestation_job for requirement in attestation_contract
    ):
        errors.append(
            "GA workflow does not bind the exact evidence-attestation job to its protected environment"
        )
    publication_job = _workflow_job_block(ga_text, "publish")
    publication_contract = (
        "name: Explicitly publish authorized Stable 1.0 GA assets",
        "if: inputs.publish == true",
        f"environment: {policy['workflowPolicy']['gaPublicationEnvironment']}",
    )
    if publication_job is None or any(
        requirement not in publication_job for requirement in publication_contract
    ):
        errors.append(
            "GA workflow does not bind the exact publication job to its protected environment"
        )
    if "./gradlew build" in ga_text or "assembleCryptadDist" in ga_text:
        errors.append("GA workflow contains a forbidden product rebuild path")
    evidence_contracts = policy["requiredEvidenceContracts"]
    for evidence_id, evidence_label in (
        ("stable-supply-chain", "Stable supply-chain"),
        ("stable-vulnerability", "Stable vulnerability"),
        ("stable-dependency-vulnerability", "Stable dependency-vulnerability"),
    ):
        evidence_contract = evidence_contracts[evidence_id]
        try:
            evidence_path = _confined_file(
                workspace,
                evidence_contract["workflowPath"],
                f"{evidence_label} workflow",
            )
        except (KeyError, ValueError) as exc:
            errors.append(str(exc))
            continue
        errors.extend(_workflow_action_errors(evidence_path))
        evidence_text = evidence_path.read_text(encoding="utf-8")
        if f"environment: {evidence_contract['environment']}" not in evidence_text:
            errors.append(
                f"{evidence_label} workflow omits the protected evidence environment"
            )
    return errors


def _freeze_mode_errors(contract: dict[str, Any]) -> list[str]:
    mode = contract["release"]["freezeMode"]
    previous = contract["release"]["previousRcFreeze"]
    if mode == "first-freeze" and previous is not None:
        return ["first-freeze cannot supply a previous RC freeze"]
    if mode == "refreeze" and previous is None:
        return ["refreeze requires the exact previous RC freeze"]
    return []


def _rc_input_errors(
    workspace: Path,
    contract: dict[str, Any],
    evaluation_time: datetime,
) -> list[str]:
    errors: list[str] = []
    for name, label in (
        ("publicBetaKnownIssues", "public beta known issues"),
        ("thirdPartyIntake", "third-party intake"),
        ("goNoGoWaivers", "go/no-go waivers"),
        ("stableReadinessWaivers", "Stable readiness waivers"),
        ("freezeExceptions", "Stable RC freeze exceptions"),
    ):
        binding = contract["rcInputs"][name]
        if binding is None:
            continue
        _path, value, binding_errors = _file_binding_errors(
            workspace,
            binding,
            label,
        )
        errors.extend(binding_errors)
        if value is not None:
            errors.extend(f"{label}: {error}" for error in _unsafe_evidence_classification(value))
            if name == "thirdPartyIntake":
                if str(value.get("status", "")).strip().lower() != "pass":
                    errors.append("third-party intake status is not pass")
                for field in ("fixtureOnly", "simulatedOnly", "nonRelease", "nonProduction"):
                    if value.get(field) is not False:
                        errors.append(
                            f"third-party intake requires explicit {field}=false"
                        )
                if value.get("releaseId") != contract["release"]["id"]:
                    errors.append("third-party intake release ID differs from the candidate")
                if str(value.get("buildVersion")) != contract["release"]["integerBuild"]:
                    errors.append("third-party intake build differs from the candidate")
                candidate = value.get("candidateSourceCommit", value.get("sourceCommit"))
                if candidate is not None and candidate != contract["repository"]["candidateCommit"]:
                    errors.append("third-party intake candidate commit differs")
                evidence_time = next(
                    (
                        value.get(field)
                        for field in ("generatedAt", "finishedAt", "verifiedAt", "createdAt")
                        if value.get(field) is not None
                    ),
                    None,
                )
                try:
                    generated = _timestamp(str(evidence_time))
                    if (
                        generated > evaluation_time
                        or evaluation_time - generated > timedelta(days=30)
                    ):
                        errors.append("third-party intake evidence is stale or future-dated")
                except ValueError:
                    errors.append("third-party intake evidence timestamp is missing or malformed")
    return errors


def _target_errors(contract: dict[str, Any]) -> list[str]:
    targets = contract["publicTargets"]
    errors: list[str] = []
    for field, value in (
        ("artifact base", targets["artifactBaseUri"]),
        ("catalog primary", targets["catalogPrimaryUri"]),
        ("catalog rollback", targets["catalogRollbackUri"]),
    ):
        problem = _public_https(value, base=field == "artifact base")
        if problem:
            errors.append(f"{field} URI {problem}")
        elif field == "artifact base" and (
            not is_supported_artifact_base_uri(value)
            or value
            != canonical_artifact_base_uri(canonical_public_https_uri(value))
        ):
            errors.append("artifact base URI is not in canonical Stable GA form")
        elif field != "artifact base" and (
            not is_supported_catalog_publication_uri(value)
            or value != canonical_public_https_uri(value)
        ):
            errors.append(f"{field} URI is not a supported canonical Stable catalog target")
    for index, value in enumerate(targets["catalogMirrorUris"]):
        problem = _public_https(value)
        if problem:
            errors.append(f"catalog mirror {index + 1} URI {problem}")
        elif (
            not is_supported_catalog_publication_uri(value)
            or value != canonical_public_https_uri(value)
        ):
            errors.append(
                f"catalog mirror {index + 1} URI is not a supported canonical Stable catalog target"
            )
    catalog_targets = [
        targets["catalogPrimaryUri"],
        *targets["catalogMirrorUris"],
        targets["catalogRollbackUri"],
    ]
    canonical = [canonical_public_https_uri(value) for value in catalog_targets]
    if len(canonical) != len(set(canonical)):
        errors.append("catalog primary, mirrors, and rollback targets must be distinct")
    return errors


def _publication_errors(
    workspace: Path,
    contract: dict[str, Any],
    evaluation_time: datetime | None = None,
) -> list[str]:
    ga = contract["ga"]
    if ga["publicationIntent"] != "publish":
        return []
    errors: list[str] = []
    if ga["selectedRc"] is None or ga["validationIdentityDigest"] is None or ga["authorization"] is None:
        errors.append("publication requested without exact selected-RC, validation, and authorization binding")
        return errors
    evidence_coordinate = contract["workflowCoordinates"]["gaEvidenceApproval"]
    if evidence_coordinate is None:
        errors.append("publication requested without exact protected evidence-approval coordinates")
    else:
        errors.extend(
            _coordinate_errors(
                evidence_coordinate,
                workflow=contract["authorities"]["workflowPaths"]["ga"],
                environment="stable-1-0-ga-evidence",
                commit=contract["repository"]["candidateCommit"],
                label="GA evidence approval",
            )
        )
        expected_evidence_artifact = (
            f"stable-1-0-ga-validated-{contract['release']['id']}-"
            f"{contract['release']['integerBuild']}-{evidence_coordinate['runId']}-"
            f"{evidence_coordinate['runAttempt']}"
        )
        if evidence_coordinate["artifactName"] != expected_evidence_artifact:
            errors.append("GA evidence approval artifact name is not canonical for its run")
    selected = ga["selectedRc"]
    expected_rc_artifact = (
        f"stable-1-0-rc-{contract['release']['id']}-{contract['release']['integerBuild']}-"
        f"{selected['runId']}-{selected['runAttempt']}"
    )
    if selected["artifactName"] != expected_rc_artifact:
        errors.append("selected RC artifact name is not canonical for its exact run")
    authorization = ga["authorization"]
    if authorization["file"]["sha256"] != authorization["authorizationFileDigest"]:
        errors.append("GA authorization file digest differs from its dispatch identity")
    if authorization["identityDigest"] != ga["validationIdentityDigest"]:
        errors.append("GA authorization identity differs from the validated GA identity")
    expected_targets = _canonical_publication_targets(contract)
    expected_targets_digest = _semantic_digest(expected_targets)
    if authorization["authorizedTargetsDigest"] != expected_targets_digest:
        errors.append("GA authorization target digest differs from the requested public targets")
    if authorization["file"].get("schema") != GA_AUTHORIZATION_SCHEMA:
        errors.append("GA authorization does not declare the canonical Stable GA schema")
    _path, value, file_errors = _file_binding_errors(
        workspace,
        authorization["file"],
        "GA authorization",
        scan_public=False,
    )
    errors.extend(file_errors)
    if value is not None:
        errors.extend(
            f"GA authorization: {error}"
            for error in validate_schema(value, GA_AUTHORIZATION_SCHEMA)
        )
        if value.get("status") != "authorized":
            errors.append("GA authorization is not authorized")
        if value.get("authorizationId") != authorization["authorizationId"]:
            errors.append("GA authorization ID differs from the execution contract")
        if value.get("releaseId") != contract["release"]["id"]:
            errors.append("GA authorization binds a different release")
        if str(value.get("buildVersion")) != contract["release"]["integerBuild"]:
            errors.append("GA authorization binds a different build")
        if value.get("sourceCommit") != contract["repository"]["candidateCommit"]:
            errors.append("GA authorization binds a different candidate commit")
        if value.get("gaValidationDigest") != authorization["identityDigest"]:
            errors.append("GA authorization does not bind the selected validation identity")
        if value.get("publicationTargets") != expected_targets:
            errors.append("GA authorization document binds different public targets")
        if value.get("publicationTargetsDigest") != expected_targets_digest:
            errors.append("GA authorization document target digest differs from the requested targets")
        selected = ga["selectedRc"]
        for field, expected in (
            ("freezeDigest", selected["freezeDigest"]),
            ("archiveDigest", selected["archiveDigest"]),
            ("productDistributionDigest", selected["productDigest"]),
            ("catalogDigest", selected["catalogDigest"]),
            ("catalogRevision", selected["catalogRevision"]),
        ):
            if value.get(field) != expected:
                errors.append(f"GA authorization {field} differs from the selected RC")
        if value.get("authorizationRole") != authorization["role"]:
            errors.append("GA authorization role differs from the execution contract")
        if value.get("approverIdentity") != authorization["approverId"]:
            errors.append("GA authorization approver differs from the execution contract")
        if value.get("expiresAt") != authorization["validUntil"]:
            errors.append("GA authorization expiration differs from the execution contract")
        if public_audit_redaction_findings(value) or placeholder_findings(value):
            errors.append("GA authorization contains redaction findings or placeholders")
        try:
            approved_at = _timestamp(str(value.get("approvedAt")))
            generated_at = _timestamp(str(value.get("generatedAt")))
            expires_at = _timestamp(str(value.get("expiresAt")))
            evaluation_time = evaluation_time or _timestamp(contract["evaluationTime"])
            review_hours = value.get("reviewWindowHours")
            if not (
                approved_at <= generated_at <= evaluation_time < expires_at
                and type(review_hours) is int
                and expires_at - approved_at
                <= timedelta(hours=review_hours)
            ):
                errors.append("GA authorization approval/expiration window is invalid")
        except ValueError:
            errors.append("GA authorization approval/expiration window is malformed")
    if _timestamp(authorization["validUntil"]) <= (
        evaluation_time or _timestamp(contract["evaluationTime"])
    ):
        errors.append("GA authorization is stale at the execution evaluation time")
    return errors


def _preflight(
    workspace: Path,
    contract: dict[str, Any],
    policy: dict[str, Any],
    observed_time: datetime | None = None,
) -> list[str]:
    errors = validate_schema(contract, CONTRACT_SCHEMA)
    if errors:
        return errors
    evaluation_time = observed_time or _utc_now()
    errors.extend(_evaluation_clock_errors(contract, policy, evaluation_time))
    errors.extend(_source_errors(workspace, contract))
    errors.extend(_toolchain_errors(workspace, policy))
    errors.extend(_freeze_mode_errors(contract))
    errors.extend(_rc_input_errors(workspace, contract, evaluation_time))
    errors.extend(_target_errors(contract))
    errors.extend(_policy_errors(workspace, contract, policy))
    errors.extend(_evidence_errors(workspace, contract, policy, evaluation_time))
    errors.extend(_archive_errors(workspace, contract))
    errors.extend(_contract_redaction_errors(contract))
    errors.extend(_publication_errors(workspace, contract, evaluation_time))
    previous = contract["release"]["previousRcFreeze"]
    if isinstance(previous, dict):
        _path, value, previous_errors = _file_binding_errors(
            workspace, previous, "previous RC freeze"
        )
        errors.extend(previous_errors)
        if value is not None:
            if not _contains_expected(value, {"releaseId"}, contract["release"]["id"]):
                errors.append("previous RC freeze binds a different release")
            if not _contains_expected(value, {"buildVersion"}, contract["release"]["integerBuild"]):
                errors.append("previous RC freeze binds a different build")
    return sorted(set(errors))


def _coordinate_errors(
    coordinate: dict[str, Any] | None,
    *,
    workflow: str,
    environment: str,
    commit: str,
    label: str,
) -> list[str]:
    if coordinate is None:
        return [f"{label} workflow coordinates are missing"]
    errors: list[str] = []
    if coordinate["repository"] != "crypta-network/cryptad":
        errors.append(f"{label} coordinates use the wrong repository")
    if coordinate["workflowPath"] != workflow:
        errors.append(f"{label} coordinates use the wrong workflow")
    if coordinate["environment"] != environment:
        errors.append(f"{label} coordinates use the wrong protected environment")
    if coordinate["workflowCommit"] != commit:
        errors.append(f"{label} coordinates use the wrong workflow commit")
    if coordinate["artifactDigest"] == "sha256:" + "0" * 64:
        errors.append(f"{label} artifact digest is an unset placeholder")
    return errors


def _ga_validation_coordinate_binding_errors(
    validation: dict[str, Any] | None,
    evidence: dict[str, Any] | None,
) -> list[str]:
    if validation is None or evidence is None:
        return ["GA validation and evidence coordinates are incomplete"]
    shared_fields = (
        "repository",
        "workflowPath",
        "workflowCommit",
        "runId",
        "runAttempt",
        "artifactName",
        "artifactDigest",
        "conclusion",
    )
    if any(validation.get(field) != evidence.get(field) for field in shared_fields):
        return [
            "GA validation coordinate differs from its authenticated protected evidence artifact"
        ]
    return []


def _observation_coordinate_errors(
    value: dict[str, Any],
    coordinate: dict[str, Any] | None,
    *,
    observation_workflow: str,
    observation_environment: str,
    commit: str,
    build: str,
) -> list[str]:
    if coordinate is None:
        return ["public observation workflow coordinates are missing"]
    errors: list[str] = []
    if coordinate["repository"] != "crypta-network/cryptad":
        errors.append("public observation coordinates use the wrong repository")
    if coordinate["workflowCommit"] != commit:
        errors.append("public observation coordinates use the wrong workflow commit")
    if coordinate["artifactDigest"] == "sha256:" + "0" * 64:
        errors.append("public observation artifact digest is an unset placeholder")
    if coordinate["workflowPath"] != observation_workflow:
        errors.append("public observation coordinates use the wrong read-only workflow")
    if coordinate["environment"] != observation_environment:
        errors.append("public observation coordinates use the wrong read-only environment")
    expected_artifact = (
        f"stable-1-0-public-observation-{build}-"
        f"{coordinate['runId']}-{coordinate['runAttempt']}"
    )
    if coordinate["artifactName"] != expected_artifact:
        errors.append("public observation artifact name is not canonical for its run")
    observer = value.get("observer") if isinstance(value.get("observer"), dict) else {}
    expected_observer = {
        key: item for key, item in coordinate.items() if key != "artifactDigest"
    }
    expected_observer["readOnly"] = True
    if observer != expected_observer:
        errors.append("public observation receipt differs from its exact workflow coordinates")
    return errors


def _observation_artifact_errors(
    workspace: Path,
    binding: dict[str, Any] | None,
    receipt_path: Path | None,
    coordinate: dict[str, Any] | None,
) -> list[str]:
    """Bind the extracted observation receipt to its exact Actions artifact bytes."""

    if binding is None:
        return ["public observation lacks its downloaded Actions artifact archive"]
    if coordinate is None:
        return ["public observation artifact has no workflow coordinates"]
    if binding.get("schema") is not None:
        return ["public observation artifact archive must not declare a JSON schema"]
    try:
        archive_path = _confined_file(
            workspace, binding["path"], "public observation artifact archive"
        )
    except (KeyError, OSError, ValueError) as exc:
        return [str(exc)]
    errors: list[str] = []
    archive_digest = _digest(archive_path)
    if archive_digest != binding.get("sha256"):
        errors.append(
            "public observation artifact archive digest differs from the execution contract"
        )
    if archive_digest != coordinate.get("artifactDigest"):
        errors.append(
            "public observation artifact archive differs from the exact Actions artifact digest"
        )
    if archive_path.suffix.lower() != ".zip":
        errors.append("public observation artifact archive is not a ZIP artifact")
        return errors
    try:
        inspect_archive_safety(
            archive_path,
            maximum_entries=2,
            maximum_expanded_bytes=10_000_000,
            reject_links=True,
            reject_nested_archives=True,
        )
        with zipfile.ZipFile(archive_path) as archive:
            members = [row for row in archive.infolist() if not row.is_dir()]
            if len(members) != 1 or members[0].filename != (
                "stable-1.0-public-observation.json"
            ):
                errors.append(
                    "public observation artifact archive does not contain only the canonical receipt member"
                )
            elif receipt_path is None or archive.read(members[0]) != receipt_path.read_bytes():
                errors.append(
                    "public observation receipt bytes differ from the authenticated Actions artifact member"
                )
    except (
        EOFError,
        NotImplementedError,
        OSError,
        RuntimeError,
        ValueError,
        zipfile.BadZipFile,
    ):
        errors.append("public observation artifact archive is unsafe or malformed")
    return errors


def _retained_artifact_member_errors(
    workspace: Path,
    binding: dict[str, Any] | None,
    coordinate: dict[str, Any] | None,
    *,
    label: str,
    expected_members: dict[str, dict[str, Any] | None],
) -> list[str]:
    """Authenticate extracted evidence as exact members of a retained Actions artifact."""

    if binding is None:
        return [f"{label} archive is missing"]
    if coordinate is None:
        return [f"{label} archive has no workflow coordinates"]
    if binding.get("schema") is not None:
        return [f"{label} archive must not declare a JSON schema"]
    try:
        archive_path = _confined_file(workspace, binding["path"], f"{label} archive")
    except (KeyError, OSError, ValueError) as exc:
        return [str(exc)]
    errors: list[str] = []
    archive_digest = _digest(archive_path)
    if archive_digest != binding.get("sha256"):
        errors.append(f"{label} archive digest differs from the execution contract")
    if archive_digest != coordinate.get("artifactDigest"):
        errors.append(f"{label} archive differs from the exact Actions artifact digest")
    if archive_path.suffix.lower() != ".zip":
        return [*errors, f"{label} archive is not a ZIP artifact"]
    try:
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            names = [row.filename for row in members]
            folded: set[str] = set()
            if len(names) > 20_000 or sum(row.file_size for row in members) > 5_000_000_000:
                return [*errors, f"{label} archive exceeds the closed inspection bounds"]
            for row in members:
                path = PurePosixPath(row.filename)
                parts = path.parts
                unsafe_metadata = (
                    "__MACOSX" in parts
                    or any(part.startswith("._") for part in parts)
                    or path.name == ".DS_Store"
                )
                if (
                    path.is_absolute()
                    or ".." in parts
                    or unsafe_metadata
                    or stat.S_ISLNK(row.external_attr >> 16)
                ):
                    errors.append(f"{label} archive contains an unsafe member")
                    break
                folded_name = row.filename.casefold()
                if folded_name in folded:
                    errors.append(f"{label} archive contains duplicate or colliding members")
                    break
                folded.add(folded_name)
            for member_name, member_binding in expected_members.items():
                if member_binding is None:
                    errors.append(f"{label} lacks a required extracted evidence binding")
                    continue
                matches = [row for row in members if row.filename == member_name]
                if len(matches) != 1 or matches[0].is_dir():
                    errors.append(f"{label} archive lacks exact member {member_name}")
                    continue
                try:
                    extracted = _confined_file(
                        workspace,
                        member_binding["path"],
                        f"{label} extracted member",
                    )
                except (KeyError, OSError, ValueError) as exc:
                    errors.append(str(exc))
                    continue
                if archive.read(matches[0]) != extracted.read_bytes():
                    errors.append(
                        f"{label} archive member {member_name} differs from extracted evidence bytes"
                    )
    except (
        EOFError,
        NotImplementedError,
        OSError,
        RuntimeError,
        ValueError,
        zipfile.BadZipFile,
    ):
        errors.append(f"{label} archive is unsafe or malformed")
    return errors


def _retained_artifact_member(
    workspace: Path,
    binding: dict[str, Any] | None,
    member_name: str,
    *,
    label: str,
) -> tuple[bytes | None, list[str]]:
    if binding is None:
        return None, [f"{label} archive is missing"]
    try:
        archive_path = _confined_file(workspace, binding["path"], f"{label} archive")
        with zipfile.ZipFile(archive_path) as archive:
            matches = [row for row in archive.infolist() if row.filename == member_name]
            if len(matches) != 1 or matches[0].is_dir():
                return None, [f"{label} archive lacks exact member {member_name}"]
            if matches[0].file_size > 10_000_000:
                return None, [f"{label} archive member {member_name} exceeds its size bound"]
            return archive.read(matches[0]), []
    except (
        EOFError,
        KeyError,
        NotImplementedError,
        OSError,
        RuntimeError,
        ValueError,
        zipfile.BadZipFile,
    ):
        return None, [f"{label} archive is unsafe or malformed"]


def _independent_checked_in_policies(
    _workspace: Path,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, list[str]]:
    """Load and authenticate the policy authorities needed to revalidate PR-292 members."""
    errors: list[str] = []
    loaded: list[dict[str, Any] | None] = []
    for name, label in (
        (SUPPLY_CHAIN_POLICY_FILE, "Stable supply-chain"),
        (INDEPENDENT_POLICY_FILE, "independent reproducibility"),
    ):
        path = Path(__file__).resolve().parents[2] / name
        try:
            if path.is_symlink() or not path.is_file():
                raise OSError("policy path is missing or unsafe")
            value = read_json(path)
        except (OSError, ValueError):
            value = None
        if not isinstance(value, dict):
            errors.append(f"checked-in {label} policy is missing or malformed")
            loaded.append(None)
            continue
        if value.get("policyDigest") != supply_chain_semantic_digest(
            value, "policyDigest"
        ):
            errors.append(f"checked-in {label} policy self-digest differs")
        loaded.append(value)
    return loaded[0], loaded[1], errors


def _independent_authority_semantic_errors(
    summary: dict[str, Any],
    primary: dict[str, Any],
    external: dict[str, Any],
    primary_authority: dict[str, Any],
    external_authority: dict[str, Any],
    external_manifest: dict[str, Any],
    independent_policy: dict[str, Any],
    raw_attestation: bytes | None,
    transcript_bytes: bytes | None,
    retained_member_digests: dict[str, str],
) -> list[str]:
    """Recompute receipt, provider-profile, workload, and retained-byte bindings."""

    errors: list[str] = []
    profiles = {
        row.get("profileId"): row
        for row in independent_policy.get("providerProfiles", [])
        if isinstance(row, dict)
    }
    adapters = {
        row.get("adapterId"): row
        for row in independent_policy.get("attestationAdapters", [])
        if isinstance(row, dict)
    }
    for label, authority, receipt, role in (
        ("primary", primary_authority, primary, "candidate-producer"),
        ("external", external_authority, external, "independent-verifier"),
    ):
        for field, expected in (
            ("releaseId", summary.get("releaseId")),
            ("buildVersion", summary.get("buildVersion")),
            ("tag", summary.get("tag")),
            ("sourceCommit", summary.get("sourceCommit")),
            ("executionContractDigest", summary.get("executionContractDigest")),
            (
                "independentReproducibilityPolicyDigest",
                summary.get("independentReproducibilityPolicyDigest"),
            ),
            ("builderRole", role),
        ):
            if authority.get(field) != expected:
                errors.append(f"{label} authority attestation {field} differs")
        binding = authority.get("builderReceipt", {})
        expected_schema = (
            "stable-1.0-builder-receipt-v1.schema.json"
            if role == "candidate-producer"
            else INDEPENDENT_BUILDER_SCHEMA
        )
        if (
            binding.get("sha256")
            != retained_member_digests.get(
                "primaryReceipt" if role == "candidate-producer" else "externalReceipt"
            )
            or binding.get("schema") != expected_schema
        ):
            errors.append(f"{label} authority receipt binding differs")
        profile = profiles.get(authority.get("providerProfileId"))
        identity = authority.get("authorityIdentity", {})
        pipeline = authority.get("pipelineIdentity", {})
        workload = authority.get("workloadIdentity", {})
        artifact = authority.get("artifactAttestation", {})
        if role == "candidate-producer":
            selected_supply = summary.get("selectedRc", {}).get("supplyChain", {})
            expected_definition = (
                "github.com/crypta-network/cryptad/"
                f"{selected_supply.get('workflowPath')}@{selected_supply.get('workflowCommit')}"
            )
            if (
                pipeline.get("definitionId") != expected_definition
                or pipeline.get("runId") != selected_supply.get("runId")
                or pipeline.get("runAttempt") != selected_supply.get("runAttempt")
            ):
                errors.append(
                    "primary authority differs from the selected RC supply-chain authority"
                )
        if (
            not isinstance(profile, dict)
            or profile.get("profileDigest") != authority.get("providerProfileDigest")
            or profile.get("profileDigest")
            != supply_chain_semantic_digest(profile, "profileDigest")
        ):
            errors.append(f"{label} authority provider profile is not policy-authenticated")
        else:
            for field in (
                "providerType",
                "providerId",
                "controlPlaneId",
                "trustDomainId",
                "organizationId",
                "accountId",
                "projectId",
            ):
                if identity.get(field) != profile.get(field):
                    errors.append(f"{label} authority {field} differs from its profile")
            if workload.get("issuer") != profile.get("issuer") or not set(
                profile.get("audiences", [])
            ).issubset(workload.get("audiences", [])):
                errors.append(f"{label} workload issuer or audience differs from policy")
            try:
                if not re.fullmatch(
                    str(profile.get("subjectPattern")), str(workload.get("subject"))
                ) or not re.fullmatch(
                    str(profile.get("pipelineDefinitionPattern")),
                    str(pipeline.get("definitionId")),
                ):
                    errors.append(f"{label} workload or pipeline identity is not policy-authorized")
            except re.error:
                errors.append(f"{label} authority profile contains an invalid identity pattern")
            if pipeline.get("revisionType") != profile.get("pipelineRevisionType"):
                errors.append(f"{label} pipeline revision is not immutable under its profile")
            if artifact.get("adapterId") != profile.get("adapterId"):
                errors.append(f"{label} authority uses a different attestation adapter")
        adapter = adapters.get(artifact.get("adapterId"))
        if (
            not isinstance(adapter, dict)
            or adapter.get("adapterDigest") != artifact.get("adapterDigest")
            or adapter.get("adapterDigest")
            != supply_chain_semantic_digest(adapter, "adapterDigest")
        ):
            errors.append(f"{label} attestation adapter is not policy-authenticated")
        elif (
            artifact.get("format") != adapter.get("attestationFormat")
            or artifact.get("predicateType") != adapter.get("predicateType")
        ):
            errors.append(f"{label} attestation format or predicate differs from policy")
        for nested_name, digest_field in (
            ("authorityIdentity", "authorityIdentityDigest"),
            ("pipelineIdentity", "pipelineIdentityDigest"),
            ("executorIdentity", "executorIdentityDigest"),
            ("receiptProducer", "receiptProducerIdentityDigest"),
        ):
            nested = authority.get(nested_name, {})
            if not isinstance(nested, dict) or nested.get(
                digest_field
            ) != supply_chain_semantic_digest(nested, digest_field):
                errors.append(f"{label} authority {nested_name} self-digest differs")
        if authority.get("receiptProducer", {}).get("workloadSubject") != workload.get(
            "subject"
        ):
            errors.append(f"{label} receipt producer differs from its workload identity")

    if primary_authority.get("evidenceClassification") != "protected-same-provider" or primary_authority.get(
        "operational"
    ) is not False:
        errors.append("primary authority classification is not the protected producer role")
    if external_authority.get("evidenceClassification") != "authenticated-external-provider" or external_authority.get(
        "operational"
    ) is not True:
        errors.append("external authority is self-asserted, fixture, or non-operational")
    external_profile = profiles.get(external_authority.get("providerProfileId"), {})
    external_adapter = adapters.get(
        external_authority.get("artifactAttestation", {}).get("adapterId"), {}
    )
    if not external_profile.get("operationalAllowed") or not external_adapter.get(
        "operationalAllowed"
    ):
        errors.append("external authority profile or adapter is not approved for operations")
    if external_authority.get("verifierKitDigest") != summary.get("verifierKitDigest"):
        errors.append("external authority verifier-kit binding differs")
    if primary_authority.get("verifierKitDigest") is not None:
        errors.append("primary authority must not claim receipt of the verifier kit")
    if (
        external.get("providerProfileId")
        != external_authority.get("providerProfileId")
        or external.get("providerProfileDigest")
        != external_authority.get("providerProfileDigest")
    ):
        errors.append("external receipt and authority provider profile differ")
    receipt_identity = external.get("authorityIdentity", {})
    attested_identity = external_authority.get("authorityIdentity", {})
    for field in (
        "providerType",
        "providerId",
        "controlPlaneId",
        "trustDomainId",
        "organizationId",
        "accountId",
        "projectId",
        "executorControllerId",
        "executorOwnership",
    ):
        if receipt_identity.get(field) != attested_identity.get(field):
            errors.append(f"external receipt and authority {field} differ")
    if receipt_identity.get("workloadIdentityDigest") != external_authority.get(
        "workloadIdentity", {}
    ).get("claimsDigest"):
        errors.append("external receipt and authority workload identity differ")
    pipeline = external_authority.get("pipelineIdentity", {})
    for field in ("runId", "runAttempt", "jobId", "stageId"):
        if receipt_identity.get(field) != pipeline.get(field):
            errors.append(f"external receipt and authority pipeline {field} differ")
    for execution in external.get("builderExecutions", []):
        if not isinstance(execution, dict):
            continue
        for field, expected in (
            ("pipelineDefinitionId", pipeline.get("definitionId")),
            ("pipelineRevision", pipeline.get("immutableRevision")),
            ("runId", pipeline.get("runId")),
            ("runAttempt", pipeline.get("runAttempt")),
        ):
            if execution.get(field) != expected:
                errors.append(
                    f"external builder execution {execution.get('executionId')} {field} differs from authority"
                )
    manifest_binding = external_authority.get("outputManifest", {})
    if (
        manifest_binding.get("sha256")
        != retained_member_digests.get("externalManifest")
        or manifest_binding.get("schema") != INDEPENDENT_OUTPUT_SCHEMA
    ):
        errors.append("external authority output-manifest binding differs")
    if external_authority.get("outputBundle", {}).get("sha256") != summary.get(
        "externalOutputBundleDigest"
    ):
        errors.append("external authority output-bundle binding differs")
    artifact = external_authority.get("artifactAttestation", {})
    if artifact.get("subjectSetDigest") != external_manifest.get("subjectSetDigest"):
        errors.append("external artifact attestation subject set differs from manifest")
    if raw_attestation is None or artifact.get("bundleDigest") != _bytes_digest(
        raw_attestation or b""
    ):
        errors.append("external raw artifact attestation bytes differ")
    if transcript_bytes is None or artifact.get(
        "verificationTranscriptDigest"
    ) != _bytes_digest(transcript_bytes or b""):
        errors.append("external verification transcript bytes differ")
    transcript: Any = None
    if transcript_bytes is not None:
        try:
            transcript = read_json_bytes(
                transcript_bytes, "independent reproducibility verification transcript"
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            transcript = None
    expected_transcript_fields = {
        "schemaVersion",
        "kind",
        "adapterId",
        "adapterDigest",
        "rawBundleDigest",
        "statementDigest",
        "subjectSetDigest",
        "verificationStatus",
        "issuer",
        "subject",
        "audiences",
        "pipelineDefinitionId",
        "pipelineRevision",
        "verifiedAt",
        "transcriptDigest",
    }
    if not isinstance(transcript, dict) or set(transcript) != expected_transcript_fields:
        errors.append("external verification transcript is not a closed adapter result")
    else:
        expected_transcript = {
            "schemaVersion": 1,
            "kind": "stable-1.0-independent-attestation-verification-transcript",
            "adapterId": artifact.get("adapterId"),
            "adapterDigest": artifact.get("adapterDigest"),
            "rawBundleDigest": artifact.get("bundleDigest"),
            "statementDigest": artifact.get("statementDigest"),
            "subjectSetDigest": artifact.get("subjectSetDigest"),
            "verificationStatus": "pass",
            "issuer": external_authority.get("workloadIdentity", {}).get("issuer"),
            "subject": external_authority.get("workloadIdentity", {}).get("subject"),
            "audiences": external_authority.get("workloadIdentity", {}).get("audiences"),
            "pipelineDefinitionId": external_authority.get("pipelineIdentity", {}).get(
                "definitionId"
            ),
            "pipelineRevision": external_authority.get("pipelineIdentity", {}).get(
                "immutableRevision"
            ),
            "verifiedAt": artifact.get("verifiedAt"),
        }
        if any(transcript.get(key) != value for key, value in expected_transcript.items()):
            errors.append("external verification transcript does not bind the retained claims")
        if transcript.get("transcriptDigest") != supply_chain_semantic_digest(
            transcript, "transcriptDigest"
        ):
            errors.append("external verification transcript self-digest differs")
    return errors


def _independent_manifest_and_plan_errors(
    summary: dict[str, Any],
    primary: dict[str, Any],
    external: dict[str, Any],
    manifest: dict[str, Any],
    plan: dict[str, Any],
    supply_chain_policy: dict[str, Any],
) -> list[str]:
    """Derive the retained output manifest and comparison plan from both receipts."""

    errors: list[str] = []
    for field, expected in (
        ("releaseId", summary.get("releaseId")),
        ("buildVersion", summary.get("buildVersion")),
        ("tag", summary.get("tag")),
        ("sourceCommit", summary.get("sourceCommit")),
        ("executionContractDigest", summary.get("executionContractDigest")),
        ("verifierKitDigest", summary.get("verifierKitDigest")),
        ("builderReceiptDigest", external.get("receiptDigest")),
        ("providerProfileDigest", external.get("providerProfileDigest")),
        ("sourceTreeDigest", external.get("source", {}).get("treeDigest")),
        ("materialsDigest", external.get("materialsDigest")),
        ("resolutionSnapshotDigest", external.get("resolutionSnapshotDigest")),
    ):
        if manifest.get(field) != expected:
            errors.append(f"external output manifest {field} differs")
    if manifest.get("taskSetDigest") != _semantic_digest(external.get("buildTasks")):
        errors.append("external output manifest task-set digest differs")
    if manifest.get("canonicalEnvironmentDigest") != _semantic_digest(
        external.get("canonicalEnvironment")
    ):
        errors.append("external output manifest environment digest differs")
    rules = {
        row.get("subjectKey"): row
        for row in supply_chain_policy.get("releaseSubjects", [])
        if isinstance(row, dict) and row.get("evidencePhase") == "independent-builder"
    }
    primary_subjects = {row.get("subjectKey"): row for row in primary.get("subjects", [])}
    external_subjects = {row.get("subjectKey"): row for row in external.get("subjects", [])}
    expected_manifest_rows: list[dict[str, Any]] = []
    expected_plan_rows: list[dict[str, Any]] = []
    for key in sorted(rules):
        first = primary_subjects.get(key, {})
        second = external_subjects.get(key, {})
        rule = rules[key]
        expected_manifest_rows.append(
            {
                "subjectKey": key,
                "fileName": second.get("fileName"),
                "bundlePath": f"subjects/{second.get('fileName')}",
                "digest": second.get("digest"),
                "size": second.get("size"),
                "reproducibilityClass": rule.get("reproducibilityClass"),
                "normalizationRuleId": rule.get("normalizationRuleId"),
                "payloadManifestDigest": second.get("payloadManifestDigest"),
                "extractionEvidenceDigest": second.get("extractionEvidenceDigest"),
            }
        )
        expected_plan_rows.append(
            {
                "subjectKey": key,
                "fileName": first.get("fileName"),
                "reproducibilityClass": rule.get("reproducibilityClass"),
                "normalizationRuleId": rule.get("normalizationRuleId"),
                "primaryDigest": first.get("digest"),
                "verifierDigest": second.get("digest"),
                "primarySize": first.get("size"),
                "verifierSize": second.get("size"),
                "primaryPayloadManifestDigest": first.get("payloadManifestDigest"),
                "verifierPayloadManifestDigest": second.get("payloadManifestDigest"),
            }
        )
    if manifest.get("subjects") != expected_manifest_rows:
        errors.append("external output manifest subjects differ from the retained receipt")
    projection_fields = (
        "subjectKey",
        "fileName",
        "bundlePath",
        "digest",
        "size",
        "reproducibilityClass",
        "normalizationRuleId",
        "payloadManifestDigest",
        "extractionEvidenceDigest",
    )
    projection = [
        {field: row.get(field) for field in projection_fields}
        for row in manifest.get("subjects", [])
        if isinstance(row, dict)
    ]
    if manifest.get("subjectSetDigest") != _semantic_digest(projection):
        errors.append("external output manifest subject-set digest differs")
    normalized_keys = sorted(
        key
        for key, rule in rules.items()
        if rule.get("reproducibilityClass") == "normalized-payload-identical"
    )
    payload_rows = manifest.get("payloadManifests", [])
    if [row.get("subjectKey") for row in payload_rows if isinstance(row, dict)] != normalized_keys:
        errors.append("external output manifest payload bindings are incomplete")
    for row in payload_rows:
        if not isinstance(row, dict):
            continue
        key = row.get("subjectKey")
        if (
            row.get("bundlePath") != f"payload-manifests/{key}.json"
            or row.get("manifestDigest")
            != external_subjects.get(key, {}).get("payloadManifestDigest")
        ):
            errors.append(f"external payload-manifest binding differs for {key}")
    expected_plan = {
        "schemaVersion": 1,
        "kind": "stable-1.0-rebuild-comparison-plan",
        "releaseId": summary.get("releaseId"),
        "buildVersion": summary.get("buildVersion"),
        "tag": summary.get("tag"),
        "sourceCommit": summary.get("sourceCommit"),
        "sourceRef": summary.get("sourceRef"),
        "policyDigest": summary.get("stableSupplyChainPolicyDigest"),
        "componentInventoryDigest": summary.get("componentInventoryDigest"),
        "subjectInventoryDigest": summary.get("subjectInventoryDigest"),
        "primaryBuilderReceiptDigest": primary.get("receiptDigest"),
        "verifierBuilderReceiptDigest": external.get("receiptDigest"),
        "comparisons": expected_plan_rows,
        "equalityInferred": False,
        "planDigest": plan.get("planDigest"),
    }
    expected_plan["planDigest"] = supply_chain_semantic_digest(
        expected_plan, "planDigest"
    )
    if plan != expected_plan:
        errors.append("comparison plan was not derived from the exact retained receipts")
    return errors


def _independent_reproducibility_errors(
    workspace: Path,
    contract: dict[str, Any],
    policy: dict[str, Any],
    result_binding: dict[str, Any],
    authenticated_selected_freeze: dict[str, Any] | None,
) -> list[str]:
    """Authenticate provider-distinct PR-292 evidence and its retained artifact."""

    errors: list[str] = []
    supply_chain_policy, independent_policy, policy_errors = (
        _independent_checked_in_policies(workspace)
    )
    errors.extend(policy_errors)
    summary_path, summary, binding_errors = _file_binding_errors(
        workspace, result_binding, "independent reproducibility summary"
    )
    errors.extend(binding_errors)
    if result_binding.get("schema") != INDEPENDENT_SUMMARY_SCHEMA:
        errors.append("independent reproducibility summary schema differs")
    if not isinstance(summary, dict):
        return [*errors, "independent reproducibility summary is missing or malformed"]
    from .stable_1_0_independent_reproducibility import independent_summary_errors

    summary_schema_valid = not validate_schema(summary, INDEPENDENT_SUMMARY_SCHEMA)
    errors.extend(independent_summary_errors(summary))
    if summary.get("status") not in {
        "authenticated-external-build",
        "independently-reproduced",
    } or type(summary.get("operational")) is not bool:
        errors.append(
            "independent reproducibility is not authenticated operational success or an authenticated external comparison"
        )
    if (
        summary.get("fixture")
        or summary.get("selfTest")
        or summary.get("publicVerification") != "not-performed"
    ):
        errors.append("fixture, self-test, or public claims cannot satisfy protected closeout")
    coordinator_claim = summary.get("coordinator")
    if not isinstance(coordinator_claim, dict):
        return [*errors, "independent reproducibility lacks protected coordinator identity"]
    coordinator = contract["operationEvidence"].get(
        "independentReproducibilityCoordinate"
    )
    if not isinstance(coordinator, dict):
        return [*errors, "independent reproducibility lacks one protected coordinator authority"]
    for field in (
        "repository",
        "workflowPath",
        "workflowCommit",
        "runId",
        "runAttempt",
        "artifactName",
        "environment",
    ):
        claimed = coordinator_claim.get(field)
        authenticated = coordinator.get(field)
        if field == "runAttempt":
            authenticated = int(authenticated) if str(authenticated).isdigit() else authenticated
        if claimed != authenticated:
            errors.append(f"independent reproducibility coordinator {field} differs")
    errors.extend(
        _coordinate_errors(
            coordinator,
            workflow=".github/workflows/stable-1.0-independent-reproducibility.yml",
            environment="stable-1.0-independent-reproducibility-external-receipt",
            commit=contract["repository"]["candidateCommit"],
            label="independent reproducibility coordinator",
        )
    )
    errors.extend(
        _github_actions_coordinate_errors(
            coordinator,
            label="independent reproducibility coordinator",
            required_job_name="Authenticate and compare independent rebuild",
        )
    )
    archive_binding = contract["operationEvidence"].get("independentReproducibilityArtifact")
    errors.extend(
        _retained_artifact_member_errors(
            workspace,
            archive_binding,
            coordinator,
            label="independent reproducibility",
            expected_members={
                "stable-1.0-independent-reproducibility-summary.json": result_binding,
            },
        )
    )
    if isinstance(archive_binding, dict) and coordinator.get("artifactDigest") != archive_binding.get("sha256"):
        errors.append("independent reproducibility coordinator artifact digest differs")

    member_contract = {
        "plan": ("stable-1.0-rebuild-comparison-plan.json", REPRODUCIBILITY_PLAN_SCHEMA, "planDigest"),
        "result": ("stable-1.0-reproducibility-report.json", REPRODUCIBILITY_SCHEMA, "resultDigest"),
        "primaryReceipt": ("stable-1.0-primary-builder-receipt.json", "stable-1.0-builder-receipt-v1.schema.json", "receiptDigest"),
        "primaryAuthority": ("stable-1.0-primary-authority-attestation.json", INDEPENDENT_AUTHORITY_SCHEMA, "attestationDigest"),
        "externalReceipt": ("stable-1.0-independent-builder-receipt.json", INDEPENDENT_BUILDER_SCHEMA, "receiptDigest"),
        "externalAuthority": ("stable-1.0-independent-builder-attestation.json", INDEPENDENT_AUTHORITY_SCHEMA, "attestationDigest"),
        "externalManifest": ("stable-1.0-independent-output-manifest.json", INDEPENDENT_OUTPUT_SCHEMA, "manifestDigest"),
    }
    members: dict[str, dict[str, Any]] = {}
    schema_valid_members: set[str] = set()
    retained_member_digests: dict[str, str] = {}
    for key, (name, schema_name, digest_field) in member_contract.items():
        raw, member_errors = _retained_artifact_member(
            workspace, archive_binding, name, label="independent reproducibility"
        )
        errors.extend(member_errors)
        if raw is None:
            continue
        retained_member_digests[key] = _bytes_digest(raw)
        try:
            value = read_json_bytes(raw, f"independent reproducibility {name}")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            errors.append(f"independent reproducibility member {name} is not strict JSON")
            continue
        if not isinstance(value, dict):
            errors.append(f"independent reproducibility member {name} is not an object")
            continue
        members[key] = value
        member_schema_errors = validate_schema(value, schema_name)
        errors.extend(member_schema_errors)
        if not member_schema_errors:
            schema_valid_members.add(key)
        if value.get(digest_field) != supply_chain_semantic_digest(value, digest_field):
            errors.append(f"independent reproducibility member {name} self-digest differs")
    raw_attestation, raw_errors = _retained_artifact_member(
        workspace,
        archive_binding,
        "stable-1.0-independent-raw-artifact-attestation.bundle",
        label="independent reproducibility",
    )
    errors.extend(raw_errors)
    transcript_bytes, transcript_errors = _retained_artifact_member(
        workspace,
        archive_binding,
        "stable-1.0-independent-attestation-verification-transcript.json",
        label="independent reproducibility",
    )
    errors.extend(transcript_errors)
    selected_supply_bytes, selected_supply_errors = _retained_artifact_member(
        workspace, archive_binding, "stable-1.0-selected-rc-supply-chain-coordinate.json",
        label="independent reproducibility")
    errors.extend(selected_supply_errors)
    selected_supply: dict[str, Any] | None = None
    if selected_supply_bytes is not None:
        try:
            loaded_supply = read_json_bytes(selected_supply_bytes,
                "independent reproducibility selected RC supply-chain coordinate")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            loaded_supply = None
        if isinstance(loaded_supply, dict) and set(loaded_supply) == {
            "runId", "runAttempt", "artifactName", "artifactDigest"}:
            selected_supply = loaded_supply
        else:
            errors.append("selected RC supply-chain coordinate is malformed")

    plan = members.get("plan")
    result = members.get("result")
    release_identity = {
        "releaseId": contract["release"]["id"],
        "buildVersion": int(contract["release"]["integerBuild"]),
        "tag": f"v{contract['release']['integerBuild']}",
        "sourceCommit": contract["repository"]["candidateCommit"],
        "sourceRef": f"commit:{contract['repository']['candidateCommit']}",
        "policyDigest": summary.get("stableSupplyChainPolicyDigest"),
    }
    if plan is not None and result is not None:
        from .stable_1_0_supply_chain_reproducibility import reproducibility_result_errors

        errors.extend(reproducibility_result_errors(result, release_identity, plan))
        if result.get("status") != "pass" or result.get("unexplainedDifferences") != 0:
            errors.append("independent reproducibility comparison did not pass exactly")
    else:
        errors.append("independent reproducibility lacks its plan or result")
    digest_bindings = {
        "comparisonPlanDigest": ("plan", "planDigest"),
        "reproducibilityResultDigest": ("result", "resultDigest"),
        "primaryBuilderReceiptDigest": ("primaryReceipt", "receiptDigest"),
        "primaryAuthorityAttestationDigest": ("primaryAuthority", "attestationDigest"),
        "externalBuilderReceiptDigest": ("externalReceipt", "receiptDigest"),
        "externalAuthorityAttestationDigest": ("externalAuthority", "attestationDigest"),
        "externalOutputManifestDigest": ("externalManifest", "manifestDigest"),
    }
    for summary_field, (member_key, member_field) in digest_bindings.items():
        if summary.get(summary_field) != members.get(member_key, {}).get(member_field):
            errors.append(f"independent reproducibility summary {summary_field} differs")
    external_authority = members.get("externalAuthority", {})
    if (
        external_authority.get("builderRole") != "independent-verifier"
        or external_authority.get("evidenceClassification") != "authenticated-external-provider"
        or external_authority.get("operational") is not True
    ):
        errors.append("external authority member is self-asserted, fixture, or non-operational")
    artifact_attestation = external_authority.get("artifactAttestation", {})
    if raw_attestation is None or artifact_attestation.get("bundleDigest") != _bytes_digest(raw_attestation):
        errors.append("external raw artifact attestation bytes differ")
    if transcript_bytes is None or artifact_attestation.get("verificationTranscriptDigest") != _bytes_digest(transcript_bytes or b""):
        errors.append("external verification transcript bytes differ")
    elif transcript_bytes is not None:
        try:
            transcript = read_json_bytes(
                transcript_bytes,
                "independent reproducibility verification transcript",
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            transcript = None
        if not isinstance(transcript, dict) or transcript.get("verificationStatus") != "pass":
            errors.append("external verification transcript is malformed or did not pass")
    if members.get("primaryAuthority", {}).get("builderRole") != "candidate-producer":
        errors.append("primary authority member has the wrong role")
    summary_supply = summary.get("selectedRc", {}).get("supplyChain")
    summary_supply_projection = (
        {field: summary_supply.get(field) for field in selected_supply}
        if isinstance(summary_supply, dict) and isinstance(selected_supply, dict) else None)
    if selected_supply != summary_supply_projection:
        errors.append("selected RC retained a different supply-chain authority")
    if (
        summary_schema_valid
        and isinstance(supply_chain_policy, dict)
        and isinstance(independent_policy, dict)
        and all(
            key in schema_valid_members
            for key in (
                "plan",
                "primaryReceipt",
                "primaryAuthority",
                "externalReceipt",
                "externalAuthority",
                "externalManifest",
            )
        )
    ):
        primary_receipt = members["primaryReceipt"]
        external_receipt = members["externalReceipt"]
        primary_authority = members["primaryAuthority"]
        external_authority = members["externalAuthority"]
        external_manifest = members["externalManifest"]
        errors.extend(
            _independent_receipt_semantic_errors(
                summary,
                primary_receipt,
                external_receipt,
                supply_chain_policy,
                independent_policy,
            )
        )
        errors.extend(
            _independent_authority_semantic_errors(
                summary,
                primary_receipt,
                external_receipt,
                primary_authority,
                external_authority,
                external_manifest,
                independent_policy,
                raw_attestation,
                transcript_bytes,
                retained_member_digests,
            )
        )
        errors.extend(
            _independent_manifest_and_plan_errors(
                summary,
                primary_receipt,
                external_receipt,
                external_manifest,
                members["plan"],
                supply_chain_policy,
            )
        )
        try:
            from .stable_1_0_independent_reproducibility import (
                _independence_evaluation,
            )

            expected_independence, independence_errors = _independence_evaluation(
                primary_authority,
                external_authority,
                {
                    "expectedVerifierAuthority": {
                        "requireProviderDistinct": True,
                        "requireControlPlaneDistinct": True,
                        "requireTrustDomainDistinct": True,
                        "requireOrganizationDistinct": bool(
                            summary.get("providerIndependence", {}).get(
                                "organizationIndependenceRequired"
                            )
                        ),
                    }
                },
            )
            errors.extend(independence_errors)
            if summary.get("providerIndependence") != expected_independence:
                errors.append(
                    "provider-independence evaluation was not derived from retained authorities"
                )
        except (KeyError, TypeError, ValueError):
            errors.append("retained provider authorities cannot be independently evaluated")
    if authenticated_selected_freeze is None:
        errors.append("independent reproducibility lacks an authenticated selected RC freeze")
    else:
        selected = summary.get("selectedRc", {})
        if selected.get("freezeFileDigest") != authenticated_selected_freeze.get("freezeFileDigest"):
            errors.append("independent reproducibility binds a different selected RC freeze")
        if selected.get("productDigest") != authenticated_selected_freeze.get("productDistributionDigest"):
            errors.append("independent reproducibility binds different selected RC product bytes")
    timing = summary.get("timing", {})
    try:
        if _timestamp(str(timing.get("externalOutputsSealedAt"))) >= _timestamp(
            str(timing.get("candidateInputsAvailableAt"))
        ):
            errors.append("candidate inputs were available before external outputs were sealed")
    except ValueError:
        errors.append("independent reproducibility withholding timing is malformed")
    if summary_path is None:
        errors.append("independent reproducibility extracted evidence is incomplete")
    return sorted(set(errors))


def _ga_publication_receipt_errors(
    receipt: dict[str, Any],
    contract: dict[str, Any],
    coordinate: dict[str, Any] | None,
    authorization_document: dict[str, Any] | None,
    promotion_plan: dict[str, Any] | None,
    promotion_identity_digest: str | None,
) -> list[str]:
    """Authenticate contract-visible fields of the canonical Stable GA receipt."""

    errors = validate_schema(receipt, GA_PUBLICATION_RECEIPT_SCHEMA)
    selected = contract["ga"]["selectedRc"]
    if selected is None:
        return [*errors, "GA publication receipt has no selected RC binding"]
    release = contract["release"]
    commit = contract["repository"]["candidateCommit"]
    targets = contract["publicTargets"]
    expected = {
        "releaseId": release["id"],
        "buildVersion": release["integerBuild"],
        "sourceCommit": commit,
        "publicationState": "publication-complete",
        "artifactBaseUri": targets["artifactBaseUri"],
        "freezeDigest": selected["freezeDigest"],
        "productDistributionDigest": selected["productDigest"],
        "archiveDigest": selected["archiveDigest"],
        "gaPromotionSummaryDigest": promotion_identity_digest,
        "finalVerificationStatus": "pass",
    }
    for field, expected_value in expected.items():
        if receipt.get(field) != expected_value:
            errors.append(f"GA publication receipt {field} differs from the execution contract")
    if receipt.get("operation") not in {"created", "verified-existing"}:
        errors.append("GA publication receipt is not a completed idempotent operation")
    if "failureCategory" in receipt:
        errors.append("completed GA publication receipt contains a failure category")

    tag = receipt.get("tag") if isinstance(receipt.get("tag"), dict) else {}
    if tag != {
        "name": f"v{release['integerBuild']}",
        "targetCommit": commit,
        "annotated": True,
        "verificationStatus": "pass",
    }:
        errors.append("GA publication receipt tag differs from the exact candidate")
    github_release = (
        receipt.get("githubRelease")
        if isinstance(receipt.get("githubRelease"), dict)
        else {}
    )
    expected_release_url = (
        "https://github.com/crypta-network/cryptad/releases/tag/"
        f"v{release['integerBuild']}"
    )
    if (
        github_release.get("publicUrl") != expected_release_url
        or github_release.get("releaseNotesDigest") != receipt.get("releaseNotesDigest")
        or github_release.get("verificationStatus") != "pass"
    ):
        errors.append("GA publication receipt GitHub Release identity differs from the plan")

    if coordinate is None:
        errors.append("GA publication receipt has no workflow coordinate")
    else:
        workflow = receipt.get("workflow") if isinstance(receipt.get("workflow"), dict) else {}
        if (
            workflow.get("repository") != coordinate["repository"]
            or workflow.get("runId") != int(coordinate["runId"])
            or workflow.get("runAttempt") != int(coordinate["runAttempt"])
            or workflow.get("environment") != coordinate["environment"]
        ):
            errors.append("GA publication receipt workflow differs from the exact protected run")
        expected_artifact = (
            f"stable-1-0-ga-publication-receipt-{release['id']}-"
            f"{release['integerBuild']}-{coordinate['runId']}-{coordinate['runAttempt']}"
        )
        if coordinate["artifactName"] != expected_artifact:
            errors.append("GA publication receipt artifact name is not canonical for its run")

    assets = [row for row in receipt.get("assets", []) if isinstance(row, dict)]
    expected_asset_names = {
        f"cryptad-stable-1.0-rc-{release['integerBuild']}.tar.gz",
        f"crypta-stable-1.0-rc-{release['integerBuild']}-product.tar.gz",
        "stable-1.0-ga-release-notes.md",
        "stable-1.0-ga-known-limitations.json",
        "stable-1.0-ga-provenance.json",
        "stable-1.0-maintenance-baseline.json",
        "stable-1.0-ga-checksums.txt",
    }
    asset_names = [row.get("name") for row in assets]
    if len(asset_names) != len(set(asset_names)) or set(asset_names) != expected_asset_names:
        errors.append("GA publication receipt asset allowlist is incomplete or unexpected")
    for row in assets:
        if (
            row.get("verificationStatus") != "pass"
            or row.get("publicUri") != f"{targets['artifactBaseUri']}{row.get('name', '')}"
        ):
            errors.append("GA publication receipt asset URI or verification status is invalid")
            break
    expected_asset_digests = {
        f"cryptad-stable-1.0-rc-{release['integerBuild']}.tar.gz": selected["archiveDigest"],
        f"crypta-stable-1.0-rc-{release['integerBuild']}-product.tar.gz": selected["productDigest"],
        "stable-1.0-ga-release-notes.md": receipt.get("releaseNotesDigest"),
    }
    actual_asset_digests = {row.get("name"): row.get("digest") for row in assets}
    for name, expected_digest in expected_asset_digests.items():
        if actual_asset_digests.get(name) != expected_digest:
            errors.append(f"GA publication receipt asset {name} has the wrong digest")
    if promotion_plan is None:
        errors.append("GA publication receipt lacks an authenticated GA publication plan")
    else:
        planned_assets = {
            row.get("name"): (row.get("digest"), row.get("sizeBytes"))
            for row in promotion_plan.get("assets", [])
            if isinstance(row, dict)
        }
        receipt_assets = {
            row.get("name"): (row.get("digest"), row.get("sizeBytes"))
            for row in assets
        }
        if receipt_assets != planned_assets:
            errors.append("GA publication receipt assets differ from the authenticated plan")

    catalog = receipt.get("catalog") if isinstance(receipt.get("catalog"), dict) else {}
    primary = catalog.get("primary") if isinstance(catalog.get("primary"), dict) else {}
    mirrors = [row for row in catalog.get("mirrors", []) if isinstance(row, dict)]
    rollback = catalog.get("rollback") if isinstance(catalog.get("rollback"), dict) else {}
    if (
        catalog.get("channel") != "stable"
        or catalog.get("signingKeyId")
        != contract["authorities"]["keyIdentities"]["catalogSigningKeyId"]
        or catalog.get("verificationStatus") != "pass"
        or primary.get("publicUri") != targets["catalogPrimaryUri"]
        or primary.get("digest") != catalog.get("catalogDigest")
        or primary.get("signatureVerified") is not True
        or primary.get("verificationStatus") != "pass"
        or [row.get("publicUri") for row in mirrors] != targets["catalogMirrorUris"]
        or any(
            row.get("digest") != catalog.get("catalogDigest")
            or row.get("signatureVerified") is not True
            or row.get("verificationStatus") != "pass"
            for row in mirrors
        )
        or rollback.get("publicUri") != targets["catalogRollbackUri"]
        or rollback.get("signatureVerified") is not True
        or rollback.get("verificationStatus") != "pass"
    ):
        errors.append("GA publication receipt catalog identity differs from the exact targets")
    if authorization_document is None:
        errors.append("GA publication receipt lacks an authenticated authorization document")
    elif (
        catalog.get("catalogDigest") != selected.get("catalogDigest")
        or catalog.get("revision") != selected.get("catalogRevision")
        or catalog.get("catalogDigest") != authorization_document.get("catalogDigest")
        or catalog.get("revision") != authorization_document.get("catalogRevision")
    ):
        errors.append("GA publication receipt catalog differs from the authorized catalog")
    if promotion_plan is not None:
        planned_catalog = (
            promotion_plan.get("catalog")
            if isinstance(promotion_plan.get("catalog"), dict)
            else {}
        )
        planned_primary = (
            planned_catalog.get("primary")
            if isinstance(planned_catalog.get("primary"), dict)
            else {}
        )
        planned_mirrors = [
            row
            for row in planned_catalog.get("mirrors", [])
            if isinstance(row, dict)
        ]
        if (
            catalog.get("catalogId") != planned_catalog.get("catalogId")
            or catalog.get("revision") != planned_catalog.get("revision")
            or catalog.get("catalogDigest") != planned_catalog.get("catalogDigest")
            or catalog.get("signatureDigest")
            != planned_catalog.get("signatureDigest")
            or catalog.get("signingKeyId") != planned_catalog.get("signingKeyId")
            or primary.get("publicUri") != planned_primary.get("publicUri")
            or [row.get("publicUri") for row in mirrors]
            != [row.get("publicUri") for row in planned_mirrors]
            or rollback.get("publicUri") != planned_catalog.get("rollbackUri")
            or rollback.get("revision") != planned_catalog.get("rollbackRevision")
            or rollback.get("digest") != planned_catalog.get("rollbackDigest")
            or rollback.get("signingKeyId") != planned_catalog.get("signingKeyId")
        ):
            errors.append("GA publication receipt catalog differs from the authenticated plan")
    try:
        if authorization_document is not None and not (
            _timestamp(str(authorization_document.get("approvedAt")))
            <= _timestamp(str(receipt.get("publishedAt")))
            < _timestamp(str(authorization_document.get("expiresAt")))
        ):
            errors.append("GA publication occurred outside the authorization window")
        if _timestamp(str(receipt.get("publishedAt"))) > _timestamp(
            str(receipt.get("generatedAt"))
        ):
            errors.append("GA publication receipt predates its claimed publication")
    except ValueError:
        errors.append("GA publication receipt or authorization timestamp is malformed")
    public_state = (
        receipt.get("publicStateObservation")
        if isinstance(receipt.get("publicStateObservation"), dict)
        else {}
    )
    asset_observation = (
        public_state.get("releaseAssets")
        if isinstance(public_state.get("releaseAssets"), dict)
        else {}
    )
    if (
        asset_observation.get("observedCount") != len(expected_asset_names)
        or asset_observation.get("missingPlannedAssets") != []
        or asset_observation.get("unexpectedCount") != 0
        or asset_observation.get("unexpectedNameDigests") != []
    ):
        errors.append("GA publication receipt public asset observation is incomplete")
    redaction = receipt.get("redaction") if isinstance(receipt.get("redaction"), dict) else {}
    if (
        redaction.get("status") != "pass"
        or redaction.get("findingCount") != 0
        or redaction.get("findings") != []
    ):
        errors.append("GA publication receipt redaction status is not passing")
    if scan_value(receipt) or placeholder_findings(receipt):
        errors.append("GA publication receipt contains redaction findings or placeholders")
    return sorted(set(errors))


def _ga_promotion_plan_errors(
    plan: dict[str, Any],
    contract: dict[str, Any],
    authorization_document: dict[str, Any] | None,
    promotion_identity_digest: str | None,
    freeze_record: dict[str, Any] | None,
) -> list[str]:
    """Bind the retained canonical GA plan to the selected RC and authorization."""

    errors = validate_schema(plan, GA_PUBLICATION_PLAN_SCHEMA)
    selected = contract["ga"]["selectedRc"]
    if not isinstance(selected, dict):
        return [*errors, "GA publication plan has no selected RC binding"]
    release = contract["release"]
    targets = contract["publicTargets"]
    expected = {
        "releaseId": release["id"],
        "buildVersion": release["integerBuild"],
        "sourceCommit": contract["repository"]["candidateCommit"],
        "expectedTag": f"v{release['integerBuild']}",
        "expectedReleaseBranch": f"release/{release['integerBuild']}",
        "artifactBaseUri": targets["artifactBaseUri"],
        "publicationTargetsDigest": _semantic_digest(
            _canonical_publication_targets(contract)
        ),
        "publicationState": "publication-authorized",
        "promotionIdentityDigest": promotion_identity_digest,
        "sideEffectsPerformed": False,
    }
    for field, expected_value in expected.items():
        if plan.get(field) != expected_value:
            errors.append(f"GA publication plan {field} differs from the execution contract")

    assets = [row for row in plan.get("assets", []) if isinstance(row, dict)]
    assets_by_role = {row.get("role"): row for row in assets}
    expected_roles = {
        "rc-archive",
        "rc-product",
        "release-notes",
        "known-limitations",
        "provenance",
        "maintenance-baseline",
        "checksums",
    }
    if len(assets_by_role) != len(assets) or set(assets_by_role) != expected_roles:
        errors.append("GA publication plan does not contain the exact canonical asset roles")
    elif (
        assets_by_role["rc-archive"].get("digest") != selected["archiveDigest"]
        or assets_by_role["rc-product"].get("digest") != selected["productDigest"]
        or assets_by_role["rc-archive"].get("sourceKind") != "immutable-rc"
        or assets_by_role["rc-product"].get("sourceKind") != "immutable-rc"
    ):
        errors.append("GA publication plan substitutes the selected RC bytes")

    catalog = plan.get("catalog") if isinstance(plan.get("catalog"), dict) else {}
    primary = catalog.get("primary") if isinstance(catalog.get("primary"), dict) else {}
    mirrors = [row for row in catalog.get("mirrors", []) if isinstance(row, dict)]
    if (
        catalog.get("signingKeyId")
        != contract["authorities"]["keyIdentities"]["catalogSigningKeyId"]
        or primary.get("publicUri") != targets["catalogPrimaryUri"]
        or [row.get("publicUri") for row in mirrors] != targets["catalogMirrorUris"]
        or catalog.get("rollbackUri") != targets["catalogRollbackUri"]
    ):
        errors.append("GA publication plan catalog targets differ from the execution contract")
    if authorization_document is None:
        errors.append("GA publication plan lacks an authenticated authorization document")
    elif (
        catalog.get("catalogDigest") != selected.get("catalogDigest")
        or catalog.get("revision") != selected.get("catalogRevision")
        or catalog.get("catalogDigest") != authorization_document.get("catalogDigest")
        or catalog.get("revision") != authorization_document.get("catalogRevision")
    ):
        errors.append("GA publication plan catalog differs from the authorized catalog")
    frozen_catalog = (
        freeze_record.get("stableCatalog")
        if isinstance(freeze_record, dict)
        and isinstance(freeze_record.get("stableCatalog"), dict)
        else {}
    )
    frozen_rollback = (
        frozen_catalog.get("verifiedRollback")
        if isinstance(frozen_catalog.get("verifiedRollback"), dict)
        else {}
    )
    if (
        catalog.get("catalogId") != frozen_catalog.get("catalogId")
        or catalog.get("revision") != frozen_catalog.get("revision")
        or catalog.get("catalogDigest") != frozen_catalog.get("catalogDigest")
        or catalog.get("signatureDigest") != frozen_catalog.get("signatureDigest")
        or catalog.get("signingKeyId") != frozen_catalog.get("catalogSigningKeyId")
        or catalog.get("rollbackRevision") != frozen_rollback.get("revision")
        or catalog.get("rollbackDigest") != frozen_rollback.get("digest")
    ):
        errors.append("GA publication plan catalog differs from the authenticated RC freeze")
    if scan_value(plan) or placeholder_findings(plan):
        errors.append("GA publication plan contains redaction findings or placeholders")
    return sorted(set(errors))


def _ga_validation_identity_errors(
    identity: dict[str, Any],
    contract: dict[str, Any],
    lineage_digest: str | None,
    selected_freeze: dict[str, Any] | None,
    authorization_document: dict[str, Any] | None,
    freeze_record: dict[str, Any] | None,
    ga_validation: dict[str, Any] | None,
    post_freeze_validation: dict[str, Any] | None,
    post_freeze_validation_digest: str | None,
    checksums_digest: str | None,
    provenance_digest: str | None,
) -> list[str]:
    """Authenticate the existing GA authorization identity against prior authorities."""

    errors = validate_schema(identity, GA_VALIDATION_IDENTITY_SCHEMA)
    selected = contract["ga"]["selectedRc"]
    if (
        not isinstance(selected, dict)
        or not isinstance(selected_freeze, dict)
        or not isinstance(freeze_record, dict)
        or not isinstance(ga_validation, dict)
        or not isinstance(post_freeze_validation, dict)
    ):
        return [*errors, "GA validation identity lacks an authenticated selected RC"]
    expected_targets = _canonical_publication_targets(contract)
    post_freeze_record = (
        ga_validation.get("postFreezeValidation")
        if isinstance(ga_validation.get("postFreezeValidation"), dict)
        else {}
    )
    upgrade = (
        post_freeze_validation.get("scenarios", {}).get(
            "upgradeRollbackStatePreservation"
        )
        if isinstance(post_freeze_validation.get("scenarios"), dict)
        and isinstance(
            post_freeze_validation.get("scenarios", {}).get(
                "upgradeRollbackStatePreservation"
            ),
            dict,
        )
        else {}
    )
    predecessor = {
        "releaseId": upgrade.get("previousReleaseId"),
        "buildVersion": upgrade.get("previousBuildVersion"),
        "previousCandidateDigest": upgrade.get("previousCandidateDigest"),
        "productDistributionDigest": upgrade.get("previousProductDigest"),
    }
    expected = {
        "releaseId": contract["release"]["id"],
        "buildVersion": contract["release"]["integerBuild"],
        "sourceCommit": contract["repository"]["candidateCommit"],
        "sourceRef": contract["repository"]["sourceRef"],
        "lineageDigest": lineage_digest,
        "freezeDigest": selected["freezeDigest"],
        "freezeFileDigest": selected_freeze.get("freezeFileDigest"),
        "archiveDigest": selected["archiveDigest"],
        "productDistributionDigest": selected["productDigest"],
        "checksumsDigest": checksums_digest,
        "provenanceDigest": provenance_digest,
        "postFreezeValidationDigest": post_freeze_validation_digest,
        "postFreezeValidationGeneratedAt": post_freeze_validation.get("generatedAt"),
        "requiredUpgradePredecessor": predecessor,
        "catalogDigest": selected["catalogDigest"],
        "catalogRevision": selected["catalogRevision"],
        "platformApiDigest": _semantic_digest(freeze_record.get("platformApi")),
        "firstPartyAppsDigest": _semantic_digest(freeze_record.get("firstPartyApps")),
        "contentProfilesDigest": _semantic_digest(
            freeze_record.get("contentFormatProfiles")
        ),
        "limitationsDigest": _semantic_digest(
            freeze_record.get("limitationsAndPolicy")
        ),
        "publicationTargets": expected_targets,
        "publicationTargetsDigest": _semantic_digest(expected_targets),
    }
    for field, expected_value in expected.items():
        if identity.get(field) != expected_value:
            errors.append(f"GA validation identity {field} differs from prior authorities")
    if post_freeze_record.get("requiredUpgradePredecessor") != predecessor:
        errors.append(
            "GA validation required upgrade predecessor differs from post-freeze evidence"
        )
    if post_freeze_record.get("validationDigest") != post_freeze_validation_digest:
        errors.append(
            "GA validation post-freeze digest differs from the retained validation evidence"
        )
    payload = identity.get("payloadIdentity") if isinstance(identity.get("payloadIdentity"), dict) else {}
    if payload != {
        "rcProductDigest": selected["productDigest"],
        "gaProductDigest": selected["productDigest"],
        "bitIdentical": True,
        "rebuildPerformed": False,
    }:
        errors.append("GA validation identity does not prove exact-byte no-rebuild promotion")
    if authorization_document is None:
        errors.append("GA validation identity lacks an authenticated authorization document")
    elif (
        identity.get("catalogDigest") != authorization_document.get("catalogDigest")
        or identity.get("catalogRevision") != authorization_document.get("catalogRevision")
        or authorization_document.get("gaValidationDigest") != _semantic_digest(identity)
    ):
        errors.append("GA validation identity differs from the exact authorization")
    return sorted(set(errors))


def _ga_promotion_identity_digest(identity: dict[str, Any]) -> str:
    """Reconstruct the canonical Stable GA promotion identity from authenticated input."""

    promotion_identity = {
        "schemaVersion": 1,
        "kind": "stable-1.0-ga-promotion-identity",
        "stableMilestone": "1.0",
        "releaseId": identity.get("releaseId"),
        "buildVersion": identity.get("buildVersion"),
        "expectedTag": f"v{identity.get('buildVersion')}",
        "expectedReleaseBranch": f"release/{identity.get('buildVersion')}",
        "sourceCommit": identity.get("sourceCommit"),
        "sourceRef": identity.get("sourceRef"),
        "freezeDigest": identity.get("freezeDigest"),
        "freezeFileDigest": identity.get("freezeFileDigest"),
        "archiveDigest": identity.get("archiveDigest"),
        "productDistributionDigest": identity.get("productDistributionDigest"),
        "lineageDigest": identity.get("lineageDigest"),
        "validationAuthorizationIdentityDigest": _semantic_digest(identity),
        "catalogDigest": identity.get("catalogDigest"),
        "catalogRevision": identity.get("catalogRevision"),
        "platformApiDigest": identity.get("platformApiDigest"),
        "firstPartyAppsDigest": identity.get("firstPartyAppsDigest"),
        "contentProfilesDigest": identity.get("contentProfilesDigest"),
        "limitationsDigest": identity.get("limitationsDigest"),
    }
    return _semantic_digest(promotion_identity)


def _receipt_classification_errors(value: dict[str, Any], label: str) -> list[str]:
    errors = [f"{label}: {error}" for error in _unsafe_evidence_classification(value)]
    if True in _all_values(value, {"selfTest", "selfTestOnly", "offlineOnly"}):
        errors.append(f"{label} is self-test or offline-only evidence")
    kinds = _all_values(value, {"kind", "evidenceClassification"})
    if any(
        isinstance(kind, str)
        and re.search(r"(?i)(?:fixture|self[-_]?test|simulated)", kind)
        for kind in kinds
    ):
        errors.append(f"{label} is fixture, self-test, or simulated evidence")
    repositories = _all_values(value, {"repository", "repositoryIdentity"})
    allowed_repositories = {
        "crypta-network/cryptad",
        "github.com/crypta-network/cryptad",
    }
    if repositories and any(
        repository not in allowed_repositories for repository in repositories
    ):
        errors.append(f"{label} binds the wrong repository")
    return errors


def _preflight_receipt_errors(
    contract: dict[str, Any],
    binding: dict[str, Any],
    value: dict[str, Any] | None,
) -> list[str]:
    """Authenticate the exact canonical passing preflight summary for this plan."""

    errors: list[str] = []
    if binding.get("schema") != SUMMARY_SCHEMA:
        errors.append("preflight receipt does not declare the canonical execution-summary schema")
    if value is None:
        errors.append("preflight receipt is missing or malformed")
        return errors
    errors.extend(f"preflight receipt: {error}" for error in validate_schema(value, SUMMARY_SCHEMA))
    expected_classification = {
        "repositoryImplementation": "present",
        "offlineVerification": "passed",
        "protectedRcOperation": "not-performed",
        "gaValidation": "not-performed",
        "gaPublication": "not-performed",
        "publicObservation": "not-performed",
        "independentReproducibility": "pending",
    }
    expected_fields = {
        "schemaVersion": 1,
        "kind": "stable-1.0-protected-release-execution-summary",
        "executionId": contract["executionId"],
        "mode": "preflight",
        "status": "pass",
        "promotionReady": True,
        "lifecycleState": "preflight-passed",
        "contractDigest": _plan_digest(contract),
        "candidateCommit": contract["repository"]["candidateCommit"],
        "releaseId": contract["release"]["id"],
        "buildVersion": contract["release"]["integerBuild"],
        "evidenceClassification": expected_classification,
        "dispatchPackage": _dispatch_package(contract),
        "findings": [],
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }
    if any(value.get(field) != expected for field, expected in expected_fields.items()):
        errors.append("preflight receipt does not prove this exact passing execution plan")
    errors.extend(_receipt_classification_errors(value, "preflight receipt"))
    return errors


def credential_free_preflight_receipt_errors(
    contract: dict[str, Any],
    receipt: dict[str, Any],
    receipt_digest: str,
) -> list[str]:
    """Authenticate a reviewed preflight receipt before protected RC access.

    This deliberately checks only repository-public data.  The protected RC job
    performs the later materialized-evidence and runtime-identity checks, but it
    must not be entered unless the dispatch already carries the exact canonical
    receipt for the complete reviewed execution plan.
    """

    contract_errors = validate_schema(contract, CONTRACT_SCHEMA)
    if contract_errors:
        return [
            f"protected execution contract: {error}" for error in contract_errors
        ]
    binding = contract["operationEvidence"]["preflight"]
    if not isinstance(binding, dict):
        return ["protected execution contract omits the reviewed preflight receipt binding"]
    errors: list[str] = []
    if receipt_digest != binding["sha256"]:
        errors.append("preflight receipt digest differs from the protected execution contract")
    errors.extend(_preflight_receipt_errors(contract, binding, receipt))
    return sorted(set(errors))


def _rc_preflight_receipt_errors(
    contract: dict[str, Any],
    binding: dict[str, Any],
    value: dict[str, Any] | None,
) -> list[str]:
    """Authenticate the exact passing preflight receipt consumed by Stable RC."""

    errors: list[str] = []
    if binding.get("schema") != SUMMARY_SCHEMA:
        errors.append("RC preflight receipt does not declare the canonical execution-summary schema")
    if value is None:
        errors.append("RC preflight receipt is missing or malformed")
        return errors
    errors.extend(
        f"RC preflight receipt: {error}" for error in validate_schema(value, SUMMARY_SCHEMA)
    )
    expected_classification = {
        "repositoryImplementation": "present",
        "offlineVerification": "passed",
        "protectedRcOperation": "not-performed",
        "gaValidation": "not-performed",
        "gaPublication": "not-performed",
        "publicObservation": "not-performed",
        "independentReproducibility": "pending",
    }
    expected_fields = {
        "schemaVersion": 1,
        "kind": "stable-1.0-protected-release-execution-summary",
        "executionId": contract["executionId"],
        "mode": "preflight",
        "status": "pass",
        "promotionReady": True,
        "lifecycleState": "preflight-passed",
        "candidateCommit": contract["repository"]["candidateCommit"],
        "releaseId": contract["release"]["id"],
        "buildVersion": contract["release"]["integerBuild"],
        "evidenceClassification": expected_classification,
        "findings": [],
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }
    if any(value.get(field) != expected for field, expected in expected_fields.items()):
        errors.append("RC preflight receipt does not prove a passing review of this RC candidate")
    receipt_dispatch = value.get("dispatchPackage")
    receipt_rc = receipt_dispatch.get("rc") if isinstance(receipt_dispatch, dict) else None
    expected_rc = copy.deepcopy(_dispatch_package(contract)["rc"])
    if isinstance(receipt_rc, dict):
        receipt_rc = copy.deepcopy(receipt_rc)
        receipt_rc.pop("contractDigest", None)
    expected_rc.pop("contractDigest", None)
    if receipt_rc != expected_rc:
        errors.append("RC preflight receipt binds a different reviewed RC dispatch package")
    errors.extend(_receipt_classification_errors(value, "RC preflight receipt"))
    return errors


def _rc_lineage_coordinate_errors(
    value: dict[str, Any], coordinate: dict[str, Any] | None
) -> list[str]:
    if coordinate is None:
        return ["protected RC lineage has no workflow coordinates"]
    selected = value.get("selectedFreeze")
    workflow = selected.get("workflow") if isinstance(selected, dict) else None
    if not isinstance(workflow, dict):
        return ["protected RC receipt is not the authenticated RC lineage record"]
    expected = {
        "repository": coordinate["repository"],
        "runId": int(coordinate["runId"]),
        "runAttempt": int(coordinate["runAttempt"]),
        "artifactName": coordinate["artifactName"],
        "artifactDigest": coordinate["artifactDigest"],
        "environment": coordinate["environment"],
        "conclusion": "success",
    }
    if any(workflow.get(field) != expected_value for field, expected_value in expected.items()):
        return ["protected RC lineage differs from the exact workflow run, attempt, or artifact"]
    return []


def _closeout(
    workspace: Path,
    contract: dict[str, Any],
    policy: dict[str, Any],
) -> tuple[list[str], dict[str, str]]:
    errors = validate_schema(contract, CONTRACT_SCHEMA)
    statuses = {
        "repositoryImplementation": "missing",
        "offlineVerification": "pending",
        "protectedRcOperation": "not-performed",
        "gaValidation": "not-performed",
        "gaPublication": "not-performed",
        "publicObservation": "not-performed",
        "independentReproducibility": "pending",
    }
    if errors:
        return errors, statuses
    source_failures = _source_errors(workspace, contract)
    policy_failures = _policy_errors(workspace, contract, policy)
    errors.extend(source_failures)
    errors.extend(policy_failures)
    if not source_failures and not policy_failures:
        statuses["repositoryImplementation"] = "present"
    commit = contract["repository"]["candidateCommit"]
    workflows = policy["requiredWorkflowPaths"]
    environments = policy["workflowPolicy"]
    selected_rc_lineage_errors: list[str] = []
    authenticated_lineage_digest: str | None = None
    authenticated_selected_freeze: dict[str, Any] | None = None
    authenticated_freeze_record: dict[str, Any] | None = None
    authenticated_authorization_document: dict[str, Any] | None = None
    authenticated_promotion_plan: dict[str, Any] | None = None
    authenticated_promotion_identity_digest: str | None = None
    derived_promotion_identity_digest: str | None = None

    preflight = contract["operationEvidence"]["preflight"]
    if preflight is not None:
        _path, value, item_errors = _file_binding_errors(workspace, preflight, "preflight receipt")
        preflight_errors = list(item_errors)
        preflight_errors.extend(_preflight_receipt_errors(contract, preflight, value))
        errors.extend(preflight_errors)
        if not preflight_errors:
            statuses["offlineVerification"] = "passed"
        else:
            statuses["offlineVerification"] = "failed"

    rc = contract["operationEvidence"]["rcFreeze"]
    freeze_binding = contract["operationEvidence"]["rcFreezeRecord"]
    rc_preflight_binding = contract["operationEvidence"]["rcPreflight"]
    if rc is not None:
        statuses["protectedRcOperation"] = "partial"
        rc_coordinate = contract["workflowCoordinates"]["rc"]
        rc_errors = _coordinate_errors(
            rc_coordinate,
            workflow=workflows["rc"],
            environment=environments["rcEnvironment"],
            commit=commit,
            label="RC freeze",
        )
        if isinstance(rc_coordinate, dict):
            expected_rc_artifact = (
                f"stable-1-0-rc-{contract['release']['id']}-"
                f"{contract['release']['integerBuild']}-{rc_coordinate['runId']}-"
                f"{rc_coordinate['runAttempt']}"
            )
            if rc_coordinate.get("artifactName") != expected_rc_artifact:
                rc_errors.append(
                    "RC freeze artifact name is not canonical for its exact run attempt"
                )
        rc_errors.extend(
            _github_actions_coordinate_errors(
                rc_coordinate,
                label="RC freeze",
            )
        )
        if statuses["offlineVerification"] != "passed":
            rc_errors.append("protected RC closeout lacks its exact passing preflight receipt")
        rc_preflight_value: dict[str, Any] | None = None
        if not isinstance(rc_preflight_binding, dict):
            rc_errors.append("protected RC closeout lacks the preflight receipt consumed by RC")
        else:
            _rc_preflight_path, rc_preflight_value, rc_preflight_errors = (
                _file_binding_errors(
                    workspace,
                    rc_preflight_binding,
                    "RC-consumed preflight receipt",
                )
            )
            rc_errors.extend(rc_preflight_errors)
            rc_errors.extend(
                _rc_preflight_receipt_errors(
                    contract,
                    rc_preflight_binding,
                    rc_preflight_value,
                )
            )
        rc_path, value, item_errors = _file_binding_errors(
            workspace, rc, "protected RC freeze"
        )
        rc_errors.extend(item_errors)
        if rc.get("schema") != RC_LINEAGE_SCHEMA:
            rc_errors.append("protected RC lineage does not declare the canonical schema")
        lineage_schema_errors = (
            validate_schema(value, RC_LINEAGE_SCHEMA)
            if isinstance(value, dict)
            else ["protected RC lineage is missing or malformed"]
        )
        rc_errors.extend(lineage_schema_errors)
        lineage_schema_valid = isinstance(value, dict) and not lineage_schema_errors
        if isinstance(value, dict):
            rc_errors.extend(
                _receipt_classification_errors(value, "protected RC lineage")
            )
        if lineage_schema_valid:
            rc_errors.extend(_rc_lineage_coordinate_errors(value, rc_coordinate))
        if lineage_schema_valid and not (
            value.get("kind") == "stable-1.0-rc-lineage"
            and value.get("status") == "pass"
            and value.get("releaseId") == contract["release"]["id"]
            and value.get("buildVersion") == contract["release"]["integerBuild"]
            and value.get("sourceCommit") == commit
            and value.get("sourceRef") == contract["repository"]["sourceRef"]
        ):
            rc_errors.append("protected RC lineage does not bind the exact candidate and workflow")
        selected = contract["ga"]["selectedRc"]
        if selected is not None and rc_coordinate is not None and lineage_schema_valid:
            for coordinate_field, selected_field in (
                ("runId", "runId"),
                ("runAttempt", "runAttempt"),
                ("artifactName", "artifactName"),
                ("artifactDigest", "artifactDigest"),
            ):
                if rc_coordinate[coordinate_field] != selected[selected_field]:
                    selected_rc_lineage_errors.append(
                        "selected RC differs from the authenticated RC workflow coordinates"
                    )
                    break
            selected_freeze = (
                value.get("selectedFreeze") if isinstance(value, dict) else None
            )
            latest_freeze = (
                value.get("latestSuccessfulFreeze")
                if isinstance(value, dict)
                else None
            )
            if not isinstance(selected_freeze, dict):
                selected_rc_lineage_errors.append(
                    "authenticated RC lineage omits its selected freeze"
                )
            else:
                for contract_field, lineage_field in (
                    ("freezeDigest", "freezeDigest"),
                    ("productDigest", "productDistributionDigest"),
                    ("archiveDigest", "archiveDigest"),
                ):
                    if selected.get(contract_field) != selected_freeze.get(
                        lineage_field
                    ):
                        selected_rc_lineage_errors.append(
                            "selected RC payload digests differ from the authenticated lineage"
                        )
                        break
                if selected_freeze.get("sourceCommit") != commit:
                    selected_rc_lineage_errors.append(
                        "selected RC lineage source commit differs from the execution candidate"
                    )
                if latest_freeze != selected_freeze:
                    selected_rc_lineage_errors.append(
                        "selected RC is not the latest successful authenticated freeze"
                    )
                history = value.get("history") if isinstance(value, dict) else None
                successful_history = (
                    [
                        row
                        for row in history
                        if isinstance(row, dict) and row.get("successful") is True
                    ]
                    if isinstance(history, list)
                    else []
                )
                latest_history = (
                    max(successful_history, key=lambda row: row.get("ordinal", 0))
                    if successful_history
                    else None
                )
                freeze_fields = (
                    "freezeDigest",
                    "freezeFileDigest",
                    "archiveDigest",
                    "productDistributionDigest",
                    "sourceCommit",
                    "workflow",
                )
                if latest_history is None or any(
                    latest_history.get(field) != selected_freeze.get(field)
                    for field in freeze_fields
                ):
                    selected_rc_lineage_errors.append(
                        "selected RC differs from the final successful lineage history entry"
                    )
        rc_errors.extend(selected_rc_lineage_errors)
        if freeze_binding is None:
            rc_errors.append("protected RC lineage lacks its exact frozen record")
        else:
            freeze_path, freeze_value, freeze_errors = _file_binding_errors(
                workspace,
                freeze_binding,
                "protected RC freeze record",
                scan_public=False,
            )
            rc_errors.extend(freeze_errors)
            if freeze_binding.get("schema") != RC_FREEZE_SCHEMA:
                rc_errors.append(
                    "protected RC freeze record does not declare the canonical schema"
                )
            freeze_schema_errors = (
                validate_schema(freeze_value, RC_FREEZE_SCHEMA)
                if isinstance(freeze_value, dict)
                else ["protected RC freeze record is absent or malformed"]
            )
            rc_errors.extend(freeze_schema_errors)
            if (
                isinstance(freeze_value, dict)
                and not freeze_schema_errors
                and lineage_schema_valid
            ):
                freeze_candidate = (
                    freeze_value.get("candidate")
                    if isinstance(freeze_value.get("candidate"), dict)
                    else {}
                )
                freeze_catalog = (
                    freeze_value.get("stableCatalog")
                    if isinstance(freeze_value.get("stableCatalog"), dict)
                    else {}
                )
                selected_freeze = (
                    value.get("selectedFreeze") if isinstance(value, dict) else {}
                )
                selected = contract["ga"]["selectedRc"]
                if (
                    freeze_path is None
                    or not isinstance(selected_freeze, dict)
                    or _digest(freeze_path) != selected_freeze.get("freezeFileDigest")
                    or freeze_value.get("contentDigest")
                    != freeze_content_digest(freeze_value)
                    or freeze_value.get("contentDigest")
                    != selected_freeze.get("freezeDigest")
                    or freeze_candidate.get("releaseId") != contract["release"]["id"]
                    or str(freeze_candidate.get("buildVersion"))
                    != contract["release"]["integerBuild"]
                    or freeze_candidate.get("sourceCommit") != commit
                    or freeze_candidate.get("sourceRef")
                    != contract["repository"]["sourceRef"]
                    or (
                        isinstance(selected, dict)
                        and freeze_candidate.get("productionDistributionDigest")
                        != selected.get("productDigest")
                    )
                    or (
                        isinstance(selected, dict)
                        and (
                            freeze_catalog.get("catalogDigest")
                            != selected.get("catalogDigest")
                            or freeze_catalog.get("revision")
                            != selected.get("catalogRevision")
                        )
                    )
                ):
                    rc_errors.append(
                        "protected RC freeze record differs from the authenticated lineage or catalog"
                    )
        rc_errors.extend(
            _retained_artifact_member_errors(
                workspace,
                contract["operationEvidence"]["rcFreezeArtifact"],
                rc_coordinate,
                label="Stable RC Actions artifact",
                expected_members={
                    "artifacts/legacy/stable-1.0-rc-freeze.json": freeze_binding,
                    (
                        "artifacts/protected-execution/"
                        "stable-1.0-protected-release-preflight-summary.json"
                    ): rc_preflight_binding,
                },
            )
        )
        errors.extend(rc_errors)
        if not rc_errors and rc_path is not None:
            statuses["protectedRcOperation"] = "completed"
            authenticated_lineage_digest = _digest(rc_path)
            authenticated_selected_freeze = value.get("selectedFreeze")
            authenticated_freeze_record = freeze_value

    ga_validation = contract["operationEvidence"]["gaValidation"]
    if ga_validation is not None:
        statuses["gaValidation"] = "partial"
        ga_validation_errors = _coordinate_errors(
            contract["workflowCoordinates"]["gaValidation"],
            workflow=workflows["ga"],
            environment="none",
            commit=commit,
            label="GA validation",
        )
        ga_validation_errors.extend(
            _coordinate_errors(
                contract["workflowCoordinates"]["gaEvidenceApproval"],
                workflow=workflows["ga"],
                environment=environments["gaEvidenceEnvironment"],
                commit=commit,
                label="GA evidence approval",
            )
        )
        ga_validation_errors.extend(
            _ga_validation_coordinate_binding_errors(
                contract["workflowCoordinates"]["gaValidation"],
                contract["workflowCoordinates"]["gaEvidenceApproval"],
            )
        )
        ga_validation_errors.extend(
            _github_actions_coordinate_errors(
                contract["workflowCoordinates"]["gaEvidenceApproval"],
                label="GA evidence approval",
                required_job_name="Attest protected Stable GA evidence bytes",
                required_job_steps=(
                    "Verify the exact protected attestation subjects",
                    "Attest exact validation, authorization, and publication-target identity",
                ),
            )
        )
        ga_validation_errors.extend(selected_rc_lineage_errors)
        if statuses["offlineVerification"] != "passed":
            ga_validation_errors.append(
                "GA validation closeout lacks its exact passing preflight receipt"
            )
        _path, value, item_errors = _file_binding_errors(
            workspace,
            ga_validation,
            "GA validation",
            scan_public=False,
        )
        ga_validation_errors.extend(item_errors)
        if ga_validation.get("schema") != GA_VALIDATION_SCHEMA:
            ga_validation_errors.append("GA validation does not declare the canonical schema")
        if isinstance(value, dict):
            ga_validation_errors.extend(validate_schema(value, GA_VALIDATION_SCHEMA))
            ga_validation_errors.extend(
                _receipt_classification_errors(value, "GA validation")
            )
        payload = value.get("payloadIdentity", {}) if isinstance(value, dict) else {}
        validation_selected = (
            value.get("selectedRc", {}) if isinstance(value, dict) else {}
        )
        authorization_record = (
            value.get("authorization", {}) if isinstance(value, dict) else {}
        )
        selected = contract["ga"]["selectedRc"]
        if not (
            isinstance(value, dict)
            and value.get("status") == "pass"
            and value.get("state") == "publication-authorized"
            and value.get("promotionReady") is True
            and value.get("decision") in {"go", "go-with-waivers"}
            and value.get("blockers") == []
            and value.get("releaseId") == contract["release"]["id"]
            and value.get("buildVersion") == contract["release"]["integerBuild"]
            and value.get("sourceCommit") == commit
            and value.get("sourceRef") == contract["repository"]["sourceRef"]
            and payload.get("bitIdentical") is True
            and payload.get("rebuildPerformed") is False
            and payload.get("rcProductDigest") == payload.get("gaProductDigest")
            and selected is not None
            and payload.get("rcProductDigest")
            == selected.get("productDigest")
        ):
            ga_validation_errors.append("GA validation does not prove exact-byte no-rebuild promotion")
        if selected is not None and (
            validation_selected.get("freezeDigest") != selected.get("freezeDigest")
            or validation_selected.get("archiveDigest") != selected.get("archiveDigest")
            or validation_selected.get("productDistributionDigest")
            != selected.get("productDigest")
            or validation_selected.get("lineageDigest")
            != authenticated_lineage_digest
            or validation_selected.get("catalogDigest") != selected.get("catalogDigest")
            or validation_selected.get("catalogRevision")
            != selected.get("catalogRevision")
        ):
            ga_validation_errors.append(
                "GA validation selected RC differs from the authenticated lineage"
            )
        authorization_binding = contract["ga"].get("authorization")
        authorization_value: dict[str, Any] | None = None
        if isinstance(authorization_binding, dict):
            authorization_path, loaded_authorization, authorization_errors = (
                _file_binding_errors(
                    workspace,
                    authorization_binding["file"],
                    "GA validation authorization",
                    scan_public=False,
                )
            )
            ga_validation_errors.extend(authorization_errors)
            if authorization_binding["file"].get("schema") != GA_AUTHORIZATION_SCHEMA:
                ga_validation_errors.append(
                    "GA validation authorization does not declare the canonical schema"
                )
            if isinstance(loaded_authorization, dict):
                authorization_value = loaded_authorization
                authenticated_authorization_document = loaded_authorization
            authorization_digest = (
                _digest(authorization_path) if authorization_path is not None else None
            )
            if authorization_digest != authorization_binding.get(
                "authorizationFileDigest"
            ):
                ga_validation_errors.append(
                    "GA validation authorization file digest differs from dispatch"
                )
            if not (
                isinstance(authorization_value, dict)
                and authorization_record.get("status") == "authorized"
                and authorization_record.get("authorizationDigest")
                == authorization_digest
                and authorization_record.get("authorizationId")
                == authorization_value.get("authorizationId")
                and authorization_record.get("publicationTargetsDigest")
                == authorization_binding.get("authorizedTargetsDigest")
                and authorization_record.get("allowedPublicationScope")
                == authorization_value.get("allowedPublicationScope")
            ):
                ga_validation_errors.append(
                    "GA validation does not bind the exact authorization and publication targets"
                )
            if selected is not None and isinstance(authorization_value, dict) and (
                validation_selected.get("catalogDigest")
                != authorization_value.get("catalogDigest")
                or validation_selected.get("catalogRevision")
                != authorization_value.get("catalogRevision")
            ):
                ga_validation_errors.append(
                    "GA validation selected catalog differs from the exact authorization"
                )
            if isinstance(authorization_value, dict) and selected is not None:
                expected_targets = _canonical_publication_targets(contract)
                exact_authorization = {
                    "releaseId": contract["release"]["id"],
                    "buildVersion": contract["release"]["integerBuild"],
                    "sourceCommit": commit,
                    "freezeDigest": selected["freezeDigest"],
                    "archiveDigest": selected["archiveDigest"],
                    "productDistributionDigest": selected["productDigest"],
                    "catalogDigest": selected["catalogDigest"],
                    "catalogRevision": selected["catalogRevision"],
                    "gaValidationDigest": contract["ga"]["validationIdentityDigest"],
                    "publicationTargets": expected_targets,
                    "publicationTargetsDigest": _semantic_digest(expected_targets),
                    "status": "authorized",
                    "authorizationRole": authorization_binding["role"],
                    "approverIdentity": authorization_binding["approverId"],
                    "expiresAt": authorization_binding["validUntil"],
                    "authorizationId": authorization_binding["authorizationId"],
                }
                if any(
                    authorization_value.get(field) != expected_value
                    for field, expected_value in exact_authorization.items()
                ):
                    ga_validation_errors.append(
                        "GA validation authorization differs from the exact execution authority"
                    )
        else:
            ga_validation_errors.append(
                "publication-authorized GA validation lacks an exact authorization binding"
            )

        waivers = value.get("acceptedRcWaivers", []) if isinstance(value, dict) else []
        expected_decision = "go-with-waivers" if waivers else "go"
        if isinstance(value, dict) and value.get("decision") != expected_decision:
            ga_validation_errors.append(
                "GA validation decision contradicts its accepted RC waivers"
            )
        if isinstance(value, dict):
            try:
                validation_time = _timestamp(str(value.get("generatedAt")))
                if any(
                    not isinstance(waiver, dict)
                    or _timestamp(str(waiver.get("expiresAt"))) <= validation_time
                    for waiver in waivers
                ):
                    ga_validation_errors.append(
                        "GA validation contains a stale accepted RC waiver"
                    )
            except ValueError:
                ga_validation_errors.append(
                    "GA validation accepted RC waiver timestamp is malformed"
                )

        validation_artifact = contract["operationEvidence"]["gaValidationArtifact"]
        checksums_bytes, checksums_errors = _retained_artifact_member(
            workspace,
            validation_artifact,
            "publication-inputs/checksums.txt",
            label="GA validation Actions artifact",
        )
        provenance_bytes, provenance_errors = _retained_artifact_member(
            workspace,
            validation_artifact,
            "publication-inputs/provenance.json",
            label="GA validation Actions artifact",
        )
        post_freeze_bytes, post_freeze_errors = _retained_artifact_member(
            workspace,
            validation_artifact,
            "publication-inputs/stable-1.0-rc-validation.json",
            label="GA validation Actions artifact",
        )
        ga_validation_errors.extend(checksums_errors)
        ga_validation_errors.extend(provenance_errors)
        ga_validation_errors.extend(post_freeze_errors)
        post_freeze_value: dict[str, Any] | None = None
        if post_freeze_bytes is not None:
            try:
                import json

                loaded_post_freeze = json.loads(post_freeze_bytes)
                if isinstance(loaded_post_freeze, dict):
                    post_freeze_value = loaded_post_freeze
                    ga_validation_errors.extend(
                        validate_schema(post_freeze_value, RC_VALIDATION_SCHEMA)
                    )
                else:
                    ga_validation_errors.append(
                        "retained post-freeze validation is not a JSON object"
                    )
            except (UnicodeDecodeError, ValueError):
                ga_validation_errors.append(
                    "retained post-freeze validation is malformed JSON"
                )

        identity_binding = contract["operationEvidence"]["gaValidationIdentity"]
        identity_value: dict[str, Any] | None = None
        if identity_binding is None:
            ga_validation_errors.append(
                "GA validation lacks its canonical authorization identity record"
            )
        else:
            _identity_path, loaded_identity, identity_errors = _file_binding_errors(
                workspace,
                identity_binding,
                "GA validation authorization identity",
                scan_public=False,
            )
            ga_validation_errors.extend(identity_errors)
            if identity_binding.get("schema") != GA_VALIDATION_IDENTITY_SCHEMA:
                ga_validation_errors.append(
                    "GA validation identity does not declare the canonical schema"
                )
            if isinstance(loaded_identity, dict):
                identity_value = loaded_identity
                ga_validation_errors.extend(
                    _ga_validation_identity_errors(
                        identity_value,
                        contract,
                        authenticated_lineage_digest,
                        authenticated_selected_freeze,
                        authorization_value,
                        authenticated_freeze_record,
                        value,
                        post_freeze_value,
                        (
                            _bytes_digest(post_freeze_bytes)
                            if post_freeze_bytes is not None
                            else None
                        ),
                        (
                            _bytes_digest(checksums_bytes)
                            if checksums_bytes is not None
                            else None
                        ),
                        (
                            _bytes_digest(provenance_bytes)
                            if provenance_bytes is not None
                            else None
                        ),
                    )
                )
                if (
                    contract["ga"]["validationIdentityDigest"]
                    != _semantic_digest(identity_value)
                    or (
                        value.get("postFreezeValidation", {})
                        if isinstance(value, dict)
                        else {}
                    ).get("validationDigest")
                    != identity_value.get("postFreezeValidationDigest")
                    or (value.get("acceptedRcWaivers") if isinstance(value, dict) else None)
                    != identity_value.get("acceptedRcWaivers")
                ):
                    ga_validation_errors.append(
                        "GA validation differs from its exact authorization identity"
                    )
            else:
                ga_validation_errors.append("GA validation identity is absent or malformed")
        authorization_binding = contract["ga"].get("authorization")
        ga_validation_errors.extend(
            _retained_artifact_member_errors(
                workspace,
                validation_artifact,
                contract["workflowCoordinates"]["gaEvidenceApproval"],
                label="GA validation Actions artifact",
                expected_members={
                    "component/artifacts/legacy/stable-1.0-ga-validation.json": ga_validation,
                    "publication-inputs/stable-1.0-ga-validation-authorization-identity.json": identity_binding,
                    "publication-inputs/stable-1.0-ga-authorization.json": (
                        authorization_binding.get("file")
                        if isinstance(authorization_binding, dict)
                        else None
                    ),
                    "publication-inputs/stable-1.0-rc-lineage.json": rc,
                    "publication-inputs/stable-1.0-rc-freeze.json": freeze_binding,
                },
            )
        )
        errors.extend(ga_validation_errors)
        if not ga_validation_errors:
            statuses["gaValidation"] = "completed"
            assert identity_value is not None
            derived_promotion_identity_digest = _ga_promotion_identity_digest(
                identity_value
            )

    promotion_plan = contract["operationEvidence"]["gaPromotionPlan"]
    if promotion_plan is not None:
        plan_errors: list[str] = []
        if statuses["gaValidation"] != "completed":
            plan_errors.append(
                "GA publication plan lacks a completed authenticated GA validation"
            )
        plan_path, plan_value, item_errors = _file_binding_errors(
            workspace,
            promotion_plan,
            "GA publication plan",
            scan_public=False,
        )
        plan_errors.extend(item_errors)
        if promotion_plan.get("schema") != GA_PUBLICATION_PLAN_SCHEMA:
            plan_errors.append(
                "GA publication plan does not declare the canonical Stable GA schema"
            )
        plan_errors.extend(
            _retained_artifact_member_errors(
                workspace,
                contract["operationEvidence"]["gaValidationArtifact"],
                contract["workflowCoordinates"]["gaEvidenceApproval"],
                label="GA validation Actions artifact",
                expected_members={
                    "component/artifacts/legacy/stable-1.0-ga-publication-plan.json": promotion_plan,
                },
            )
        )
        if isinstance(plan_value, dict):
            plan_errors.extend(
                _receipt_classification_errors(plan_value, "GA publication plan")
            )
            plan_errors.extend(
                _ga_promotion_plan_errors(
                    plan_value,
                    contract,
                    authenticated_authorization_document,
                    derived_promotion_identity_digest,
                    authenticated_freeze_record,
                )
            )
        else:
            plan_errors.append("GA publication plan is absent or malformed")
        errors.extend(plan_errors)
        if isinstance(plan_value, dict) and plan_path is not None and not plan_errors:
            authenticated_promotion_plan = plan_value
            authenticated_promotion_identity_digest = derived_promotion_identity_digest

    publication = contract["operationEvidence"]["gaPublication"]
    publication_digest: str | None = None
    publication_receipt: dict[str, Any] | None = None
    if publication is not None:
        statuses["gaPublication"] = "partial"
        publication_errors: list[str] = []
        publication_errors.extend(selected_rc_lineage_errors)
        if statuses["protectedRcOperation"] != "completed":
            publication_errors.append(
                "GA publication lacks a completed authenticated RC operation"
            )
        if statuses["gaValidation"] != "completed":
            publication_errors.append(
                "GA publication lacks a completed authenticated GA validation"
            )
        if authenticated_promotion_identity_digest is None:
            publication_errors.append(
                "GA publication lacks an authenticated canonical promotion identity"
            )
        if contract["ga"]["publicationIntent"] != "publish":
            publication_errors.append(
                "GA publication receipt is present for a validate-only execution plan"
            )
        publication_errors.extend(_target_errors(contract))
        publication_errors.extend(_publication_errors(workspace, contract))
        publication_errors.extend(
            _coordinate_errors(
                contract["workflowCoordinates"]["gaPublication"],
                workflow=workflows["ga"],
                environment=environments["gaPublicationEnvironment"],
                commit=commit,
                label="GA publication",
            )
        )
        evidence_coordinate = contract["workflowCoordinates"]["gaEvidenceApproval"]
        publication_coordinate = contract["workflowCoordinates"]["gaPublication"]
        if (
            isinstance(evidence_coordinate, dict)
            and isinstance(publication_coordinate, dict)
            and evidence_coordinate.get("runId") == publication_coordinate.get("runId")
        ):
            publication_errors.append(
                "GA evidence approval and publication must come from separate workflow dispatches"
            )
        publication_errors.extend(
            _github_actions_coordinate_errors(
                contract["workflowCoordinates"]["gaPublication"],
                label="GA publication",
            )
        )
        path, value, item_errors = _file_binding_errors(
            workspace,
            publication,
            "GA publication receipt",
            scan_public=False,
        )
        publication_errors.extend(item_errors)
        publication_errors.extend(
            _retained_artifact_member_errors(
                workspace,
                contract["operationEvidence"]["gaPublicationArtifact"],
                contract["workflowCoordinates"]["gaPublication"],
                label="GA publication Actions artifact",
                expected_members={
                    "stable-1.0-ga-publication-receipt.json": publication,
                },
            )
        )
        if publication.get("schema") != GA_PUBLICATION_RECEIPT_SCHEMA:
            publication_errors.append(
                "GA publication receipt does not declare the canonical Stable GA schema"
            )
        authorization_document: dict[str, Any] | None = None
        authorization = contract["ga"].get("authorization")
        if isinstance(authorization, dict):
            _authorization_path, authorization_value, authorization_file_errors = (
                _file_binding_errors(
                    workspace,
                    authorization["file"],
                    "GA authorization",
                    scan_public=False,
                )
            )
            publication_errors.extend(authorization_file_errors)
            if isinstance(authorization_value, dict):
                authorization_document = authorization_value
                publication_errors.extend(
                    f"GA authorization: {finding['summary']}"
                    for finding in public_audit_redaction_findings(
                        authorization_document
                    )
                )
        if isinstance(value, dict):
            publication_errors.extend(
                _receipt_classification_errors(value, "GA publication receipt")
            )
            publication_errors.extend(
                _ga_publication_receipt_errors(
                    value,
                    contract,
                    contract["workflowCoordinates"]["gaPublication"],
                    authorization_document,
                    authenticated_promotion_plan,
                    authenticated_promotion_identity_digest,
                )
            )
        else:
            publication_errors.append(
                "GA publication receipt is absent, partial, conflicting, or unsuccessful"
            )
        errors.extend(publication_errors)
        if isinstance(value, dict) and path is not None and not publication_errors:
            statuses["gaPublication"] = "completed"
            publication_receipt = value
            publication_digest = _digest(path)
        else:
            if not any("absent, partial" in error for error in publication_errors):
                errors.append(
                    "GA publication receipt is absent, partial, conflicting, or unsuccessful"
                )

    observation = contract["operationEvidence"]["publicObservation"]
    if observation is not None:
        statuses["publicObservation"] = "partial"
        observation_errors: list[str] = []
        observation_path, value, item_errors = _file_binding_errors(
            workspace, observation, "public observation receipt"
        )
        observation_errors.extend(item_errors)
        observation_errors.extend(
            _observation_artifact_errors(
                workspace,
                contract["operationEvidence"]["publicObservationArtifact"],
                observation_path,
                contract["workflowCoordinates"]["publicObservation"],
            )
        )
        if isinstance(value, dict):
            observation_errors.extend(validate_schema(value, OBSERVATION_SCHEMA))
            observation_errors.extend(
                _receipt_classification_errors(value, "public observation receipt")
            )
            observation_errors.extend(
                _observation_coordinate_errors(
                    value,
                    contract["workflowCoordinates"]["publicObservation"],
                    observation_workflow=workflows["publicObservation"],
                    observation_environment=environments[
                        "publicObservationEnvironment"
                    ],
                    commit=commit,
                    build=contract["release"]["integerBuild"],
                )
            )
            observation_errors.extend(
                _github_actions_coordinate_errors(
                    contract["workflowCoordinates"]["publicObservation"],
                    label="public observation",
                )
            )
            if value.get("releaseId") != contract["release"]["id"]:
                observation_errors.append("public observation binds a different release")
            if value.get("buildVersion") != contract["release"]["integerBuild"]:
                observation_errors.append("public observation binds a different build")
            if publication_digest is None or value.get("publicationReceiptDigest") != publication_digest:
                observation_errors.append(
                    "public observation does not bind the exact GA publication receipt"
                )
            if value.get("candidateCommit") != commit:
                observation_errors.append("public observation binds a different candidate commit")
            selected = contract["ga"]["selectedRc"]
            if selected is None or value.get("productDigest") != selected.get("productDigest"):
                observation_errors.append("public observation binds different product bytes")
            if publication_receipt is not None:
                try:
                    if _timestamp(str(value.get("observedAt"))) < _timestamp(
                        str(publication_receipt.get("publishedAt"))
                    ):
                        observation_errors.append(
                            "public observation predates the authenticated GA publication"
                        )
                except ValueError:
                    observation_errors.append("public observation timestamp is malformed")
            else:
                observation_errors.append(
                    "public observation lacks an authenticated GA publication receipt"
                )
            targets = value.get("targets")
            targets = targets if isinstance(targets, list) else []
            observed_uris = [
                row.get("publicUri") for row in targets if isinstance(row, dict)
            ]
            if len(observed_uris) != len(set(observed_uris)):
                observation_errors.append(
                    "public observation contains duplicate target identities"
                )
            for uri in observed_uris:
                if not isinstance(uri, str) or _public_https(uri) is not None:
                    observation_errors.append(
                        "public observation contains a non-public target URI"
                    )
                    break
            required_catalog_uris = {
                contract["publicTargets"]["catalogPrimaryUri"],
                *contract["publicTargets"]["catalogMirrorUris"],
                contract["publicTargets"]["catalogRollbackUri"],
            }
            try:
                catalog_signature_uris = {
                    uri: catalog_signature_uri(uri)
                    for uri in required_catalog_uris
                }
            except PublicObservationTransportError:
                catalog_signature_uris = {}
                observation_errors.append(
                    "public observation catalog target has no canonical detached signature URI"
                )
            required_catalog_uris.update(catalog_signature_uris.values())
            if not required_catalog_uris.issubset(set(observed_uris)):
                observation_errors.append(
                    "public observation omits catalog bytes or a detached signature target"
                )
            if publication_receipt is not None:
                receipt_tag = publication_receipt.get("tag")
                receipt_tag = receipt_tag if isinstance(receipt_tag, dict) else {}
                if value.get("tag") != {
                    "name": receipt_tag.get("name"),
                    "targetCommit": receipt_tag.get("targetCommit"),
                    "annotated": True,
                    "status": "observed-exact",
                }:
                    observation_errors.append(
                        "public observation does not prove the exact annotated release tag"
                    )
                receipt_release = publication_receipt.get("githubRelease")
                receipt_release = (
                    receipt_release if isinstance(receipt_release, dict) else {}
                )
                if value.get("githubRelease") != {
                    "releaseId": receipt_release.get("releaseId"),
                    "publicUrl": receipt_release.get("publicUrl"),
                    "name": f"Cryptad Stable 1.0 (v{contract['release']['integerBuild']})",
                    "tagName": f"v{contract['release']['integerBuild']}",
                    "targetCommitish": commit,
                    "draft": False,
                    "prerelease": False,
                    "releaseNotesDigest": receipt_release.get(
                        "releaseNotesDigest"
                    ),
                    "status": "observed-exact",
                }:
                    observation_errors.append(
                        "public observation does not prove the exact GitHub Release identity"
                    )
                receipt_catalog = publication_receipt.get("catalog")
                receipt_catalog = (
                    receipt_catalog if isinstance(receipt_catalog, dict) else {}
                )
                receipt_rollback = receipt_catalog.get("rollback")
                receipt_rollback = (
                    receipt_rollback if isinstance(receipt_rollback, dict) else {}
                )
                expected_catalog_digests = {
                    contract["publicTargets"]["catalogPrimaryUri"]: receipt_catalog.get(
                        "catalogDigest"
                    ),
                    catalog_signature_uris.get(
                        contract["publicTargets"]["catalogPrimaryUri"]
                    ): receipt_catalog.get("signatureDigest"),
                    **{
                        uri: receipt_catalog.get("catalogDigest")
                        for uri in contract["publicTargets"]["catalogMirrorUris"]
                    },
                    **{
                        catalog_signature_uris.get(uri): receipt_catalog.get(
                            "signatureDigest"
                        )
                        for uri in contract["publicTargets"]["catalogMirrorUris"]
                    },
                    contract["publicTargets"]["catalogRollbackUri"]: receipt_rollback.get(
                        "digest"
                    ),
                    catalog_signature_uris.get(
                        contract["publicTargets"]["catalogRollbackUri"]
                    ): receipt_rollback.get("signatureDigest"),
                }
                for uri, digest in expected_catalog_digests.items():
                    matches = [
                        row
                        for row in targets
                        if isinstance(row, dict)
                        and row.get("publicUri") == uri
                        and row.get("sha256") == digest
                        and row.get("status") == "observed-exact"
                    ]
                    if len(matches) != 1:
                        observation_errors.append(
                            "public observation does not bind exact catalog or signature bytes"
                        )
                        break
            receipt_assets = (
                [
                    row
                    for row in publication_receipt.get("assets", [])
                    if isinstance(row, dict)
                ]
                if publication_receipt is not None
                else []
            )
            for asset in receipt_assets:
                matches = [
                    row
                    for row in targets
                    if isinstance(row, dict)
                    and row.get("publicUri") == asset.get("publicUri")
                    and row.get("sha256") == asset.get("digest")
                    and row.get("size") == asset.get("sizeBytes")
                    and row.get("status") == "observed-exact"
                ]
                if len(matches) != 1:
                    observation_errors.append(
                        "public observation does not match every exact published GA asset"
                    )
                    break
            expected_observed_uris = {
                *required_catalog_uris,
                *(asset.get("publicUri") for asset in receipt_assets),
            }
            if (
                set(observed_uris) != expected_observed_uris
                or len(targets) != len(expected_observed_uris)
            ):
                observation_errors.append(
                    "public observation target set differs from the exact published GA state"
                )
        else:
            observation_errors.append("public observation receipt is missing or malformed")
        errors.extend(observation_errors)
        if not observation_errors:
            statuses["publicObservation"] = "completed"

    reproducibility = contract["operationEvidence"]["independentReproducibility"]
    if reproducibility is None and (
        contract["operationEvidence"]["independentReproducibilityArtifact"] is not None
        or contract["operationEvidence"].get("independentReproducibilityCoordinate") is not None
    ):
        errors.append("independent reproducibility artifact or coordinate lacks its summary")
    if reproducibility is not None:
        reproducibility_errors = _independent_reproducibility_errors(
            workspace,
            contract,
            policy,
            reproducibility,
            authenticated_selected_freeze,
        )
        errors.extend(reproducibility_errors)
        if not reproducibility_errors:
            statuses["independentReproducibility"] = "independently-reproduced"
        else:
            _summary_path, independent_summary, _summary_errors = _file_binding_errors(
                workspace,
                reproducibility,
                "independent reproducibility summary status",
            )
            if (
                isinstance(independent_summary, dict)
                and not validate_schema(independent_summary, INDEPENDENT_SUMMARY_SCHEMA)
                and independent_summary.get("status")
                in {
                    "pending",
                    "authenticated-external-build",
                    "comparison-failed",
                    "blocked",
                    "partial",
                }
            ):
                statuses["independentReproducibility"] = independent_summary["status"]
    claimed_state = contract["lifecycleState"]
    state_status = {
        "rc-frozen": statuses["protectedRcOperation"],
        "ga-validated": statuses["gaValidation"],
        "ga-published": statuses["gaPublication"],
        "publicly-observed": statuses["publicObservation"],
    }
    if claimed_state in state_status and state_status[claimed_state] != "completed":
        errors.append("contract lifecycle state claims protected evidence that closeout cannot authenticate")
    claimed_classification = contract["evidenceClassification"]
    protected_statuses = (
        statuses["protectedRcOperation"],
        statuses["gaValidation"],
        statuses["gaPublication"],
    )
    if "partial" in protected_statuses:
        protected_operation = "partial"
    elif "completed" in protected_statuses:
        protected_operation = "completed"
    else:
        protected_operation = "not-performed"
    expected_classification = {
        "repositoryImplementation": statuses["repositoryImplementation"],
        "offlineVerification": statuses["offlineVerification"],
        "protectedOperation": protected_operation,
        "publicObservation": statuses["publicObservation"],
    }
    if claimed_classification != expected_classification:
        errors.append("contract evidence classification differs from authenticated closeout state")
    return sorted(set(errors)), statuses


def _dispatch_package(contract: dict[str, Any]) -> dict[str, Any]:
    release = contract["release"]
    repository = contract["repository"]
    targets = contract["publicTargets"]
    selected = contract["ga"]["selectedRc"]
    evidence = [
        {
            "id": row["id"],
            "authorityClass": row["authorityClass"],
            "sha256": row["file"]["sha256"],
            "producer": row["producer"],
        }
        for row in contract["upstreamEvidence"]
    ]
    return {
        "rc": {
            "workflow": contract["authorities"]["workflowPaths"]["rc"],
            "ref": repository["sourceRef"],
            "candidateCommit": repository["candidateCommit"],
            "releaseId": release["id"],
            "integerBuild": release["integerBuild"],
            "freezeMode": release["freezeMode"],
            "artifactBaseUri": targets["artifactBaseUri"],
            "contractDigest": _plan_digest(contract),
            "executionContractRequired": True,
            "keyIdentities": contract["authorities"]["keyIdentities"],
            "evidenceBindings": evidence,
            "rcGeneratedEvidenceIds": [
                row["id"]
                for row in contract["upstreamEvidence"]
                if row["authorityClass"] == "rc-generated-prerequisite"
            ],
            "rcInputs": contract["rcInputs"],
            "previousRcFreeze": release["previousRcFreeze"],
        },
        "gaValidation": {
            "workflow": contract["authorities"]["workflowPaths"]["ga"],
            "ref": repository["sourceRef"],
            "publish": False,
            "selectedRc": selected,
            "publicTargets": targets,
        },
        "gaPublication": {
            "workflow": contract["authorities"]["workflowPaths"]["ga"],
            "ref": repository["sourceRef"],
            "publish": True,
            "selectedRc": selected,
            "evidenceApproval": contract["workflowCoordinates"]["gaEvidenceApproval"],
            "publicTargets": targets,
            "freshApprovalRequired": True,
        },
    }


def _materialized_file_digest_errors(
    workspace: Path,
    relative: Any,
    expected_digest: str,
    label: str,
    *,
    allow_runner_temp: bool = False,
) -> list[str]:
    if not isinstance(relative, str):
        return [f"{label} materialized path is missing or malformed"]
    try:
        candidate = Path(relative)
        if candidate.is_absolute() and allow_runner_temp:
            runner_temp_value = os.environ.get("RUNNER_TEMP")
            if not runner_temp_value:
                raise ValueError(f"{label} cannot authenticate an external path without RUNNER_TEMP")
            runner_temp = Path(runner_temp_value).resolve()
            try:
                lexical_relative = candidate.relative_to(runner_temp)
            except ValueError as exc:
                raise ValueError(f"{label} is outside the protected runner-temporary root") from exc
            if ".." in lexical_relative.parts:
                raise ValueError(f"{label} contains traversal inside the runner-temporary root")
            current = runner_temp
            for part in lexical_relative.parts:
                current = current / part
                if current.is_symlink():
                    raise ValueError(f"{label} path contains a symbolic link")
            path = candidate.resolve()
            try:
                path.relative_to(runner_temp)
            except ValueError as exc:
                raise ValueError(f"{label} resolves outside the protected runner-temporary root") from exc
            if (
                not path.is_file()
                or path.is_symlink()
                or path.stat().st_nlink != 1
                or path.stat().st_size > 64 * 1024 * 1024
            ):
                raise ValueError(f"{label} is missing, linked, or exceeds the protected size bound")
        else:
            path = _confined_file(workspace, relative, label)
    except (OSError, ValueError) as exc:
        return [str(exc)]
    if _digest(path) != expected_digest:
        return [f"{label} bytes differ from the reviewed execution contract"]
    return []


def _rc_dispatch_errors(
    workspace: Path,
    contract: dict[str, Any],
    policy: dict[str, Any],
    input_map: dict[str, Any],
    observed_time: datetime,
) -> list[str]:
    """Bind the exact preflight-reviewed package to one protected RC invocation."""

    errors: list[str] = []
    expected_keys = {
        "schemaVersion",
        "repository",
        "release",
        "artifactBaseUri",
        "keyIdentities",
        "evidenceFiles",
        "stableAuthorityCoordinates",
        "rcGeneratedEvidenceIds",
        "rcInputs",
        "preflightReceipt",
    }
    if set(input_map) != expected_keys or input_map.get("schemaVersion") != 1:
        return ["RC materialized-input map has an unexpected or incomplete shape"]
    repository = input_map.get("repository")
    release = input_map.get("release")
    if repository != {
        "candidateCommit": contract["repository"]["candidateCommit"],
        "sourceRef": contract["repository"]["sourceRef"],
    }:
        errors.append("RC materialized-input map binds a different source identity")
    if release != {
        "id": contract["release"]["id"],
        "integerBuild": contract["release"]["integerBuild"],
        "freezeMode": contract["release"]["freezeMode"],
    }:
        errors.append("RC materialized-input map binds a different release identity")
    if input_map.get("artifactBaseUri") != contract["publicTargets"]["artifactBaseUri"]:
        errors.append("RC materialized-input map binds a different artifact base URI")
    if input_map.get("keyIdentities") != contract["authorities"]["keyIdentities"]:
        errors.append("RC runtime signing and review identities differ from the reviewed contract")
    rows = {row["id"]: row for row in contract["upstreamEvidence"]}
    evidence_contracts = policy["requiredEvidenceContracts"]
    release_id = contract["release"]["id"]
    commit = contract["repository"]["candidateCommit"]
    for evidence_id, row in rows.items():
        expected_contract = evidence_contracts[evidence_id]
        authority_class = expected_contract["authorityClass"]
        if row.get("authorityClass") != authority_class:
            errors.append(f"RC {evidence_id} authority class differs from repository policy")
        if row.get("kind") != expected_contract["kind"]:
            errors.append(f"RC {evidence_id} kind differs from repository policy")
        if row.get("file", {}).get("schema") != expected_contract["schema"]:
            errors.append(f"RC {evidence_id} schema differs from repository policy")
        expected_classification = (
            "protected-operation"
            if authority_class == "protected-producer"
            else "offline-prerequisite"
        )
        if row.get("classification") != expected_classification:
            errors.append(f"RC {evidence_id} classification differs from repository policy")
        producer = row.get("producer")
        if authority_class == "protected-producer":
            if not isinstance(producer, dict):
                errors.append(f"RC {evidence_id} omits its protected producer")
            else:
                if (
                    producer.get("workflowPath") != expected_contract.get("workflowPath")
                    or producer.get("workflowCommit") != commit
                    or producer.get("environment") != expected_contract.get("environment")
                    or producer.get("repository") != "crypta-network/cryptad"
                    or producer.get("conclusion") != "success"
                ):
                    errors.append(f"RC {evidence_id} producer authority differs from repository policy")
                expected_artifact = {
                    "stable-supply-chain": f"stable-1.0-supply-chain-{release_id}-comparison",
                    "stable-dependency-vulnerability": (
                        f"stable-1.0-dependency-vulnerability-{release_id}-evaluation"
                    ),
                    "stable-vulnerability": (
                        "stable-1.0-vulnerability-protected-ledger-wide-"
                        f"{producer.get('runId')}-{producer.get('runAttempt')}"
                    ),
                }[evidence_id]
                if producer.get("artifactName") != expected_artifact:
                    errors.append(f"RC {evidence_id} artifact name is not canonical")
        elif producer is not None:
            errors.append(f"RC {evidence_id} must not claim a protected producer")
        if (
            authority_class == "exact-dispatch-input"
            and row.get("file", {}).get("path") != expected_contract.get("rcInputPath")
        ):
            errors.append(f"RC {evidence_id} reviewed input path differs from repository policy")
    for evidence_id, row in rows.items():
        try:
            if _timestamp(row["validUntil"]) <= observed_time:
                errors.append(f"RC materialized {evidence_id} evidence is stale")
        except (TypeError, ValueError):
            errors.append(f"RC materialized {evidence_id} validity timestamp is malformed")
    generated_ids = policy["requiredRcGeneratedEvidenceIds"]
    if input_map.get("rcGeneratedEvidenceIds") != generated_ids:
        errors.append("RC-generated evidence identity set differs from repository policy")
    expected_materialized_ids = sorted(set(rows) - set(generated_ids))
    evidence_files = input_map.get("evidenceFiles")
    if not isinstance(evidence_files, dict) or sorted(evidence_files) != expected_materialized_ids:
        errors.append("RC materialized evidence does not contain the exact reviewed input set")
        evidence_files = {}
    for evidence_id in expected_materialized_ids:
        errors.extend(
            _materialized_file_digest_errors(
                workspace,
                evidence_files.get(evidence_id),
                rows[evidence_id]["file"]["sha256"],
                f"RC materialized {evidence_id} evidence",
                allow_runner_temp=(
                    rows[evidence_id].get("authorityClass") == "protected-producer"
                ),
            )
        )

    stable_coordinates = input_map.get("stableAuthorityCoordinates")
    stable_coordinates = stable_coordinates if isinstance(stable_coordinates, dict) else {}
    stable_coordinate_names = {
        "stable-vulnerability": "stableVulnerability",
        "stable-supply-chain": "stableSupplyChain",
        "stable-dependency-vulnerability": "stableDependencyVulnerability",
    }
    if set(stable_coordinates) != set(stable_coordinate_names.values()):
        errors.append("RC Stable authority coordinate set is incomplete or unexpected")
    coordinate_fields = ("runId", "runAttempt", "artifactName", "artifactDigest")
    for evidence_id, coordinate_name in stable_coordinate_names.items():
        producer = rows[evidence_id].get("producer")
        expected = (
            {field: producer.get(field) for field in coordinate_fields}
            if isinstance(producer, dict)
            else None
        )
        if stable_coordinates.get(coordinate_name) != expected:
            errors.append(
                f"RC {evidence_id} coordinates differ from the reviewed execution contract"
            )

    rc_inputs = input_map.get("rcInputs")
    rc_inputs = rc_inputs if isinstance(rc_inputs, dict) else {}
    expected_rc_input_keys = {
        "publicBetaKnownIssues",
        "thirdPartyIntake",
        "goNoGoWaivers",
        "stableReadinessWaivers",
        "freezeExceptions",
        "previousRcFreeze",
    }
    if set(rc_inputs) != expected_rc_input_keys:
        errors.append("RC supplemental input map is incomplete or unexpected")
    supplemental_bindings = {
        "publicBetaKnownIssues": contract["rcInputs"]["publicBetaKnownIssues"],
        "thirdPartyIntake": contract["rcInputs"]["thirdPartyIntake"],
        "goNoGoWaivers": contract["rcInputs"]["goNoGoWaivers"],
        "stableReadinessWaivers": contract["rcInputs"]["stableReadinessWaivers"],
        "freezeExceptions": contract["rcInputs"]["freezeExceptions"],
        "previousRcFreeze": contract["release"]["previousRcFreeze"],
    }
    for name, binding in supplemental_bindings.items():
        relative = rc_inputs.get(name)
        if binding is None:
            if relative is not None:
                errors.append(f"RC supplemental input {name} was not reviewed by preflight")
            continue
        errors.extend(
            _materialized_file_digest_errors(
                workspace,
                relative,
                binding["sha256"],
                f"RC supplemental input {name}",
            )
        )
    materialized_contract = copy.deepcopy(contract)
    for name, binding in materialized_contract["rcInputs"].items():
        materialized_path = rc_inputs.get(name)
        if isinstance(binding, dict) and isinstance(materialized_path, str):
            binding["path"] = materialized_path
    previous_binding = materialized_contract["release"].get("previousRcFreeze")
    previous_path = rc_inputs.get("previousRcFreeze")
    if isinstance(previous_binding, dict) and isinstance(previous_path, str):
        previous_binding["path"] = previous_path
    errors.extend(_dispatch_clock_errors(materialized_contract, policy, observed_time))
    errors.extend(_freeze_mode_errors(materialized_contract))
    errors.extend(_rc_input_errors(workspace, materialized_contract, observed_time))
    errors.extend(_target_errors(materialized_contract))
    preflight_binding = contract["operationEvidence"].get("preflight")
    preflight_relative = input_map.get("preflightReceipt")
    if not isinstance(preflight_binding, dict):
        errors.append("RC dispatch requires the exact passing preflight receipt binding")
    elif not isinstance(preflight_relative, str):
        errors.append("RC dispatch omits the materialized preflight receipt")
    else:
        actual_binding = dict(preflight_binding)
        actual_binding["path"] = preflight_relative
        _path, receipt, receipt_file_errors = _file_binding_errors(
            workspace,
            actual_binding,
            "RC preflight receipt",
        )
        errors.extend(receipt_file_errors)
        if receipt is not None:
            errors.extend(
                _preflight_receipt_errors(contract, actual_binding, receipt)
            )
    return sorted(set(errors))


def _report(summary: dict[str, Any]) -> str:
    lines = [
        "# Stable 1.0 protected release execution",
        "",
        f"- Execution: `{summary['executionId']}`",
        f"- Mode: `{summary['mode']}`",
        f"- Status: `{summary['status']}`",
        f"- Lifecycle state: `{summary['lifecycleState']}`",
        f"- Contract digest: `{summary['contractDigest']}`",
        "",
        "## Evidence classification",
        "",
    ]
    for name, status in summary["evidenceClassification"].items():
        lines.append(f"- `{name}`: `{status}`")
    lines.extend(["", "## Findings", ""])
    if summary["findings"]:
        lines.extend(f"- {finding}" for finding in summary["findings"])
    else:
        lines.append("- None.")
    lines.extend(
        [
            "",
            "This report is side-effect-free. It does not claim a Stable RC freeze, GA publication,",
            "or public observation unless the corresponding exact protected receipt passed closeout.",
        ]
    )
    return "\n".join(lines)


def _summary_identity(value: Any, pattern: re.Pattern[str]) -> str | None:
    """Return only a canonical public identity that is safe for failure output."""

    return value if isinstance(value, str) and pattern.fullmatch(value) else None


def run(
    workspace_root: Path,
    contract_path: Path,
    mode: str,
    out_dir: Path | None,
    rc_input_map_path: Path | None = None,
) -> int:
    """Validate one protected execution plan and write deterministic review artifacts."""

    workspace = workspace_root.resolve()
    if contract_path.is_absolute():
        try:
            contract_relative = contract_path.relative_to(workspace)
        except ValueError as exc:
            raise ValueError(
                "execution contract must be inside the repository workspace"
            ) from exc
    else:
        contract_relative = contract_path
    contract_resolved = _confined_file(
        workspace,
        contract_relative.as_posix(),
        "execution contract",
    )
    contract = read_json(contract_resolved)
    if not isinstance(contract, dict):
        raise ValueError("execution contract must be a JSON object")
    policy = read_json(Path(__file__).resolve().parents[2] / POLICY_FILE)
    if not isinstance(policy, dict):
        raise ValueError("protected release policy is malformed")
    execution_id = contract.get("executionId")
    if not isinstance(execution_id, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", execution_id) is None:
        raise ValueError("execution contract has no safe execution ID")
    default_output = (
        workspace
        / "build/release-certification"
        / execution_id
        / "stable-protected-release"
    )
    requested_output = (
        out_dir
        if out_dir is not None
        else default_output if mode == "preflight" else default_output / mode
    )
    output = _confined_output_directory(workspace, requested_output)
    input_map_resolved: Path | None = None
    contract_schema_findings = validate_schema(contract, CONTRACT_SCHEMA)
    if mode == "preflight":
        if rc_input_map_path is not None:
            raise ValueError("preflight does not accept --rc-input-map")
        observed_time = _utc_now()
        findings = _preflight(
            workspace,
            contract,
            policy,
            observed_time,
        )
        implementation_findings = (
            contract_schema_findings
            if contract_schema_findings
            else _policy_errors(workspace, contract, policy)
        )
        statuses = {
            "repositoryImplementation": (
                "present" if not implementation_findings else "missing"
            ),
            "offlineVerification": "passed" if not findings else "failed",
            "protectedRcOperation": "not-performed",
            "gaValidation": "not-performed",
            "gaPublication": "not-performed",
            "publicObservation": "not-performed",
            "independentReproducibility": "pending",
        }
        lifecycle = "preflight-passed" if not findings else "blocked"
    elif mode == "rc-dispatch":
        if rc_input_map_path is None:
            raise ValueError("rc-dispatch requires --rc-input-map")
        if rc_input_map_path.is_absolute():
            try:
                input_map_relative = rc_input_map_path.relative_to(workspace)
            except ValueError as exc:
                raise ValueError("RC input map must be inside the repository workspace") from exc
        else:
            input_map_relative = rc_input_map_path
        input_map_resolved = _confined_file(
            workspace,
            input_map_relative.as_posix(),
            "RC materialized-input map",
        )
        input_map = read_json(input_map_resolved)
        if not isinstance(input_map, dict):
            raise ValueError("RC materialized-input map must be a JSON object")
        observed_time = _utc_now()
        implementation_findings = (
            contract_schema_findings
            if contract_schema_findings
            else _policy_errors(workspace, contract, policy)
        )
        findings = list(implementation_findings)
        if not contract_schema_findings:
            findings.extend(_source_errors(workspace, contract))
            findings.extend(_contract_redaction_errors(contract))
            findings.extend(
                _rc_dispatch_errors(workspace, contract, policy, input_map, observed_time)
            )
        findings = sorted(set(findings))
        statuses = {
            "repositoryImplementation": (
                "present" if not implementation_findings else "missing"
            ),
            "offlineVerification": "passed" if not findings else "failed",
            "protectedRcOperation": "not-performed",
            "gaValidation": "not-performed",
            "gaPublication": "not-performed",
            "publicObservation": "not-performed",
            "independentReproducibility": "pending",
        }
        lifecycle = "preflight-passed" if not findings else "blocked"
    elif mode == "closeout":
        if rc_input_map_path is not None:
            raise ValueError("closeout does not accept --rc-input-map")
        findings, statuses = _closeout(workspace, contract, policy)
        if findings:
            lifecycle = "blocked"
        elif statuses["publicObservation"] == "completed":
            lifecycle = "publicly-observed"
        elif statuses["gaPublication"] == "completed":
            lifecycle = "ga-published"
        elif statuses["gaValidation"] == "completed":
            lifecycle = "ga-validated"
        elif statuses["protectedRcOperation"] == "completed":
            lifecycle = "rc-frozen"
        else:
            lifecycle = "preflight-passed" if statuses["offlineVerification"] == "passed" else "planned"
    else:
        raise ValueError(
            "stable protected release mode must be preflight, rc-dispatch, or closeout"
        )
    summary = {
        "schemaVersion": 1,
        "kind": "stable-1.0-protected-release-execution-summary",
        "executionId": execution_id,
        "mode": mode,
        "status": "pass" if not findings else "fail",
        "promotionReady": not findings and mode in {"preflight", "rc-dispatch"},
        "lifecycleState": lifecycle,
        "contractDigest": (
            _semantic_digest(contract)
            if contract_schema_findings
            else _plan_digest(contract)
        ),
        "candidateCommit": _summary_identity(
            contract.get("repository", {}).get("candidateCommit")
            if isinstance(contract.get("repository"), dict)
            else None,
            COMMIT_RE,
        ),
        "releaseId": _summary_identity(
            contract.get("release", {}).get("id")
            if isinstance(contract.get("release"), dict)
            else None,
            RELEASE_ID_RE,
        ),
        "buildVersion": _summary_identity(
            contract.get("release", {}).get("integerBuild")
            if isinstance(contract.get("release"), dict)
            else None,
            BUILD_RE,
        ),
        "evidenceClassification": statuses,
        "dispatchPackage": _dispatch_package(contract) if not findings else None,
        "findings": findings,
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }
    redaction_findings = scan_value(summary)
    if redaction_findings:
        summary["status"] = "fail"
        summary["promotionReady"] = False
        summary["lifecycleState"] = "blocked"
        summary["dispatchPackage"] = None
        summary["findings"] = sorted(
            set(summary["findings"] + [finding["summary"] for finding in redaction_findings])
        )
        summary["redaction"] = {
            "status": "fail",
            "findingCount": len(redaction_findings),
            "findings": redaction_findings,
        }
    summary_schema_findings = validate_schema(summary, SUMMARY_SCHEMA)
    if summary_schema_findings:
        summary = {
            "schemaVersion": 1,
            "kind": "stable-1.0-protected-release-execution-summary",
            "executionId": execution_id,
            "mode": mode,
            "status": "fail",
            "promotionReady": False,
            "lifecycleState": "blocked",
            "contractDigest": (
                _semantic_digest(contract)
                if contract_schema_findings
                else _plan_digest(contract)
            ),
            "candidateCommit": _summary_identity(
                contract.get("repository", {}).get("candidateCommit")
                if isinstance(contract.get("repository"), dict)
                else None,
                COMMIT_RE,
            ),
            "releaseId": _summary_identity(
                contract.get("release", {}).get("id")
                if isinstance(contract.get("release"), dict)
                else None,
                RELEASE_ID_RE,
            ),
            "buildVersion": _summary_identity(
                contract.get("release", {}).get("integerBuild")
                if isinstance(contract.get("release"), dict)
                else None,
                BUILD_RE,
            ),
            "evidenceClassification": statuses,
            "dispatchPackage": None,
            "findings": ["execution summary rejected malformed or unsafe input details"],
            "redaction": {"status": "pass", "findingCount": 0, "findings": []},
        }
    if validate_schema(summary, SUMMARY_SCHEMA) or scan_value(summary):
        raise ValueError("failed execution summary could not be represented safely")
    _reject_output_input_collisions(
        workspace,
        output,
        contract,
        contract_resolved,
        input_map_resolved,
    )
    write_json(output / SUMMARY_FILE, summary)
    write_text(output / REPORT_FILE, _report(summary))
    write_json(
        output / REDACTION_FILE,
        {
            "schemaVersion": 1,
            "kind": "stable-1.0-protected-release-redaction",
            **summary["redaction"],
        },
    )
    print(f"stable-protected-release: {output / SUMMARY_FILE}")
    return 0 if summary["status"] == "pass" else 1
