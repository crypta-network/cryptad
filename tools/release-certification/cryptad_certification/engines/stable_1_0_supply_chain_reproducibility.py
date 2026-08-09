"""Independent builder, payload comparison, and immutable publication verification."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptad_certification.schema_validation import validate_schema

from .stable_1_0_supply_chain_core import (
    BUILDER_RECEIPT_SCHEMA,
    COMPARISON_PLAN_SCHEMA,
    DIGEST_RE,
    PUBLICATION_OPERATIONS,
    PUBLICATION_PLAN_SCHEMA,
    PUBLICATION_RECEIPT_SCHEMA,
    PUBLICATION_ROLE_FILES,
    PUBLIC_OBSERVATION_SCHEMA,
    REPRODUCIBILITY_SCHEMA,
    SUMMARY_SCHEMA,
    canonical_json_bytes,
    confined_child,
    exact_release_errors,
    file_digest,
    parse_timestamp,
    payload_manifest_errors,
    semantic_digest,
    sha256_digest,
)

REPRODUCIBILITY_DIFFERENCES = frozenset(
    {
        "candidate subject bytes are absent",
        "verifier subject bytes are absent",
        "candidate subject differs from authenticated receipt",
        "verifier subject differs from authenticated receipt",
        "byte-identical subject bytes differ",
        "normalized comparison lacks a builder payload manifest",
        "candidate payload manifest differs from receipt",
        "verifier payload manifest differs from receipt",
        "normalized package payload differs",
        "pre-signing staged payload differs",
    }
)


def builder_receipt_errors(
    receipt: dict[str, Any],
    expected_role: str,
    release: dict[str, Any],
    policy: dict[str, Any],
    materials_digest: str,
    snapshot_digest: str,
    materials: dict[str, Any] | None = None,
    subjects_document: dict[str, Any] | None = None,
    snapshot: dict[str, Any] | None = None,
) -> list[str]:
    """Authenticate a builder receipt and all exact source/material/subject bindings."""

    errors = validate_schema(receipt, BUILDER_RECEIPT_SCHEMA)
    errors.extend(exact_release_errors(receipt, release, "builder receipt"))
    errors.extend(_self_digest_errors(receipt, "receiptDigest", "builder receipt"))
    if receipt.get("role") != expected_role:
        errors.append(f"builder receipt role must be {expected_role}")
    if receipt.get("materialsDigest") != materials_digest:
        errors.append("builder receipt uses different build materials")
    if receipt.get("resolutionSnapshotDigest") != snapshot_digest:
        errors.append("builder receipt uses different dependency resolution")
    identity = receipt.get("builderIdentity", {})
    if identity.get("repository") != policy.get("repositoryIdentity"):
        errors.append("builder receipt repository identity differs")
    if identity.get("attestationVerified") is not True:
        errors.append("builder receipt is not authenticated by an attestation")
    allowed_workflows = set(policy.get("builderPolicy", {}).get("allowedWorkflowPaths", []))
    workflow_ref = identity.get("workflowRef")
    expected_suffix = "@" + str(release.get("sourceCommit"))
    workflow_path = (
        workflow_ref.removesuffix(expected_suffix)
        if isinstance(workflow_ref, str) and workflow_ref.endswith(expected_suffix)
        else None
    )
    if workflow_path not in allowed_workflows or identity.get("workflowSha") != release.get(
        "sourceCommit"
    ):
        errors.append("builder receipt workflow is not policy-authorized")
    if receipt.get("source", {}).get("clean") is not True:
        errors.append("builder receipt used a dirty source tree")
    if receipt.get("source", {}).get("commit") != release.get("sourceCommit"):
        errors.append("builder source commit differs")
    if receipt.get("source", {}).get("ref") != release.get("sourceRef"):
        errors.append("builder source ref differs")
    errors.extend(
        _builder_execution_errors(
            receipt,
            expected_role,
            release,
            policy,
            materials_digest,
            snapshot_digest,
            materials,
            snapshot,
        )
    )
    if receipt.get("buildTasks") != policy.get("builderPolicy", {}).get("buildTasks"):
        errors.append("builder task set differs from policy")
    direct_inputs = receipt.get("directInputs", [])
    direct_names = [row.get("name") for row in direct_inputs if isinstance(row, dict)]
    required_direct = policy.get("buildMaterialRules", {}).get("requiredDirectInputs", [])
    if direct_names != sorted(required_direct):
        errors.append("builder direct inputs are not the exact sorted policy set")
    for row in direct_inputs:
        if not isinstance(row, dict):
            continue
        expected_mechanism = (
            "gradle-wrapper-checksum"
            if row.get("name") == "gradle-wrapper-distribution"
            else "sha256-before-use"
        )
        if row.get("verificationMechanism") != expected_mechanism:
            errors.append("builder direct input uses the wrong verification mechanism")
    if materials is not None:
        expected_direct = {
            row.get("name"): {
                "digest": row.get("digest"),
                "origin": row.get("origin"),
                "immutabilityClass": row.get("immutabilityClass"),
            }
            for row in materials.get("directInputs", [])
            if isinstance(row, dict)
        }
        actual_direct = {
            row.get("name"): {
                "digest": row.get("digest"),
                "origin": row.get("origin"),
                "immutabilityClass": row.get("immutabilityClass"),
            }
            for row in direct_inputs
            if isinstance(row, dict)
        }
        if actual_direct != expected_direct:
            errors.append("builder direct inputs differ from authenticated build materials")
    if receipt.get("candidateProductAvailableBeforeBuild") is not False:
        errors.append("builder received candidate product bytes before its build completed")
    expected_published_candidate = expected_role == "candidate-producer"
    subjects = receipt.get("subjects", [])
    if any(
        row.get("publishedCandidate") is not expected_published_candidate
        for row in subjects
        if isinstance(row, dict)
    ):
        errors.append("builder receipt misidentifies verifier output as the published candidate")
    keys = [row.get("subjectKey") for row in subjects if isinstance(row, dict)]
    if keys != sorted(set(keys)):
        errors.append("builder receipt subjects are not uniquely and deterministically sorted")
    if subjects_document is None:
        errors.append("builder receipt lacks an authenticated subject inventory")
    else:
        errors.extend(
            builder_subject_coverage_errors(
                receipt, subjects_document, policy, expected_role
            )
        )
    try:
        started = parse_timestamp(receipt.get("buildStartedAt"), "builder start time")
        completed = parse_timestamp(receipt.get("buildCompletedAt"), "builder completion time")
        if completed < started:
            errors.append("builder completion predates its build start")
    except ValueError as exc:
        errors.append(str(exc))
    return errors


def independent_builder_subjects(
    policy: dict[str, Any], subjects_document: dict[str, Any]
) -> list[dict[str, Any]]:
    """Return the exact sorted release-subject rows eligible for independent rebuilds."""

    phases = {
        row.get("subjectKey"): row.get("evidencePhase")
        for row in policy.get("releaseSubjects", [])
        if isinstance(row, dict)
    }
    return sorted(
        [
            row
            for row in subjects_document.get("subjects", [])
            if isinstance(row, dict)
            and phases.get(row.get("subjectKey")) == "independent-builder"
        ],
        key=lambda row: row["subjectKey"],
    )


def builder_subject_coverage_errors(
    receipt: dict[str, Any],
    subjects_document: dict[str, Any],
    policy: dict[str, Any],
    expected_role: str,
) -> list[str]:
    """Require a receipt to assert exactly, and only, independently rebuilt subjects."""

    errors: list[str] = []
    expected_rows = independent_builder_subjects(policy, subjects_document)
    expected = {row["subjectKey"]: row for row in expected_rows}
    actual_rows = [row for row in receipt.get("subjects", []) if isinstance(row, dict)]
    actual = {row.get("subjectKey"): row for row in actual_rows}
    expected_keys = [row["subjectKey"] for row in expected_rows]
    actual_keys = [row.get("subjectKey") for row in actual_rows]
    if actual_keys != expected_keys:
        errors.append("builder receipt does not cover the exact independent-builder subject set")
        return errors
    for key in expected_keys:
        expected_row = expected[key]
        actual_row = actual[key]
        if actual_row.get("fileName") != expected_row.get("fileName"):
            errors.append(f"builder receipt subject {key} file name differs from inventory")
        if expected_role == "candidate-producer":
            for field in (
                "digest",
                "size",
                "payloadManifestDigest",
                "signatureReceiptDigest",
                "notarizationReceiptDigest",
            ):
                if actual_row.get(field) != expected_row.get(field):
                    errors.append(
                        f"producer receipt subject {key} {field} differs from inventory"
                    )
        elif actual_row.get("signatureReceiptDigest") is not None or actual_row.get(
            "notarizationReceiptDigest"
        ) is not None:
            errors.append(f"verifier receipt subject {key} claims candidate authentication")
        extraction_required = (
            expected_row.get("reproducibilityClass") == "normalized-payload-identical"
        )
        if (actual_row.get("extractionEvidenceDigest") is not None) != extraction_required:
            errors.append(f"builder receipt subject {key} extraction evidence differs")
    return errors


def _builder_execution_errors(
    receipt: dict[str, Any],
    expected_role: str,
    release: dict[str, Any],
    policy: dict[str, Any],
    materials_digest: str,
    snapshot_digest: str,
    materials: dict[str, Any] | None,
    snapshot: dict[str, Any] | None,
) -> list[str]:
    """Authenticate every platform execution contributing subjects to one builder role."""

    errors: list[str] = []
    executions = receipt.get("builderExecutions", [])
    expected_ids = policy.get("builderPolicy", {}).get("executionIds", [])
    execution_ids = [
        row.get("executionId") for row in executions if isinstance(row, dict)
    ]
    if execution_ids != sorted(expected_ids):
        errors.append("builder executions are not the exact sorted policy set")
    subject_rows = {
        row.get("subjectKey"): row
        for row in receipt.get("subjects", [])
        if isinstance(row, dict) and isinstance(row.get("subjectKey"), str)
    }
    covered: list[str] = []
    identity = receipt.get("builderIdentity", {})
    expected_runner_os = {
        "linux-installers": "linux",
        "macos-installer": "macos",
        "portable-apps": "linux",
        "windows-installer": "windows",
    }
    top_started: Any = None
    top_completed: Any = None
    try:
        top_started = parse_timestamp(receipt.get("buildStartedAt"), "builder start time")
        top_completed = parse_timestamp(
            receipt.get("buildCompletedAt"), "builder completion time"
        )
    except ValueError:
        pass
    for execution in executions:
        if not isinstance(execution, dict):
            continue
        execution_id = execution.get("executionId")
        subject_keys = execution.get("subjectKeys", [])
        if subject_keys != sorted(set(subject_keys)):
            errors.append(f"builder execution {execution_id} subject keys are not canonical")
        covered.extend(str(key) for key in subject_keys)
        for key in subject_keys:
            if key not in subject_rows:
                errors.append(f"builder execution {execution_id} references an absent subject")
            elif _execution_for_subject(str(key)) != execution_id:
                errors.append(f"builder execution {execution_id} contains a misrouted subject")
        exact_bindings = (
            ("workflow ref", execution.get("workflowRef"), identity.get("workflowRef")),
            ("workflow SHA", execution.get("workflowSha"), identity.get("workflowSha")),
            ("run id", execution.get("runId"), identity.get("runId")),
            ("run attempt", execution.get("runAttempt"), identity.get("runAttempt")),
            ("source commit", execution.get("sourceCommit"), release.get("sourceCommit")),
            (
                "source tree",
                execution.get("sourceTreeDigest"),
                receipt.get("source", {}).get("treeDigest"),
            ),
            ("materials", execution.get("materialsDigest"), materials_digest),
            (
                "dependency resolution",
                execution.get("resolutionSnapshotDigest"),
                snapshot_digest,
            ),
            ("runner OS", execution.get("runnerOs"), expected_runner_os.get(execution_id)),
            ("runner architecture", execution.get("runnerArchitecture"), "amd64"),
        )
        for label, actual, expected in exact_bindings:
            if actual != expected:
                errors.append(f"builder execution {execution_id} {label} differs")
        if execution.get("jobName") != f"{expected_role}-{execution_id}":
            errors.append(f"builder execution {execution_id} job identity differs")
        if execution.get("attestationVerified") is not True:
            errors.append(f"builder execution {execution_id} attestation is unauthenticated")
        if "latest" in str(execution.get("runnerImageIdentity", "")).casefold():
            errors.append(f"builder execution {execution_id} uses a mutable runner image")
        selected_rows = [subject_rows[key] for key in subject_keys if key in subject_rows]
        expected_subject_set_digest = sha256_digest(
            canonical_json_bytes(sorted(selected_rows, key=lambda row: row["subjectKey"]))
        )
        if execution.get("subjectSetDigest") != expected_subject_set_digest:
            errors.append(f"builder execution {execution_id} subject set digest differs")
        expected_tasks = policy.get("builderPolicy", {}).get("executionTasks", {}).get(
            execution_id
        )
        if execution.get("taskSet") != expected_tasks:
            errors.append(f"builder execution {execution_id} task set differs")
        if execution.get("taskSetDigest") != sha256_digest(
            canonical_json_bytes(expected_tasks)
        ):
            errors.append(f"builder execution {execution_id} task set digest differs")
        if execution.get("directInputsDigest") != sha256_digest(
            canonical_json_bytes(receipt.get("directInputs", []))
        ):
            errors.append(f"builder execution {execution_id} direct inputs digest differs")
        if materials is not None:
            jdk = materials.get("jdk", {})
            gradle = materials.get("gradle", {})
            environment = materials.get("environment", {})
            toolchain = execution.get("toolchain", {})
            java_identity = {
                "javaVendor": toolchain.get("javaVendor"),
                "javaVersion": toolchain.get("javaVersion"),
                "javaBuild": toolchain.get("javaBuild"),
                "javaEncoding": toolchain.get("javaEncoding"),
                "javaArchitecture": toolchain.get("javaArchitecture"),
                "javaInstallationManifestDigest": toolchain.get(
                    "javaInstallationManifestDigest"
                ),
                "javaReleaseFileDigest": toolchain.get("javaReleaseFileDigest"),
            }
            matching_installations = [
                row
                for row in jdk.get("installations", [])
                if isinstance(row, dict)
                and row.get("runnerOs") == execution.get("runnerOs")
                and row.get("architecture") == execution.get("runnerArchitecture")
            ]
            installation = (
                matching_installations[0] if len(matching_installations) == 1 else {}
            )
            if len(matching_installations) != 1:
                errors.append(
                    f"builder execution {execution_id} has no unique reviewed JDK installation"
                )
            for field, expected in (
                ("javaVendor", jdk.get("vendor")),
                ("javaVersion", jdk.get("version")),
                ("javaBuild", jdk.get("build")),
                ("javaEncoding", environment.get("encoding")),
                ("javaArchitecture", installation.get("architecture")),
                (
                    "javaInstallationManifestDigest",
                    installation.get("installationManifestDigest"),
                ),
                ("javaReleaseFileDigest", installation.get("releaseFileDigest")),
                ("gradleWrapperJarDigest", gradle.get("wrapperJarDigest")),
                ("gradleWrapperPropertiesDigest", gradle.get("wrapperPropertiesDigest")),
                ("gradleDistributionDigest", gradle.get("distributionDigest")),
            ):
                if toolchain.get(field) != expected:
                    errors.append(f"builder execution {execution_id} {field} differs")
            if toolchain.get("javaIdentityDigest") != sha256_digest(
                canonical_json_bytes(java_identity)
            ):
                errors.append(f"builder execution {execution_id} Java identity digest differs")
            expected_canonical_environment = {
                "locale": environment.get("locale"),
                "timezone": environment.get("timezone"),
                "encoding": environment.get("encoding"),
                "sourceDateEpoch": materials.get("canonicalBuildEpoch"),
            }
            if execution.get("canonicalEnvironment") != expected_canonical_environment:
                errors.append(f"builder execution {execution_id} canonical environment differs")
            if execution.get("environmentVariables") != {
                "LANG": environment.get("locale"),
                "LC_ALL": environment.get("locale"),
                "SOURCE_DATE_EPOCH": str(materials.get("canonicalBuildEpoch")),
                "TZ": environment.get("timezone"),
            }:
                errors.append(
                    f"builder execution {execution_id} observed environment variables differ"
                )
        if snapshot is not None:
            digests = snapshot.get("materialDigests", {})
            if execution.get("materialIdentities") != {
                "dependencyVerificationDigest": digests.get("verificationMetadata"),
                "verificationKeyringDigest": digests.get("verificationKeyring"),
                "pluginResolutionDigest": digests.get("pluginResolution"),
                "buildLogicDigest": digests.get("buildLogic"),
                "resolutionSnapshotDigest": snapshot_digest,
            }:
                errors.append(f"builder execution {execution_id} material identities differ")
        if execution.get("candidateProductAvailableBeforeBuild") is not False:
            errors.append(
                f"builder execution {execution_id} candidate-byte isolation differs"
            )
        try:
            started = parse_timestamp(
                execution.get("buildStartedAt"), f"builder execution {execution_id} start"
            )
            completed = parse_timestamp(
                execution.get("buildCompletedAt"),
                f"builder execution {execution_id} completion",
            )
            if completed < started:
                errors.append(f"builder execution {execution_id} completion predates start")
            if (
                top_started is not None
                and top_completed is not None
                and (started < top_started or completed > top_completed)
            ):
                errors.append(f"builder execution {execution_id} time is outside its receipt")
        except ValueError as exc:
            errors.append(str(exc))
    if sorted(covered) != sorted(subject_rows) or len(covered) != len(set(covered)):
        errors.append("builder executions do not partition the exact subject set")
    return errors


def _execution_for_subject(subject_key: str) -> str:
    if subject_key in {"amd64.deb", "amd64.flatpak", "amd64.rpm", "amd64.snap"}:
        return "linux-installers"
    if subject_key == "amd64.dmg":
        return "macos-installer"
    if subject_key == "amd64.exe":
        return "windows-installer"
    return "portable-apps"


def builder_independence_errors(
    primary: dict[str, Any], verifier: dict[str, Any], policy: dict[str, Any]
) -> list[str]:
    """Reject reuse of a producer execution as the independent verifier."""

    errors: list[str] = []
    first = primary.get("builderIdentity", {})
    second = verifier.get("builderIdentity", {})
    if first.get("runId") == second.get("runId"):
        errors.append("candidate producer and verifier use the same workflow run")
    if (
        first.get("workflowRef"),
        first.get("workflowSha"),
        first.get("jobName"),
        first.get("runAttempt"),
    ) == (
        second.get("workflowRef"),
        second.get("workflowSha"),
        second.get("jobName"),
        second.get("runAttempt"),
    ):
        errors.append("candidate producer and verifier use the same builder identity")
    required_count = policy.get("builderPolicy", {}).get("requiredBuilderCount")
    if required_count != 2:
        errors.append("policy does not require exactly two independent builders")
    if primary.get("receiptDigest") == verifier.get("receiptDigest"):
        errors.append("candidate producer and verifier receipts are identical")
    if primary.get("materialsDigest") != verifier.get("materialsDigest"):
        errors.append("builder materials differ")
    if primary.get("resolutionSnapshotDigest") != verifier.get("resolutionSnapshotDigest"):
        errors.append("builder dependency resolution differs")
    if primary.get("buildTasks") != verifier.get("buildTasks"):
        errors.append("builder task sets differ")
    if primary.get("directInputs") != verifier.get("directInputs"):
        errors.append("builder direct input identities differ")
    primary_executions = {
        row.get("executionId"): row
        for row in primary.get("builderExecutions", [])
        if isinstance(row, dict)
    }
    verifier_executions = {
        row.get("executionId"): row
        for row in verifier.get("builderExecutions", [])
        if isinstance(row, dict)
    }
    expected_ids = set(policy.get("builderPolicy", {}).get("executionIds", []))
    if set(primary_executions) != expected_ids or set(verifier_executions) != expected_ids:
        errors.append("builder execution sets differ from policy")
    for execution_id in sorted(
        set(primary_executions).intersection(verifier_executions)
    ):
        producer_execution = primary_executions[execution_id]
        verifier_execution = verifier_executions[execution_id]
        if producer_execution.get("runId") == verifier_execution.get("runId"):
            errors.append(
                f"candidate producer and verifier reuse the {execution_id} execution run"
            )
        # payloadManifestSetDigest is the role-neutral normalized comparison view.
        # extractionManifestSetDigest instead binds each role's own extraction
        # evidence, including candidate signing facts that an isolated verifier
        # must neither possess nor claim, so those digests intentionally may differ.
        for field, label in (
            ("subjectKeys", "subject routing"),
            ("sourceCommit", "source commit"),
            ("sourceTreeDigest", "source tree"),
            ("materialsDigest", "materials"),
            ("resolutionSnapshotDigest", "dependency resolution"),
            ("runnerOs", "runner OS"),
            ("runnerArchitecture", "runner architecture"),
            ("runnerImageIdentity", "runner image identity"),
            ("runnerImageDigest", "runner image digest"),
            ("toolchain", "toolchain identity"),
            ("materialIdentities", "material identities"),
            ("taskSet", "task set"),
            ("taskSetDigest", "task set digest"),
            ("canonicalEnvironment", "canonical environment"),
            ("directInputsDigest", "direct inputs digest"),
            ("payloadManifestSetDigest", "payload manifest set digest"),
        ):
            if producer_execution.get(field) != verifier_execution.get(field):
                errors.append(f"builder {execution_id} {label} differs")
        if producer_execution.get("handoffDigest") == verifier_execution.get(
            "handoffDigest"
        ):
            errors.append(f"builder {execution_id} handoffs are not independent")
        if producer_execution.get("artifactAttestationDigest") == verifier_execution.get(
            "artifactAttestationDigest"
        ):
            errors.append(f"builder {execution_id} attestations are not independent")
    return errors


def _receipt_subjects(receipt: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        row["subjectKey"]: row
        for row in receipt.get("subjects", [])
        if isinstance(row, dict) and isinstance(row.get("subjectKey"), str)
    }


def build_comparison_plan(
    release: dict[str, Any],
    policy: dict[str, Any],
    subjects_document: dict[str, Any],
    primary: dict[str, Any],
    verifier: dict[str, Any],
) -> dict[str, Any]:
    """Emit a closed comparison plan without inferring equality."""

    errors = builder_independence_errors(primary, verifier, policy)
    errors.extend(
        builder_subject_coverage_errors(
            primary, subjects_document, policy, "candidate-producer"
        )
    )
    errors.extend(
        builder_subject_coverage_errors(
            verifier, subjects_document, policy, "independent-verifier"
        )
    )
    if errors:
        raise ValueError(errors[0])
    primary_subjects = _receipt_subjects(primary)
    verifier_subjects = _receipt_subjects(verifier)
    comparisons = []
    policy_rules = {
        row["subjectKey"]: row for row in policy["releaseSubjects"]
    }
    for subject in independent_builder_subjects(policy, subjects_document):
        key = subject["subjectKey"]
        first = primary_subjects.get(key)
        second = verifier_subjects.get(key)
        if first is None or second is None:
            raise ValueError(f"both builders must cover subject {key}")
        rule = policy_rules[key]
        if first.get("digest") != subject.get("digest"):
            raise ValueError(f"producer receipt does not bind candidate subject {key}")
        comparisons.append(
            {
                "subjectKey": key,
                "fileName": subject["fileName"],
                "reproducibilityClass": rule["reproducibilityClass"],
                "normalizationRuleId": rule.get("normalizationRuleId"),
                "primaryDigest": first["digest"],
                "verifierDigest": second["digest"],
                "primarySize": first["size"],
                "verifierSize": second["size"],
                "primaryPayloadManifestDigest": first.get("payloadManifestDigest"),
                "verifierPayloadManifestDigest": second.get("payloadManifestDigest"),
            }
        )
    plan = {
        "schemaVersion": 1,
        "kind": "stable-1.0-rebuild-comparison-plan",
        **release,
        "componentInventoryDigest": subjects_document["componentInventoryDigest"],
        "subjectInventoryDigest": subjects_document["subjectInventoryDigest"],
        "primaryBuilderReceiptDigest": primary["receiptDigest"],
        "verifierBuilderReceiptDigest": verifier["receiptDigest"],
        "comparisons": comparisons,
        "equalityInferred": False,
        "planDigest": "sha256:" + "0" * 64,
    }
    plan["planDigest"] = semantic_digest(plan, "planDigest")
    errors = validate_schema(plan, COMPARISON_PLAN_SCHEMA)
    if errors:
        raise ValueError(f"generated comparison plan violates schema: {errors[0]}")
    return plan


def comparison_plan_errors(
    supplied: dict[str, Any],
    release: dict[str, Any],
    policy: dict[str, Any],
    subjects_document: dict[str, Any],
    primary: dict[str, Any],
    verifier: dict[str, Any],
) -> list[str]:
    """Require an exact authenticated plan freshly derived from both receipts."""

    errors = validate_schema(supplied, COMPARISON_PLAN_SCHEMA)
    errors.extend(_self_digest_errors(supplied, "planDigest", "comparison plan"))
    try:
        expected = build_comparison_plan(
            release, policy, subjects_document, primary, verifier
        )
    except ValueError as exc:
        errors.append(str(exc))
        return errors
    if supplied != expected:
        errors.append("comparison plan is stale or differs from authenticated builder inputs")
    return errors


def _load_payload_manifests(
    directory: Path | None, policy: dict[str, Any]
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    manifests: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    if directory is None:
        return manifests, errors
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        if path.is_symlink() or not path.is_file() or path.suffix != ".json":
            errors.append("payload-manifest directory contains an unexpected entry")
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            errors.append("payload manifest is not strict UTF-8 JSON")
            continue
        if not isinstance(value, dict):
            errors.append("payload manifest is not an object")
            continue
        manifest_errors = payload_manifest_errors(value, policy)
        errors.extend(manifest_errors)
        key = value.get("subjectKey")
        if isinstance(key, str):
            if key in manifests:
                errors.append("payload manifest subject is duplicated")
            manifests[key] = value
    return manifests, errors


def compare_rebuilds(
    release: dict[str, Any],
    policy: dict[str, Any],
    plan: dict[str, Any],
    primary_root: Path,
    verifier_root: Path,
    primary_manifest_root: Path | None,
    verifier_manifest_root: Path | None,
) -> tuple[dict[str, Any], list[str]]:
    """Compare independent build bytes through the one policy-approved view per subject."""

    errors: list[str] = []
    primary_manifests, manifest_errors = _load_payload_manifests(primary_manifest_root, policy)
    errors.extend(manifest_errors)
    verifier_manifests, manifest_errors = _load_payload_manifests(verifier_manifest_root, policy)
    errors.extend(manifest_errors)
    comparisons = []
    for row in plan.get("comparisons", []):
        key = row["subjectKey"]
        subject_class = row["reproducibilityClass"]
        first_path = confined_child(primary_root, row["fileName"])
        second_path = confined_child(verifier_root, row["fileName"])
        differences: list[str] = []
        first_digest = None
        second_digest = None
        if subject_class != "not-a-product-subject":
            if first_path is None or not first_path.is_file() or first_path.is_symlink():
                differences.append("candidate subject bytes are absent")
            else:
                first_digest = file_digest(first_path)
            if second_path is None or not second_path.is_file() or second_path.is_symlink():
                differences.append("verifier subject bytes are absent")
            else:
                second_digest = file_digest(second_path)
        if first_digest is not None and first_digest != row.get("primaryDigest"):
            differences.append("candidate subject differs from authenticated receipt")
        if second_digest is not None and second_digest != row.get("verifierDigest"):
            differences.append("verifier subject differs from authenticated receipt")
        if subject_class == "byte-identical" and first_digest != second_digest:
            differences.append("byte-identical subject bytes differ")
        if subject_class == "normalized-payload-identical":
            first_manifest = primary_manifests.get(key)
            second_manifest = verifier_manifests.get(key)
            if first_manifest is None or second_manifest is None:
                differences.append("normalized comparison lacks a builder payload manifest")
            else:
                if first_manifest.get("manifestDigest") != row.get(
                    "primaryPayloadManifestDigest"
                ):
                    differences.append("candidate payload manifest differs from receipt")
                if second_manifest.get("manifestDigest") != row.get(
                    "verifierPayloadManifestDigest"
                ):
                    differences.append("verifier payload manifest differs from receipt")
                comparable_first = _payload_comparison_view(first_manifest)
                comparable_second = _payload_comparison_view(second_manifest)
                if comparable_first != comparable_second:
                    differences.append("normalized package payload differs")
                if first_manifest.get("preSigningPayloadDigest") != second_manifest.get(
                    "preSigningPayloadDigest"
                ):
                    differences.append("pre-signing staged payload differs")
        differences.sort()
        comparisons.append(
            {
                "subjectKey": key,
                "reproducibilityClass": subject_class,
                "status": "pass" if not differences else "fail",
                "primaryDigest": first_digest or row.get("primaryDigest"),
                "verifierDigest": second_digest or row.get("verifierDigest"),
                "primaryPayloadManifestDigest": row.get("primaryPayloadManifestDigest"),
                "verifierPayloadManifestDigest": row.get("verifierPayloadManifestDigest"),
                "differences": differences,
            }
        )
        errors.extend(f"{key}: {difference}" for difference in differences)
    result = {
        "schemaVersion": 1,
        "kind": "stable-1.0-reproducibility-result",
        **release,
        "comparisonPlanDigest": plan["planDigest"],
        "primaryBuilderReceiptDigest": plan["primaryBuilderReceiptDigest"],
        "verifierBuilderReceiptDigest": plan["verifierBuilderReceiptDigest"],
        "comparisons": comparisons,
        "status": "pass" if not errors else "fail",
        "unexplainedDifferences": len(errors),
        "resultDigest": "sha256:" + "0" * 64,
    }
    result["resultDigest"] = semantic_digest(result, "resultDigest")
    schema_errors = validate_schema(result, REPRODUCIBILITY_SCHEMA)
    if schema_errors:
        raise ValueError(f"generated reproducibility result violates schema: {schema_errors[0]}")
    return result, errors


def reproducibility_result_errors(
    result: dict[str, Any],
    release: dict[str, Any],
    plan: dict[str, Any],
) -> list[str]:
    """Validate every result assertion against its authenticated comparison plan."""

    errors = validate_schema(result, REPRODUCIBILITY_SCHEMA)
    errors.extend(exact_release_errors(result, release, "reproducibility result"))
    errors.extend(_self_digest_errors(result, "resultDigest", "reproducibility result"))
    for result_field, plan_field in (
        ("comparisonPlanDigest", "planDigest"),
        ("primaryBuilderReceiptDigest", "primaryBuilderReceiptDigest"),
        ("verifierBuilderReceiptDigest", "verifierBuilderReceiptDigest"),
    ):
        if result.get(result_field) != plan.get(plan_field):
            errors.append(f"reproducibility result {result_field} differs from plan")

    plan_rows = plan.get("comparisons", [])
    result_rows = result.get("comparisons", [])
    plan_keys = [row.get("subjectKey") for row in plan_rows if isinstance(row, dict)]
    result_keys = [row.get("subjectKey") for row in result_rows if isinstance(row, dict)]
    if plan_keys != sorted(set(plan_keys)):
        errors.append("comparison plan subjects are not canonical")
    if result_keys != plan_keys:
        errors.append("reproducibility result does not cover the exact sorted plan subjects")
    for expected, actual in zip(plan_rows, result_rows, strict=False):
        if not isinstance(expected, dict) or not isinstance(actual, dict):
            continue
        key = expected.get("subjectKey")
        for result_field, plan_field in (
            ("subjectKey", "subjectKey"),
            ("reproducibilityClass", "reproducibilityClass"),
            ("primaryDigest", "primaryDigest"),
            ("verifierDigest", "verifierDigest"),
            ("primaryPayloadManifestDigest", "primaryPayloadManifestDigest"),
            ("verifierPayloadManifestDigest", "verifierPayloadManifestDigest"),
        ):
            if actual.get(result_field) != expected.get(plan_field):
                errors.append(
                    f"reproducibility result subject {key} {result_field} differs from plan"
                )
        differences = actual.get("differences", [])
        if differences != sorted(set(differences)):
            errors.append(f"reproducibility result subject {key} differences are not canonical")
        if any(value not in REPRODUCIBILITY_DIFFERENCES for value in differences):
            errors.append(f"reproducibility result subject {key} has an unknown difference")
        expected_status = "fail" if differences else "pass"
        if actual.get("status") != expected_status:
            errors.append(f"reproducibility result subject {key} status is inconsistent")

    difference_count = sum(
        len(row.get("differences", []))
        for row in result_rows
        if isinstance(row, dict) and isinstance(row.get("differences"), list)
    )
    expected_status = "fail" if difference_count else "pass"
    if result.get("status") != expected_status:
        errors.append("reproducibility result status is inconsistent with its rows")
    if result.get("unexplainedDifferences") != difference_count:
        errors.append("reproducibility result difference count is inconsistent")
    return errors


def _payload_comparison_view(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return the exact closed payload view; there are no candidate ignore controls."""

    return {
        "normalizationRuleId": manifest["normalizationRuleId"],
        "normalizationRuleVersion": manifest["normalizationRuleVersion"],
        "preSigningPayloadDigest": manifest["preSigningPayloadDigest"],
        "packageMetadataDigest": manifest["packageMetadataDigest"],
        "entries": manifest["entries"],
        "ignoredPaths": manifest["ignoredPaths"],
    }


def promotion_summary_errors(
    summary: dict[str, Any], release: dict[str, Any]
) -> list[str]:
    """Authenticate one promotion summary and its fail-closed readiness assertions."""

    errors = validate_schema(summary, SUMMARY_SCHEMA)
    errors.extend(exact_release_errors(summary, release, "supply-chain summary"))
    for field in ("tag", "sourceRef"):
        if summary.get(field) != release.get(field):
            errors.append(f"supply-chain summary {field} differs")
    errors.extend(_self_digest_errors(summary, "summaryDigest", "supply-chain summary"))

    blockers = summary.get("blockers")
    has_blockers = isinstance(blockers, list) and bool(blockers)
    expected_status = "fail" if has_blockers else "pass"
    if summary.get("status") != expected_status:
        errors.append("supply-chain summary status is inconsistent with its blockers")
    expected_ready = not has_blockers and summary.get("mode") in {
        "evaluate-promotion",
        "verify-publication",
    }
    if summary.get("promotionReady") is not expected_ready:
        errors.append("supply-chain summary readiness is inconsistent")

    evidence = summary.get("evidence")
    if isinstance(evidence, list) and any(
        not isinstance(row, dict) or row.get("status") != "pass" for row in evidence
    ):
        errors.append("supply-chain summary contains failing evidence assertions")
    redaction = summary.get("redaction")
    if isinstance(redaction, dict) and redaction.get("status") != expected_status:
        errors.append("supply-chain summary redaction status is inconsistent")
    return errors


def publication_errors(
    plan: dict[str, Any],
    receipt: dict[str, Any],
    observation: dict[str, Any],
    summary: dict[str, Any],
    release: dict[str, Any],
    policy: dict[str, Any],
    evaluation_clock: str,
) -> list[str]:
    """Verify immutable publication operations and fresh exact-byte public observations."""

    errors = promotion_summary_errors(summary, release)
    errors.extend(validate_schema(plan, PUBLICATION_PLAN_SCHEMA))
    errors.extend(validate_schema(receipt, PUBLICATION_RECEIPT_SCHEMA))
    errors.extend(validate_schema(observation, PUBLIC_OBSERVATION_SCHEMA))
    errors.extend(_self_digest_errors(plan, "planDigest", "publication plan"))
    errors.extend(_self_digest_errors(receipt, "receiptDigest", "publication receipt"))
    errors.extend(
        _self_digest_errors(observation, "observationDigest", "public observation")
    )
    for value, label in (
        (plan, "publication plan"),
        (receipt, "publication receipt"),
        (observation, "public observation"),
    ):
        errors.extend(exact_release_errors(value, release, label))
        for field in ("tag", "sourceRef"):
            if value.get(field) != release.get(field):
                errors.append(f"{label} {field} differs")
    if plan.get("summaryDigest") != summary.get("summaryDigest"):
        errors.append("publication plan binds a different supply-chain summary")
    if plan.get("allowedOperations") != list(PUBLICATION_OPERATIONS):
        errors.append("publication plan operation vocabulary is reordered or altered")
    if receipt.get("planDigest") != plan.get("planDigest"):
        errors.append("publication receipt binds a different plan")
    if observation.get("receiptDigest") != receipt.get("receiptDigest"):
        errors.append("public observation binds a different receipt")
    if receipt.get("backendAuthenticated") is not True:
        errors.append("publication receipt backend is unauthenticated")
    if observation.get("observerAuthenticated") is not True:
        errors.append("public observation producer is unauthenticated")

    planned = {
        row["role"]: (row["digest"], row["size"], row["uri"])
        for row in plan.get("assets", [])
    }
    operated = {
        row["role"]: (row["digest"], row["size"], row["uri"])
        for row in receipt.get("operations", [])
        if row.get("operation") in PUBLICATION_OPERATIONS
    }
    observed = {
        row["role"]: (row["digest"], row["size"], row["uri"])
        for row in observation.get("assets", [])
    }
    if operated != planned:
        errors.append("publication receipt operations differ from the exact plan")
    if observed != planned:
        errors.append("public observations differ from the exact planned bytes")
    required_roles = set(policy.get("publicationPolicy", {}).get("requiredRoles", []))
    if set(planned) != required_roles:
        errors.append("publication plan lacks the exact policy-required artifact roles")
    policy_roles = policy.get("publicationPolicy", {}).get("requiredRoles", [])
    if policy_roles != list(PUBLICATION_ROLE_FILES):
        errors.append("publication policy role-to-file vocabulary differs")
    planned_rows = plan.get("assets", [])
    receipt_rows = receipt.get("operations", [])
    observation_rows = observation.get("assets", [])
    if [row.get("role") for row in planned_rows] != policy_roles:
        errors.append("publication plan roles are duplicated, reordered, or incomplete")
    if [row.get("role") for row in receipt_rows] != policy_roles:
        errors.append("publication receipt roles are duplicated, reordered, or incomplete")
    if [row.get("role") for row in observation_rows] != policy_roles:
        errors.append("public observation roles are duplicated, reordered, or incomplete")
    immutable_base = str(
        policy.get("publicationPolicy", {}).get("immutableBaseUri", "")
    ).rstrip("/")
    expected_tag = f"v{release.get('buildVersion')}"
    for row in planned_rows:
        role = row.get("role")
        expected_file = PUBLICATION_ROLE_FILES.get(role)
        expected_uri = (
            f"{immutable_base}/{expected_tag}/{expected_file}"
            if expected_file is not None
            else None
        )
        if row.get("fileName") != expected_file or row.get("uri") != expected_uri:
            errors.append(
                f"publication target for {role} differs from the policy-derived immutable target"
            )
    for role, (_, _, uri) in planned.items():
        parsed = urlsplit(uri)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            errors.append(f"publication URI for {role} is unsafe or mutable")
        if parsed.query or parsed.fragment:
            errors.append(f"publication URI for {role} contains mutable query or fragment data")
    try:
        evaluation = parse_timestamp(evaluation_clock, "publication evaluation clock")
        observed_at = parse_timestamp(observation.get("observedAt"), "public observation time")
        generated_at = parse_timestamp(receipt.get("generatedAt"), "publication receipt time")
        maximum_age = policy.get("publicationPolicy", {}).get("maximumObservationAgeSeconds", 0)
        if observed_at < generated_at or observed_at > evaluation:
            errors.append("public observation time is outside the authenticated publication window")
        if (evaluation - observed_at).total_seconds() > maximum_age:
            errors.append("public observation is stale")
    except ValueError as exc:
        errors.append(str(exc))
    return errors


def _self_digest_errors(value: dict[str, Any], field: str, label: str) -> list[str]:
    expected = value.get(field)
    if not isinstance(expected, str) or DIGEST_RE.fullmatch(expected) is None:
        return [f"{label} lacks a valid {field}"]
    if semantic_digest(value, field) != expected:
        return [f"{label} {field} is invalid"]
    return []
