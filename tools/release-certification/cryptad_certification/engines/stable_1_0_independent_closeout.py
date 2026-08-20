"""Retained-receipt authentication shared by PR-292 and PR-291 closeout."""

from __future__ import annotations

from typing import Any

from .stable_1_0_independent_reproducibility import (
    candidate_free_subject_projection,
)
from .stable_1_0_supply_chain_core import canonical_json_bytes, sha256_digest


def _digest(value: Any) -> str:
    return sha256_digest(canonical_json_bytes(value))


def independent_receipt_semantic_errors(
    summary: dict[str, Any],
    primary: dict[str, Any],
    external: dict[str, Any],
    supply_chain_policy: dict[str, Any],
    independent_policy: dict[str, Any],
) -> list[str]:
    """Bind both retained receipts to one exact release, recipe, and subject set."""

    errors: list[str] = []
    common = {
        "releaseId": summary.get("releaseId"),
        "buildVersion": summary.get("buildVersion"),
        "tag": summary.get("tag"),
        "sourceCommit": summary.get("sourceCommit"),
        "sourceRef": summary.get("sourceRef"),
    }
    for label, receipt in (("primary", primary), ("external", external)):
        for field, expected in common.items():
            if receipt.get(field) != expected:
                errors.append(f"{label} builder receipt {field} differs from closeout")
    if primary.get("role") != "candidate-producer":
        errors.append("primary builder receipt has the wrong role")
    if external.get("role") != "independent-verifier":
        errors.append("external builder receipt has the wrong role")
    selected_supply = summary.get("selectedRc", {}).get("supplyChain", {})
    primary_identity = primary.get("builderIdentity", {})
    expected_workflow_ref = (
        "github.com/crypta-network/cryptad/"
        f"{selected_supply.get('workflowPath')}@{selected_supply.get('workflowCommit')}"
    )
    if (
        primary_identity.get("workflowRef") != expected_workflow_ref
        or primary_identity.get("workflowSha") != selected_supply.get("workflowCommit")
        or str(primary_identity.get("runId")) != selected_supply.get("runId")
        or primary_identity.get("runAttempt") != selected_supply.get("runAttempt")
    ):
        errors.append("primary builder receipt differs from the selected RC supply-chain authority")
    if primary.get("policyDigest") != summary.get("stableSupplyChainPolicyDigest"):
        errors.append("primary builder receipt uses a different Stable policy")
    for field, expected in (
        ("stableSupplyChainPolicyDigest", summary.get("stableSupplyChainPolicyDigest")),
        (
            "independentReproducibilityPolicyDigest",
            summary.get("independentReproducibilityPolicyDigest"),
        ),
        ("executionContractDigest", summary.get("executionContractDigest")),
        ("verifierKitDigest", summary.get("verifierKitDigest")),
    ):
        if external.get(field) != expected:
            errors.append(f"external builder receipt {field} differs from closeout")
    for field in ("materialsDigest", "resolutionSnapshotDigest", "directInputs"):
        if primary.get(field) != external.get(field):
            errors.append(f"producer and external builder {field} differ")
    producer_recipe = supply_chain_policy.get("builderPolicy", {})
    if primary.get("buildTasks") != producer_recipe.get("buildTasks"):
        errors.append("primary builder task set differs from Stable policy")
    if external.get("buildTasks") != independent_policy.get("requiredBuildTasks"):
        errors.append(
            "external builder task set differs from the independent verifier policy"
        )
    primary_environments = [
        row.get("canonicalEnvironment")
        for row in primary.get("builderExecutions", [])
        if isinstance(row, dict)
    ]
    if (
        not primary_environments
        or any(value != primary_environments[0] for value in primary_environments)
        or external.get("canonicalEnvironment") != primary_environments[0]
    ):
        errors.append("producer and external builder canonical environment differs")
    for label, receipt in (("primary", primary), ("external", external)):
        source = receipt.get("source")
        if not isinstance(source, dict):
            errors.append(f"{label} builder receipt lacks a source identity")
            continue
        if (
            source.get("commit") != summary.get("sourceCommit")
            or source.get("ref") != summary.get("sourceRef")
            or source.get("clean") is not True
        ):
            errors.append(f"{label} builder receipt source identity differs")
    if primary.get("source", {}).get("treeDigest") != external.get("source", {}).get(
        "treeDigest"
    ):
        errors.append("producer and external builder source-tree identities differ")
    if external.get("candidateProductAvailableBeforeBuild") is not False:
        errors.append("external builder had candidate product bytes before its build")

    rules = {
        row.get("subjectKey"): row
        for row in supply_chain_policy.get("releaseSubjects", [])
        if isinstance(row, dict) and row.get("evidencePhase") == "independent-builder"
    }
    required_keys = sorted(rules)
    primary_subjects = {
        row.get("subjectKey"): row
        for row in primary.get("subjects", [])
        if isinstance(row, dict) and isinstance(row.get("subjectKey"), str)
    }
    external_subjects = {
        row.get("subjectKey"): row
        for row in external.get("subjects", [])
        if isinstance(row, dict) and isinstance(row.get("subjectKey"), str)
    }
    for label, receipt, subjects in (
        ("primary", primary, primary_subjects),
        ("external", external, external_subjects),
    ):
        keys = [
            row.get("subjectKey")
            for row in receipt.get("subjects", [])
            if isinstance(row, dict)
        ]
        if keys != required_keys or sorted(subjects) != required_keys:
            errors.append(f"{label} builder receipt does not cover the exact Stable subject set")
    for key in required_keys:
        first = primary_subjects.get(key, {})
        second = external_subjects.get(key, {})
        if first.get("fileName") != second.get("fileName"):
            errors.append(f"producer and external builder output name differs for {key}")
        if second.get("publishedCandidate") is not False:
            errors.append(f"external builder subject {key} is marked as a published candidate")
        if second.get("signatureReceiptDigest") is not None or second.get(
            "notarizationReceiptDigest"
        ) is not None:
            errors.append(f"external builder subject {key} asserts release-signing authority")

    expected_outputs = [
        {
            "subjectKey": key,
            "fileName": primary_subjects.get(key, {}).get("fileName"),
            "reproducibilityClass": rules[key].get("reproducibilityClass"),
            "normalizationRuleId": rules[key].get("normalizationRuleId"),
        }
        for key in required_keys
    ]
    primary_executions = {
        row.get("executionId"): row
        for row in primary.get("builderExecutions", [])
        if isinstance(row, dict) and isinstance(row.get("executionId"), str)
    }
    external_executions = [
        row for row in external.get("builderExecutions", []) if isinstance(row, dict)
    ]
    external_execution_ids = [row.get("executionId") for row in external_executions]
    if (
        len(primary_executions) != len(primary.get("builderExecutions", []))
        or external_execution_ids != sorted(primary_executions)
    ):
        errors.append("external builder executions do not match the producer execution set")
    for execution in external_executions:
        execution_id = execution.get("executionId")
        primary_execution = primary_executions.get(execution_id, {})
        expected_keys = primary_execution.get("subjectKeys")
        producer_tasks = producer_recipe.get("executionTasks", {}).get(execution_id)
        verifier_tasks = independent_policy.get("requiredExecutionTasks", {}).get(
            execution_id
        )
        if primary_execution.get("taskSet") != producer_tasks or primary_execution.get(
            "taskSetDigest"
        ) != _digest(producer_tasks):
            errors.append(
                f"primary builder execution {execution_id} task set differs from Stable policy"
            )
        if execution.get("taskSet") != verifier_tasks or execution.get(
            "taskSetDigest"
        ) != _digest(verifier_tasks):
            errors.append(
                f"external builder execution {execution_id} task set differs from the independent verifier policy"
            )
        if execution.get("subjectKeys") != expected_keys or not isinstance(
            expected_keys, list
        ):
            errors.append(
                f"external builder execution {execution_id} subject keys differ from the authenticated partition"
            )
            continue
        try:
            projection = candidate_free_subject_projection(
                expected_outputs, expected_keys
            )
        except ValueError:
            errors.append(
                f"external builder execution {execution_id} candidate-free subject projection is invalid"
            )
            continue
        if execution.get("subjectSetDigest") != _digest(projection):
            errors.append(
                f"external builder execution {execution_id} candidate-free subject-set digest differs"
            )
    return errors
