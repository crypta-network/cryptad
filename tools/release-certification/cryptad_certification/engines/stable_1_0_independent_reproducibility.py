"""Provider-distinct Stable 1.0 reproducible-build verification."""

from __future__ import annotations

import copy
import hashlib
import re
import stat
import tarfile
import tempfile
import unicodedata
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from ..io import read_json, read_json_bytes, write_bytes, write_json, write_text
from ..redaction import scan_value
from ..schema_validation import validate_schema
from .stable_1_0_supply_chain_core import (
    build_material_errors,
    canonical_json_bytes,
    component_inventory_errors,
    file_digest,
    parse_timestamp,
    resolution_snapshot_errors,
    semantic_digest,
    sha256_digest,
    subject_inventory_errors,
)
from .stable_1_0_supply_chain_reproducibility import (
    build_comparison_plan,
    builder_receipt_errors,
    compare_rebuilds,
    reproducibility_result_errors,
)

CONTRACT_SCHEMA = "stable-1.0-independent-reproducibility-execution-v1.schema.json"
BUILDER_RECEIPT_SCHEMA = "stable-1.0-independent-builder-receipt-v2.schema.json"
AUTHORITY_ATTESTATION_SCHEMA = (
    "stable-1.0-independent-authority-attestation-v1.schema.json"
)
VERIFIER_KIT_SCHEMA = "stable-1.0-independent-verifier-kit-v1.schema.json"
OUTPUT_MANIFEST_SCHEMA = "stable-1.0-independent-output-manifest-v1.schema.json"
SUMMARY_SCHEMA = "stable-1.0-independent-reproducibility-summary-v1.schema.json"
PRIMARY_RECEIPT_SCHEMA = "stable-1.0-builder-receipt-v1.schema.json"
COMPARISON_PLAN_SCHEMA = "stable-1.0-rebuild-comparison-plan-v1.schema.json"
REPRODUCIBILITY_RESULT_SCHEMA = "stable-1.0-reproducibility-result-v1.schema.json"
POLICY_FILE = "stable-1.0-independent-reproducibility-policy.json"
SUPPLY_CHAIN_POLICY_FILE = "stable-1.0-supply-chain-policy.json"
KIT_FILE = "stable-1.0-independent-verifier-kit.json"
KIT_DIGEST_FILE = "stable-1.0-independent-verifier-kit.sha256"
ATTESTATION_FILE = "stable-1.0-independent-builder-attestation.json"
EXTERNAL_RECEIPT_FILE = "stable-1.0-independent-builder-receipt.json"
EXTERNAL_MANIFEST_FILE = "stable-1.0-independent-output-manifest.json"
PRIMARY_RECEIPT_FILE = "stable-1.0-primary-builder-receipt.json"
PRIMARY_ATTESTATION_FILE = "stable-1.0-primary-authority-attestation.json"
RAW_ATTESTATION_FILE = "stable-1.0-independent-raw-artifact-attestation.bundle"
VERIFICATION_TRANSCRIPT_FILE = "stable-1.0-independent-attestation-verification-transcript.json"
PLAN_FILE = "stable-1.0-rebuild-comparison-plan.json"
RESULT_FILE = "stable-1.0-reproducibility-report.json"
SUMMARY_FILE = "stable-1.0-independent-reproducibility-summary.json"
REPORT_FILE = "stable-1.0-independent-reproducibility-report.md"
REDACTION_FILE = "stable-1.0-independent-reproducibility-redaction-report.json"

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,159}")
_PROHIBITED_ARCHIVE_NAMES = frozenset({".DS_Store"})
_MAX_JSON_BYTES = 10_000_000
# Enabling an adapter in policy is necessary but not sufficient.  An adapter may enter this set
# only after this engine contains an offline cryptographic verifier for its raw bundle format and
# tests pin the certificate/key, signed statement, subject set, and workload claims.  PR-292 ships
# no approved external provider or trust root, so operational external completion remains closed.
_IMPLEMENTED_OPERATIONAL_EXTERNAL_ADAPTERS: frozenset[str] = frozenset()
_CANDIDATE_FREE_SUBJECT_FIELDS = (
    "subjectKey",
    "fileName",
    "reproducibilityClass",
    "normalizationRuleId",
)


def _schema_root() -> Path:
    return Path(__file__).resolve().parents[2] / "schemas"


def _policy_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _strict_digest(value: dict[str, Any], field: str) -> str:
    return semantic_digest(value, field)


def execution_contract_digest(value: dict[str, Any]) -> str:
    """Digest the immutable plan shared by all lifecycle invocations.

    Transport bindings, coordinator coordinates, mode, timestamps, and lifecycle
    assertions are deliberately outside this projection: they cannot exist before
    the external builder seals a receipt.  Their exact bytes are authenticated by
    their own file bindings and the final coordinator artifact.
    """

    immutable_fields = (
        "schemaVersion",
        "kind",
        "executionId",
        "repository",
        "release",
        "selectedRc",
        "policies",
        "authenticatedInputs",
        "authenticatedInputFiles",
        "buildRecipe",
        "producerAuthority",
        "expectedVerifierAuthority",
    )
    projection = {field: value.get(field) for field in immutable_fields}
    return sha256_digest(canonical_json_bytes(projection))


def candidate_free_subject_projection(
    expected_outputs: list[dict[str, Any]], subject_keys: list[str]
) -> list[dict[str, Any]]:
    """Return the canonical expected-subject view available before candidate access."""

    if subject_keys != sorted(set(subject_keys)):
        raise ValueError("candidate-free subject keys are not canonical")
    outputs_by_key = {
        row.get("subjectKey"): row for row in expected_outputs if isinstance(row, dict)
    }
    if len(outputs_by_key) != len(expected_outputs) or any(
        key not in outputs_by_key for key in subject_keys
    ):
        raise ValueError("candidate-free subject projection is incomplete or ambiguous")
    return [
        {field: outputs_by_key[key].get(field) for field in _CANDIDATE_FREE_SUBJECT_FIELDS}
        for key in subject_keys
    ]


def _timestamp(value: Any, label: str) -> datetime:
    return parse_timestamp(value, label)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _runner_utc_now() -> datetime:
    """Return the current runner clock at the contract timestamp precision."""

    return datetime.now(timezone.utc).replace(microsecond=0)


def _runner_clock_errors(
    contract: dict[str, Any],
    policy: dict[str, Any],
    runner_time: datetime | None = None,
) -> list[str]:
    """Bind the caller-supplied evaluation time to the local runner clock."""

    try:
        evaluation = _timestamp(
            contract.get("evaluationTime"), "execution evaluation time"
        )
        observed = runner_time or _runner_utc_now()
        if observed.tzinfo is None:
            raise ValueError("runner clock is not timezone-aware")
        observed = observed.astimezone(timezone.utc).replace(microsecond=0)
        maximum_skew = timedelta(
            seconds=int(policy["freshness"]["maximumClockSkewSeconds"])
        )
        if abs(evaluation - observed) > maximum_skew:
            return ["execution evaluation time differs from the runner clock"]
    except (KeyError, TypeError, ValueError) as exc:
        return [str(exc)]
    return []


def _confined_file(workspace: Path, relative: Any, label: str) -> Path:
    if not isinstance(relative, (str, Path)):
        raise ValueError(f"{label} path is missing or malformed")
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"{label} path is not repository-relative")
    current = workspace
    for part in candidate.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"{label} path contains a symbolic link")
    resolved = current.resolve()
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise ValueError(f"{label} path escapes the repository workspace") from exc
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError(f"{label} is missing or is not a regular file")
    metadata = resolved.stat(follow_symlinks=False)
    if metadata.st_nlink != 1:
        raise ValueError(f"{label} has ambiguous hard-link identity")
    return resolved


def _output_directory(workspace: Path, requested: Path) -> Path:
    resolved_workspace = workspace.resolve()
    if ".." in requested.parts:
        raise ValueError("independent reproducibility output contains traversal")
    target = requested if requested.is_absolute() else resolved_workspace / requested
    try:
        relative = target.relative_to(resolved_workspace)
    except ValueError as exc:
        raise ValueError("independent reproducibility output escapes the workspace") from exc

    def validate_components() -> None:
        current = resolved_workspace
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError(
                    "independent reproducibility output contains a symbolic-link component"
                )
            if current.exists() and not current.is_dir():
                raise ValueError(
                    "independent reproducibility output contains a non-directory component"
                )

    validate_components()
    target.mkdir(parents=True, exist_ok=True)
    validate_components()
    resolved = target.resolve()
    try:
        resolved.relative_to(resolved_workspace)
    except ValueError as exc:
        raise ValueError("independent reproducibility output escapes the workspace") from exc
    if resolved.is_symlink() or not resolved.is_dir():
        raise ValueError("independent reproducibility output is not a regular directory")
    return resolved


def _binding_file(
    workspace: Path,
    binding: Any,
    label: str,
    *,
    expected_schema: str | None | object = ...,
) -> tuple[Path | None, list[str]]:
    errors: list[str] = []
    if not isinstance(binding, dict):
        return None, [f"{label} binding is missing or malformed"]
    if expected_schema is not ... and binding.get("schema") != expected_schema:
        errors.append(f"{label} schema identity differs")
    try:
        path = _confined_file(workspace, binding.get("path"), label)
    except (OSError, ValueError) as exc:
        return None, [*errors, str(exc)]
    if file_digest(path) != binding.get("sha256"):
        errors.append(f"{label} bytes differ from the execution contract")
    size = binding.get("size")
    if size is not None and size != path.stat().st_size:
        errors.append(f"{label} size differs from the execution contract")
    return path, errors


def _binding_json(
    workspace: Path,
    binding: Any,
    label: str,
    schema: str,
) -> tuple[Path | None, dict[str, Any] | None, list[str]]:
    path, errors = _binding_file(
        workspace,
        binding,
        label,
        expected_schema=schema,
    )
    if path is None:
        return None, None, errors
    if path.stat().st_size > _MAX_JSON_BYTES:
        return path, None, [*errors, f"{label} exceeds the bounded JSON size limit"]
    try:
        loaded = read_json(path)
    except (OSError, ValueError):
        return path, None, [*errors, f"{label} is not strict UTF-8 JSON"]
    if not isinstance(loaded, dict):
        return path, None, [*errors, f"{label} is not a JSON object"]
    errors.extend(validate_schema(loaded, schema))
    return path, loaded, errors


def _load_policy() -> tuple[dict[str, Any], dict[str, Any]]:
    independent = read_json(_policy_root() / POLICY_FILE)
    supply_chain = read_json(_policy_root() / SUPPLY_CHAIN_POLICY_FILE)
    if not isinstance(independent, dict) or not isinstance(supply_chain, dict):
        raise ValueError("independent reproducibility policy is malformed")
    return independent, supply_chain


def _profile(policy: dict[str, Any], profile_id: Any) -> dict[str, Any] | None:
    matches = [
        row
        for row in policy.get("providerProfiles", [])
        if isinstance(row, dict) and row.get("profileId") == profile_id
    ]
    return matches[0] if len(matches) == 1 else None


def _adapter(policy: dict[str, Any], adapter_id: Any) -> dict[str, Any] | None:
    matches = [
        row
        for row in policy.get("attestationAdapters", [])
        if isinstance(row, dict) and row.get("adapterId") == adapter_id
    ]
    return matches[0] if len(matches) == 1 else None


def _policy_errors(
    contract: dict[str, Any],
    policy: dict[str, Any],
    supply_chain: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    if policy.get("policyDigest") != _strict_digest(policy, "policyDigest"):
        errors.append("independent reproducibility policy self-digest differs")
    if supply_chain.get("policyDigest") != _strict_digest(
        supply_chain, "policyDigest"
    ):
        errors.append("Stable supply-chain policy self-digest differs")
    for collection, digest_field in (
        ("attestationAdapters", "adapterDigest"),
        ("providerProfiles", "profileDigest"),
    ):
        for row in policy.get(collection, []):
            if not isinstance(row, dict) or row.get(digest_field) != _strict_digest(
                row, digest_field
            ):
                errors.append(f"independent reproducibility {collection} digest differs")
    policies = contract.get("policies", {})
    if policies.get("independentReproducibilityPolicyDigest") != policy.get(
        "policyDigest"
    ):
        errors.append("execution contract uses a different independent policy")
    if policies.get("stableSupplyChainPolicyDigest") != supply_chain.get(
        "policyDigest"
    ):
        errors.append("execution contract uses a different Stable supply-chain policy")
    for field, schema_name in (
        ("comparisonPlanSchemaDigest", COMPARISON_PLAN_SCHEMA),
        ("reproducibilityResultSchemaDigest", REPRODUCIBILITY_RESULT_SCHEMA),
    ):
        schema_path = _schema_root() / schema_name
        if policies.get(field) != file_digest(schema_path):
            errors.append(f"execution contract {field} differs from the checked-in schema")
    return errors


def _contract_errors(
    contract: dict[str, Any],
    mode: str,
    policy: dict[str, Any],
    supply_chain: dict[str, Any],
) -> list[str]:
    errors = validate_schema(contract, CONTRACT_SCHEMA)
    if errors:
        return errors
    if contract.get("operationMode") != mode:
        errors.append("execution contract operation mode differs from the requested operation")
    expected_lifecycle = {
        "prepare-verifier-kit": "planned",
        "verify-external-receipt": "external-build-sealed",
        "compare": "external-build-sealed",
        "closeout": "external-build-sealed",
        "self-test": "planned",
    }.get(mode)
    if expected_lifecycle is None or contract.get("lifecycleState") != expected_lifecycle:
        errors.append("execution contract lifecycle state is invalid for the requested operation")
    phase_errors = _phase_binding_errors(contract, mode)
    errors.extend(phase_errors)
    if contract.get("executionContractDigest") != execution_contract_digest(contract):
        errors.append("independent reproducibility execution contract digest differs")
    repository = contract["repository"]
    release = contract["release"]
    selected = contract["selectedRc"]
    if repository["sourceRef"] != f"commit:{repository['sourceCommit']}":
        errors.append("execution contract source ref does not bind the exact commit")
    if release["tag"] != f"v{release['integerBuild']}":
        errors.append("execution contract Stable tag differs from the integer build")
    if selected["workflowCommit"] != repository["sourceCommit"]:
        errors.append("selected RC workflow commit differs from the source commit")
    if selected["supplyChain"]["workflowCommit"] != repository["sourceCommit"]:
        errors.append("selected RC supply-chain workflow commit differs from the source commit")
    if selected["subjectInventoryDigest"] != contract["authenticatedInputs"][
        "subjectInventoryDigest"
    ]:
        errors.append("selected RC subject inventory digest differs")
    errors.extend(_policy_errors(contract, policy, supply_chain))
    build_recipe = contract["buildRecipe"]
    builder_policy = supply_chain.get("builderPolicy", {})
    verifier_tasks = policy.get("requiredBuildTasks")
    if build_recipe["buildTasks"] != verifier_tasks:
        errors.append(
            "execution contract build tasks differ from the independent verifier policy"
        )
    required_rules = {
        row.get("subjectKey"): row
        for row in supply_chain.get("releaseSubjects", [])
        if isinstance(row, dict) and row.get("evidencePhase") == "independent-builder"
    }
    required_keys = sorted(required_rules)
    if build_recipe["requiredSubjectKeys"] != required_keys:
        errors.append("execution contract required subjects differ from Stable policy")
    outputs = build_recipe.get("expectedOutputs", [])
    output_keys = [row.get("subjectKey") for row in outputs if isinstance(row, dict)]
    if output_keys != required_keys:
        errors.append("execution contract expected outputs are not canonical and complete")
    output_names = [row.get("fileName") for row in outputs if isinstance(row, dict)]
    if len(output_names) != len(set(output_names)):
        errors.append("execution contract output paths are not unique")
    for row in outputs:
        if not isinstance(row, dict):
            continue
        rule = required_rules.get(row.get("subjectKey"), {})
        if (
            row.get("reproducibilityClass") != rule.get("reproducibilityClass")
            or row.get("normalizationRuleId") != rule.get("normalizationRuleId")
        ):
            errors.append("execution contract changes a Stable reproducibility class")
    if build_recipe.get("normalizationPolicyDigest") != sha256_digest(
        canonical_json_bytes(supply_chain.get("normalizationRules", []))
    ):
        errors.append("execution contract normalization policy digest differs")
    partitions = build_recipe.get("executionPartitions", [])
    partition_ids = [row.get("executionId") for row in partitions if isinstance(row, dict)]
    if partition_ids != sorted(builder_policy.get("executionIds", [])):
        errors.append("execution partitions differ from Stable policy")
    covered: list[str] = []
    for row in partitions:
        if not isinstance(row, dict):
            continue
        execution_id = row.get("executionId")
        if row.get("taskSet") != policy.get("requiredExecutionTasks", {}).get(
            execution_id
        ):
            errors.append(
                f"execution partition {execution_id} task set differs from the independent verifier policy"
            )
        if row.get("subjectKeys") != sorted(set(row.get("subjectKeys", []))):
            errors.append(f"execution partition {execution_id} subjects are not canonical")
        covered.extend(str(key) for key in row.get("subjectKeys", []))
    if sorted(covered) != required_keys or len(covered) != len(set(covered)):
        errors.append("execution partitions do not cover the exact subject set")
    environment = build_recipe.get("canonicalEnvironment", {})
    if environment.get("sourceDateEpoch") != repository.get("canonicalCommitEpoch"):
        errors.append("canonical environment does not use the authenticated commit epoch")
    for authority_name in ("producerAuthority", "expectedVerifierAuthority"):
        authority = contract[authority_name]
        profile = _profile(policy, authority.get("profileId"))
        if profile is None:
            errors.append(f"{authority_name} selects an unknown provider profile")
            continue
        if authority.get("profileDigest") != profile.get("profileDigest"):
            errors.append(f"{authority_name} provider profile digest differs")
        for field in (
            "providerId",
            "controlPlaneId",
            "trustDomainId",
            "organizationId",
        ):
            if authority.get(field) != profile.get(field):
                errors.append(f"{authority_name} {field} differs from its profile")
        if authority.get("requireOrganizationDistinct") is not profile.get(
            "organizationIndependenceRequired"
        ):
            errors.append(f"{authority_name} organization-independence rule differs from its profile")
    if scan_value(contract):
        errors.append("execution contract contains private material or local absolute paths")
    return sorted(set(errors))


def _phase_binding_errors(contract: dict[str, Any], mode: str) -> list[str]:
    """Reject lifecycle claims and file availability that do not match the invocation phase."""

    errors: list[str] = []
    verifier_kit = contract.get("verifierKit")
    external = contract.get("externalBuild", {})
    comparison = contract.get("comparison", {})
    closeout = contract.get("closeout", {})
    external_fields = (
        "builderReceipt",
        "authorityAttestation",
        "rawArtifactAttestationBundle",
        "verificationTranscript",
        "outputManifest",
        "outputBundle",
    )
    primary_fields = (
        "primaryBuilderReceipt",
        "primaryAuthorityAttestation",
        "candidateSubjectBundle",
    )
    generated_comparison_fields = ("comparisonPlan", "reproducibilityResult")

    if mode in {"prepare-verifier-kit", "self-test"}:
        if verifier_kit is not None:
            errors.append("planned execution contract already exposes a verifier kit")
        if any(external.get(field) is not None for field in external_fields):
            errors.append("planned execution contract already exposes an external build")
        if any(comparison.get(field) is not None for field in (*primary_fields, *generated_comparison_fields)):
            errors.append("planned execution contract already exposes comparison evidence")
        if any(closeout.get(field) is not None for field in ("summary", "coordinatorArtifact")):
            errors.append("planned execution contract already exposes closeout evidence")
    else:
        if verifier_kit is None:
            errors.append("external-build phase lacks the exact verifier-kit binding")
        if any(external.get(field) is None for field in external_fields):
            errors.append("external-build phase lacks a complete sealed external evidence set")
        if mode == "verify-external-receipt":
            if any(comparison.get(field) is not None for field in (*primary_fields, *generated_comparison_fields)):
                errors.append("external receipt verification exposes candidate comparison inputs")
        else:
            if any(comparison.get(field) is None for field in primary_fields):
                errors.append("comparison phase lacks the authenticated primary evidence set")
            if any(comparison.get(field) is not None for field in generated_comparison_fields):
                errors.append("comparison outputs must not be supplied as trusted inputs")
        if any(closeout.get(field) is not None for field in ("summary", "coordinatorArtifact")):
            errors.append("closeout outputs must not be supplied as trusted inputs")

    classification = contract.get("evidenceClassification", {})
    if classification.get("repositoryImplementation") != "present":
        errors.append("execution contract does not bind the repository implementation")
    if classification.get("selfTest") != "not-performed":
        errors.append("operational invocation cannot be derived from self-test evidence")
    if classification.get("externalProviderExecution") != "not-authenticated":
        errors.append("execution contract self-asserts external-provider authentication")
    if classification.get("publicVerification") != "not-performed":
        errors.append("execution contract self-asserts public verification")
    if contract.get("blockedReason") is not None:
        errors.append("active execution contract contains a self-asserted blocked state")
    return errors


def _input_documents(
    workspace: Path,
    contract: dict[str, Any],
    supply_chain: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    schemas = {
        "buildMaterials": "stable-1.0-build-materials-v1.schema.json",
        "resolutionSnapshot": "stable-1.0-resolved-dependency-snapshot-v1.schema.json",
        "componentInventory": "stable-1.0-component-inventory-v1.schema.json",
        "subjectInventory": "stable-1.0-release-subject-inventory-v1.schema.json",
        "sbomBinding": "stable-1.0-sbom-binding-v1.schema.json",
    }
    bindings = contract.get("authenticatedInputFiles")
    if not isinstance(bindings, dict):
        return {}, ["execution contract lacks authenticated input file bindings"]
    values: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for name, schema in schemas.items():
        _path, value, item_errors = _binding_json(
            workspace,
            bindings.get(name),
            f"authenticated {name}",
            schema,
        )
        errors.extend(item_errors)
        if value is not None:
            values[name] = value
    expected_digests = {
        "buildMaterials": ("materialsDigest", "buildMaterialsDigest"),
        "resolutionSnapshot": ("snapshotDigest", "resolutionSnapshotDigest"),
        "componentInventory": ("inventoryDigest", "componentInventoryDigest"),
        "subjectInventory": ("subjectInventoryDigest", "subjectInventoryDigest"),
        "sbomBinding": ("sbomDigest", "sbomDigest"),
    }
    for name, (document_field, contract_field) in expected_digests.items():
        value = values.get(name)
        if value is not None and value.get(document_field) != contract.get(
            "authenticatedInputs", {}
        ).get(contract_field):
            errors.append(f"authenticated {name} semantic digest differs from the contract")
    materials = values.get("buildMaterials")
    subjects = values.get("subjectInventory")
    if materials is not None:
        direct_inputs = [
            {
                **row,
                "verificationMechanism": (
                    "gradle-wrapper-checksum"
                    if row.get("name") == "gradle-wrapper-distribution"
                    else "sha256-before-use"
                ),
            }
            for row in materials.get("directInputs", [])
            if isinstance(row, dict)
        ]
        recipe = contract.get("buildRecipe", {})
        if contract.get("authenticatedInputs", {}).get("directInputsDigest") != sha256_digest(
            canonical_json_bytes(direct_inputs)
        ):
            errors.append("execution contract direct-input aggregate digest differs")
        if recipe.get("jdkIdentityDigest") != sha256_digest(
            canonical_json_bytes(materials.get("jdk", {}))
        ):
            errors.append("execution contract JDK identity digest differs")
        if recipe.get("gradleIdentityDigest") != sha256_digest(
            canonical_json_bytes(materials.get("gradle", {}))
        ):
            errors.append("execution contract Gradle identity digest differs")
    if subjects is not None:
        inventory_names = {
            row.get("subjectKey"): row.get("fileName")
            for row in subjects.get("subjects", [])
            if isinstance(row, dict)
        }
        for row in contract.get("buildRecipe", {}).get("expectedOutputs", []):
            if inventory_names.get(row.get("subjectKey")) != row.get("fileName"):
                errors.append(f"execution output path differs for subject {row.get('subjectKey')}")
    if set(values) == set(schemas):
        release = _release_projection(contract)
        components = values["componentInventory"]
        subjects_document = values["subjectInventory"]
        snapshot = values["resolutionSnapshot"]
        materials = values["buildMaterials"]
        errors.extend(component_inventory_errors(components, supply_chain, release))
        errors.extend(
            subject_inventory_errors(
                subjects_document,
                components,
                supply_chain,
                release,
            )
        )
        errors.extend(resolution_snapshot_errors(snapshot, release, supply_chain))
        errors.extend(
            build_material_errors(
                materials,
                release,
                snapshot["snapshotDigest"],
                supply_chain,
                snapshot,
            )
        )
        sbom_binding = values["sbomBinding"]
        if sbom_binding.get("bindingDigest") != _strict_digest(
            sbom_binding, "bindingDigest"
        ):
            errors.append("authenticated SBOM binding self-digest differs")
        for field, expected in (
            ("componentInventoryDigest", components["inventoryDigest"]),
            ("subjectInventoryDigest", subjects_document["subjectInventoryDigest"]),
            ("sourceCommit", contract["repository"]["sourceCommit"]),
        ):
            if sbom_binding.get(field) != expected:
                errors.append(f"authenticated SBOM binding {field} differs")
    return values, errors


def _build_verifier_kit(
    contract: dict[str, Any],
    policy: dict[str, Any],
    supply_chain: dict[str, Any],
    documents: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    materials = documents["buildMaterials"]
    gradle = materials["gradle"]
    jdk = materials["jdk"]
    profile = _profile(policy, contract["expectedVerifierAuthority"]["profileId"])
    if profile is None:
        raise ValueError("verifier profile is absent from independent policy")
    schema_names = sorted(
        {
            value
            for value in policy.get("schemas", {}).values()
            if isinstance(value, str) and (_schema_root() / value).is_file()
        }
    )
    used_rule_ids = {
        row["normalizationRuleId"]
        for row in contract["buildRecipe"]["expectedOutputs"]
        if row.get("normalizationRuleId") is not None
    }
    normalization_rules = []
    for rule in supply_chain["normalizationRules"]:
        if rule["id"] in used_rule_ids:
            normalization_rules.append(
                {
                    "id": rule["id"],
                    "version": rule["version"],
                    "ruleDigest": sha256_digest(canonical_json_bytes(rule)),
                }
            )
    direct_inputs = []
    for row in materials["directInputs"]:
        direct_inputs.append(
            {
                **row,
                "verificationMechanism": (
                    "gradle-wrapper-checksum"
                    if row["name"] == "gradle-wrapper-distribution"
                    else "sha256-before-use"
                ),
            }
        )
    selected_identity = {
        field: contract["selectedRc"][field]
        for field in (
            "workflowPath",
            "workflowCommit",
            "runId",
            "runAttempt",
            "artifactName",
        )
    }
    prepared = _timestamp(contract["evaluationTime"], "kit preparation time")
    maximum_age = int(policy["freshness"]["verifierKitMaximumAgeSeconds"])
    source_archive = contract["repository"].get("authenticatedSourceArchive")
    if not isinstance(source_archive, dict):
        raise ValueError("execution contract lacks an authenticated source archive")
    kit = {
        "schemaVersion": 1,
        "kind": "stable-1.0-independent-verifier-kit",
        "releaseId": contract["release"]["id"],
        "buildVersion": contract["release"]["integerBuild"],
        "tag": contract["release"]["tag"],
        "repositoryIdentity": contract["repository"]["identity"],
        "sourceCommit": contract["repository"]["sourceCommit"],
        "sourceRef": contract["repository"]["sourceRef"],
        "sourceTreeDigest": contract["repository"]["sourceTreeDigest"],
        "sourceArchive": {**source_archive, "commit": contract["repository"]["sourceCommit"]},
        "selectedRcIdentityDigest": sha256_digest(
            canonical_json_bytes(selected_identity)
        ),
        "executionContractDigest": contract["executionContractDigest"],
        "canonicalCommitEpoch": contract["repository"]["canonicalCommitEpoch"],
        "policies": {
            "stableSupplyChainPolicyDigest": supply_chain["policyDigest"],
            "independentReproducibilityPolicyDigest": policy["policyDigest"],
            "normalizationPolicyDigest": contract["buildRecipe"][
                "normalizationPolicyDigest"
            ],
            "providerProfileDigest": profile["profileDigest"],
        },
        "schemas": [
            {"name": name, "digest": file_digest(_schema_root() / name)}
            for name in schema_names
        ],
        "toolchain": {
            "jdkVendor": jdk["vendor"],
            "jdkVersion": jdk["version"],
            "jdkBuild": jdk["build"],
            "jdkIdentityDigest": contract["buildRecipe"]["jdkIdentityDigest"],
            "gradleVersion": gradle["version"],
            "gradleDistributionDigest": gradle["distributionDigest"],
            "gradleWrapperJarDigest": gradle["wrapperJarDigest"],
            "gradleWrapperPropertiesDigest": gradle["wrapperPropertiesDigest"],
            "dependencyVerificationMetadataDigest": gradle[
                "verificationMetadataDigest"
            ],
            "verificationKeyringDigest": gradle["verificationKeyringDigest"],
        },
        "buildMaterialsDigest": materials["materialsDigest"],
        "resolutionSnapshotDigest": documents["resolutionSnapshot"]["snapshotDigest"],
        "directInputs": direct_inputs,
        "repositoryConstraints": {
            "repositoryConfigurationDigest": gradle["repositoryConfigurationDigest"],
            "pluginResolutionDigest": gradle["pluginResolutionDigest"],
            "buildLogicDigest": gradle["buildLogicDigest"],
            "dynamicVersionsProhibited": True,
            "changingModulesProhibited": True,
            "dependencyVerificationRequired": True,
        },
        "canonicalEnvironment": contract["buildRecipe"]["canonicalEnvironment"],
        "buildTasks": contract["buildRecipe"]["buildTasks"],
        "executionPartitions": contract["buildRecipe"]["executionPartitions"],
        "expectedOutputs": contract["buildRecipe"]["expectedOutputs"],
        "normalizationRules": normalization_rules,
        "outputInstructions": {
            "builderReceiptSchema": BUILDER_RECEIPT_SCHEMA,
            "authorityAttestationSchema": AUTHORITY_ATTESTATION_SCHEMA,
            "outputManifestSchema": OUTPUT_MANIFEST_SCHEMA,
            "bundleFormat": "zip-store-v1",
            "sealBeforeCandidateAccess": True,
            "absolutePathsProhibited": True,
            "linksProhibited": True,
        },
        "preparedAt": _format_timestamp(prepared),
        "expiresAt": _format_timestamp(prepared + timedelta(seconds=maximum_age)),
        "candidateExclusions": {
            "candidateBytesExcluded": True,
            "candidateProductDigestsExcluded": True,
            "producerReceiptExcluded": True,
            "signingSecretsExcluded": True,
            "publicationCredentialsExcluded": True,
            "privateUrisExcluded": True,
            "rawContentExcluded": True,
            "absolutePathsExcluded": True,
        },
        "kitDigest": "sha256:" + "0" * 64,
    }
    kit["kitDigest"] = _strict_digest(kit, "kitDigest")
    schema_errors = validate_schema(kit, VERIFIER_KIT_SCHEMA)
    if schema_errors:
        raise ValueError(f"generated verifier kit violates schema: {schema_errors[0]}")
    prohibited = {
        contract["selectedRc"][field]
        for field in (
            "artifactDigest",
            "freezeDigest",
            "freezeFileDigest",
            "productDigest",
            "subjectInventoryDigest",
        )
    }
    kit_text = canonical_json_bytes(kit).decode("utf-8")
    if any(value in kit_text for value in prohibited):
        raise ValueError("generated verifier kit contains a candidate product digest")
    if scan_value(kit):
        raise ValueError("generated verifier kit contains private or local-path material")
    return kit


def _release_projection(contract: dict[str, Any]) -> dict[str, Any]:
    release = contract["release"]
    repository = contract["repository"]
    return {
        "releaseId": release["id"],
        "buildVersion": release["integerBuild"],
        "tag": release["tag"],
        "sourceCommit": repository["sourceCommit"],
        "sourceRef": repository["sourceRef"],
        "policyDigest": contract["policies"]["stableSupplyChainPolicyDigest"],
    }


def _identity_digest_errors(value: dict[str, Any], fields: tuple[str, ...], label: str) -> list[str]:
    errors: list[str] = []
    for field in fields:
        nested = value.get(field)
        digest_field = field.removesuffix("Identity") + "IdentityDigest"
        if isinstance(nested, dict) and digest_field in nested:
            if nested[digest_field] != _strict_digest(nested, digest_field):
                errors.append(f"{label} {field} digest differs")
    return errors


def _external_receipt_errors(
    receipt: dict[str, Any],
    contract: dict[str, Any],
    kit: dict[str, Any],
    policy: dict[str, Any],
    documents: dict[str, dict[str, Any]],
) -> list[str]:
    errors = validate_schema(receipt, BUILDER_RECEIPT_SCHEMA)
    if errors:
        return errors
    if receipt["receiptDigest"] != _strict_digest(receipt, "receiptDigest"):
        errors.append("external builder receipt self-digest differs")
    expected = {
        "releaseId": contract["release"]["id"],
        "buildVersion": contract["release"]["integerBuild"],
        "tag": contract["release"]["tag"],
        "repositoryIdentity": contract["repository"]["identity"],
        "sourceCommit": contract["repository"]["sourceCommit"],
        "sourceRef": contract["repository"]["sourceRef"],
        "stableSupplyChainPolicyDigest": contract["policies"]["stableSupplyChainPolicyDigest"],
        "independentReproducibilityPolicyDigest": policy["policyDigest"],
        "executionContractDigest": contract["executionContractDigest"],
        "verifierKitDigest": kit["kitDigest"],
        "role": "independent-verifier",
        "providerProfileId": contract["expectedVerifierAuthority"]["profileId"],
        "providerProfileDigest": contract["expectedVerifierAuthority"]["profileDigest"],
        "materialsDigest": contract["authenticatedInputs"]["buildMaterialsDigest"],
        "resolutionSnapshotDigest": contract["authenticatedInputs"]["resolutionSnapshotDigest"],
        "buildTasks": contract["buildRecipe"]["buildTasks"],
        "candidateProductAvailableBeforeBuild": False,
        "canonicalEnvironment": contract["buildRecipe"]["canonicalEnvironment"],
    }
    for field, expected_value in expected.items():
        if receipt.get(field) != expected_value:
            errors.append(f"external builder receipt {field} differs")
    source = receipt["source"]
    if source != {
        "commit": contract["repository"]["sourceCommit"],
        "ref": contract["repository"]["sourceRef"],
        "treeDigest": contract["repository"]["sourceTreeDigest"],
        "clean": True,
    }:
        errors.append("external builder receipt source identity differs")
    if receipt["directInputs"] != kit["directInputs"]:
        errors.append("external builder receipt direct inputs differ from the verifier kit")
    required_outputs = {
        row["subjectKey"]: row for row in contract["buildRecipe"]["expectedOutputs"]
    }
    subjects = receipt["subjects"]
    keys = [row["subjectKey"] for row in subjects]
    if keys != sorted(required_outputs):
        errors.append("external builder receipt subjects are not canonical and complete")
    for row in subjects:
        expected_output = required_outputs.get(row["subjectKey"])
        if expected_output is None:
            continue
        for field in ("fileName",):
            if row.get(field) != expected_output.get(field):
                errors.append(f"external builder receipt subject {row['subjectKey']} {field} differs")
        if row.get("publishedCandidate") is not False:
            errors.append(f"external builder receipt subject {row['subjectKey']} is marked published")
        if row.get("signatureReceiptDigest") is not None or row.get("notarizationReceiptDigest") is not None:
            errors.append(f"external builder receipt subject {row['subjectKey']} asserts signing authority")
    partitions = {row["executionId"]: row for row in contract["buildRecipe"]["executionPartitions"]}
    materials = documents["buildMaterials"]
    snapshot = documents["resolutionSnapshot"]
    executions = receipt["builderExecutions"]
    execution_ids = [row["executionId"] for row in executions]
    if execution_ids != sorted(partitions):
        errors.append("external builder executions are not canonical and complete")
    authority = receipt["authorityIdentity"]
    if authority["authorityIdentityDigest"] != _strict_digest(
        authority, "authorityIdentityDigest"
    ):
        errors.append("external builder authority identity digest differs")
    for execution in executions:
        expected_partition = partitions.get(execution["executionId"])
        if expected_partition is None:
            continue
        comparisons = {
            "runnerOs": expected_partition["runnerOs"],
            "runnerArchitecture": expected_partition["runnerArchitecture"],
            "taskSet": expected_partition["taskSet"],
            "subjectKeys": expected_partition["subjectKeys"],
            "sourceCommit": contract["repository"]["sourceCommit"],
            "sourceTreeDigest": contract["repository"]["sourceTreeDigest"],
            "materialsDigest": contract["authenticatedInputs"]["buildMaterialsDigest"],
            "resolutionSnapshotDigest": contract["authenticatedInputs"]["resolutionSnapshotDigest"],
            "canonicalEnvironment": contract["buildRecipe"]["canonicalEnvironment"],
            "candidateProductAvailableBeforeBuild": False,
        }
        for field, expected_value in comparisons.items():
            if execution.get(field) != expected_value:
                errors.append(f"external builder execution {execution['executionId']} {field} differs")
        if execution["taskSetDigest"] != sha256_digest(
            canonical_json_bytes(execution["taskSet"])
        ):
            errors.append(f"external builder execution {execution['executionId']} task digest differs")
        if execution["directInputsDigest"] != contract["authenticatedInputs"]["directInputsDigest"]:
            errors.append(f"external builder execution {execution['executionId']} direct inputs differ")
        expected_subject_rows = candidate_free_subject_projection(
            kit["expectedOutputs"], execution["subjectKeys"]
        )
        if execution["subjectSetDigest"] != sha256_digest(
            canonical_json_bytes(expected_subject_rows)
        ):
            errors.append(f"external builder execution {execution['executionId']} subject-set digest differs")
        material_digests = snapshot["materialDigests"]
        if execution["materialIdentities"] != {
            "dependencyVerificationDigest": material_digests["verificationMetadata"],
            "verificationKeyringDigest": material_digests["verificationKeyring"],
            "pluginResolutionDigest": material_digests["pluginResolution"],
            "buildLogicDigest": material_digests["buildLogic"],
            "resolutionSnapshotDigest": snapshot["snapshotDigest"],
        }:
            errors.append(f"external builder execution {execution['executionId']} material identities differ")
        installations = [
            row
            for row in materials["jdk"]["installations"]
            if row["runnerOs"] == execution["runnerOs"]
            and row["architecture"] == execution["runnerArchitecture"]
        ]
        if len(installations) != 1:
            errors.append(f"external builder execution {execution['executionId']} JDK installation differs")
        else:
            installation = installations[0]
            expected_toolchain = {
                "javaVendor": materials["jdk"]["vendor"],
                "javaVersion": materials["jdk"]["version"],
                "javaBuild": materials["jdk"]["build"],
                "javaEncoding": contract["buildRecipe"]["canonicalEnvironment"]["encoding"],
                "javaArchitecture": installation["architecture"],
                "javaInstallationManifestDigest": installation["installationManifestDigest"],
                "javaReleaseFileDigest": installation["releaseFileDigest"],
                "javaIdentityDigest": sha256_digest(
                    canonical_json_bytes(
                        {
                            "javaVendor": materials["jdk"]["vendor"],
                            "javaVersion": materials["jdk"]["version"],
                            "javaBuild": materials["jdk"]["build"],
                            "javaEncoding": contract["buildRecipe"]["canonicalEnvironment"]["encoding"],
                            "javaArchitecture": installation["architecture"],
                            "javaInstallationManifestDigest": installation["installationManifestDigest"],
                            "javaReleaseFileDigest": installation["releaseFileDigest"],
                        }
                    )
                ),
                "gradleWrapperJarDigest": materials["gradle"]["wrapperJarDigest"],
                "gradleWrapperPropertiesDigest": materials["gradle"]["wrapperPropertiesDigest"],
                "gradleDistributionDigest": materials["gradle"]["distributionDigest"],
            }
            if execution["toolchain"] != expected_toolchain:
                errors.append(f"external builder execution {execution['executionId']} toolchain differs")
        if "latest" in execution["runnerImageIdentity"].casefold():
            errors.append(f"external builder execution {execution['executionId']} uses a mutable runner image")
        try:
            execution_started = _timestamp(execution["buildStartedAt"], "external execution start")
            execution_completed = _timestamp(execution["buildCompletedAt"], "external execution completion")
            if execution_started > execution_completed:
                errors.append(f"external builder execution {execution['executionId']} completion predates start")
        except ValueError as exc:
            errors.append(str(exc))
    try:
        started = _timestamp(receipt["buildStartedAt"], "external build start")
        completed = _timestamp(receipt["buildCompletedAt"], "external build completion")
        sealed = _timestamp(receipt["outputsSealedAt"], "external output seal")
        if not started <= completed <= sealed:
            errors.append("external build and seal timing is inconsistent")
        if sealed >= _timestamp(contract["evaluationTime"], "execution evaluation time"):
            errors.append("external outputs were not sealed before receipt evaluation")
        maximum_age = timedelta(seconds=int(policy["freshness"]["externalReceiptMaximumAgeSeconds"]))
        if _timestamp(contract["evaluationTime"], "execution evaluation time") - completed >= maximum_age:
            errors.append("external builder receipt is stale")
    except ValueError as exc:
        errors.append(str(exc))
    if scan_value(receipt):
        errors.append("external builder receipt contains private material or local absolute paths")
    return sorted(set(errors))


def _profile_attestation_errors(
    attestation: dict[str, Any],
    receipt: dict[str, Any],
    receipt_path: Path,
    manifest: dict[str, Any],
    manifest_path: Path,
    bundle_path: Path,
    raw_attestation_path: Path,
    verification_transcript_path: Path,
    contract: dict[str, Any],
    kit: dict[str, Any],
    policy: dict[str, Any],
) -> list[str]:
    errors = validate_schema(attestation, AUTHORITY_ATTESTATION_SCHEMA)
    if errors:
        return errors
    if attestation["attestationDigest"] != _strict_digest(attestation, "attestationDigest"):
        errors.append("external authority attestation self-digest differs")
    expected = {
        "releaseId": contract["release"]["id"],
        "buildVersion": contract["release"]["integerBuild"],
        "tag": contract["release"]["tag"],
        "sourceCommit": contract["repository"]["sourceCommit"],
        "executionContractDigest": contract["executionContractDigest"],
        "verifierKitDigest": kit["kitDigest"],
        "independentReproducibilityPolicyDigest": policy["policyDigest"],
        "providerProfileId": contract["expectedVerifierAuthority"]["profileId"],
        "providerProfileDigest": contract["expectedVerifierAuthority"]["profileDigest"],
        "builderRole": "independent-verifier",
        "candidateProductAvailableBeforeBuild": False,
    }
    for field, expected_value in expected.items():
        if attestation.get(field) != expected_value:
            errors.append(f"external authority attestation {field} differs")
    profile = _profile(policy, attestation["providerProfileId"])
    adapter = _adapter(policy, attestation["artifactAttestation"]["adapterId"])
    if profile is None:
        errors.append("external authority profile is not policy-authorized")
    else:
        if profile["profileDigest"] != attestation["providerProfileDigest"]:
            errors.append("external authority profile digest differs")
        identity = attestation["authorityIdentity"]
        for field in (
            "providerType", "providerId", "controlPlaneId", "trustDomainId", "organizationId",
            "accountId", "projectId",
        ):
            if identity.get(field) != profile.get(field):
                errors.append(f"external authority {field} differs from its profile")
        allowed_ownership = {
            "provider-hosted": {"provider-hosted"},
            "provider-hosted-or-independently-controlled": {
                "provider-hosted",
                "third-party-controlled",
            },
            "fixture-only": {"organization-controlled"},
        }.get(profile.get("executorPolicy"), set())
        if identity.get("executorOwnership") not in allowed_ownership:
            errors.append("external authority executor ownership differs from its profile")
        pipeline = attestation["pipelineIdentity"]
        if not re.fullmatch(profile["pipelineDefinitionPattern"], pipeline["definitionId"]):
            errors.append("external pipeline definition is not policy-authorized")
        if pipeline["revisionType"] != profile["pipelineRevisionType"]:
            errors.append("external pipeline revision is mutable or has the wrong identity type")
        workload = attestation["workloadIdentity"]
        if workload["issuer"] != profile["issuer"]:
            errors.append("external workload identity issuer differs")
        if not set(profile["audiences"]).issubset(workload["audiences"]):
            errors.append("external workload identity audience differs")
        if not re.fullmatch(profile["subjectPattern"], workload["subject"]):
            errors.append("external workload identity subject is not policy-authorized")
        if profile["executorPolicy"] == "provider-hosted" and attestation["executorIdentity"]["selfHosted"]:
            errors.append("producer-controlled or self-hosted verifier is prohibited")
        if profile["immutableRunnerImageRequired"] and not attestation["executorIdentity"].get("runnerImageDigest"):
            errors.append("external runner image lacks an immutable digest")
        if attestation["operational"] and not profile["operationalAllowed"]:
            errors.append("template or fixture profile cannot produce operational evidence")
    artifact = attestation["artifactAttestation"]
    if adapter is None or artifact["adapterDigest"] != (adapter or {}).get("adapterDigest"):
        errors.append("external artifact attestation adapter is not policy-authorized")
    elif attestation["operational"] and not adapter["operationalAllowed"]:
        errors.append("non-operational attestation adapter cannot authenticate an external build")
    if (
        attestation["operational"]
        and artifact["adapterId"] not in _IMPLEMENTED_OPERATIONAL_EXTERNAL_ADAPTERS
    ):
        errors.append(
            "external attestation adapter lacks an implemented cryptographic verifier"
        )
    fixture = attestation["evidenceClassification"] in {"fixture", "self-test"}
    expected_verification_status = "fixture-only" if fixture else "verified"
    if artifact["verificationStatus"] != expected_verification_status:
        errors.append("external artifact attestation verification status differs")
    if profile is not None and artifact["adapterId"] != profile["adapterId"]:
        errors.append("external provider profile selects a different attestation adapter")
    if adapter is not None:
        if artifact["format"] != adapter["attestationFormat"]:
            errors.append("external artifact attestation format differs from adapter policy")
        if artifact["predicateType"] != adapter["predicateType"]:
            errors.append("external artifact attestation predicate differs from adapter policy")
    if artifact["subjectSetDigest"] != manifest["subjectSetDigest"]:
        errors.append("external artifact attestation subject set differs from output manifest")
    if attestation["workloadIdentity"]["trustRootSetDigest"] != artifact["trustRootSetDigest"]:
        errors.append("external workload and artifact attestation trust roots differ")
    expected_operational = attestation["evidenceClassification"] == "authenticated-external-provider"
    if attestation["operational"] is not expected_operational:
        errors.append("external attestation operational classification is inconsistent")
    for field in ("authorityIdentity", "pipelineIdentity", "executorIdentity"):
        nested = attestation[field]
        digest_field = field + "Digest"
        if nested[digest_field] != _strict_digest(nested, digest_field):
            errors.append(f"external attestation {field} digest differs")
    bindings = (
        ("builderReceipt", file_digest(receipt_path), BUILDER_RECEIPT_SCHEMA, receipt_path.stat().st_size),
        ("outputManifest", file_digest(manifest_path), OUTPUT_MANIFEST_SCHEMA, manifest_path.stat().st_size),
        ("outputBundle", file_digest(bundle_path), None, bundle_path.stat().st_size),
        ("rawArtifactAttestationBundle", file_digest(raw_attestation_path), None, raw_attestation_path.stat().st_size),
        ("verificationTranscript", file_digest(verification_transcript_path), None, verification_transcript_path.stat().st_size),
    )
    for field, digest, schema, size in bindings:
        binding = attestation[field]
        if binding["sha256"] != digest or binding["schema"] != schema:
            errors.append(f"external attestation {field} binding differs")
        if size is not None and binding["size"] != size:
            errors.append(f"external attestation {field} size differs")
    if artifact["bundleDigest"] != file_digest(raw_attestation_path):
        errors.append("raw external artifact attestation bundle digest differs")
    if artifact["verificationTranscriptDigest"] != file_digest(verification_transcript_path):
        errors.append("external artifact verification transcript digest differs")
    try:
        transcript = read_json(verification_transcript_path)
    except (OSError, ValueError):
        transcript = None
    if not isinstance(transcript, dict) or scan_value(transcript):
        errors.append("external artifact verification transcript is malformed or unsafe")
    elif attestation["operational"]:
        transcript_fields = {
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
        if set(transcript) != transcript_fields:
            errors.append("external artifact verification transcript is not a closed adapter result")
        required_transcript = {
            "schemaVersion": 1,
            "kind": "stable-1.0-independent-attestation-verification-transcript",
            "adapterId": artifact["adapterId"],
            "adapterDigest": artifact["adapterDigest"],
            "rawBundleDigest": artifact["bundleDigest"],
            "statementDigest": artifact["statementDigest"],
            "subjectSetDigest": artifact["subjectSetDigest"],
            "verificationStatus": "pass",
            "issuer": attestation["workloadIdentity"]["issuer"],
            "subject": attestation["workloadIdentity"]["subject"],
            "pipelineDefinitionId": attestation["pipelineIdentity"]["definitionId"],
            "pipelineRevision": attestation["pipelineIdentity"]["immutableRevision"],
            "audiences": attestation["workloadIdentity"]["audiences"],
            "verifiedAt": artifact["verifiedAt"],
        }
        if any(transcript.get(field) != value for field, value in required_transcript.items()):
            errors.append("external artifact verification transcript does not bind verified claims")
        if transcript.get("transcriptDigest") != _strict_digest(
            transcript, "transcriptDigest"
        ):
            errors.append("external artifact verification transcript self-digest differs")
    receipt_identity = receipt["authorityIdentity"]
    attested_identity = attestation["authorityIdentity"]
    for field in (
        "providerType", "providerId", "controlPlaneId", "trustDomainId", "organizationId",
        "accountId", "projectId", "executorControllerId", "executorOwnership",
    ):
        if receipt_identity.get(field) != attested_identity.get(field):
            errors.append(f"external receipt and attestation {field} differ")
    if receipt_identity["workloadIdentityDigest"] != attestation["workloadIdentity"]["claimsDigest"]:
        errors.append("external receipt workload identity binding differs")
    pipeline = attestation["pipelineIdentity"]
    for field in ("runId", "runAttempt", "jobId", "stageId"):
        if receipt_identity.get(field) != pipeline.get(field):
            errors.append(f"external receipt and pipeline {field} differ")
    for execution in receipt["builderExecutions"]:
        for field, expected_value in (
            ("pipelineDefinitionId", pipeline["definitionId"]),
            ("pipelineRevision", pipeline["immutableRevision"]),
            ("runId", pipeline["runId"]),
            ("runAttempt", pipeline["runAttempt"]),
        ):
            if execution.get(field) != expected_value:
                errors.append(
                    f"external builder execution {execution['executionId']} {field} differs from authority"
                )
    producer = attestation["receiptProducer"]
    if producer["receiptProducerIdentityDigest"] != _strict_digest(
        producer, "receiptProducerIdentityDigest"
    ):
        errors.append("external receipt-producer identity digest differs")
    if producer["workloadSubject"] != attestation["workloadIdentity"]["subject"]:
        errors.append("external receipt producer differs from workload identity")
    if (
        attestation["buildStartedAt"] != receipt["buildStartedAt"]
        or attestation["buildCompletedAt"] != receipt["buildCompletedAt"]
        or attestation["outputsSealedAt"] != receipt["outputsSealedAt"]
    ):
        errors.append("external authority timing differs from the builder receipt")
    try:
        issued = _timestamp(attestation["workloadIdentity"]["issuedAt"], "workload identity issue time")
        expires = _timestamp(attestation["workloadIdentity"]["expiresAt"], "workload identity expiry")
        verified = _timestamp(artifact["verifiedAt"], "artifact attestation verification time")
        evaluation = _timestamp(contract["evaluationTime"], "execution evaluation time")
        skew = timedelta(seconds=int(policy["freshness"]["maximumClockSkewSeconds"]))
        if not issued <= verified <= expires + skew or verified > evaluation + skew:
            errors.append("external workload identity or attestation is stale")
        sealed = _timestamp(attestation["outputsSealedAt"], "external authority output seal")
        maximum_age = timedelta(
            seconds=int(policy["freshness"]["authorityAttestationMaximumAgeSeconds"])
        )
        if evaluation - verified >= maximum_age or verified < sealed - skew:
            errors.append("external authority verification is stale or predates output sealing")
    except ValueError as exc:
        errors.append(str(exc))
    if scan_value(attestation):
        errors.append("external authority attestation contains private material or local absolute paths")
    return sorted(set(errors))


def _output_manifest_errors(
    manifest: dict[str, Any],
    receipt: dict[str, Any],
    contract: dict[str, Any],
    kit: dict[str, Any],
) -> list[str]:
    errors = validate_schema(manifest, OUTPUT_MANIFEST_SCHEMA)
    if errors:
        return errors
    if manifest["manifestDigest"] != _strict_digest(manifest, "manifestDigest"):
        errors.append("external output manifest self-digest differs")
    expected = {
        "releaseId": contract["release"]["id"],
        "buildVersion": contract["release"]["integerBuild"],
        "tag": contract["release"]["tag"],
        "sourceCommit": contract["repository"]["sourceCommit"],
        "executionContractDigest": contract["executionContractDigest"],
        "verifierKitDigest": kit["kitDigest"],
        "builderReceiptDigest": receipt["receiptDigest"],
        "providerProfileDigest": contract["expectedVerifierAuthority"]["profileDigest"],
        "sourceTreeDigest": contract["repository"]["sourceTreeDigest"],
        "materialsDigest": contract["authenticatedInputs"]["buildMaterialsDigest"],
        "resolutionSnapshotDigest": contract["authenticatedInputs"]["resolutionSnapshotDigest"],
        "candidateProductAvailableBeforeBuild": False,
    }
    for field, expected_value in expected.items():
        if manifest.get(field) != expected_value:
            errors.append(f"external output manifest {field} differs")
    if manifest["taskSetDigest"] != sha256_digest(
        canonical_json_bytes(receipt["buildTasks"])
    ):
        errors.append("external output manifest task-set digest differs")
    if manifest["canonicalEnvironmentDigest"] != sha256_digest(
        canonical_json_bytes(receipt["canonicalEnvironment"])
    ):
        errors.append("external output manifest environment digest differs")
    receipt_subjects = {row["subjectKey"]: row for row in receipt["subjects"]}
    manifest_subjects = manifest["subjects"]
    keys = [row["subjectKey"] for row in manifest_subjects]
    if keys != sorted(receipt_subjects):
        errors.append("external output manifest subjects are not canonical and complete")
    expected_outputs = {
        row["subjectKey"]: row for row in contract["buildRecipe"]["expectedOutputs"]
    }
    for row in manifest_subjects:
        source = receipt_subjects.get(row["subjectKey"], {})
        output = expected_outputs.get(row["subjectKey"], {})
        for field in (
            "fileName", "digest", "size", "payloadManifestDigest", "extractionEvidenceDigest"
        ):
            if row.get(field) != source.get(field):
                errors.append(f"external output subject {row['subjectKey']} {field} differs from receipt")
        for field in ("reproducibilityClass", "normalizationRuleId"):
            if row.get(field) != output.get(field):
                errors.append(f"external output subject {row['subjectKey']} {field} differs from policy")
        if row.get("bundlePath") != f"subjects/{row.get('fileName')}":
            errors.append(f"external output subject {row['subjectKey']} bundle path differs")
    subject_projection = [
        {
            key: row[key]
            for key in (
                "subjectKey", "fileName", "bundlePath", "digest", "size",
                "reproducibilityClass", "normalizationRuleId", "payloadManifestDigest",
                "extractionEvidenceDigest",
            )
        }
        for row in manifest_subjects
    ]
    if manifest["subjectSetDigest"] != sha256_digest(canonical_json_bytes(subject_projection)):
        errors.append("external output manifest subject-set digest differs")
    normalized_keys = sorted(
        row["subjectKey"]
        for row in contract["buildRecipe"]["expectedOutputs"]
        if row["reproducibilityClass"] == "normalized-payload-identical"
    )
    payload_rows = manifest["payloadManifests"]
    if [row["subjectKey"] for row in payload_rows] != normalized_keys:
        errors.append("external payload-manifest bindings are not canonical and complete")
    for row in payload_rows:
        key = row["subjectKey"]
        if row["bundlePath"] != f"payload-manifests/{key}.json":
            errors.append(f"external payload-manifest path differs for {key}")
        if row["manifestDigest"] != receipt_subjects.get(key, {}).get("payloadManifestDigest"):
            errors.append(f"external payload-manifest semantic digest differs for {key}")
    try:
        completed = _timestamp(manifest["buildCompletedAt"], "output manifest build completion")
        sealed = _timestamp(manifest["outputsSealedAt"], "output manifest seal")
        if completed > sealed:
            errors.append("external output manifest was sealed before build completion")
        if manifest["buildCompletedAt"] != receipt["buildCompletedAt"] or manifest["outputsSealedAt"] != receipt["outputsSealedAt"]:
            errors.append("external output manifest timing differs from the builder receipt")
    except ValueError as exc:
        errors.append(str(exc))
    if scan_value(manifest):
        errors.append("external output manifest contains private material or local absolute paths")
    return sorted(set(errors))


def _authority_projection(attestation: dict[str, Any]) -> dict[str, Any]:
    identity = attestation["authorityIdentity"]
    pipeline = attestation["pipelineIdentity"]
    artifact = attestation["artifactAttestation"]
    return {
        "providerProfileId": attestation["providerProfileId"],
        "providerProfileDigest": attestation["providerProfileDigest"],
        "providerId": identity["providerId"],
        "controlPlaneId": identity["controlPlaneId"],
        "trustDomainId": identity["trustDomainId"],
        "organizationId": identity["organizationId"],
        "accountId": identity["accountId"],
        "projectId": identity["projectId"],
        "pipelineDefinitionId": pipeline["definitionId"],
        "pipelineRevision": pipeline["immutableRevision"],
        "runId": pipeline["runId"],
        "runAttempt": pipeline["runAttempt"],
        "jobId": pipeline["jobId"],
        "artifactAttestationDigest": artifact["bundleDigest"],
    }


def _independence_evaluation(
    producer: dict[str, Any],
    verifier: dict[str, Any],
    contract: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    first = _authority_projection(producer)
    second = _authority_projection(verifier)
    first_identity = producer["authorityIdentity"]
    second_identity = verifier["authorityIdentity"]
    first_pipeline = producer["pipelineIdentity"]
    second_pipeline = verifier["pipelineIdentity"]
    requirements = contract["expectedVerifierAuthority"]
    checks: list[dict[str, Any]] = []
    errors: list[str] = []

    def check(check_id: str, passed: bool, required: bool, failure: str) -> None:
        checks.append({"id": check_id, "status": "pass" if passed else ("fail" if required else "not-required")})
        if required and not passed:
            errors.append(failure)

    check("provider-distinct", first["providerId"] != second["providerId"], requirements["requireProviderDistinct"], "producer and verifier use the same provider")
    check("control-plane-distinct", first["controlPlaneId"] != second["controlPlaneId"], requirements["requireControlPlaneDistinct"], "producer and verifier use the same control plane")
    check("trust-domain-distinct", first["trustDomainId"] != second["trustDomainId"], requirements["requireTrustDomainDistinct"], "producer and verifier use the same trust domain")
    organization_distinct = (
        first["organizationId"] != second["organizationId"]
        and first["accountId"] != second["accountId"]
    )
    check("organization-distinct", organization_distinct, requirements["requireOrganizationDistinct"], "producer and verifier use the same organization or provider account")
    check("pipeline-run-distinct", (first["providerId"], first["runId"], first["runAttempt"]) != (second["providerId"], second["runId"], second["runAttempt"]), True, "producer and verifier reuse a build identity")
    producer_workflow_reused = (
        first["providerId"], first["pipelineDefinitionId"]
    ) == (
        second["providerId"], second["pipelineDefinitionId"]
    )
    check("producer-workflow-not-reused", not producer_workflow_reused, True, "producer workflow was relabeled as an external verifier")
    check("executor-controller-independent", first_identity["executorControllerId"] != second_identity["executorControllerId"], True, "producer controls the verifier executor")
    first_artifact = producer["artifactAttestation"]
    second_artifact = verifier["artifactAttestation"]
    artifact_distinct = all(
        first_artifact[field] != second_artifact[field]
        for field in ("bundleDigest", "statementDigest")
    )
    check("artifact-attestation-distinct", artifact_distinct, True, "producer and verifier reuse an artifact attestation or signed statement")
    workload_ok = (
        producer["workloadIdentity"]["claimsDigest"]
        != verifier["workloadIdentity"]["claimsDigest"]
        and verifier["artifactAttestation"]["verificationStatus"]
        in {"verified", "fixture-only"}
    )
    check("workload-identity-authenticated", workload_ok, True, "verifier workload identity is unauthenticated or reused")
    checks.sort(key=lambda row: row["id"])
    evaluation = {
        "producer": first,
        "verifier": second,
        "organizationIndependenceRequired": requirements["requireOrganizationDistinct"],
        "checks": checks,
        "status": "pass" if not errors else "fail",
        "evaluationDigest": None,
    }
    evaluation["evaluationDigest"] = _strict_digest(evaluation, "evaluationDigest")
    return evaluation, errors


def _safe_archive_name(name: str) -> bool:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or ".." in path.parts or "" in path.parts:
        return False
    if any(part in _PROHIBITED_ARCHIVE_NAMES or part == "__MACOSX" or part.startswith("._") for part in path.parts):
        return False
    return "\\" not in name and "\x00" not in name


def _extract_bundle(
    bundle: Path,
    destination: Path,
    policy: dict[str, Any],
    expected_paths: set[str],
) -> list[str]:
    errors: list[str] = []
    limit_members = int(policy["limits"]["maximumArchiveMembers"])
    limit_bytes = int(policy["limits"]["maximumExpandedArchiveBytes"])
    try:
        with zipfile.ZipFile(bundle) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos if not info.is_dir()]
            if len(infos) > limit_members:
                return ["subject bundle exceeds the archive member limit"]
            if names != sorted(set(names)):
                errors.append("subject bundle member names are duplicated or non-canonical")
            folded_names = [unicodedata.normalize("NFC", name).casefold() for name in names]
            if len(folded_names) != len(set(folded_names)):
                errors.append("subject bundle has a case-folding or Unicode name collision")
            if set(names) != expected_paths:
                errors.append("subject bundle has missing or extra members")
            if errors:
                return sorted(set(errors))
            total = 0
            for info in infos:
                if not _safe_archive_name(info.filename):
                    errors.append("subject bundle contains an unsafe or private member name")
                    continue
                mode = (info.external_attr >> 16) & 0xFFFF
                if (
                    stat.S_ISLNK(mode)
                    or (mode and not stat.S_ISREG(mode) and not stat.S_ISDIR(mode))
                    or info.create_system not in (0, 3)
                ):
                    errors.append("subject bundle contains an ambiguous link or creator identity")
                    continue
                if info.compress_type != zipfile.ZIP_STORED:
                    errors.append("subject bundle does not use the closed zip-store format")
                total += info.file_size
                if total > limit_bytes:
                    errors.append("subject bundle exceeds the expanded-size limit")
                    break
                if info.is_dir():
                    continue
                target = destination.joinpath(*PurePosixPath(info.filename).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with archive.open(info) as source, target.open("wb") as output:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > info.file_size:
                            errors.append("subject bundle member exceeds its declared size")
                            break
                        output.write(chunk)
                if written != info.file_size:
                    errors.append("subject bundle member size differs")
    except (OSError, zipfile.BadZipFile, RuntimeError):
        return ["subject bundle is not a bounded valid ZIP archive"]
    return sorted(set(errors))


def _primary_attestation_errors(
    workspace: Path,
    attestation: dict[str, Any],
    receipt: dict[str, Any],
    receipt_path: Path,
    contract: dict[str, Any],
    policy: dict[str, Any],
) -> list[str]:
    errors = validate_schema(attestation, AUTHORITY_ATTESTATION_SCHEMA)
    if errors:
        return errors
    if attestation["attestationDigest"] != _strict_digest(attestation, "attestationDigest"):
        errors.append("primary authority attestation self-digest differs")
    expected = {
        "releaseId": contract["release"]["id"],
        "buildVersion": contract["release"]["integerBuild"],
        "tag": contract["release"]["tag"],
        "sourceCommit": contract["repository"]["sourceCommit"],
        "executionContractDigest": contract["executionContractDigest"],
        "independentReproducibilityPolicyDigest": policy["policyDigest"],
        "providerProfileId": contract["producerAuthority"]["profileId"],
        "providerProfileDigest": contract["producerAuthority"]["profileDigest"],
        "builderRole": "candidate-producer",
        "evidenceClassification": "protected-same-provider",
        "operational": False,
        "candidateProductAvailableBeforeBuild": False,
        "verifierKitDigest": None,
        "outputManifest": None,
        "outputBundle": None,
    }
    for field, expected_value in expected.items():
        if attestation.get(field) != expected_value:
            errors.append(f"primary authority attestation {field} differs")
    profile = _profile(policy, attestation["providerProfileId"])
    identity = attestation["authorityIdentity"]
    if profile is None or profile.get("profileDigest") != attestation["providerProfileDigest"]:
        errors.append("primary authority profile is not policy-authorized")
    else:
        for field in ("providerType", "providerId", "controlPlaneId", "trustDomainId", "organizationId", "accountId", "projectId"):
            if identity.get(field) != profile.get(field):
                errors.append(f"primary authority {field} differs from its profile")
        if not re.fullmatch(profile["pipelineDefinitionPattern"], attestation["pipelineIdentity"]["definitionId"]):
            errors.append("primary pipeline definition is not policy-authorized")
        pipeline = attestation["pipelineIdentity"]
        workload = attestation["workloadIdentity"]
        if pipeline["revisionType"] != profile["pipelineRevisionType"]:
            errors.append("primary pipeline revision identity differs")
        if workload["issuer"] != profile["issuer"] or not set(profile["audiences"]).issubset(
            workload["audiences"]
        ):
            errors.append("primary workload identity issuer or audience differs")
        if not re.fullmatch(profile["subjectPattern"], workload["subject"]):
            errors.append("primary workload identity subject differs")
        if attestation["executorIdentity"]["selfHosted"]:
            errors.append("primary producer profile requires a provider-hosted executor")
    if attestation["artifactAttestation"]["verificationStatus"] != "verified":
        errors.append("primary artifact attestation is not verified")
    artifact = attestation["artifactAttestation"]
    adapter = _adapter(policy, artifact["adapterId"])
    if profile is not None and artifact["adapterId"] != profile["adapterId"]:
        errors.append("primary authority uses a different attestation adapter")
    if adapter is None or artifact["adapterDigest"] != (adapter or {}).get("adapterDigest"):
        errors.append("primary attestation adapter is not policy-authorized")
    elif artifact["format"] != adapter["attestationFormat"] or artifact["predicateType"] != adapter["predicateType"]:
        errors.append("primary attestation format or predicate differs")
    if attestation["workloadIdentity"]["trustRootSetDigest"] != artifact["trustRootSetDigest"]:
        errors.append("primary workload and artifact trust roots differ")
    receipt_binding = attestation["builderReceipt"]
    if (
        receipt_binding["sha256"] != file_digest(receipt_path)
        or receipt_binding["size"] != receipt_path.stat().st_size
        or receipt_binding["schema"] != PRIMARY_RECEIPT_SCHEMA
    ):
        errors.append("primary authority attestation receipt binding differs")
    for field in ("authorityIdentity", "pipelineIdentity", "executorIdentity"):
        nested = attestation[field]
        digest_field = field + "Digest"
        if nested[digest_field] != _strict_digest(nested, digest_field):
            errors.append(f"primary attestation {field} digest differs")
    builder_identity = receipt.get("builderIdentity", {})
    pipeline = attestation["pipelineIdentity"]
    if str(builder_identity.get("runId")) != pipeline.get("runId") or builder_identity.get("runAttempt") != pipeline.get("runAttempt"):
        errors.append("primary receipt and authority run identity differ")
    if builder_identity.get("artifactAttestationDigest") != attestation["artifactAttestation"]["bundleDigest"]:
        errors.append("primary receipt and artifact attestation digest differ")
    supply_coordinate = contract["selectedRc"]["supplyChain"]
    expected_workflow_ref = (
        "github.com/crypta-network/cryptad/"
        f"{supply_coordinate['workflowPath']}@{supply_coordinate['workflowCommit']}"
    )
    if (
        builder_identity.get("workflowRef") != expected_workflow_ref
        or builder_identity.get("workflowSha") != supply_coordinate["workflowCommit"]
        or str(builder_identity.get("runId")) != supply_coordinate["runId"]
        or builder_identity.get("runAttempt") != supply_coordinate["runAttempt"]
    ):
        errors.append("primary receipt differs from the selected RC supply-chain authority")
    expected_pipeline = (
        "github.com/crypta-network/cryptad/"
        f"{supply_coordinate['workflowPath']}@{supply_coordinate['workflowCommit']}"
    )
    if (
        pipeline.get("definitionId") != expected_pipeline
        or pipeline.get("runId") != supply_coordinate["runId"]
        or pipeline.get("runAttempt") != supply_coordinate["runAttempt"]
    ):
        errors.append("primary authority differs from the selected RC supply-chain authority")
    for field, digest_field in (
        ("rawArtifactAttestationBundle", "bundleDigest"),
        ("verificationTranscript", "verificationTranscriptDigest"),
    ):
        path, binding_errors = _binding_file(
            workspace, attestation[field], f"primary {field}", expected_schema=None
        )
        errors.extend(binding_errors)
        if path is not None and file_digest(path) != attestation["artifactAttestation"][digest_field]:
            errors.append(f"primary authority {field} digest differs")
    producer_identity = attestation["receiptProducer"]
    if producer_identity["receiptProducerIdentityDigest"] != _strict_digest(
        producer_identity, "receiptProducerIdentityDigest"
    ):
        errors.append("primary receipt-producer identity digest differs")
    if producer_identity["workloadSubject"] != attestation["workloadIdentity"]["subject"]:
        errors.append("primary receipt producer differs from workload identity")
    if (
        attestation["buildStartedAt"] != receipt["buildStartedAt"]
        or attestation["buildCompletedAt"] != receipt["buildCompletedAt"]
        or attestation["candidateProductAvailableBeforeBuild"] is not False
    ):
        errors.append("primary authority timing or candidate-withholding assertion differs")
    if scan_value(attestation):
        errors.append("primary authority attestation contains private material or local absolute paths")
    return sorted(set(errors))


def _load_kit(
    workspace: Path,
    contract: dict[str, Any],
    policy: dict[str, Any],
    supply_chain: dict[str, Any],
    documents: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any] | None, list[str]]:
    _path, kit, errors = _binding_json(
        workspace, contract.get("verifierKit"), "verifier kit", VERIFIER_KIT_SCHEMA
    )
    if kit is None:
        return None, errors
    if kit.get("kitDigest") != _strict_digest(kit, "kitDigest"):
        errors.append("verifier kit self-digest differs")
    if kit.get("executionContractDigest") != contract.get("executionContractDigest"):
        errors.append("verifier kit execution-contract digest differs")
    try:
        preparation_contract = copy.deepcopy(contract)
        preparation_contract["evaluationTime"] = kit["preparedAt"]
        expected = _build_verifier_kit(
            preparation_contract, policy, supply_chain, documents
        )
        if kit != expected:
            errors.append("verifier kit differs from authenticated recipe inputs")
    except ValueError as exc:
        errors.append(str(exc))
    try:
        evaluation = _timestamp(contract["evaluationTime"], "execution evaluation time")
        prepared = _timestamp(kit["preparedAt"], "verifier kit preparation time")
        expires = _timestamp(kit["expiresAt"], "verifier kit expiration")
        if not prepared <= evaluation < expires:
            errors.append("verifier kit is not fresh at execution evaluation time")
    except ValueError as exc:
        errors.append(str(exc))
    return kit, sorted(set(errors))


def _load_external_evidence(
    workspace: Path,
    contract: dict[str, Any],
    kit: dict[str, Any],
    policy: dict[str, Any],
    documents: dict[str, dict[str, Any]],
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    Path | None,
    Path | None,
    Path | None,
    list[str],
]:
    external = contract["externalBuild"]
    receipt_path, receipt, errors = _binding_json(
        workspace, external["builderReceipt"], "external builder receipt", BUILDER_RECEIPT_SCHEMA
    )
    manifest_path, manifest, item_errors = _binding_json(
        workspace, external["outputManifest"], "external output manifest", OUTPUT_MANIFEST_SCHEMA
    )
    errors.extend(item_errors)
    _attestation_path, attestation, item_errors = _binding_json(
        workspace, external["authorityAttestation"], "external authority attestation", AUTHORITY_ATTESTATION_SCHEMA
    )
    errors.extend(item_errors)
    raw_attestation_path, item_errors = _binding_file(
        workspace,
        external["rawArtifactAttestationBundle"],
        "raw external artifact attestation bundle",
        expected_schema=None,
    )
    errors.extend(item_errors)
    verification_transcript_path, item_errors = _binding_file(
        workspace,
        external["verificationTranscript"],
        "external artifact verification transcript",
        expected_schema=None,
    )
    errors.extend(item_errors)
    for path, label in (
        (raw_attestation_path, "raw external artifact attestation bundle"),
        (verification_transcript_path, "external artifact verification transcript"),
    ):
        if path is not None and path.stat().st_size > int(policy["limits"]["maximumJsonBytes"]):
            errors.append(f"{label} exceeds the bounded evidence size limit")
    bundle_path, item_errors = _binding_file(
        workspace, external["outputBundle"], "external output bundle", expected_schema=None
    )
    errors.extend(item_errors)
    if (
        receipt is None
        or receipt_path is None
        or manifest is None
        or manifest_path is None
        or attestation is None
        or bundle_path is None
        or raw_attestation_path is None
        or verification_transcript_path is None
    ):
        return (
            receipt or {},
            attestation or {},
            manifest or {},
            bundle_path,
            raw_attestation_path,
            verification_transcript_path,
            sorted(set(errors)),
        )
    errors.extend(
        _external_receipt_errors(receipt, contract, kit, policy, documents)
    )
    errors.extend(_output_manifest_errors(manifest, receipt, contract, kit))
    errors.extend(
        _profile_attestation_errors(
            attestation,
            receipt,
            receipt_path,
            manifest,
            manifest_path,
            bundle_path,
            raw_attestation_path,
            verification_transcript_path,
            contract,
            kit,
            policy,
        )
    )
    return (
        receipt,
        attestation,
        manifest,
        bundle_path,
        raw_attestation_path,
        verification_transcript_path,
        sorted(set(errors)),
    )


def _load_primary_evidence(
    workspace: Path,
    contract: dict[str, Any],
    policy: dict[str, Any],
    supply_chain: dict[str, Any],
    documents: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any], Path | None, list[str]]:
    comparison = contract["comparison"]
    receipt_path, receipt, errors = _binding_json(
        workspace, comparison["primaryBuilderReceipt"], "primary builder receipt", PRIMARY_RECEIPT_SCHEMA
    )
    _attestation_path, attestation, item_errors = _binding_json(
        workspace, comparison["primaryAuthorityAttestation"], "primary authority attestation", AUTHORITY_ATTESTATION_SCHEMA
    )
    errors.extend(item_errors)
    bundle, item_errors = _binding_file(
        workspace, comparison["candidateSubjectBundle"], "candidate subject bundle", expected_schema=None
    )
    errors.extend(item_errors)
    if receipt is None or receipt_path is None or attestation is None or bundle is None:
        return receipt or {}, attestation or {}, bundle, sorted(set(errors))
    release = _release_projection(contract)
    errors.extend(
        builder_receipt_errors(
            receipt,
            "candidate-producer",
            release,
            supply_chain,
            contract["authenticatedInputs"]["buildMaterialsDigest"],
            contract["authenticatedInputs"]["resolutionSnapshotDigest"],
            documents["buildMaterials"],
            documents["subjectInventory"],
            documents["resolutionSnapshot"],
        )
    )
    errors.extend(
        _primary_attestation_errors(
            workspace, attestation, receipt, receipt_path, contract, policy
        )
    )
    return receipt, attestation, bundle, sorted(set(errors))


def _bundle_paths(
    receipt: dict[str, Any], manifest: dict[str, Any] | None = None
) -> set[str]:
    paths = {f"subjects/{row['fileName']}" for row in receipt["subjects"]}
    if manifest is None:
        paths.update(
            f"payload-manifests/{row['subjectKey']}.json"
            for row in receipt["subjects"]
            if row.get("payloadManifestDigest") is not None
        )
    else:
        paths.update(row["bundlePath"] for row in manifest["payloadManifests"])
    return paths


def _stage_comparison_view(
    extracted: Path,
    receipt: dict[str, Any],
    destination: Path,
    output_manifest: dict[str, Any] | None = None,
) -> tuple[Path, Path, list[str]]:
    subject_root = destination / "subjects"
    manifest_root = destination / "payload-manifests"
    subject_root.mkdir(parents=True, exist_ok=True)
    manifest_root.mkdir(parents=True, exist_ok=True)
    errors: list[str] = []
    payload_bindings = {
        row["subjectKey"]: row
        for row in (output_manifest or {}).get("payloadManifests", [])
    }
    for row in receipt["subjects"]:
        source = extracted / "subjects" / row["fileName"]
        target = subject_root / row["fileName"]
        target.parent.mkdir(parents=True, exist_ok=True)
        if not source.is_file() or file_digest(source) != row["digest"] or source.stat().st_size != row["size"]:
            errors.append(f"subject bundle bytes differ for {row['subjectKey']}")
        else:
            target.write_bytes(source.read_bytes())
        payload_digest = row.get("payloadManifestDigest")
        if payload_digest is not None:
            manifest_source = extracted / "payload-manifests" / f"{row['subjectKey']}.json"
            manifest_target = manifest_root / f"{row['subjectKey']}.json"
            try:
                payload_value = read_json(manifest_source)
            except (OSError, ValueError):
                payload_value = None
            if (
                not isinstance(payload_value, dict)
                or payload_value.get("manifestDigest") != payload_digest
            ):
                errors.append(f"payload manifest bytes differ for {row['subjectKey']}")
            elif payload_value.get("publishedSubjectDigest") != row["digest"]:
                errors.append(
                    f"payload manifest binds different published package bytes for {row['subjectKey']}"
                )
            elif output_manifest is not None and (
                file_digest(manifest_source) != payload_bindings.get(row["subjectKey"], {}).get("sha256")
                or manifest_source.stat().st_size != payload_bindings.get(row["subjectKey"], {}).get("size")
            ):
                errors.append(f"payload manifest file binding differs for {row['subjectKey']}")
            else:
                manifest_target.write_bytes(manifest_source.read_bytes())
    return subject_root, manifest_root, errors


_DIFFERENCE_CLASS_MAP = {
    "candidate subject bytes are absent": "missing-subject",
    "verifier subject bytes are absent": "missing-subject",
    "candidate subject differs from authenticated receipt": "file-content-drift",
    "verifier subject differs from authenticated receipt": "file-content-drift",
    "byte-identical subject bytes differ": "file-content-drift",
    "normalized comparison lacks a builder payload manifest": "missing-subject",
    "candidate payload manifest differs from receipt": "normalized-payload-drift",
    "verifier payload manifest differs from receipt": "normalized-payload-drift",
    "normalized package payload differs": "normalized-payload-drift",
    "pre-signing staged payload differs": "signing-or-notarization-envelope-only-drift",
}

_VALIDATION_DIFFERENCE_RULES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("source tree", "source commit", "source ref"), "source-tree-drift"),
    (("material", "direct input"), "build-material-drift"),
    (("resolution", "dependency"), "dependency-resolution-drift"),
    (("jdk", "gradle", "toolchain", "runner image"), "toolchain-drift"),
    (("task set", "build task", "task-set"), "task-set-drift"),
    (("environment", "locale", "timezone", "encoding", "source date epoch"), "environment-drift"),
    (("missing subject", "missing member", "bytes are absent"), "missing-subject"),
    (("extra subject", "extra member"), "extra-subject"),
    (("payload permission",), "payload-permission-drift"),
    (("payload",), "normalized-payload-drift"),
)


def _validation_difference_classes(errors: list[str]) -> list[str]:
    classes: set[str] = set()
    for error in errors:
        lowered = error.casefold()
        for needles, classification in _VALIDATION_DIFFERENCE_RULES:
            if any(needle in lowered for needle in needles):
                classes.add(classification)
                break
    return sorted(classes)


def _failure_report(errors: list[str]) -> dict[str, Any]:
    report = {
        "schemaVersion": 1,
        "kind": "stable-1.0-independent-reproducibility-redaction-report",
        "status": "fail",
        "differenceClassifications": _validation_difference_classes(errors),
        "findings": _blocker_rows(errors),
        "redacted": True,
        "sideEffectsPerformed": False,
        "reportDigest": "sha256:" + "0" * 64,
    }
    report["reportDigest"] = _strict_digest(report, "reportDigest")
    return report


def _stream_fingerprints(source: Any) -> tuple[bytes, bytes]:
    """Hash raw and CRLF-normalized bytes without retaining product content."""

    raw = hashlib.sha256()
    normalized = hashlib.sha256()
    pending_carriage_return = False
    while True:
        chunk = source.read(1024 * 1024)
        if not chunk:
            break
        raw.update(chunk)
        if pending_carriage_return:
            chunk = b"\r" + chunk
            pending_carriage_return = False
        if chunk.endswith(b"\r"):
            chunk = chunk[:-1]
            pending_carriage_return = True
        normalized.update(chunk.replace(b"\r\n", b"\n"))
    if pending_carriage_return:
        normalized.update(b"\r")
    return raw.digest(), normalized.digest()


def _zip_difference_classes(
    first: Path,
    second: Path,
    maximum_members: int = 20_000,
    maximum_expanded_bytes: int = 5_000_000_000,
) -> set[str]:
    classes: set[str] = set()
    try:
        with zipfile.ZipFile(first) as left, zipfile.ZipFile(second) as right:
            left_infos = left.infolist()
            right_infos = right.infolist()
            if len(left_infos) > maximum_members or len(right_infos) > maximum_members:
                return {"unknown-or-unexplained-difference"}
            if (
                sum(row.file_size for row in left_infos) > maximum_expanded_bytes
                or sum(row.file_size for row in right_infos) > maximum_expanded_bytes
            ):
                return {"unknown-or-unexplained-difference"}
            left_names = [row.filename for row in left_infos]
            right_names = [row.filename for row in right_infos]
            if left_names != right_names and sorted(left_names) == sorted(right_names):
                classes.add("archive-member-ordering-drift")
            if set(left_names) != set(right_names):
                classes.add("file-content-drift")
            for name in sorted(set(left_names).intersection(right_names)):
                first_info = left.getinfo(name)
                second_info = right.getinfo(name)
                if first_info.date_time != second_info.date_time:
                    classes.add("archive-timestamp-drift")
                if (first_info.external_attr >> 16) != (second_info.external_attr >> 16):
                    classes.add("owner-group-or-mode-drift")
                if first_info.compress_type != second_info.compress_type:
                    classes.add("compression-parameter-drift")
                with left.open(first_info) as first_member, right.open(
                    second_info
                ) as second_member:
                    first_raw, first_normalized = _stream_fingerprints(first_member)
                    second_raw, second_normalized = _stream_fingerprints(second_member)
                if first_raw != second_raw:
                    if first_normalized == second_normalized:
                        classes.add("line-ending-or-encoding-drift")
                    else:
                        classes.add("file-content-drift")
            if not classes and file_digest(first) != file_digest(second):
                classes.add("compression-parameter-drift")
    except (OSError, zipfile.BadZipFile, RuntimeError):
        classes.add("unknown-or-unexplained-difference")
    return classes


def _bounded_tar_members(
    archive: tarfile.TarFile,
    maximum_members: int,
    maximum_expanded_bytes: int,
) -> list[tarfile.TarInfo]:
    members: list[tarfile.TarInfo] = []
    expanded_bytes = 0
    for member in archive:
        members.append(member)
        expanded_bytes += member.size
        if len(members) > maximum_members or expanded_bytes > maximum_expanded_bytes:
            raise ValueError("nested archive exceeds difference-attribution limits")
    return members


def _tar_member_fingerprints(source: Any | None) -> tuple[bytes, bytes]:
    if source is None:
        empty = hashlib.sha256(b"").digest()
        return empty, empty
    try:
        return _stream_fingerprints(source)
    finally:
        source.close()


def _tar_difference_classes(
    first: Path,
    second: Path,
    maximum_members: int = 20_000,
    maximum_expanded_bytes: int = 5_000_000_000,
) -> set[str]:
    classes: set[str] = set()
    try:
        with tarfile.open(first, "r:*") as left, tarfile.open(second, "r:*") as right:
            left_rows = _bounded_tar_members(
                left, maximum_members, maximum_expanded_bytes
            )
            right_rows = _bounded_tar_members(
                right, maximum_members, maximum_expanded_bytes
            )
            left_names = [row.name for row in left_rows]
            right_names = [row.name for row in right_rows]
            if left_names != right_names and sorted(left_names) == sorted(right_names):
                classes.add("archive-member-ordering-drift")
            if set(left_names) != set(right_names):
                classes.add("file-content-drift")
            left_by_name = {row.name: row for row in left_rows}
            right_by_name = {row.name: row for row in right_rows}
            for name in sorted(set(left_by_name).intersection(right_by_name)):
                first_info = left_by_name[name]
                second_info = right_by_name[name]
                if first_info.mtime != second_info.mtime:
                    classes.add("archive-timestamp-drift")
                if (first_info.uid, first_info.gid, first_info.mode) != (
                    second_info.uid,
                    second_info.gid,
                    second_info.mode,
                ):
                    classes.add("owner-group-or-mode-drift")
                first_member = left.extractfile(first_info) if first_info.isfile() else None
                second_member = right.extractfile(second_info) if second_info.isfile() else None
                first_raw, first_normalized = _tar_member_fingerprints(first_member)
                second_raw, second_normalized = _tar_member_fingerprints(second_member)
                if first_raw != second_raw:
                    if first_normalized == second_normalized:
                        classes.add("line-ending-or-encoding-drift")
                    else:
                        classes.add("file-content-drift")
            if not classes and file_digest(first) != file_digest(second):
                classes.add("compression-parameter-drift")
    except (OSError, tarfile.TarError, RuntimeError, ValueError):
        classes.add("unknown-or-unexplained-difference")
    return classes


def _difference_report(
    result: dict[str, Any],
    plan: dict[str, Any],
    primary_root: Path,
    verifier_root: Path,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if policy is None:
        policy, _supply_chain = _load_policy()
    rows: list[dict[str, Any]] = []
    plan_by_key = {row["subjectKey"]: row for row in plan["comparisons"]}
    for row in result["comparisons"]:
        classes = {_DIFFERENCE_CLASS_MAP.get(value, "unknown-or-unexplained-difference") for value in row["differences"]}
        plan_row = plan_by_key[row["subjectKey"]]
        first = primary_root / plan_row["fileName"]
        second = verifier_root / plan_row["fileName"]
        maximum_members = int(policy["limits"]["maximumArchiveMembers"])
        maximum_expanded_bytes = int(policy["limits"]["maximumExpandedArchiveBytes"])
        if row["differences"] and first.suffix.lower() in {".zip", ".jar"} and first.is_file() and second.is_file():
            classes.update(
                _zip_difference_classes(
                    first, second, maximum_members, maximum_expanded_bytes
                )
            )
        if (
            row["differences"]
            and (first.name.endswith(".tar") or first.name.endswith(".tar.gz") or first.name.endswith(".tgz"))
            and first.is_file()
            and second.is_file()
        ):
            classes.update(
                _tar_difference_classes(
                    first, second, maximum_members, maximum_expanded_bytes
                )
            )
        rows.append(
            {
                "subjectKey": row["subjectKey"],
                "status": row["status"],
                "classifications": sorted(classes),
                "differenceCount": len(row["differences"]),
            }
        )
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-independent-reproducibility-difference-report",
        "comparisonPlanDigest": plan["planDigest"],
        "reproducibilityResultDigest": result["resultDigest"],
        "rows": rows,
        "unknownDifferenceCount": sum(
            "unknown-or-unexplained-difference" in row["classifications"] for row in rows
        ),
        "redacted": True,
        "reportDigest": "sha256:" + "0" * 64,
    }


def _compare_evidence(
    contract: dict[str, Any],
    policy: dict[str, Any],
    supply_chain: dict[str, Any],
    documents: dict[str, dict[str, Any]],
    primary: dict[str, Any],
    verifier: dict[str, Any],
    primary_bundle: Path,
    verifier_bundle: Path,
    verifier_manifest: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    release = _release_projection(contract)
    try:
        plan = build_comparison_plan(
            release,
            supply_chain,
            documents["subjectInventory"],
            primary,
            verifier,
            provider_distinct=True,
            provider_distinct_recipe={
                "buildTasks": policy.get("requiredBuildTasks"),
                "executionTasks": policy.get("requiredExecutionTasks"),
            },
        )
    except ValueError as exc:
        return None, None, None, [str(exc)]
    with tempfile.TemporaryDirectory(prefix="cryptad-independent-rebuild-") as temporary:
        root = Path(temporary)
        primary_extracted = root / "primary-extracted"
        verifier_extracted = root / "verifier-extracted"
        primary_extracted.mkdir()
        verifier_extracted.mkdir()
        errors.extend(_extract_bundle(primary_bundle, primary_extracted, policy, _bundle_paths(primary)))
        errors.extend(
            _extract_bundle(
                verifier_bundle,
                verifier_extracted,
                policy,
                _bundle_paths(verifier, verifier_manifest),
            )
        )
        primary_root, primary_manifests, stage_errors = _stage_comparison_view(primary_extracted, primary, root / "primary")
        errors.extend(stage_errors)
        verifier_root, verifier_manifests, stage_errors = _stage_comparison_view(
            verifier_extracted,
            verifier,
            root / "verifier",
            verifier_manifest,
        )
        errors.extend(stage_errors)
        result, comparison_errors = compare_rebuilds(
            release,
            supply_chain,
            plan,
            primary_root,
            verifier_root,
            primary_manifests,
            verifier_manifests,
        )
        errors.extend(comparison_errors)
        errors.extend(reproducibility_result_errors(result, release, plan))
        difference_report = _difference_report(
            result, plan, primary_root, verifier_root, policy
        )
    difference_report["validationClassifications"] = _validation_difference_classes(
        errors
    )
    difference_report["unknownDifferenceCount"] += sum(
        classification == "unknown-or-unexplained-difference"
        for classification in difference_report["validationClassifications"]
    )
    difference_report["reportDigest"] = _strict_digest(difference_report, "reportDigest")
    if difference_report["unknownDifferenceCount"]:
        errors.append("comparison contains an unknown or unexplained difference")
    return plan, result, difference_report, sorted(set(errors))


def _summary(
    contract: dict[str, Any],
    policy: dict[str, Any],
    primary: dict[str, Any],
    primary_attestation: dict[str, Any],
    verifier: dict[str, Any],
    verifier_attestation: dict[str, Any],
    manifest: dict[str, Any],
    verifier_bundle: Path,
    plan: dict[str, Any],
    result: dict[str, Any],
    independence: dict[str, Any],
    blockers: list[str],
    operation_mode: str,
) -> dict[str, Any]:
    required = contract["buildRecipe"]["requiredSubjectKeys"]
    compared = [row["subjectKey"] for row in result["comparisons"]]
    missing = sorted(set(required) - set(compared))
    extra = sorted(set(compared) - set(required))
    external_operational = verifier_attestation["operational"]
    coordinator = contract.get("coordinator")
    # A local contract can name a coordinator, but it cannot authenticate that coordinator or
    # the final retained artifact without creating a circular self-assertion.  This command may
    # authenticate the external build and complete the comparison; only PR-291 protected
    # closeout, after verifying the exact coordinator artifact, may derive operational success.
    operational = False
    if result["status"] == "fail":
        status = "comparison-failed"
        lifecycle = "comparison-complete"
    elif missing or extra:
        status = "partial"
        lifecycle = "partial"
    elif external_operational:
        status = "authenticated-external-build"
        lifecycle = "comparison-complete"
    elif blockers:
        status = "blocked"
        lifecycle = "blocked"
    else:
        status = "pending"
        lifecycle = "comparison-complete"
    evidence = (
        "authenticated-external-provider"
        if external_operational
        else verifier_attestation["evidenceClassification"]
    )
    redaction_findings = scan_value(
        {
            "contract": contract,
            "primaryAttestation": primary_attestation,
            "externalAttestation": verifier_attestation,
        }
    )
    blocker_rows = _blocker_rows(blockers)
    summary = {
        "schemaVersion": 1,
        "kind": "stable-1.0-independent-reproducibility-summary",
        "releaseId": contract["release"]["id"],
        "buildVersion": contract["release"]["integerBuild"],
        "tag": contract["release"]["tag"],
        "sourceCommit": contract["repository"]["sourceCommit"],
        "sourceRef": contract["repository"]["sourceRef"],
        "selectedRc": contract["selectedRc"],
        "stableSupplyChainPolicyDigest": contract["policies"]["stableSupplyChainPolicyDigest"],
        "independentReproducibilityPolicyDigest": policy["policyDigest"],
        "executionContractDigest": contract["executionContractDigest"],
        "verifierKitDigest": verifier["verifierKitDigest"],
        "componentInventoryDigest": contract["authenticatedInputs"]["componentInventoryDigest"],
        "subjectInventoryDigest": contract["authenticatedInputs"]["subjectInventoryDigest"],
        "buildMaterialsDigest": contract["authenticatedInputs"]["buildMaterialsDigest"],
        "resolutionSnapshotDigest": contract["authenticatedInputs"]["resolutionSnapshotDigest"],
        "primaryBuilderReceiptDigest": primary["receiptDigest"],
        "primaryAuthorityAttestationDigest": primary_attestation["attestationDigest"],
        "externalBuilderReceiptDigest": verifier["receiptDigest"],
        "externalAuthorityAttestationDigest": verifier_attestation["attestationDigest"],
        "externalOutputManifestDigest": manifest["manifestDigest"],
        "externalOutputBundleDigest": file_digest(verifier_bundle),
        "comparisonPlanDigest": plan["planDigest"],
        "reproducibilityResultDigest": result["resultDigest"],
        "providerIndependence": independence,
        "subjectCoverage": {
            "requiredSubjectCount": len(required),
            "comparedSubjectCount": len(compared),
            "missingSubjectKeys": missing,
            "extraSubjectKeys": extra,
            "complete": not missing and not extra,
        },
        "coordinator": coordinator,
        "timing": {
            "kitPreparedAt": None,
            "externalBuildStartedAt": verifier["buildStartedAt"],
            "externalBuildCompletedAt": verifier["buildCompletedAt"],
            "externalOutputsSealedAt": verifier["outputsSealedAt"],
            "externalReceiptAuthenticatedAt": contract["evaluationTime"],
            "candidateInputsAvailableAt": contract["evaluationTime"],
            "comparisonCompletedAt": contract["evaluationTime"],
        },
        "operationMode": operation_mode,
        "lifecycleState": lifecycle,
        "status": status,
        "comparisonStatus": result["status"],
        "evidenceClassification": evidence,
        "fixture": evidence == "fixture",
        "selfTest": evidence == "self-test",
        "operational": operational,
        "publicVerification": "not-performed",
        "blockers": blocker_rows,
        "redaction": {
            "status": "pass" if not redaction_findings else "fail",
            "credentialsExcluded": not redaction_findings,
            "privateUrisExcluded": not redaction_findings,
            "absolutePathsExcluded": not redaction_findings,
            "rawContentExcluded": not redaction_findings,
            "candidateBytesExcludedFromVerifierKit": True,
            "sideEffectsPerformed": False,
        },
        "generatedAt": contract["evaluationTime"],
        "summaryDigest": "sha256:" + "0" * 64,
    }
    summary["summaryDigest"] = _strict_digest(summary, "summaryDigest")
    schema_errors = validate_schema(summary, SUMMARY_SCHEMA)
    if schema_errors:
        raise ValueError(f"generated independent summary violates schema: {schema_errors[0]}")
    return summary


def _blocker_rows(errors: list[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for error in sorted(set(errors)):
        lowered = error.casefold()
        if any(word in lowered for word in ("provider", "authority", "attestation", "workload", "pipeline", "executor")):
            classification = "authority"
        elif any(word in lowered for word in ("candidate inputs", "candidate product", "sealed", "withholding")):
            classification = "withholding"
        elif "subject" in lowered or "coverage" in lowered:
            classification = "subject-coverage"
        elif any(word in lowered for word in ("stale", "fresh", "expir", "time")):
            classification = "freshness"
        elif any(word in lowered for word in ("redact", "private", "secret", "absolute path")):
            classification = "redaction"
        elif any(word in lowered for word in ("comparison", "difference", "payload", "byte")):
            classification = "comparison"
        else:
            classification = "binding"
        message = re.sub(r"[^A-Za-z0-9 .:_/-]", " ", error)
        message = re.sub(r"\s+", " ", message).strip()[:512]
        if not message or not message[0].isalnum():
            message = "Independent reproducibility validation failed"
        code = "pr292." + hashlib.sha256(error.encode("utf-8")).hexdigest()[:16]
        rows.append({"code": code, "classification": classification, "message": message})
    return rows


def independent_summary_errors(
    summary: dict[str, Any],
    contract: dict[str, Any] | None = None,
) -> list[str]:
    """Authenticate a PR-292 summary before protected-release closeout trusts it."""

    errors = validate_schema(summary, SUMMARY_SCHEMA)
    if errors:
        return errors
    if summary["summaryDigest"] != _strict_digest(summary, "summaryDigest"):
        errors.append("independent reproducibility summary self-digest differs")
    if contract is not None:
        expected = {
            "releaseId": contract["release"]["id"],
            "buildVersion": contract["release"]["integerBuild"],
            "tag": contract["release"]["tag"],
            "sourceCommit": contract["repository"]["sourceCommit"],
            "sourceRef": contract["repository"]["sourceRef"],
            "selectedRc": contract["selectedRc"],
            "executionContractDigest": contract["executionContractDigest"],
        }
        for field, expected_value in expected.items():
            if summary.get(field) != expected_value:
                errors.append(f"independent reproducibility summary {field} differs")
    checks = summary["providerIndependence"]["checks"]
    if [row["id"] for row in checks] != sorted(row["id"] for row in checks):
        errors.append("provider-independence checks are not canonical")
    independence_passed = all(row["status"] in {"pass", "not-required"} for row in checks)
    if summary["providerIndependence"]["status"] != ("pass" if independence_passed else "fail"):
        errors.append("provider-independence status is inconsistent")
    if summary["providerIndependence"]["evaluationDigest"] != _strict_digest(
        summary["providerIndependence"], "evaluationDigest"
    ):
        errors.append("provider-independence evaluation digest differs")
    if summary["operational"]:
        if summary["status"] != "independently-reproduced" or summary["comparisonStatus"] != "pass":
            errors.append("operational independent reproducibility status is inconsistent")
        if summary["fixture"] or summary["selfTest"] or summary["coordinator"] is None:
            errors.append("fixture, self-test, or uncoordinated evidence cannot be operational")
        if not summary["subjectCoverage"]["complete"] or not independence_passed:
            errors.append("operational independent reproducibility lacks complete independent coverage")
        if summary["evidenceClassification"] != "authenticated-external-provider":
            errors.append("operational independent reproducibility lacks external classification")
        if summary["blockers"] or summary["redaction"]["status"] != "pass":
            errors.append("operational independent reproducibility has blockers or redaction failures")
    elif summary["status"] == "independently-reproduced":
        errors.append("non-operational evidence claims independent reproduction")
    if summary["publicVerification"] != "not-performed":
        errors.append("local closeout cannot assert public verification")
    if summary["fixture"] is not (summary["evidenceClassification"] == "fixture"):
        errors.append("independent reproducibility fixture classification is inconsistent")
    if summary["selfTest"] is not (summary["evidenceClassification"] == "self-test"):
        errors.append("independent reproducibility self-test classification is inconsistent")
    coverage = summary["subjectCoverage"]
    expected_complete = (
        not coverage["missingSubjectKeys"]
        and not coverage["extraSubjectKeys"]
        and coverage["requiredSubjectCount"] == coverage["comparedSubjectCount"]
    )
    if coverage["complete"] is not expected_complete:
        errors.append("independent reproducibility subject-coverage status is inconsistent")
    try:
        sealed = summary["timing"]["externalOutputsSealedAt"]
        available = summary["timing"]["candidateInputsAvailableAt"]
        if summary["operational"] and (
            sealed is None
            or available is None
            or _timestamp(sealed, "external output seal")
            >= _timestamp(available, "candidate input availability")
        ):
            errors.append("operational summary violates candidate-byte withholding order")
    except ValueError as exc:
        errors.append(str(exc))
    if scan_value(summary):
        errors.append("independent reproducibility summary contains private material or local absolute paths")
    return sorted(set(errors))


def _markdown_report(summary: dict[str, Any]) -> str:
    return "\n".join(
        (
            "# Stable 1.0 independent reproducibility",
            "",
            f"- Status: `{summary['status']}`",
            f"- Lifecycle: `{summary['lifecycleState']}`",
            f"- Comparison: `{summary['comparisonStatus']}`",
            f"- Provider independence: `{summary['providerIndependence']['status']}`",
            f"- Complete subject coverage: `{str(summary['subjectCoverage']['complete']).lower()}`",
            f"- Operational external evidence: `{str(summary['operational']).lower()}`",
            f"- Public verification: `{summary['publicVerification']}`",
            "",
            "This local report performs no publication or external mutation.",
        )
    )


def run(
    workspace: Path,
    contract_path: Path,
    mode: str,
    out_dir: Path | None,
) -> int:
    """Run one side-effect-free local PR-292 lifecycle operation."""

    if contract_path.is_absolute():
        try:
            contract_relative = contract_path.resolve().relative_to(workspace)
        except ValueError as exc:
            raise ValueError("execution contract path escapes the repository workspace") from exc
    else:
        contract_relative = contract_path
    resolved_contract = _confined_file(workspace, contract_relative, "execution contract")
    try:
        contract = read_json(resolved_contract)
    except (OSError, ValueError) as exc:
        raise ValueError(
            "independent reproducibility execution contract is not strict UTF-8 JSON"
        ) from exc
    if not isinstance(contract, dict):
        raise ValueError("independent reproducibility execution contract is not an object")
    policy, supply_chain = _load_policy()
    errors = _contract_errors(contract, mode, policy, supply_chain)
    errors.extend(_runner_clock_errors(contract, policy))
    documents, input_errors = _input_documents(workspace, contract, supply_chain)
    errors.extend(input_errors)
    output = _output_directory(
        workspace,
        out_dir or Path("build/release-certification/stable-independent-reproducibility"),
    )
    if errors:
        write_json(output / REDACTION_FILE, _failure_report(sorted(set(errors))))
        raise ValueError(sorted(set(errors))[0])
    if mode == "prepare-verifier-kit":
        kit = _build_verifier_kit(contract, policy, supply_chain, documents)
        write_json(output / KIT_FILE, kit)
        write_text(output / KIT_DIGEST_FILE, kit["kitDigest"])
        write_json(
            output / REDACTION_FILE,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-independent-reproducibility-redaction-report",
                "status": "pass",
                "candidateBytesExcluded": True,
                "candidateProductDigestsExcluded": True,
                "sideEffectsPerformed": False,
                "findings": [],
            },
        )
        print(f"stable-independent-reproducibility: {output / KIT_FILE}")
        return 0
    kit, kit_errors = _load_kit(workspace, contract, policy, supply_chain, documents)
    if kit is None or kit_errors:
        write_json(
            output / REDACTION_FILE,
            _failure_report(kit_errors or ["verifier kit is missing"]),
        )
        raise ValueError((kit_errors or ["verifier kit is missing"])[0])
    (
        verifier,
        verifier_attestation,
        manifest,
        verifier_bundle,
        raw_attestation,
        verification_transcript,
        external_errors,
    ) = _load_external_evidence(workspace, contract, kit, policy, documents)
    if (
        verifier_bundle is None
        or raw_attestation is None
        or verification_transcript is None
        or external_errors
    ):
        write_json(
            output / REDACTION_FILE,
            _failure_report(external_errors or ["external output bundle is missing"]),
        )
        raise ValueError((external_errors or ["external output bundle is missing"])[0])
    write_json(output / ATTESTATION_FILE, verifier_attestation)
    write_json(output / EXTERNAL_RECEIPT_FILE, verifier)
    write_json(output / EXTERNAL_MANIFEST_FILE, manifest)
    write_bytes(output / RAW_ATTESTATION_FILE, raw_attestation.read_bytes())
    write_bytes(
        output / VERIFICATION_TRANSCRIPT_FILE,
        verification_transcript.read_bytes(),
    )
    if mode == "verify-external-receipt":
        write_json(
            output / REDACTION_FILE,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-independent-reproducibility-redaction-report",
                "status": "pass",
                "candidateBytesExcluded": True,
                "candidateProductDigestsExcluded": True,
                "sideEffectsPerformed": False,
                "findings": [],
            },
        )
        print(f"stable-independent-reproducibility: {output / ATTESTATION_FILE}")
        return 0
    primary, primary_attestation, primary_bundle, primary_errors = _load_primary_evidence(
        workspace, contract, policy, supply_chain, documents
    )
    if primary_bundle is None or primary_errors:
        write_json(
            output / REDACTION_FILE,
            _failure_report(primary_errors or ["candidate subject bundle is missing"]),
        )
        raise ValueError((primary_errors or ["candidate subject bundle is missing"])[0])
    write_json(output / PRIMARY_RECEIPT_FILE, primary)
    write_json(output / PRIMARY_ATTESTATION_FILE, primary_attestation)
    independence, independence_errors = _independence_evaluation(
        primary_attestation, verifier_attestation, contract
    )
    plan, result, difference_report, comparison_errors = _compare_evidence(
        contract,
        policy,
        supply_chain,
        documents,
        primary,
        verifier,
        primary_bundle,
        verifier_bundle,
        manifest,
    )
    if plan is None or result is None or difference_report is None:
        write_json(
            output / REDACTION_FILE,
            _failure_report(
                comparison_errors or ["comparison could not be completed"]
            ),
        )
        raise ValueError((comparison_errors or ["comparison could not be completed"])[0])
    write_json(output / PLAN_FILE, plan)
    write_json(output / RESULT_FILE, result)
    write_json(output / REDACTION_FILE, difference_report)
    blockers = sorted(set(independence_errors + comparison_errors))
    summary = _summary(
        contract,
        policy,
        primary,
        primary_attestation,
        verifier,
        verifier_attestation,
        manifest,
        verifier_bundle,
        plan,
        result,
        independence,
        blockers,
        mode,
    )
    summary_errors = independent_summary_errors(summary, contract)
    if summary_errors:
        raise ValueError(summary_errors[0])
    write_json(output / SUMMARY_FILE, summary)
    write_text(output / REPORT_FILE, _markdown_report(summary))
    print(f"stable-independent-reproducibility: {output / SUMMARY_FILE}")
    return 0 if not blockers else 1
