"""PR-292 retained-artifact fixtures for protected-release closeout tests."""

from __future__ import annotations

import copy
import json
import tempfile
import zipfile
from pathlib import Path
from unittest import mock

from cryptad_certification.engines import stable_1_0_protected_release as protected
from cryptad_certification.engines import (
    stable_1_0_independent_reproducibility as independent,
)
from cryptad_certification.io import write_json
from cryptad_certification.tests.test_stable_supply_chain import SupplyChainFixture
from cryptad_certification.tests.support import workspace_root
from cryptad_certification.tests import test_stable_protected_release as base

COMMIT = base.COMMIT
DIGEST_ZERO = base.DIGEST_ZERO
RELEASE_ID = base.RELEASE_ID
_binding = base._binding
_coordinate = base._coordinate

def _sealed(value: dict[str, object], field: str) -> dict[str, object]:
    value[field] = DIGEST_ZERO
    value[field] = protected.supply_chain_semantic_digest(value, field)
    return value


def _attestation_file_binding(
    path: Path, schema: str | None
) -> dict[str, object]:
    return {
        "path": path.name,
        "sha256": protected._digest(path),  # noqa: SLF001
        "schema": schema,
        "size": path.stat().st_size,
    }


def _independent_test_policy() -> dict[str, object]:
    policy = json.loads(
        (
            workspace_root()
            / "tools/release-certification/stable-1.0-independent-reproducibility-policy.json"
        ).read_text(encoding="utf-8")
    )
    external_adapter = next(
        row
        for row in policy["attestationAdapters"]
        if row["adapterId"] == "external-oidc-dsse-v1"
    )
    external_adapter["operationalAllowed"] = True
    external_adapter["adapterDigest"] = protected.supply_chain_semantic_digest(
        external_adapter, "adapterDigest"
    )
    external_profile = _sealed(
        {
            "profileId": "external-test-v1",
            "profileType": "provider",
            "providerType": "external-oidc",
            "providerId": "external.example",
            "controlPlaneId": "external.example/builds",
            "trustDomainId": "external.example/workloads",
            "organizationId": "external-verifier",
            "accountId": "external-account",
            "projectId": "external-project",
            "adapterId": "external-oidc-dsse-v1",
            "issuer": "https://issuer.external.example",
            "audiences": ["cryptad-stable-independent-reproducibility"],
            "subjectPattern": "^external-immutable-workload$",
            "pipelineDefinitionPattern": "^external-pipeline$",
            "pipelineRevisionType": "sha256",
            "executorPolicy": "provider-hosted",
            "immutableRunnerImageRequired": True,
            "organizationIndependenceRequired": True,
            "operationalAllowed": True,
            "profileDigest": DIGEST_ZERO,
        },
        "profileDigest",
    )
    policy["providerProfiles"].append(external_profile)
    policy["policyDigest"] = protected.supply_chain_semantic_digest(
        policy, "policyDigest"
    )
    return policy


def _independent_policy_authority_patch():
    supply_chain_policy = json.loads(
        (
            workspace_root()
            / "tools/release-certification/stable-1.0-supply-chain-policy.json"
        ).read_text(encoding="utf-8")
    )
    return mock.patch.object(
        protected,
        "_independent_checked_in_policies",
        return_value=(supply_chain_policy, _independent_test_policy(), []),
    )


def _authority_attestation(
    *,
    label: str,
    role: str,
    receipt_path: Path,
    output_manifest_path: Path | None,
    output_bundle_path: Path | None,
    root: Path,
    independent_policy_digest: str,
    evidence_classification: str,
    operational: bool,
    same_provider: bool = False,
) -> dict[str, object]:
    provider = "github.com" if role == "candidate-producer" or same_provider else "external.example"
    control_plane = "github.com/actions" if role == "candidate-producer" or same_provider else "external.example/builds"
    trust_domain = "github.com/actions" if role == "candidate-producer" or same_provider else "external.example/workloads"
    organization = "crypta-network" if role == "candidate-producer" or same_provider else "external-verifier"
    account = "crypta-network" if role == "candidate-producer" or same_provider else "external-account"
    raw_path = root / f"{label}-raw-attestation.json"
    transcript_path = root / f"{label}-verification-transcript.json"
    raw_path.write_text(
        json.dumps({"attestation": f"{label}-sealed"}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    independent_policy = _independent_test_policy()
    profile_id = (
        "github-actions-cryptad-producer-v1"
        if role == "candidate-producer"
        else "external-test-v1"
    )
    profile = next(
        row
        for row in independent_policy["providerProfiles"]
        if row["profileId"] == profile_id
    )
    adapter = next(
        row
        for row in independent_policy["attestationAdapters"]
        if row["adapterId"] == profile["adapterId"]
    )
    authority = _sealed(
        {
            "providerType": "github-actions" if provider == "github.com" else "external-oidc",
            "providerId": provider,
            "controlPlaneId": control_plane,
            "trustDomainId": trust_domain,
            "organizationId": organization,
            "accountId": account,
            "projectId": "crypta-network/cryptad" if provider == "github.com" else "external-project",
            "executorControllerId": control_plane,
            "executorOwnership": "provider-hosted",
            "authorityIdentityDigest": DIGEST_ZERO,
        },
        "authorityIdentityDigest",
    )
    pipeline = _sealed(
        {
            "definitionId": (
                f"github.com/crypta-network/cryptad/.github/workflows/"
                f"stable-1.0-supply-chain.yml@{COMMIT}"
                if role == "candidate-producer"
                else "external-pipeline"
            ),
            "immutableRevision": (
                "sha256:" + "6" * 64
            ),
            "revisionType": profile["pipelineRevisionType"],
            "runId": (
                str(json.loads(receipt_path.read_text(encoding="utf-8"))["builderIdentity"]["runId"])
                if role == "candidate-producer"
                else f"{label}-run"
            ),
            "runAttempt": (
                json.loads(receipt_path.read_text(encoding="utf-8"))["builderIdentity"]["runAttempt"]
                if role == "candidate-producer"
                else 1
            ),
            "jobId": f"{label}-job",
            "stageId": f"{label}-stage",
            "eventType": "manual-release-verification",
            "pipelineIdentityDigest": DIGEST_ZERO,
        },
        "pipelineIdentityDigest",
    )
    executor = _sealed(
        {
            "runnerOs": "mixed-platform-partitions",
            "runnerArchitecture": "mixed",
            "runnerImageIdentity": f"{label}-immutable-runner",
            "runnerImageDigest": "sha256:" + "7" * 64,
            "runnerImageDigestType": "provider-image-sha256",
            "executorPoolId": f"{label}-pool",
            "selfHosted": False,
            "executorIdentityDigest": DIGEST_ZERO,
        },
        "executorIdentityDigest",
    )
    receipt_binding = _attestation_file_binding(
        receipt_path,
        (
            "stable-1.0-builder-receipt-v1.schema.json"
            if role == "candidate-producer"
            else protected.INDEPENDENT_BUILDER_SCHEMA
        ),
    )
    artifact = {
        "format": adapter["attestationFormat"],
        "predicateType": adapter["predicateType"],
        "bundleDigest": protected._digest(raw_path),  # noqa: SLF001
        "statementDigest": protected._semantic_digest(f"{label}-statement"),  # noqa: SLF001
        "subjectSetDigest": protected._semantic_digest(f"{label}-subject-set"),  # noqa: SLF001
        "adapterId": adapter["adapterId"],
        "adapterDigest": adapter["adapterDigest"],
        "trustRootSetDigest": protected._semantic_digest(f"{label}-trust-roots"),  # noqa: SLF001
        "transparencyLogEntryDigest": protected._semantic_digest(f"{label}-transparency"),  # noqa: SLF001
        "verificationTranscriptDigest": DIGEST_ZERO,
        "verificationStatus": "verified",
        "verifiedAt": "2026-08-16T00:45:00Z",
    }
    if output_manifest_path is not None:
        output_manifest = json.loads(output_manifest_path.read_text(encoding="utf-8"))
        artifact["subjectSetDigest"] = output_manifest["subjectSetDigest"]
    workload_subject = (
        f"repo:crypta-network/cryptad:ref:refs/heads/release/3"
        if role == "candidate-producer"
        else "external-immutable-workload"
    )
    workload = {
        "mechanism": "sigstore-keyless" if provider == "github.com" else "oidc-dsse",
        "issuer": profile["issuer"],
        "subject": workload_subject,
        "audiences": profile["audiences"],
        "certificateIdentity": f"{label}-certificate-identity",
        "issuedAt": "2026-08-16T00:00:00Z",
        "expiresAt": "2026-08-17T00:00:00Z",
        "trustRootSetDigest": artifact["trustRootSetDigest"],
        "claimsDigest": protected._semantic_digest(f"{label}-claims"),  # noqa: SLF001
    }
    receipt_producer = _sealed(
        {
            "workloadSubject": workload_subject,
            "softwareName": "cryptad-certification",
            "softwareVersion": "1",
            "softwareDigest": protected._semantic_digest(f"{label}-software"),  # noqa: SLF001
            "receiptProducerIdentityDigest": DIGEST_ZERO,
        },
        "receiptProducerIdentityDigest",
    )
    attestation = {
            "schemaVersion": 1,
            "kind": "stable-1.0-independent-authority-attestation",
            "releaseId": RELEASE_ID,
            "buildVersion": 3,
            "tag": "v3",
            "sourceCommit": COMMIT,
            "executionContractDigest": "sha256:" + "8" * 64,
            "verifierKitDigest": (
                None if role == "candidate-producer" else "sha256:" + "9" * 64
            ),
            "independentReproducibilityPolicyDigest": independent_policy_digest,
            "providerProfileId": profile_id,
            "providerProfileDigest": profile["profileDigest"],
            "builderRole": role,
            "authorityIdentity": authority,
            "pipelineIdentity": pipeline,
            "workloadIdentity": workload,
            "executorIdentity": executor,
            "artifactAttestation": artifact,
            "rawArtifactAttestationBundle": _attestation_file_binding(raw_path, None),
            "verificationTranscript": None,
            "receiptProducer": receipt_producer,
            "builderReceipt": receipt_binding,
            "outputManifest": (
                _attestation_file_binding(
                    output_manifest_path, protected.INDEPENDENT_OUTPUT_SCHEMA
                )
                if output_manifest_path is not None
                else None
            ),
            "outputBundle": (
                _attestation_file_binding(output_bundle_path, None)
                if output_bundle_path is not None
                else None
            ),
            "buildStartedAt": "2026-08-16T00:00:00Z",
            "buildCompletedAt": "2026-08-16T00:30:00Z",
            "outputsSealedAt": "2026-08-16T00:31:00Z",
            "candidateProductAvailableBeforeBuild": False,
            "evidenceClassification": evidence_classification,
            "operational": operational,
            "attestationDigest": DIGEST_ZERO,
    }
    transcript = _sealed(
        {
            "schemaVersion": 1,
            "kind": "stable-1.0-independent-attestation-verification-transcript",
            "adapterId": artifact["adapterId"],
            "adapterDigest": artifact["adapterDigest"],
            "rawBundleDigest": artifact["bundleDigest"],
            "statementDigest": artifact["statementDigest"],
            "subjectSetDigest": artifact["subjectSetDigest"],
            "verificationStatus": "pass",
            "issuer": workload["issuer"],
            "subject": workload["subject"],
            "audiences": workload["audiences"],
            "pipelineDefinitionId": pipeline["definitionId"],
            "pipelineRevision": pipeline["immutableRevision"],
            "verifiedAt": artifact["verifiedAt"],
            "transcriptDigest": DIGEST_ZERO,
        },
        "transcriptDigest",
    )
    write_json(transcript_path, transcript)
    artifact["verificationTranscriptDigest"] = protected._digest(  # noqa: SLF001
        transcript_path
    )
    attestation["verificationTranscript"] = _attestation_file_binding(
        transcript_path, None
    )
    return _sealed(attestation, "attestationDigest")


def _independent_reproducibility_evidence(
    root: Path,
    contract: dict[str, object],
    policy: dict[str, object],
    *,
    status: str = "independently-reproduced",
    same_provider: bool = False,
    fixture: bool = False,
    self_test: bool = False,
) -> dict[str, Path]:
    selected = contract["ga"]["selectedRc"]  # type: ignore[index]
    assert isinstance(selected, dict)
    lineage_binding = contract["operationEvidence"]["rcFreeze"]  # type: ignore[index]
    assert isinstance(lineage_binding, dict)
    lineage = json.loads((root / str(lineage_binding["path"])).read_text(encoding="utf-8"))
    stable_policy_digest = policy["requiredEvidenceContracts"]["stable-supply-chain"][  # type: ignore[index]
        "policyDigest"
    ]
    independent_policy = _independent_test_policy()
    independent_policy_digest = independent_policy["policyDigest"]
    fixture_root = Path(tempfile.mkdtemp(prefix="pr292-member-fixture-", dir=root))
    supply_fixture = SupplyChainFixture(fixture_root)
    primary = supply_fixture.receipt("candidate-producer", 101)
    primary.update(
        releaseId=RELEASE_ID,
        buildVersion=3,
        tag="v3",
        sourceCommit=COMMIT,
        sourceRef=f"commit:{COMMIT}",
        policyDigest=stable_policy_digest,
    )
    primary["builderIdentity"].update(
        workflowRef=(
            "github.com/crypta-network/cryptad/"
            f".github/workflows/stable-1.0-supply-chain.yml@{COMMIT}"
        ),
        workflowSha=COMMIT,
    )
    for execution in primary["builderExecutions"]:
        execution.update(
            workflowRef=(
                "github.com/crypta-network/cryptad/"
                f".github/workflows/stable-1.0-supply-chain.yml@{COMMIT}"
            ),
            workflowSha=COMMIT,
        )
    primary["source"].update(commit=COMMIT, ref=f"commit:{COMMIT}")
    primary = _sealed(primary, "receiptDigest")
    primary_path = root / "stable-1.0-primary-builder-receipt.json"
    write_json(primary_path, primary)

    authority_identity = _sealed(
        {
            "providerType": "external-oidc",
            "providerId": "github.com" if same_provider else "external.example",
            "controlPlaneId": "github.com/actions" if same_provider else "external.example/builds",
            "trustDomainId": "github.com/actions" if same_provider else "external.example/workloads",
            "organizationId": "crypta-network" if same_provider else "external-verifier",
            "accountId": "crypta-network" if same_provider else "external-account",
            "projectId": "external-project",
            "pipelineDefinitionId": "external-pipeline",
            "pipelineRevision": "sha256:" + "4" * 64,
            "runId": "external-run",
            "runAttempt": 1,
            "jobId": "external-job",
            "stageId": "external-stage",
            "executorControllerId": "github.com/actions" if same_provider else "external.example/builds",
            "executorOwnership": "provider-hosted",
            "workloadIdentityDigest": protected._semantic_digest(  # noqa: SLF001
                "external-claims"
            ),
            "authorityIdentityDigest": DIGEST_ZERO,
        },
        "authorityIdentityDigest",
    )
    supply_chain_policy = json.loads(
        (
            workspace_root()
            / "tools/release-certification/stable-1.0-supply-chain-policy.json"
        ).read_text(encoding="utf-8")
    )
    independent_rules = {
        row["subjectKey"]: row
        for row in supply_chain_policy["releaseSubjects"]
        if row["evidencePhase"] == "independent-builder"
    }
    primary_subjects_by_key = {row["subjectKey"]: row for row in primary["subjects"]}
    expected_outputs = [
        {
            "subjectKey": key,
            "fileName": primary_subjects_by_key[key]["fileName"],
            "reproducibilityClass": independent_rules[key]["reproducibilityClass"],
            "normalizationRuleId": independent_rules[key].get("normalizationRuleId"),
        }
        for key in sorted(independent_rules)
    ]
    executions = []
    for row in primary["builderExecutions"]:
        verifier_task_set = independent_policy["requiredExecutionTasks"][
            row["executionId"]
        ]
        subject_projection = independent.candidate_free_subject_projection(
            expected_outputs, row["subjectKeys"]
        )
        executions.append(
            {
                "executionId": row["executionId"],
                "pipelineDefinitionId": "external-pipeline",
                "pipelineRevision": "sha256:" + "6" * 64,
                "runId": "external-run",
                "runAttempt": 1,
                "jobId": f"external-{row['executionId']}",
                "stageId": row["executionId"],
                "runnerOs": row["runnerOs"],
                "runnerArchitecture": row["runnerArchitecture"],
                "runnerImageIdentity": row["runnerImageIdentity"],
                "runnerImageDigest": row["runnerImageDigest"],
                "runnerImageDigestType": "provider-image-sha256",
                "toolchain": row["toolchain"],
                "materialIdentities": row["materialIdentities"],
                "taskSet": verifier_task_set,
                "taskSetDigest": protected._semantic_digest(  # noqa: SLF001
                    verifier_task_set
                ),
                "canonicalEnvironment": row["canonicalEnvironment"],
                "directInputsDigest": row["directInputsDigest"],
                "payloadManifestSetDigest": row["payloadManifestSetDigest"],
                "extractionManifestSetDigest": row["extractionManifestSetDigest"],
                "handoffDigest": row["handoffDigest"],
                "subjectSetDigest": protected._semantic_digest(  # noqa: SLF001
                    subject_projection
                ),
                "subjectKeys": row["subjectKeys"],
                "sourceCommit": COMMIT,
                "sourceTreeDigest": row["sourceTreeDigest"],
                "materialsDigest": row["materialsDigest"],
                "resolutionSnapshotDigest": row["resolutionSnapshotDigest"],
                "buildStartedAt": "2026-08-16T00:00:00Z",
                "buildCompletedAt": "2026-08-16T00:30:00Z",
                "candidateProductAvailableBeforeBuild": False,
            }
        )
    external_subjects = copy.deepcopy(primary["subjects"])
    for subject in external_subjects:
        subject["signatureReceiptDigest"] = None
        subject["notarizationReceiptDigest"] = None
        subject["publishedCandidate"] = False
    external = _sealed(
        {
            "schemaVersion": 2,
            "kind": "stable-1.0-independent-builder-receipt",
            "releaseId": RELEASE_ID,
            "buildVersion": 3,
            "tag": "v3",
            "repositoryIdentity": "github.com/crypta-network/cryptad",
            "sourceCommit": COMMIT,
            "sourceRef": f"commit:{COMMIT}",
            "stableSupplyChainPolicyDigest": stable_policy_digest,
            "independentReproducibilityPolicyDigest": independent_policy_digest,
            "executionContractDigest": "sha256:" + "8" * 64,
            "verifierKitDigest": "sha256:" + "9" * 64,
            "role": "independent-verifier",
            "providerProfileId": "external-test-v1",
            "providerProfileDigest": next(
                row["profileDigest"]
                for row in independent_policy["providerProfiles"]
                if row["profileId"] == "external-test-v1"
            ),
            "authorityIdentity": authority_identity,
            "builderExecutions": executions,
            "source": {
                "commit": COMMIT,
                "ref": f"commit:{COMMIT}",
                "treeDigest": primary["source"]["treeDigest"],
                "clean": True,
            },
            "materialsDigest": primary["materialsDigest"],
            "resolutionSnapshotDigest": primary["resolutionSnapshotDigest"],
            "directInputs": primary["directInputs"],
            "buildTasks": independent_policy["requiredBuildTasks"],
            "canonicalEnvironment": executions[0]["canonicalEnvironment"],
            "buildStartedAt": "2026-08-16T00:00:00Z",
            "buildCompletedAt": "2026-08-16T00:30:00Z",
            "outputsSealedAt": "2026-08-16T00:31:00Z",
            "candidateProductAvailableBeforeBuild": False,
            "subjects": external_subjects,
            "receiptDigest": DIGEST_ZERO,
        },
        "receiptDigest",
    )
    external_path = root / "stable-1.0-independent-builder-receipt.json"
    write_json(external_path, external)

    independent_rules = {
        row["subjectKey"]: row
        for row in supply_fixture.policy["releaseSubjects"]
        if row["evidencePhase"] == "independent-builder"
    }
    output_subjects = [
        {
            "subjectKey": row["subjectKey"],
            "fileName": row["fileName"],
            "bundlePath": f"subjects/{row['fileName']}",
            "digest": row["digest"],
            "size": row["size"],
            "reproducibilityClass": independent_rules[row["subjectKey"]][
                "reproducibilityClass"
            ],
            "normalizationRuleId": independent_rules[row["subjectKey"]].get(
                "normalizationRuleId"
            ),
            "payloadManifestDigest": row["payloadManifestDigest"],
            "extractionEvidenceDigest": row["extractionEvidenceDigest"],
        }
        for row in external_subjects
    ]
    payload_manifests = [
        {
            "subjectKey": row["subjectKey"],
            "bundlePath": f"payload-manifests/{row['subjectKey']}.json",
            "sha256": "sha256:" + "b" * 64,
            "size": 1,
            "schema": "stable-1.0-payload-manifest-v1.schema.json",
            "manifestDigest": row["payloadManifestDigest"],
        }
        for row in external_subjects
        if independent_rules[row["subjectKey"]]["reproducibilityClass"]
        == "normalized-payload-identical"
    ]
    output_manifest = _sealed(
        {
            "schemaVersion": 1,
            "kind": "stable-1.0-independent-output-manifest",
            "releaseId": RELEASE_ID,
            "buildVersion": 3,
            "tag": "v3",
            "sourceCommit": COMMIT,
            "executionContractDigest": "sha256:" + "8" * 64,
            "verifierKitDigest": "sha256:" + "9" * 64,
            "builderReceiptDigest": external["receiptDigest"],
            "providerProfileDigest": external["providerProfileDigest"],
            "sourceTreeDigest": external["source"]["treeDigest"],
            "materialsDigest": external["materialsDigest"],
            "resolutionSnapshotDigest": external["resolutionSnapshotDigest"],
            "taskSetDigest": protected._semantic_digest(external["buildTasks"]),  # noqa: SLF001
            "canonicalEnvironmentDigest": protected._semantic_digest(
                external["canonicalEnvironment"]
            ),  # noqa: SLF001
            "subjects": output_subjects,
            "payloadManifests": payload_manifests,
            "subjectSetDigest": protected._semantic_digest(output_subjects),  # noqa: SLF001
            "buildCompletedAt": external["buildCompletedAt"],
            "outputsSealedAt": external["outputsSealedAt"],
            "candidateProductAvailableBeforeBuild": False,
            "manifestDigest": DIGEST_ZERO,
        },
        "manifestDigest",
    )
    manifest_path = root / "stable-1.0-independent-output-manifest.json"
    write_json(manifest_path, output_manifest)
    bundle_path = root / "external-output-bundle.zip"
    with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("subjects/fixture", b"fixture")

    external_classification = (
        "fixture" if fixture else "self-test" if self_test else "authenticated-external-provider"
    )
    external_operational = not fixture and not self_test
    primary_authority = _authority_attestation(
        label="primary",
        role="candidate-producer",
        receipt_path=primary_path,
        output_manifest_path=None,
        output_bundle_path=None,
        root=root,
        independent_policy_digest=independent_policy_digest,
        evidence_classification="protected-same-provider",
        operational=False,
    )
    external_authority = _authority_attestation(
        label="external",
        role="independent-verifier",
        receipt_path=external_path,
        output_manifest_path=manifest_path,
        output_bundle_path=bundle_path,
        root=root,
        independent_policy_digest=independent_policy_digest,
        evidence_classification=external_classification,
        operational=external_operational,
        same_provider=same_provider,
    )
    primary_authority_path = root / "stable-1.0-primary-authority-attestation.json"
    external_authority_path = root / "stable-1.0-independent-builder-attestation.json"
    write_json(primary_authority_path, primary_authority)
    write_json(external_authority_path, external_authority)

    digest = "sha256:" + "9" * 64
    comparison_failed = status == "comparison-failed"
    release = {
        "releaseId": RELEASE_ID,
        "buildVersion": 3,
        "tag": "v3",
        "sourceCommit": COMMIT,
        "sourceRef": f"commit:{COMMIT}",
        "policyDigest": stable_policy_digest,
    }
    primary_subjects = {row["subjectKey"]: row for row in primary["subjects"]}
    external_subject_rows = {row["subjectKey"]: row for row in external["subjects"]}
    plan_comparisons = []
    result_comparisons = []
    for key in sorted(independent_rules):
        first = primary_subjects[key]
        second = external_subject_rows[key]
        rule = independent_rules[key]
        row_failed = comparison_failed and key == sorted(independent_rules)[0]
        verifier_digest = DIGEST_ZERO if row_failed else first["digest"]
        second["digest"] = verifier_digest
        plan_comparisons.append(
            {
                "subjectKey": key,
                "fileName": first["fileName"],
                "reproducibilityClass": rule["reproducibilityClass"],
                "normalizationRuleId": rule.get("normalizationRuleId"),
                "primaryDigest": first["digest"],
                "verifierDigest": verifier_digest,
                "primarySize": first["size"],
                "verifierSize": second["size"],
                "primaryPayloadManifestDigest": first["payloadManifestDigest"],
                "verifierPayloadManifestDigest": second["payloadManifestDigest"],
            }
        )
        differences = ["byte-identical subject bytes differ"] if row_failed else []
        result_comparisons.append(
            {
                "subjectKey": key,
                "reproducibilityClass": rule["reproducibilityClass"],
                "status": "fail" if differences else "pass",
                "primaryDigest": first["digest"],
                "verifierDigest": verifier_digest,
                "primaryPayloadManifestDigest": first["payloadManifestDigest"],
                "verifierPayloadManifestDigest": second["payloadManifestDigest"],
                "differences": differences,
            }
        )
    external = _sealed(external, "receiptDigest")
    write_json(external_path, external)
    output_manifest["builderReceiptDigest"] = external["receiptDigest"]
    for output_row in output_manifest["subjects"]:
        source = external_subject_rows[output_row["subjectKey"]]
        output_row["digest"] = source["digest"]
    output_manifest["subjectSetDigest"] = protected._semantic_digest(  # noqa: SLF001
        output_manifest["subjects"]
    )
    output_manifest = _sealed(output_manifest, "manifestDigest")
    write_json(manifest_path, output_manifest)
    primary_authority = _authority_attestation(
        label="primary",
        role="candidate-producer",
        receipt_path=primary_path,
        output_manifest_path=None,
        output_bundle_path=None,
        root=root,
        independent_policy_digest=independent_policy_digest,
        evidence_classification="protected-same-provider",
        operational=False,
    )
    external_authority = _authority_attestation(
        label="external",
        role="independent-verifier",
        receipt_path=external_path,
        output_manifest_path=manifest_path,
        output_bundle_path=bundle_path,
        root=root,
        independent_policy_digest=independent_policy_digest,
        evidence_classification=external_classification,
        operational=external_operational,
        same_provider=same_provider,
    )
    write_json(primary_authority_path, primary_authority)
    write_json(external_authority_path, external_authority)
    plan = _sealed(
        {
            "schemaVersion": 1,
            "kind": "stable-1.0-rebuild-comparison-plan",
            **release,
            "componentInventoryDigest": digest,
            "subjectInventoryDigest": digest,
            "primaryBuilderReceiptDigest": primary["receiptDigest"],
            "verifierBuilderReceiptDigest": external["receiptDigest"],
            "comparisons": plan_comparisons,
            "equalityInferred": False,
            "planDigest": DIGEST_ZERO,
        },
        "planDigest",
    )
    result = _sealed(
        {
            "schemaVersion": 1,
            "kind": "stable-1.0-reproducibility-result",
            **release,
            "comparisonPlanDigest": plan["planDigest"],
            "primaryBuilderReceiptDigest": primary["receiptDigest"],
            "verifierBuilderReceiptDigest": external["receiptDigest"],
            "comparisons": result_comparisons,
            "status": "fail" if comparison_failed else "pass",
            "unexplainedDifferences": 1 if comparison_failed else 0,
            "resultDigest": DIGEST_ZERO,
        },
        "resultDigest",
    )
    plan_path = root / "stable-1.0-rebuild-comparison-plan.json"
    result_path = root / "stable-1.0-reproducibility-report.json"
    write_json(plan_path, plan)
    write_json(result_path, result)

    def projection(attestation: dict[str, object]) -> dict[str, object]:
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

    check_ids = (
        "artifact-attestation-distinct",
        "control-plane-distinct",
        "executor-controller-independent",
        "organization-distinct",
        "pipeline-run-distinct",
        "provider-distinct",
        "producer-workflow-not-reused",
        "trust-domain-distinct",
        "workload-identity-authenticated",
    )
    checks = [
        {
            "id": check_id,
            "status": (
                "fail"
                if same_provider
                and check_id
                in {
                    "control-plane-distinct",
                    "organization-distinct",
                    "provider-distinct",
                    "trust-domain-distinct",
                }
                else "pass"
            ),
        }
        for check_id in check_ids
    ]
    independence = _sealed(
        {
            "producer": projection(primary_authority),
            "verifier": projection(external_authority),
            "organizationIndependenceRequired": True,
            "checks": checks,
            "status": "fail" if same_provider else "pass",
            "evaluationDigest": DIGEST_ZERO,
        },
        "evaluationDigest",
    )
    independence, _ = independent._independence_evaluation(  # noqa: SLF001
        primary_authority,
        external_authority,
        {
            "expectedVerifierAuthority": {
                "requireProviderDistinct": True,
                "requireControlPlaneDistinct": True,
                "requireTrustDomainDistinct": True,
                "requireOrganizationDistinct": True,
            }
        },
    )
    coordinate = _coordinate(
        ".github/workflows/stable-1.0-independent-reproducibility.yml",
        "stable-1.0-independent-reproducibility-external-receipt",
        run_id="90",
        artifact_name=f"stable-1-0-independent-closeout-{RELEASE_ID}-3-90-1",
    )
    operational = (
        status == "independently-reproduced"
        and not same_provider
        and not fixture
        and not self_test
    )
    summary_status = status
    if same_provider and status == "independently-reproduced":
        summary_status = "blocked"
    if (fixture or self_test) and status == "independently-reproduced":
        summary_status = "pending"
    selected_summary = {
        "workflowPath": ".github/workflows/stable-1.0-rc-release.yml",
        "workflowCommit": COMMIT,
        "runId": selected["runId"],
        "runAttempt": int(str(selected["runAttempt"])),
        "artifactName": selected["artifactName"],
        "artifactDigest": selected["artifactDigest"],
        "freezeDigest": selected["freezeDigest"],
        "freezeFileDigest": lineage["selectedFreeze"]["freezeFileDigest"],
        "productDigest": selected["productDigest"],
        "subjectInventoryDigest": digest,
        "supplyChain": {
            "workflowPath": ".github/workflows/stable-1.0-supply-chain.yml",
            "workflowCommit": COMMIT,
            "runId": str(primary["builderIdentity"]["runId"]),
            "runAttempt": primary["builderIdentity"]["runAttempt"],
            "artifactName": f"stable-1.0-supply-chain-{RELEASE_ID}-comparison",
            "artifactDigest": "sha256:" + "a" * 64,
        },
    }
    summary = _sealed(
        {
            "schemaVersion": 1,
            "kind": "stable-1.0-independent-reproducibility-summary",
            "releaseId": RELEASE_ID,
            "buildVersion": 3,
            "tag": "v3",
            "sourceCommit": COMMIT,
            "sourceRef": f"commit:{COMMIT}",
            "selectedRc": selected_summary,
            "stableSupplyChainPolicyDigest": stable_policy_digest,
            "independentReproducibilityPolicyDigest": independent_policy_digest,
            "executionContractDigest": "sha256:" + "8" * 64,
            "verifierKitDigest": "sha256:" + "9" * 64,
            "componentInventoryDigest": digest,
            "subjectInventoryDigest": digest,
            "buildMaterialsDigest": primary["materialsDigest"],
            "resolutionSnapshotDigest": primary["resolutionSnapshotDigest"],
            "primaryBuilderReceiptDigest": primary["receiptDigest"],
            "primaryAuthorityAttestationDigest": primary_authority["attestationDigest"],
            "externalBuilderReceiptDigest": external["receiptDigest"],
            "externalAuthorityAttestationDigest": external_authority["attestationDigest"],
            "externalOutputManifestDigest": output_manifest["manifestDigest"],
            "externalOutputBundleDigest": protected._digest(bundle_path),  # noqa: SLF001
            "comparisonPlanDigest": plan["planDigest"],
            "reproducibilityResultDigest": result["resultDigest"],
            "providerIndependence": independence,
            "subjectCoverage": {
                "requiredSubjectCount": len(independent_rules),
                "comparedSubjectCount": len(independent_rules),
                "missingSubjectKeys": [],
                "extraSubjectKeys": [],
                "complete": True,
            },
            "coordinator": {
                "repository": "crypta-network/cryptad",
                "workflowPath": coordinate["workflowPath"],
                "workflowCommit": COMMIT,
                "runId": coordinate["runId"],
                "runAttempt": int(str(coordinate["runAttempt"])),
                "jobName": "Authenticate and compare independent rebuild",
                "environment": coordinate["environment"],
                "artifactName": coordinate["artifactName"],
                "artifactDigest": None,
            },
            "timing": {
                "kitPreparedAt": "2026-08-15T23:00:00Z",
                "externalBuildStartedAt": "2026-08-16T00:00:00Z",
                "externalBuildCompletedAt": "2026-08-16T00:30:00Z",
                "externalOutputsSealedAt": "2026-08-16T00:31:00Z",
                "externalReceiptAuthenticatedAt": "2026-08-16T00:45:00Z",
                "candidateInputsAvailableAt": "2026-08-16T01:00:00Z",
                "comparisonCompletedAt": "2026-08-16T01:15:00Z",
            },
            "operationMode": "closeout",
            "lifecycleState": (
                "independently-reproduced"
                if operational
                else "comparison-complete"
                if summary_status == "comparison-failed"
                else "blocked"
                if summary_status == "blocked"
                else "partial"
            ),
            "status": summary_status,
            "comparisonStatus": "fail" if comparison_failed else "pass",
            "evidenceClassification": external_classification,
            "fixture": fixture,
            "selfTest": self_test,
            "operational": operational,
            "publicVerification": "not-performed",
            "blockers": (
                [
                    {
                        "code": "comparison-failed",
                        "classification": "comparison",
                        "message": "External rebuild comparison failed",
                    }
                ]
                if comparison_failed
                else []
            ),
            "redaction": {
                "status": "pass",
                "credentialsExcluded": True,
                "privateUrisExcluded": True,
                "absolutePathsExcluded": True,
                "rawContentExcluded": True,
                "candidateBytesExcludedFromVerifierKit": True,
                "sideEffectsPerformed": False,
            },
            "generatedAt": "2026-08-16T01:15:00Z",
            "summaryDigest": DIGEST_ZERO,
        },
        "summaryDigest",
    )
    summary_path = root / "stable-1.0-independent-reproducibility-summary.json"
    write_json(summary_path, summary)
    selected_supply_path = root / "stable-1.0-selected-rc-supply-chain-coordinate.json"
    write_json(
        selected_supply_path,
        {
            "runId": selected_summary["supplyChain"]["runId"],
            "runAttempt": selected_summary["supplyChain"]["runAttempt"],
            "artifactName": selected_summary["supplyChain"]["artifactName"],
            "artifactDigest": selected_summary["supplyChain"]["artifactDigest"],
        },
    )
    member_paths = {
        "stable-1.0-primary-builder-receipt.json": primary_path,
        "stable-1.0-primary-authority-attestation.json": primary_authority_path,
        "stable-1.0-independent-builder-receipt.json": external_path,
        "stable-1.0-independent-builder-attestation.json": external_authority_path,
        "stable-1.0-independent-output-manifest.json": manifest_path,
        "stable-1.0-independent-raw-artifact-attestation.bundle": (
            root / "external-raw-attestation.json"
        ),
        "stable-1.0-independent-attestation-verification-transcript.json": (
            root / "external-verification-transcript.json"
        ),
        "stable-1.0-selected-rc-supply-chain-coordinate.json": selected_supply_path,
        "stable-1.0-rebuild-comparison-plan.json": plan_path,
        "stable-1.0-reproducibility-report.json": result_path,
        "stable-1.0-independent-reproducibility-summary.json": summary_path,
    }
    archive_path = root / "stable-1.0-independent-closeout.zip"
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_STORED) as archive:
        for name, path in member_paths.items():
            archive.write(path, name)
    artifact_binding = _binding(root, Path(archive_path.name))
    coordinate["artifactDigest"] = artifact_binding["sha256"]
    operation_evidence = contract["operationEvidence"]  # type: ignore[index]
    operation_evidence["independentReproducibility"] = {
        **_binding(root, Path(summary_path.name)),
        "schema": protected.INDEPENDENT_SUMMARY_SCHEMA,
    }
    operation_evidence["independentReproducibilityArtifact"] = artifact_binding
    operation_evidence["independentReproducibilityCoordinate"] = coordinate
    return {**member_paths, "archive": archive_path}


def _rebind_independent_reproducibility_artifact(
    root: Path,
    contract: dict[str, object],
    members: dict[str, Path],
) -> None:
    archive_path = members["archive"]
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_STORED) as archive:
        for name, path in members.items():
            if name != "archive":
                archive.write(path, name)
    artifact_binding = _binding(root, Path(archive_path.name))
    operation_evidence = contract["operationEvidence"]  # type: ignore[index]
    operation_evidence["independentReproducibilityArtifact"] = artifact_binding
    operation_evidence["independentReproducibility"] = {
        **_binding(
            root,
            Path("stable-1.0-independent-reproducibility-summary.json"),
        ),
        "schema": protected.INDEPENDENT_SUMMARY_SCHEMA,
    }
    operation_evidence["independentReproducibilityCoordinate"][  # type: ignore[index]
        "artifactDigest"
    ] = artifact_binding["sha256"]
