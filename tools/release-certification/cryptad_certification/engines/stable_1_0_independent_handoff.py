"""Prepare and contract-bind the primary handoff consumed by PR-292."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import zipfile
from pathlib import Path
from typing import Any

from cryptad_certification.io import read_json, write_json
from cryptad_certification.schema_validation import validate_schema

from .stable_1_0_supply_chain_core import semantic_digest

PRIMARY_RECEIPT = "stable-1.0-primary-builder-receipt.json"
PRIMARY_AUTHORITY = "stable-1.0-primary-authority-attestation.json"
PRIMARY_BUNDLE = "stable-1.0-primary-subject-bundle.zip"
PRIMARY_GITHUB_EVIDENCE = (
    "stable-1.0-primary-github-attestation-bundle-and-verification-results.json"
)
PRIMARY_TRANSCRIPT = "stable-1.0-primary-attestation-verification-transcript.json"
AUTHORITY_SCHEMA = "stable-1.0-independent-authority-attestation-v1.schema.json"
RECEIPT_SCHEMA = "stable-1.0-builder-receipt-v1.schema.json"

INPUT_FILES = {
    "buildMaterials": "stable-1.0-build-materials.json",
    "resolvedDependencySnapshot": "stable-1.0-resolved-dependency-snapshot.json",
    "componentInventory": "stable-1.0-component-inventory.json",
    "releaseSubjectInventory": "stable-1.0-release-subject-inventory.json",
    "sbomBinding": "stable-1.0-sbom-binding.json",
}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _value_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _regular(path: Path, root: Path, label: str) -> Path:
    resolved_root = root.resolve(strict=True)
    resolved = path.resolve(strict=True)
    resolved.relative_to(resolved_root)
    metadata = resolved.stat()
    if path.is_symlink() or not resolved.is_file() or metadata.st_nlink != 1:
        raise ValueError(f"{label} is not one confined regular file")
    return resolved


def _write_stored_bundle(path: Path, members: dict[str, Path]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for member_name in sorted(members):
            info = zipfile.ZipInfo(member_name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, members[member_name].read_bytes())


def stage_primary_handoff(
    workspace: Path,
    manifest_path: Path,
    original_root: Path,
    output_root: Path,
    subject_bundle: Path,
    source_ref: str,
) -> None:
    """Stage authenticated primary inputs without creating a contract-bound assertion."""

    workspace = workspace.resolve(strict=True)
    original_root = original_root.resolve(strict=True)
    producer = (original_root / "producer").resolve(strict=True)
    authentication = (original_root / "authentication").resolve(strict=True)
    manifest = read_json(_regular(manifest_path, workspace, "comparison manifest"))
    if not isinstance(manifest, dict):
        raise ValueError("comparison manifest is not an object")
    output_root.mkdir(parents=True, mode=0o700)
    subject_bundle.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    resolved_bundle = subject_bundle.resolve()
    resolved_bundle.relative_to(workspace)
    try:
        resolved_bundle.relative_to(output_root.resolve())
    except ValueError:
        pass
    else:
        raise ValueError("primary subject bundle must be outside the bounded comparison handoff")
    input_root = output_root / "authenticated-inputs"
    input_root.mkdir(mode=0o700)
    for key, file_name in INPUT_FILES.items():
        configured = manifest.get("inputs", {}).get(key)
        if not isinstance(configured, str):
            raise ValueError(f"authenticated comparison manifest omits {key}")
        shutil.copyfile(
            _regular(workspace / configured, workspace, key), input_root / file_name
        )

    receipt_source = _regular(
        original_root / "derived-producer-builder-receipt.json",
        original_root,
        "derived producer receipt",
    )
    receipt_path = output_root / PRIMARY_RECEIPT
    shutil.copyfile(receipt_source, receipt_path)
    receipt = read_json(receipt_path)
    if not isinstance(receipt, dict):
        raise ValueError("derived producer receipt is not an object")

    github_source = _regular(
        authentication / "producer-attestations.json",
        authentication,
        "producer GitHub attestation bundle and verification results",
    )
    github_path = output_root / PRIMARY_GITHUB_EVIDENCE
    shutil.copyfile(github_source, github_path)
    if _file_digest(github_path) != receipt["builderIdentity"][
        "artifactAttestationDigest"
    ]:
        raise ValueError("producer receipt does not bind its GitHub attestation evidence")

    members: dict[str, Path] = {}
    for row in receipt["subjects"]:
        key = row["subjectKey"]
        subject = _regular(
            producer / "subjects" / row["fileName"],
            producer / "subjects",
            f"producer subject {key}",
        )
        if _file_digest(subject) != row["digest"] or subject.stat().st_size != row["size"]:
            raise ValueError(f"producer subject binding differs for {key}")
        members[f"subjects/{row['fileName']}"] = subject
        if row.get("payloadManifestDigest") is not None:
            payload = _regular(
                producer / "payload-manifests" / f"{key}.json",
                producer / "payload-manifests",
                f"producer payload manifest {key}",
            )
            payload_value = read_json(payload)
            if not isinstance(payload_value, dict) or semantic_digest(
                payload_value, "manifestDigest"
            ) != row["payloadManifestDigest"]:
                raise ValueError(f"producer payload manifest binding differs for {key}")
            if payload_value.get("publishedSubjectDigest") != row["digest"]:
                raise ValueError(f"producer payload manifest binds different package bytes for {key}")
            members[f"payload-manifests/{key}.json"] = payload
    _write_stored_bundle(resolved_bundle, members)

    github_evidence = read_json(github_path)
    if not isinstance(github_evidence, list) or not github_evidence:
        raise ValueError("producer GitHub attestation evidence is not a non-empty result set")
    try:
        statements = [row["verificationResult"]["statement"] for row in github_evidence]
    except (KeyError, TypeError) as exc:
        raise ValueError("producer GitHub attestation evidence omits a signed statement") from exc
    statement_digest = _value_digest(statements)
    subject_set = sorted(
        (
            {"name": row["fileName"], "digest": row["digest"], "size": row["size"]}
            for row in receipt["subjects"]
        ),
        key=lambda row: row["name"],
    )
    transcript = {
        "schemaVersion": 1,
        "kind": "stable-1.0-primary-attestation-verification-transcript",
        "verificationMechanism": "github-artifact-attestations",
        "verificationStatus": "verified",
        "repository": "crypta-network/cryptad",
        "pipelineDefinition": receipt["builderIdentity"]["workflowRef"],
        "sourceCommit": receipt["sourceCommit"],
        "sourceRef": source_ref,
        "runId": str(receipt["builderIdentity"]["runId"]),
        "runAttempt": receipt["builderIdentity"]["runAttempt"],
        "bundleAndVerificationResultsDigest": _file_digest(github_path),
        "statementDigest": statement_digest,
        "subjectSetDigest": _value_digest(subject_set),
        "selfHostedRunnerDenied": True,
    }
    write_json(output_root / PRIMARY_TRANSCRIPT, transcript)


def _binding(path: Path, workspace: Path, schema: str | None) -> dict[str, object]:
    return {
        "path": path.relative_to(workspace).as_posix(),
        "sha256": _file_digest(path),
        "schema": schema,
        "size": path.stat().st_size,
    }


def bind_primary_authority(
    workspace: Path,
    contract_path: Path,
    primary_root: Path,
    workflow_path: Path,
) -> None:
    """Create the primary wrapper from authenticated handoff facts and one exact contract."""

    workspace = workspace.resolve(strict=True)
    contract = read_json(_regular(contract_path, workspace, "execution contract"))
    primary_root = primary_root.resolve(strict=True)
    receipt_path = _regular(primary_root / PRIMARY_RECEIPT, primary_root, "primary receipt")
    github_path = _regular(
        primary_root / PRIMARY_GITHUB_EVIDENCE, primary_root, "primary GitHub evidence"
    )
    transcript_path = _regular(
        primary_root / PRIMARY_TRANSCRIPT, primary_root, "primary verification transcript"
    )
    receipt = read_json(receipt_path)
    transcript = read_json(transcript_path)
    if not isinstance(contract, dict) or not isinstance(receipt, dict) or not isinstance(
        transcript, dict
    ):
        raise ValueError("primary authority inputs are malformed")
    if _file_digest(github_path) != receipt["builderIdentity"][
        "artifactAttestationDigest"
    ]:
        raise ValueError("primary GitHub evidence differs from the producer receipt")

    policy = read_json(
        workspace
        / "tools/release-certification/stable-1.0-independent-reproducibility-policy.json"
    )
    profile = next(
        row
        for row in policy["providerProfiles"]
        if row["profileId"] == "github-actions-cryptad-producer-v1"
    )
    adapter = next(
        row for row in policy["attestationAdapters"] if row["adapterId"] == profile["adapterId"]
    )
    pipeline_definition = receipt["builderIdentity"]["workflowRef"]
    source_ref = transcript["sourceRef"]
    workload_subject = "repo:crypta-network/cryptad:ref:" + source_ref
    trust_roots = _value_digest(
        {
            "issuer": profile["issuer"],
            "mechanism": adapter["verificationMechanism"],
            "trustRootMode": adapter["trustRootMode"],
        }
    )
    authority_identity = {
        "providerType": profile["providerType"],
        "providerId": profile["providerId"],
        "controlPlaneId": profile["controlPlaneId"],
        "trustDomainId": profile["trustDomainId"],
        "organizationId": profile["organizationId"],
        "accountId": profile["accountId"],
        "projectId": profile["projectId"],
        "executorControllerId": "github.com/actions/hosted-runners",
        "executorOwnership": "provider-hosted",
        "authorityIdentityDigest": "sha256:" + "0" * 64,
    }
    authority_identity["authorityIdentityDigest"] = semantic_digest(
        authority_identity, "authorityIdentityDigest"
    )
    pipeline_identity = {
        "definitionId": pipeline_definition,
        "immutableRevision": _file_digest(workflow_path),
        "revisionType": profile["pipelineRevisionType"],
        "runId": str(receipt["builderIdentity"]["runId"]),
        "runAttempt": receipt["builderIdentity"]["runAttempt"],
        "jobId": receipt["builderIdentity"]["jobName"],
        "stageId": "cross-platform-builder-handoff",
        "eventType": "workflow_dispatch",
        "pipelineIdentityDigest": "sha256:" + "0" * 64,
    }
    pipeline_identity["pipelineIdentityDigest"] = semantic_digest(
        pipeline_identity, "pipelineIdentityDigest"
    )
    images = sorted(
        (
            row["runnerOs"],
            row["runnerArchitecture"],
            row["runnerImageIdentity"],
            row["runnerImageDigest"],
        )
        for row in receipt["builderExecutions"]
    )
    executor_identity = {
        "runnerOs": "mixed-platform-partitions",
        "runnerArchitecture": "mixed",
        "runnerImageIdentity": "github-hosted-mixed-platform-partitions",
        "runnerImageDigest": _value_digest(images),
        "runnerImageDigestType": "hosted-runner-release-identity-sha256",
        "executorPoolId": "github.com/actions/hosted-runners",
        "selfHosted": False,
        "executorIdentityDigest": "sha256:" + "0" * 64,
    }
    executor_identity["executorIdentityDigest"] = semantic_digest(
        executor_identity, "executorIdentityDigest"
    )
    producer = {
        "workloadSubject": workload_subject,
        "softwareName": "cryptad-release-certification",
        "softwareVersion": "pr-292-v1",
        "softwareDigest": _file_digest(Path(__file__)),
        "receiptProducerIdentityDigest": "sha256:" + "0" * 64,
    }
    producer["receiptProducerIdentityDigest"] = semantic_digest(
        producer, "receiptProducerIdentityDigest"
    )
    claims = {
        "issuer": profile["issuer"],
        "audiences": profile["audiences"],
        "subject": workload_subject,
        "pipelineDefinition": pipeline_definition,
        "sourceCommit": receipt["sourceCommit"],
    }
    attestation: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": "stable-1.0-independent-authority-attestation",
        "releaseId": contract["release"]["id"],
        "buildVersion": contract["release"]["integerBuild"],
        "tag": contract["release"]["tag"],
        "sourceCommit": contract["repository"]["sourceCommit"],
        "executionContractDigest": contract["executionContractDigest"],
        "verifierKitDigest": None,
        "independentReproducibilityPolicyDigest": policy["policyDigest"],
        "providerProfileId": profile["profileId"],
        "providerProfileDigest": profile["profileDigest"],
        "builderRole": "candidate-producer",
        "authorityIdentity": authority_identity,
        "pipelineIdentity": pipeline_identity,
        "workloadIdentity": {
            "mechanism": "sigstore-keyless",
            "issuer": profile["issuer"],
            "subject": workload_subject,
            "audiences": profile["audiences"],
            "certificateIdentity": pipeline_definition,
            "issuedAt": receipt["buildStartedAt"],
            "expiresAt": receipt["buildCompletedAt"],
            "trustRootSetDigest": trust_roots,
            "claimsDigest": _value_digest(claims),
        },
        "executorIdentity": executor_identity,
        "artifactAttestation": {
            "format": adapter["attestationFormat"],
            "predicateType": adapter["predicateType"],
            "bundleDigest": _file_digest(github_path),
            "statementDigest": transcript["statementDigest"],
            "subjectSetDigest": transcript["subjectSetDigest"],
            "adapterId": adapter["adapterId"],
            "adapterDigest": adapter["adapterDigest"],
            "trustRootSetDigest": trust_roots,
            "transparencyLogEntryDigest": None,
            "verificationTranscriptDigest": _file_digest(transcript_path),
            "verificationStatus": "verified",
            "verifiedAt": receipt["buildCompletedAt"],
        },
        "rawArtifactAttestationBundle": _binding(github_path, workspace, None),
        "verificationTranscript": _binding(transcript_path, workspace, None),
        "receiptProducer": producer,
        "builderReceipt": _binding(receipt_path, workspace, RECEIPT_SCHEMA),
        "outputManifest": None,
        "outputBundle": None,
        "buildStartedAt": receipt["buildStartedAt"],
        "buildCompletedAt": receipt["buildCompletedAt"],
        "outputsSealedAt": receipt["buildCompletedAt"],
        "candidateProductAvailableBeforeBuild": False,
        "evidenceClassification": "protected-same-provider",
        "operational": False,
        "attestationDigest": "sha256:" + "0" * 64,
    }
    attestation["attestationDigest"] = semantic_digest(attestation, "attestationDigest")
    errors = validate_schema(attestation, AUTHORITY_SCHEMA)
    if errors:
        raise ValueError(f"generated primary authority attestation is invalid: {errors[0]}")
    destination = primary_root / PRIMARY_AUTHORITY
    binding = contract["comparison"]["primaryAuthorityAttestation"]
    write_json(destination, attestation)
    if (
        binding["path"] != destination.relative_to(workspace).as_posix()
        or binding["sha256"] != _file_digest(destination)
        or binding["size"] != destination.stat().st_size
        or binding["schema"] != AUTHORITY_SCHEMA
    ):
        raise ValueError("generated primary authority attestation differs from the contract")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)
    stage = subparsers.add_parser("stage-primary")
    stage.add_argument("--workspace", type=Path, default=Path("."))
    stage.add_argument("--manifest", type=Path, required=True)
    stage.add_argument("--original-root", type=Path, required=True)
    stage.add_argument("--output-root", type=Path, required=True)
    stage.add_argument("--subject-bundle", type=Path, required=True)
    stage.add_argument("--source-ref", required=True)
    bind = subparsers.add_parser("bind-primary-authority")
    bind.add_argument("--workspace", type=Path, default=Path("."))
    bind.add_argument("--contract", type=Path, required=True)
    bind.add_argument("--primary-root", type=Path, required=True)
    bind.add_argument("--workflow", type=Path, required=True)
    arguments = parser.parse_args(argv)
    if arguments.mode == "stage-primary":
        stage_primary_handoff(
            arguments.workspace,
            arguments.manifest,
            arguments.original_root,
            arguments.output_root,
            arguments.subject_bundle,
            arguments.source_ref,
        )
    else:
        bind_primary_authority(
            arguments.workspace,
            arguments.contract,
            arguments.primary_root,
            arguments.workflow,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
