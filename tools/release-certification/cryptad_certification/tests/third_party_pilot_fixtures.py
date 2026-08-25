"""Non-production fixture builder for external third-party pilot self-tests."""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import stat
import zipfile

from cryptad_certification.engines import stable_1_0_catalog_authority as authority
from cryptad_certification.engines import stable_1_0_third_party_pilot as pilot
from cryptad_certification.io import write_json


NOW = "2026-08-23T12:00:00Z"
VALID_FROM = "2026-08-22T00:00:00Z"
VALID_UNTIL = "2026-08-30T00:00:00Z"


def digest(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode()
    return "sha256:" + hashlib.sha256(value).hexdigest()


def seed(label: str) -> bytes:
    return hashlib.sha256(("pr-294-non-production-fixture:" + label).encode()).digest()


def keypair(label: str) -> tuple[bytes, bytes]:
    private_seed = seed(label)
    expanded = hashlib.sha512(private_seed).digest()
    scalar_bytes = bytearray(expanded[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")
    public = authority._encode_point(authority._scalarmult(authority._B, scalar))
    return private_seed, public


def sign(private_seed: bytes, public: bytes, message: bytes) -> bytes:
    expanded = hashlib.sha512(private_seed).digest()
    scalar_bytes = bytearray(expanded[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")
    nonce = int.from_bytes(hashlib.sha512(expanded[32:] + message).digest(), "little") % authority._L
    encoded_r = authority._encode_point(authority._scalarmult(authority._B, nonce))
    challenge = int.from_bytes(hashlib.sha512(encoded_r + public + message).digest(), "little") % authority._L
    encoded_s = ((nonce + challenge * scalar) % authority._L).to_bytes(32, "little")
    return encoded_r + encoded_s


def signature(private_seed: bytes, public: bytes, message: bytes) -> str:
    return base64.b64encode(sign(private_seed, public, message)).decode()


def spki(public: bytes) -> str:
    return base64.b64encode(authority.SPKI_PREFIX + public).decode()


def key(role: str, key_id: str) -> tuple[dict[str, object], bytes, bytes]:
    private_seed, public = keypair(key_id)
    encoded = authority.SPKI_PREFIX + public
    return (
        {
            "keyId": key_id,
            "role": role,
            "publicKeySpkiBase64": base64.b64encode(encoded).decode(),
            "fingerprint": digest(encoded),
            "lifecycle": "active",
            "validFrom": VALID_FROM,
            "validUntil": VALID_UNTIL,
        },
        private_seed,
        public,
    )


def zip_bytes(entries: dict[str, bytes], *, stored: bool = True) -> bytes:
    output = io.BytesIO()
    compression = zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED
    with zipfile.ZipFile(output, "w") as archive:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name)
            info.date_time = (1980, 1, 1, 0, 0, 0)
            info.create_system = 3
            info.extra = b"UT\x05\x00\x01\x00\x00\x00\x00"
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = compression
            archive.writestr(info, entries[name])
    return output.getvalue()


def bundle(app_id: str, version: str, publisher_id: str, publisher_seed: bytes, publisher_public: bytes, content: str) -> tuple[bytes, str, str]:
    manifest = (
        "manifest.version=1\n"
        f"app.id={app_id}\n"
        "app.name=External Pilot Fixture\n"
        f"app.version={version}\n"
        "app.exec=bin/run.sh\n"
        "app.ui.mode=static\n"
        "app.ui.entry=web/index.html\n"
        "api.minimumVersion=1\n"
        "api.maximumTestedVersion=1\n"
        "api.targetStability=stable\n"
        "api.experimentalCapabilitiesAccepted=false\n"
    ).encode()
    payload = {
        "bin/run.sh": b"#!/bin/sh\nexit 0\n",
        "cryptad-app.properties": manifest,
        "web/index.html": content.encode(),
    }
    digest_lines = ["digest.version=1", "digest.algorithm=SHA-256"]
    for index, name in enumerate(sorted(payload)):
        digest_lines.extend((f"file.{index}.path={name}", f"file.{index}.sha256={hashlib.sha256(payload[name]).hexdigest()}"))
    digest_bytes = ("\n".join(digest_lines) + "\n").encode()
    signature_bytes = (
        "signature.version=1\n"
        "signature.algorithm=Ed25519\n"
        f"signature.key.id={publisher_id}\n"
        "signature.payload=cryptad-app.digests\n"
        f"signature.value.base64={signature(publisher_seed, publisher_public, digest_bytes)}\n"
    ).encode()
    entries = {
        **payload,
        "cryptad-app.digests": digest_bytes,
        "cryptad-app.signature": signature_bytes,
    }
    return zip_bytes(entries), digest(signature_bytes), digest(manifest)


def submission(
    app_id: str,
    version: str,
    submission_id: str,
    submission_type: str,
    resubmission_of: str | None,
    publisher_id: str,
    bundle_bytes: bytes,
) -> bytes:
    with zipfile.ZipFile(io.BytesIO(bundle_bytes)) as archive:
        bundle_entries = {
            name: archive.read(name)
            for name in archive.namelist()
            if not name.endswith("/")
        }
    maintainer = {
        "name": "Fixture Developer",
        "contact": "https://external.example/contact",
    }
    source_reference = {
        "url": "https://code.external.example/outside/pilot-app",
        "revision": "b" * 40,
    }
    entries = {
        "artifacts/app-bundle.zip": bundle_bytes,
        "metadata/maintainer.json": (
            json.dumps(maintainer, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode(),
        "metadata/source.json": (
            json.dumps(source_reference, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode(),
        **{f"bundle/{name}": value for name, value in bundle_entries.items()},
    }
    redaction_subject = "".join(f"{name}\n" for name in sorted(entries)) + "redaction-scan-v1\n"
    metadata = {
        "schemaVersion": 1,
        "submissionId": submission_id,
        "submissionCreatedAt": NOW,
        "submissionType": submission_type,
        "appId": app_id,
        "appVersion": version,
        "bundleDigest": hashlib.sha256(bundle_bytes).hexdigest(),
        "bundleSignatureKeyId": publisher_id,
        "apiTargetStability": "stable",
        "experimentalCapabilitiesAccepted": False,
        "requestedPermissions": [],
        "sandboxRequirement": "none",
        "appDataSchemaDeclared": False,
        "appDataMigrationDeclared": False,
        "backupRestoreDeclared": False,
        "maintainer": maintainer,
        "sourceReference": source_reference,
        "redactionScanDigest": hashlib.sha256(redaction_subject.encode()).hexdigest(),
        "nonProduction": True,
    }
    if resubmission_of is not None:
        metadata["resubmissionOf"] = resubmission_of
    metadata_bytes = (json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n").encode()
    entries["crypta-app-submission.json"] = metadata_bytes
    return zip_bytes(entries)


def seal_receipt(value: dict[str, object], private_seed: bytes, public: bytes) -> None:
    value["receiptDigest"] = pilot._semantic_digest(value, "receiptDigest")
    value["signatureBase64"] = signature(private_seed, public, pilot._signature_subject(value))


def rechain_transparency(value: dict[str, object]) -> None:
    records = value["transparencyRecords"]
    previous = ""
    for sequence, record in enumerate(records, start=1):
        record["sequence"] = sequence
        record["previousRecordHash"] = previous
        record["recordHash"] = hashlib.sha256(
            pilot._transparency_canonical(record)
        ).hexdigest()
        previous = record["recordHash"]
    value["transparencyRecordCount"] = len(records)
    value["transparencyHead"] = "sha256:" + previous
    value["transparencyLogDigest"] = digest(pilot._transparency_jsonl(records))


def provenance(
    repository: str,
    workflow: str,
    run_id: int,
    artifact_name: str,
    *,
    workflow_commit: str = "a" * 40,
    environment: str = "stable-1-0-third-party-pilot-fixture",
) -> dict[str, object]:
    return {
        "repositoryIdentity": repository,
        "workflowPath": workflow,
        "workflowCommit": workflow_commit,
        "runId": run_id,
        "runAttempt": 1,
        "artifactName": artifact_name,
        "artifactDigest": digest("artifact:" + artifact_name),
        "environment": environment,
        "conclusion": "success",
    }


class PilotFixture:
    """Build one complete fixture cohort in a caller-owned directory."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.evidence = root / "evidence"
        self.evidence.mkdir(parents=True)
        self.material: dict[str, tuple[bytes, bytes]] = {}
        authorities = []
        for role, key_id in (
            ("catalog-signing", "catalog-fixture-294"),
            ("first-party-app-signing", "first-party-app-fixture-294"),
            ("app-reviewer", "reviewer-fixture-294"),
            ("offline-recovery", "recovery-fixture-294"),
        ):
            value, private_seed, public = key(role, key_id)
            authorities.append(value)
            self.material[role] = (private_seed, public)
        protected_release_root_digest = digest("pr291-root")
        product_distribution_digest = digest("pr291-product-distribution")
        independent_reproducibility_digest = digest("pr292-root")
        keyset_subject = {
            "schemaVersion": 1,
            "kind": "stable-1.0-public-keyset-subject",
            "keysetVersion": 1,
            "previousKeysetDigest": None,
            "ceremony": {
                "ceremonyId": "catalog-authority-fixture-294",
                "ceremonyType": "genesis",
                "releaseMilestone": "Stable 1.0",
                "preparedAt": VALID_FROM,
                "effectiveAt": VALID_FROM,
                "custodyClass": "fixture-memory-only",
                "approvalQuorum": {
                    "requiredApprovals": 1,
                    "approvalRole": "fixture-reviewer",
                    "protectedEnvironment": "fixture-only",
                },
            },
            "release": {
                "releaseId": "stable-1.0-fixture",
                "buildVersion": 294,
                "sourceCommit": "a" * 40,
                "sourceRef": "refs/heads/release/294",
            },
            "bindings": {
                "protectedReleaseSummaryDigest": digest("pr291-summary"),
                "protectedReleaseContractDigest": protected_release_root_digest,
                "protectedReleaseLifecycleState": "publicly-observed",
                "independentReproducibilitySummaryDigest": independent_reproducibility_digest,
                "independentReproducibilityResultDigest": digest("pr292-result"),
                "independentSubjectInventoryDigest": digest("pr292-subject-inventory"),
                "independentReproducibilityOperational": True,
                "providerIndependent": True,
            },
            "keys": sorted(
                (
                    {
                        "keyId": item["keyId"],
                        "role": item["role"],
                        "algorithm": "Ed25519",
                        "publicKeySpkiBase64": item["publicKeySpkiBase64"],
                        "publicKeyFingerprintSha256": item["fingerprint"],
                        "lifecycle": item["lifecycle"],
                        "validFrom": item["validFrom"],
                        "validUntil": item["validUntil"],
                        "predecessorKeyId": None,
                        "successorKeyId": None,
                        "compromiseState": "uncompromised",
                        "publicTransparencyEligible": True,
                    }
                    for item in authorities
                ),
                key=lambda item: item["keyId"],
            ),
        }
        publisher_seed, publisher_public = keypair("external-publisher-fixture-294")
        workload_seed, workload_public = keypair("external-workload-fixture-294")
        node_seed, node_public = keypair("pilot-node-fixture-294")
        self.material.update({
            "publisher": (publisher_seed, publisher_public),
            "workload": (workload_seed, workload_public),
            "node": (node_seed, node_public),
        })
        app_id = "org.external.fixturepilot"
        publisher_spki = authority.SPKI_PREFIX + publisher_public
        workload_spki = authority.SPKI_PREFIX + workload_public
        source = {
            "repositoryIdentity": "code.external.example/outside/pilot-app",
            "host": "code.external.example",
            "owner": "outside",
            "name": "pilot-app",
            "revisionType": "git-commit-sha1",
            "revision": "b" * 40,
            "archiveDigest": digest("external-source-archive"),
            "treeDigest": digest("external-source-tree"),
        }
        profile = {
            "profileId": "fixture-profile-294",
            "profileType": "fixture",
            "providerId": "external-ci",
            "organizationId": "outside",
            "accountId": "fixture-account-294",
            "issuer": "https://ci.external.example",
            "audience": "cryptad-third-party-pilot",
            "subject": "repo:outside/pilot-app:fixture",
            "pipelineDefinition": "outside/pilot-app/workflows/build.yml",
            "pipelineRevision": source["revision"],
            "workloadPublicKeySpkiBase64": spki(workload_public),
            "workloadFingerprint": digest(workload_spki),
            "operationalAllowed": False,
            "approvedAt": VALID_FROM,
            "expiresAt": VALID_UNTIL,
            "approvalReviewerKeyId": "reviewer-fixture-294",
            "approvalSignatureBase64": "A" * 86 + "==",
        }
        cohort_specs = (
            ("version-1-reviewed", "1.0.0", "submission-v1-fixture", "new_app", None, "reviewed", "first"),
            ("version-2-rejected", "2.0.0", "submission-v2-rejected-fixture", "update", None, "rejected", "unsafe-initial"),
            ("version-2-corrected", "2.0.0", "submission-v2-corrected-fixture", "resubmission", "submission-v2-rejected-fixture", "reviewed", "corrected"),
            ("version-3-caution", "3.0.0", "submission-v3-caution-fixture", "update", None, "caution", "caution"),
        )
        cohort = []
        artifacts = []
        for cohort_id, version, submission_id, submission_type, previous, decision, content in cohort_specs:
            bundle_bytes, signature_digest, manifest_digest = bundle(app_id, version, "external-publisher-fixture-294", publisher_seed, publisher_public, content)
            submission_bytes = submission(app_id, version, submission_id, submission_type, previous, "external-publisher-fixture-294", bundle_bytes)
            bundle_name = f"{cohort_id}-bundle.zip"
            submission_name = f"{cohort_id}-submission.zip"
            (self.evidence / bundle_name).write_bytes(bundle_bytes)
            (self.evidence / submission_name).write_bytes(submission_bytes)
            row = {
                "cohortId": cohort_id,
                "appVersion": version,
                "submissionId": submission_id,
                "submissionType": submission_type,
                "resubmissionOf": previous,
                "expectedDecision": decision,
                "submissionDigest": digest(submission_bytes),
                "bundleDigest": digest(bundle_bytes),
                "bundleSignatureDigest": signature_digest,
                "preReviewDigest": digest("pre-review:" + submission_id),
            }
            cohort.append(row)
            artifacts.append((row, bundle_name, len(bundle_bytes), submission_name, len(submission_bytes), manifest_digest))
        self.contract: dict[str, object] = {
            "schemaVersion": 1,
            "kind": "stable-1.0-third-party-app-pilot-execution",
            "pilotId": "pilot-fixture-294",
            "repository": {"identity": "github.com/crypta-network/cryptad", "sourceCommit": "a" * 40},
            "release": {
                "releaseId": "stable-1.0-fixture",
                "buildVersion": 294,
                "productDistributionDigest": product_distribution_digest,
            },
            "evaluationTime": NOW,
            "requestedState": "planned",
            "fixtureOnly": True,
            "selfTest": True,
            "authorities": {
                "protectedReleaseRootDigest": protected_release_root_digest,
                "independentReproducibilityDigest": independent_reproducibility_digest,
                "catalogAuthorityDigest": digest("pr293-root"),
                "keysetDigest": digest(pilot._canonical_bytes(keyset_subject)),
                "keysetSubject": keyset_subject,
                "catalogChannel": "beta",
                "keys": authorities,
            },
            "externalApp": {
                "appId": app_id,
                "publisherKeyId": "external-publisher-fixture-294",
                "publisherPublicKeySpkiBase64": spki(publisher_public),
                "publisherFingerprint": digest(publisher_spki),
                "source": source,
                "workloadProfile": profile,
            },
            "cohort": cohort,
            "protectedPilotNode": {
                "nodeId": "isolated-pilot-node-fixture-294",
                "normalStableRegistryDigest": digest("normal-stable-registry"),
                "catalogRegistryDigest": pilot._catalog_registry_digest(
                    keyset_subject
                ),
                "pilotRegistryDigest": digest("ephemeral-pilot-registry"),
            },
            "evidence": {
                name: None
                for name in (
                    "protectedRelease",
                    "independentReproducibility",
                    "selectedRcFreeze",
                    "catalogAuthority",
                    "externalHandoff",
                    "reviewCohort",
                    "publisherApproval",
                    "catalogPublication",
                    "collectorSummary",
                    "runtimeDrill",
                )
            },
        }
        reviewer_seed, reviewer_public = self.material["app-reviewer"]
        profile["approvalSignatureBase64"] = signature(reviewer_seed, reviewer_public, pilot._profile_subject(self.contract))
        handoff = self._handoff(artifacts)
        review = self._review(handoff)
        approval = self._approval(handoff, node_public)
        publication = self._publication(review)
        collector = self._collector(publication)
        collector_name = "live-network-beta-smoke-summary.json"
        collector_path = self.evidence / collector_name
        write_json(collector_path, collector)
        collector_provenance = provenance(
            "github.com/crypta-network/cryptad",
            ".github/workflows/stable-1.0-third-party-app-pilot.yml",
            2943,
            "pilot-runtime-fixture-294",
        )
        self.contract["evidence"]["collectorSummary"] = {
            "fileName": collector_name,
            "digest": digest(collector_path.read_bytes()),
            "size": collector_path.stat().st_size,
            "schema": pilot.COLLECTOR_SCHEMA,
            "provenance": collector_provenance,
        }
        runtime = self._runtime(
            review,
            approval,
            publication,
            self.contract["evidence"]["collectorSummary"],
            node_seed,
            node_public,
        )
        for field, name, schema, value in (
            ("externalHandoff", "external-handoff.json", pilot.HANDOFF_SCHEMA, handoff),
            ("reviewCohort", "review-cohort.json", pilot.REVIEW_SCHEMA, review),
            ("publisherApproval", "publisher-approval.json", pilot.APPROVAL_SCHEMA, approval),
            ("catalogPublication", "catalog-publication.json", pilot.PUBLICATION_SCHEMA, publication),
            ("runtimeDrill", "runtime-drill.json", pilot.RUNTIME_SCHEMA, runtime),
        ):
            path = self.evidence / name
            write_json(path, value)
            self.contract["evidence"][field] = {
                "fileName": name,
                "digest": digest(path.read_bytes()),
                "size": path.stat().st_size,
                "schema": schema,
                "provenance": value["provenance"],
            }
        self.contract_path = root / "execution.json"
        write_json(self.contract_path, self.contract)

    def _handoff(self, artifacts: list[tuple[dict[str, object], str, int, str, int, str]]) -> dict[str, object]:
        app = self.contract["externalApp"]
        profile = app["workloadProfile"]
        rows = []
        publisher_seed, publisher_public = self.material["publisher"]
        for row, bundle_name, bundle_size, submission_name, submission_size, manifest_digest in artifacts:
            attestation = {
                "domain": "cryptad.stable-1.0.external-third-party-app-pilot.developer-attestation.v1",
                "schemaVersion": 1,
                "pilotId": self.contract["pilotId"],
                "appId": app["appId"],
                "appVersion": row["appVersion"],
                "submissionId": row["submissionId"],
                "submissionType": row["submissionType"],
                "resubmissionOf": row["resubmissionOf"],
                "sourceRepositoryIdentity": app["source"]["repositoryIdentity"],
                "sourceRevision": app["source"]["revision"],
                "sourceArchiveDigest": app["source"]["archiveDigest"],
                "sourceTreeDigest": app["source"]["treeDigest"],
                "buildProviderId": profile["providerId"],
                "buildWorkflow": profile["pipelineDefinition"],
                "buildRunId": "294",
                "bundleDigest": row["bundleDigest"],
                "bundleSignatureDigest": row["bundleSignatureDigest"],
                "publisherKeyId": app["publisherKeyId"],
                "publisherFingerprint": app["publisherFingerprint"],
                "submissionDigest": row["submissionDigest"],
                "manifestDigest": manifest_digest,
                "createdAt": NOW,
                "effectiveAt": NOW,
                "expiresAt": VALID_UNTIL,
            }
            subject = attestation["domain"].encode() + b"\x00" + pilot._canonical_bytes(attestation)
            rows.append({
                "cohortId": row["cohortId"],
                "submissionFile": submission_name,
                "submissionDigest": row["submissionDigest"],
                "submissionSize": submission_size,
                "bundleFile": bundle_name,
                "bundleDigest": row["bundleDigest"],
                "bundleSize": bundle_size,
                "bundleSignatureDigest": row["bundleSignatureDigest"],
                "attestation": attestation,
                "attestationSignatureBase64": signature(publisher_seed, publisher_public, subject),
            })
        source = app["source"]
        handoff = {
            "schemaVersion": 1,
            "kind": "stable-1.0-external-developer-handoff",
            "pilotId": self.contract["pilotId"],
            "appId": app["appId"],
            "evidenceClassification": "fixture",
            "provenance": provenance(
                app["source"]["repositoryIdentity"],
                profile["pipelineDefinition"],
                294,
                "external-handoff-fixture-294",
                workflow_commit=profile["pipelineRevision"],
            ),
            "source": {name: source[name] for name in ("repositoryIdentity", "revision", "archiveDigest", "treeDigest")},
            "workload": {
                **{name: profile[name] for name in ("profileId", "providerId", "organizationId", "accountId", "issuer", "audience", "subject", "pipelineDefinition", "pipelineRevision")},
                "runId": "294",
                "attestationDigest": pilot.ZERO_DIGEST,
                "signatureBase64": "A" * 86 + "==",
                "verifiedAt": NOW,
            },
            "publisherKeyId": app["publisherKeyId"],
            "publisherFingerprint": app["publisherFingerprint"],
            "cohort": rows,
            "handoffDigest": pilot.ZERO_DIGEST,
        }
        workload_seed, workload_public = self.material["workload"]
        workload_subject = pilot._workload_subject(self.contract, handoff)
        handoff["workload"]["attestationDigest"] = digest(workload_subject)
        handoff["workload"]["signatureBase64"] = signature(workload_seed, workload_public, workload_subject)
        handoff["handoffDigest"] = pilot._semantic_digest(handoff, "handoffDigest")
        return handoff

    def _review(self, handoff: dict[str, object]) -> dict[str, object]:
        reviewer = next(key for key in self.contract["authorities"]["keys"] if key["role"] == "app-reviewer")
        reviewer_seed, reviewer_public = self.material["app-reviewer"]
        handoff_rows = {row["cohortId"]: row for row in handoff["cohort"]}
        rows = []
        for row in self.contract["cohort"]:
            caution = row["cohortId"] == "version-3-caution"
            decision_digest = digest("decision:" + row["submissionId"])
            standard_receipt = None
            standard_digest = None
            if row["expectedDecision"] in {"reviewed", "caution"}:
                standard_receipt = {
                    "version": 2,
                    "appId": self.contract["externalApp"]["appId"],
                    "appVersion": row["appVersion"],
                    "artifactSha256": row["bundleDigest"].removeprefix("sha256:"),
                    "artifactSizeBytes": handoff_rows[row["cohortId"]]["bundleSize"],
                    "bundleKeyId": self.contract["externalApp"]["publisherKeyId"],
                    "policyId": "third-party-pilot-review-v1",
                    "policyVersion": "1",
                    "status": row["expectedDecision"],
                    "reviewerKeyId": reviewer["keyId"],
                    "reviewedAt": NOW,
                    "expiresAt": None,
                    "evidenceSha256": row["preReviewDigest"].removeprefix("sha256:"),
                    "decisionReasonSha256": decision_digest.removeprefix("sha256:"),
                    "evidenceUri": None,
                    "note": "manual-review-warning" if caution else None,
                    "signatureAlgorithm": "Ed25519",
                    "signatureBase64": "A" * 86 + "==",
                }
                standard_receipt["signatureBase64"] = signature(
                    reviewer_seed,
                    reviewer_public,
                    pilot._standard_review_receipt_payload(standard_receipt),
                )
                standard_digest = digest(
                    pilot._standard_review_receipt_bytes(standard_receipt)
                )
            negative = row["expectedDecision"] in {"rejected", "resubmission_requested"}
            rows.append({
                "cohortId": row["cohortId"],
                "submissionId": row["submissionId"],
                "submissionDigest": row["submissionDigest"],
                "bundleDigest": row["bundleDigest"],
                "bundleSignatureDigest": row["bundleSignatureDigest"],
                "preReviewDigest": row["preReviewDigest"],
                "decision": row["expectedDecision"],
                "decisionRecordDigest": decision_digest,
                "standardReviewReceipt": standard_receipt,
                "standardReviewReceiptDigest": standard_digest,
                "resubmissionOf": row["resubmissionOf"],
                "candidateEligible": not negative,
                "cautionWarnings": ["manual-review-warning"] if caution else [],
                "cautionAllowance": caution,
            })
        assignment_digest = digest("assignment")
        transparency_records = []
        previous = ""
        for row, review_row in zip(self.contract["cohort"], rows, strict=True):
            event_kinds = [
                (
                    "submission_resubmitted"
                    if row["submissionType"] == "resubmission"
                    else "submission_created"
                ),
                "reviewer_assigned",
                "pre_review_completed",
                "review_decision_recorded",
            ]
            if row["expectedDecision"] in {"reviewed", "caution"}:
                event_kinds.append("review_receipt_issued")
            elif row["expectedDecision"] == "rejected":
                event_kinds.append("submission_rejected")
            for kind in event_kinds:
                assignment_event = kind == "reviewer_assigned"
                pre_review_event = kind == "pre_review_completed"
                decision_event = kind == "review_decision_recorded"
                authority_event = kind in {
                    "review_decision_recorded",
                    "review_receipt_issued",
                    "submission_rejected",
                }
                sequence = len(transparency_records) + 1
                status = (
                    row["expectedDecision"]
                    if authority_event
                    and row["expectedDecision"] != "resubmission_requested"
                    else None
                )
                evidence_digest = row["submissionDigest"]
                warnings = []
                if assignment_event:
                    evidence_digest = assignment_digest
                    warnings = [
                        "assignmentReasonSha256="
                        + assignment_digest.removeprefix("sha256:")
                    ]
                elif pre_review_event:
                    evidence_digest = row["preReviewDigest"]
                    warnings = ["preReviewStatus=pass"]
                elif decision_event:
                    evidence_digest = review_row["decisionRecordDigest"]
                    warnings = [
                        "decision=" + row["expectedDecision"],
                        "preReviewSha256="
                        + row["preReviewDigest"].removeprefix("sha256:"),
                    ]
                elif kind == "review_receipt_issued":
                    evidence_digest = review_row["standardReviewReceiptDigest"]
                    warnings = [
                        "receiptFingerprint="
                        + review_row["standardReviewReceiptDigest"].removeprefix(
                            "sha256:"
                        )
                    ]
                elif kind == "submission_rejected":
                    evidence_digest = review_row["decisionRecordDigest"]
                    warnings = ["decision=rejected"]
                record = {
                    "schemaVersion": 1,
                    "sequence": sequence,
                    "recordId": f"{row['submissionId']}:{kind}",
                    "createdAt": NOW,
                    "kind": kind,
                    "subjectType": "submission",
                    "appId": self.contract["externalApp"]["appId"],
                    "appVersion": row["appVersion"],
                    "catalogId": row["submissionId"],
                    "artifactSha256": row["bundleDigest"].removeprefix("sha256:"),
                    "artifactSizeBytes": handoff_rows[row["cohortId"]]["bundleSize"],
                    "reviewerKeyId": (
                        reviewer["keyId"]
                        if assignment_event or authority_event
                        else None
                    ),
                    "reviewerKeyStatus": None,
                    "policyId": "third-party-pilot-review-v1" if authority_event else None,
                    "policyVersion": "1" if authority_event else None,
                    "receiptStatus": status,
                    "trustStatus": None,
                    "trusted": None,
                    "positive": (
                        status == "reviewed" if authority_event and status else None
                    ),
                    "requiresAcknowledgement": None,
                    "blocksInstall": None,
                    "blocksUpdate": None,
                    "blocksPolicyApply": None,
                    "evidenceSha256": evidence_digest.removeprefix("sha256:"),
                    "evidenceUri": None,
                    "previousRecordHash": previous,
                    "recordHash": "0" * 64,
                    "warnings": warnings,
                }
                record["recordHash"] = hashlib.sha256(
                    pilot._transparency_canonical(record)
                ).hexdigest()
                previous = record["recordHash"]
                transparency_records.append(record)
        value = {
            "schemaVersion": 1,
            "kind": "stable-1.0-third-party-review-cohort",
            "pilotId": self.contract["pilotId"],
            "appId": self.contract["externalApp"]["appId"],
            "provenance": provenance(
                "github.com/crypta-network/cryptad",
                ".github/workflows/stable-1.0-third-party-app-pilot.yml",
                2941,
                "pilot-review-fixture-294",
            ),
            "reviewerKeyId": reviewer["keyId"],
            "reviewerFingerprint": reviewer["fingerprint"],
            "policyId": "third-party-pilot-review-v1",
            "policyVersion": "1",
            "assignmentDigest": assignment_digest,
            "transparencyLogDigest": digest(
                pilot._transparency_jsonl(transparency_records)
            ),
            "transparencyRecordCount": len(transparency_records),
            "transparencyHead": "sha256:" + previous,
            "transparencyRecords": transparency_records,
            "rows": rows,
            "reviewedAt": NOW,
            "expiresAt": VALID_UNTIL,
            "receiptDigest": pilot.ZERO_DIGEST,
            "signatureBase64": "A" * 86 + "==",
        }
        seal_receipt(value, *self.material["app-reviewer"])
        return value

    def _approval(self, handoff: dict[str, object], node_public: bytes) -> dict[str, object]:
        app = self.contract["externalApp"]
        node = self.contract["protectedPilotNode"]
        by_id = {row["cohortId"]: row for row in self.contract["cohort"]}
        value = {
            "schemaVersion": 1,
            "kind": "stable-1.0-pilot-publisher-key-approval",
            "pilotId": self.contract["pilotId"],
            "appId": app["appId"],
            "provenance": provenance(
                "github.com/crypta-network/cryptad",
                ".github/workflows/stable-1.0-third-party-app-pilot.yml",
                2942,
                "pilot-publisher-approval-fixture-294",
            ),
            "publisherKeyId": app["publisherKeyId"],
            "publisherFingerprint": app["publisherFingerprint"],
            "sourceRepositoryIdentity": app["source"]["repositoryIdentity"],
            "handoffDigest": handoff["handoffDigest"],
            "pilotNodeId": node["nodeId"],
            "nodeAttestationFingerprint": digest(authority.SPKI_PREFIX + node_public),
            "normalStableRegistryDigest": node["normalStableRegistryDigest"],
            "catalogRegistryDigest": node["catalogRegistryDigest"],
            "pilotRegistryDigest": node["pilotRegistryDigest"],
            "permittedSubjects": [
                {"version": by_id[item]["appVersion"], "bundleDigest": by_id[item]["bundleDigest"], "bundleSignatureDigest": by_id[item]["bundleSignatureDigest"]}
                for item in ("version-1-reviewed", "version-2-corrected", "version-3-caution")
            ],
            "allowedOperations": ["install", "update", "caution-update", "rollback", "cleanup"],
            "validFrom": VALID_FROM,
            "validUntil": VALID_UNTIL,
            "revoked": False,
            "cleanupRequired": True,
            "approvalAuthorityKeyId": "reviewer-fixture-294",
            "receiptDigest": pilot.ZERO_DIGEST,
            "signatureBase64": "A" * 86 + "==",
        }
        seal_receipt(value, *self.material["app-reviewer"])
        return value

    def _publication(self, review: dict[str, object]) -> dict[str, object]:
        app = self.contract["externalApp"]
        contract_rows = {row["cohortId"]: row for row in self.contract["cohort"]}
        review_rows = {row["cohortId"]: row for row in review["rows"]}
        editions = []
        for number, cohort_id in enumerate(("version-1-reviewed", "version-2-corrected", "version-3-caution"), start=1):
            row = contract_rows[cohort_id]
            reviewed = review_rows[cohort_id]
            edition = {
                "catalogRevision": number,
                "catalogEdition": number,
                "version": row["appVersion"],
                "bundleDigest": row["bundleDigest"],
                "bundleSignatureDigest": row["bundleSignatureDigest"],
                "publisherKeyId": app["publisherKeyId"],
                "publisherFingerprint": app["publisherFingerprint"],
                "submissionDigest": row["submissionDigest"],
                "reviewReceiptDigest": reviewed["standardReviewReceiptDigest"],
                "decision": reviewed["decision"],
                "cautionWarnings": reviewed["cautionWarnings"],
                "acknowledgementRequired": cohort_id == "version-3-caution",
                "entryDigest": pilot.ZERO_DIGEST,
                "subjectDigest": digest(f"beta-catalog-subject-{number}"),
                "signatureSiblingDigest": digest(
                    f"beta-catalog-signature-{number}"
                ),
            }
            edition["entryDigest"] = digest(
                pilot._canonical_bytes(
                    {
                        name: edition[name]
                        for name in edition
                        if name
                        not in {
                            "entryDigest",
                            "subjectDigest",
                            "signatureSiblingDigest",
                        }
                    }
                )
            )
            editions.append(edition)
        catalog_key = next(key for key in self.contract["authorities"]["keys"] if key["role"] == "catalog-signing")
        subject = editions[-1]["subjectDigest"]
        sibling = editions[-1]["signatureSiblingDigest"]
        value = {
            "schemaVersion": 1,
            "kind": "stable-1.0-third-party-beta-catalog-publication",
            "pilotId": self.contract["pilotId"],
            "appId": app["appId"],
            "provenance": provenance(
                "github.com/crypta-network/cryptad",
                ".github/workflows/stable-1.0-catalog-authority.yml",
                2931,
                "pilot-beta-publication-fixture-294",
            ),
            "channel": "beta",
            "catalogId": "crypta-beta-pilot",
            "catalogSigningKeyId": catalog_key["keyId"],
            "catalogSigningKeyFingerprint": catalog_key["fingerprint"],
            "keysetDigest": self.contract["authorities"]["keysetDigest"],
            "catalogAuthorityDigest": self.contract["authorities"]["catalogAuthorityDigest"],
            "editions": editions,
            "publishedSubject": {
                "catalogRevision": editions[-1]["catalogRevision"],
                "catalogEdition": editions[-1]["catalogEdition"],
                "entryDigests": [edition["entryDigest"] for edition in editions],
                "subjectDigest": subject,
                "signatureSiblingDigest": sibling,
            },
            "observations": [
                {"locationId": "primary", "locationType": "primary", "controlPlaneId": "primary-control", "subjectDigest": subject, "signatureSiblingDigest": sibling, "observedAt": NOW, "status": "pass"},
                {"locationId": "mirror-a", "locationType": "mirror", "controlPlaneId": "mirror-control", "subjectDigest": subject, "signatureSiblingDigest": sibling, "observedAt": NOW, "status": "pass"},
            ],
            "status": "pass",
            "partial": False,
            "publishedAt": NOW,
            "receiptDigest": pilot.ZERO_DIGEST,
            "signatureBase64": "A" * 86 + "==",
        }
        seal_receipt(value, *self.material["catalog-signing"])
        return value

    def _collector(self, publication: dict[str, object]) -> dict[str, object]:
        required_ids = (
            "live-network-beta.preflight",
            "live-network-beta.catalog-usk-fetch",
            "live-network-beta.app-install-update-rollback",
            "live-network-beta.content-fetch",
            "live-network-beta.feed-subscription",
            "live-network-beta.profile-publish",
            "live-network-beta.trust-statement-publish-import",
            "live-network-beta.interop-perf-budget",
            "live-network-beta.redaction",
        )
        all_ids = (*required_ids[:-2], "live-network-beta.app-service-score", *required_ids[-2:])
        evidence = []
        for evidence_id in all_ids:
            details: dict[str, object] = {}
            if evidence_id == "live-network-beta.app-install-update-rollback":
                details = {
                    "appId": self.contract["externalApp"]["appId"],
                    "catalogId": publication["catalogId"],
                    "preExistingInstall": False,
                    "preExistingRunning": False,
                    "preExistingStoppedStartedBySmoke": False,
                    "installedByThisRun": True,
                    "cleanupSucceeded": True,
                }
            evidence.append(
                {
                    "id": evidence_id,
                    "status": "pass" if evidence_id in required_ids else "skip",
                    "requiredForReleaseCandidate": evidence_id in required_ids,
                    "summary": "Non-production collector fixture result.",
                    "source": "live-network-beta-smoke",
                    "details": details,
                }
            )
        return {
            "schemaVersion": 1,
            "kind": "live-network-beta-smoke",
            "mode": "release-candidate",
            "enabled": True,
            "required": True,
            "status": "pass",
            "startedAt": NOW,
            "finishedAt": NOW,
            "durationMs": 0,
            "node": {
                "baseUrlShape": "http://localhost:<port>",
                "localhostOnly": True,
                "version": "redacted-or-safe",
                "build": "redacted-or-safe",
            },
            "fixturePresence": {
                "catalogSource": True,
                "contentFetchUri": True,
                "feedUskUri": True,
                "privateInsertFixture": True,
                "privateInsertFixtureSource": "file-indirection",
                "profilePublicUri": True,
                "trustPublicUri": True,
            },
            "stepCounts": {
                "total": len(evidence),
                "passed": len(required_ids),
                "failed": 0,
                "warnings": 0,
                "skipped": 1,
            },
            "artifactPaths": ["summary.json", "live-network-beta-smoke-report.md"],
            "evidence": evidence,
            "redaction": {
                "status": "pass",
                "forbiddenPatternsChecked": True,
                "rawBodiesStored": False,
                "privateInsertUrisStored": False,
                "localPathsStored": False,
            },
        }

    def _runtime(
        self,
        review: dict[str, object],
        approval: dict[str, object],
        publication: dict[str, object],
        collector_binding: dict[str, object],
        node_seed: bytes,
        node_public: bytes,
    ) -> dict[str, object]:
        rows = {row["cohortId"]: row for row in self.contract["cohort"]}
        warnings = next(row["cautionWarnings"] for row in review["rows"] if row["cohortId"] == "version-3-caution")
        consent = digest("consent-snapshot")
        permission = digest("permissions")

        def event(sequence: int, name: str, status: str = "pass", row: dict[str, object] | None = None, review_status: str | None = None, *, catalog_edition: dict[str, object] | None = None, consent_digest: str | None = None, warning_codes: list[str] | None = None) -> dict[str, object]:
            return {
                "sequence": sequence,
                "event": name,
                "status": status,
                "version": row["appVersion"] if row else None,
                "bundleDigest": row["bundleDigest"] if row else None,
                "publisherKeyId": self.contract["externalApp"]["publisherKeyId"] if row else None,
                "reviewStatus": review_status,
                "catalogRevision": catalog_edition["catalogRevision"] if catalog_edition else None,
                "catalogEdition": catalog_edition["catalogEdition"] if catalog_edition else None,
                "catalogEntryDigest": catalog_edition["entryDigest"] if catalog_edition else None,
                "catalogSubjectDigest": catalog_edition["subjectDigest"] if catalog_edition else None,
                "catalogSignatureSiblingDigest": catalog_edition["signatureSiblingDigest"] if catalog_edition else None,
                "consentSnapshotDigest": consent_digest,
                "warningCodes": warning_codes or [],
                "sandboxStatus": "pass" if row and not catalog_edition else None,
                "permissionsDigest": permission if row and not catalog_edition else None,
                "appDataBoundaryStatus": "pass" if row and not catalog_edition else None,
            }

        editions = publication["editions"]
        events = [
            event(1, "pilot-registry-installed"),
            event(2, "beta-catalog-refreshed", row=rows["version-1-reviewed"], review_status="reviewed", catalog_edition=editions[0]),
            event(3, "reviewed-v1-installed", row=rows["version-1-reviewed"], review_status="reviewed"),
            event(4, "rejected-v2-absent", "blocked-as-required", rows["version-2-rejected"], "rejected"),
            event(5, "corrected-v2-catalog-refreshed", row=rows["version-2-corrected"], review_status="reviewed", catalog_edition=editions[1]),
            event(6, "corrected-v2-updated", row=rows["version-2-corrected"], review_status="reviewed"),
            event(7, "caution-v3-catalog-refreshed", row=rows["version-3-caution"], review_status="caution", catalog_edition=editions[2], warning_codes=warnings),
            event(8, "caution-v3-blocked-without-acknowledgement", "blocked-as-required", rows["version-3-caution"], "caution", warning_codes=warnings),
            event(9, "caution-v3-consent-recorded", row=rows["version-3-caution"], review_status="caution", consent_digest=consent, warning_codes=warnings),
            event(10, "caution-v3-updated", row=rows["version-3-caution"], review_status="caution", consent_digest=consent, warning_codes=warnings),
            event(11, "corrected-v2-rollback", row=rows["version-2-corrected"], review_status="reviewed"),
            event(12, "app-removed-or-restored"),
            event(13, "catalog-removed-or-restored"),
            event(14, "pilot-registry-removed-or-quarantined"),
        ]
        value = {
            "schemaVersion": 1,
            "kind": "stable-1.0-third-party-runtime-drill",
            "pilotId": self.contract["pilotId"],
            "appId": self.contract["externalApp"]["appId"],
            "provenance": provenance(
                "github.com/crypta-network/cryptad",
                pilot.RUNTIME_PRODUCER_WORKFLOW,
                2943,
                "pilot-runtime-fixture-294",
                environment=pilot.RUNTIME_PRODUCER_ENVIRONMENT,
            ),
            "pilotNodeId": self.contract["protectedPilotNode"]["nodeId"],
            "daemonIdentity": {
                "identitySource": "managed-daemon-product-attestation-v1",
                "releaseId": self.contract["release"]["releaseId"],
                "buildVersion": self.contract["release"]["buildVersion"],
                "sourceCommit": self.contract["repository"]["sourceCommit"],
                "protectedReleaseRootDigest": self.contract["authorities"][
                    "protectedReleaseRootDigest"
                ],
                "productDistributionDigest": self.contract["release"][
                    "productDistributionDigest"
                ],
                "managedDaemon": True,
                "appHostVerificationPolicy": "stable-1.0-pilot-publisher-v1",
                "observedAt": NOW,
            },
            "publisherApprovalDigest": approval["receiptDigest"],
            "catalogPublicationDigest": publication["receiptDigest"],
            "collector": {
                "kind": "live-network-beta-smoke",
                "summaryFileName": collector_binding["fileName"],
                "summaryDigest": collector_binding["digest"],
                "summarySize": collector_binding["size"],
                "transportReused": True,
                "localhostOnly": True,
                "redirectsDisabled": True,
                "status": "pass",
                "redactionStatus": "pass",
            },
            "normalStableRegistryInitiallyExcludedPublisher": True,
            "normalStableRegistryDigest": self.contract["protectedPilotNode"][
                "normalStableRegistryDigest"
            ],
            "catalogRegistryDigest": self.contract["protectedPilotNode"][
                "catalogRegistryDigest"
            ],
            "pilotRegistryDigest": self.contract["protectedPilotNode"]["pilotRegistryDigest"],
            "preexistingApp": False,
            "preexistingCatalog": False,
            "events": events,
            "finalVersion": rows["version-2-corrected"]["appVersion"],
            "finalBundleDigest": rows["version-2-corrected"]["bundleDigest"],
            "finalPublisherKeyId": self.contract["externalApp"]["publisherKeyId"],
            "rollbackExact": True,
            "appCleanupStatus": "pass",
            "catalogCleanupStatus": "pass",
            "registryCleanupStatus": "pass",
            "cleanStateRestored": True,
            "status": "pass",
            "partial": False,
            "completedAt": NOW,
            "nodeAttestationPublicKeySpkiBase64": spki(node_public),
            "nodeAttestationFingerprint": digest(authority.SPKI_PREFIX + node_public),
            "receiptDigest": pilot.ZERO_DIGEST,
            "signatureBase64": "A" * 86 + "==",
        }
        seal_receipt(value, node_seed, node_public)
        return value

    def reload_contract(self) -> None:
        write_json(self.contract_path, self.contract)

    def load_evidence(self, field: str) -> dict[str, object]:
        return json.loads((self.evidence / self.contract["evidence"][field]["fileName"]).read_text())

    def replace_evidence(self, field: str, value: dict[str, object]) -> None:
        binding = self.contract["evidence"][field]
        path = self.evidence / binding["fileName"]
        write_json(path, value)
        binding["digest"] = digest(path.read_bytes())
        binding["size"] = path.stat().st_size
        self.reload_contract()

    def clone(self) -> dict[str, object]:
        return copy.deepcopy(self.contract)
