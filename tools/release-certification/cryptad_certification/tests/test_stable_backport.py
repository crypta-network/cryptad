"""End-to-end and policy tests for Stable 1.0 release-train governance."""

from __future__ import annotations

import copy
import datetime as dt
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from cryptad_certification.io import read_json, write_json
from cryptad_certification.models import (
    OutputSpec,
    ReleaseSpec,
    RunContext,
    RunManifest,
)
from cryptad_certification.schema_validation import validate_schema
from cryptad_certification.stable_backport_git import GitInspector

from ..engines import stable_1_0_backport as engine
from ..engines.stable_1_0_backport_core import (
    AUTHORIZATION_SCHEMA,
    CLASSIFICATIONS,
    DISPOSITIONS,
    FIX_STATES,
    PROVENANCE_MODES,
    build_queue,
    canonical_identity_digest,
    file_digest,
    fix_record_errors,
    intake_errors,
    phase_intake_composition_digest,
    permitted_carried_obligation_ids,
    policy_errors,
    public_phase_evolution_errors,
    queue_identity_digest,
    semantic_digest,
)

FIX_ID = "stable-fix-abcdefghijklmnop"
NOW = dt.datetime(2026, 1, 15, 12, tzinfo=dt.timezone.utc)
GENERATED = "2026-01-15T12:00:00Z"
EVIDENCE_GENERATED = "2026-01-15T11:00:00Z"
EVIDENCE_EXPIRES = "2026-01-16T12:00:00Z"
PASS_REDACTION = {"status": "pass", "findingCount": 0, "findings": []}
BACKPORT_POLICY = (
    Path(__file__).resolve().parents[2]
    / "stable-1.0-backport-release-train-policy.json"
)
EXAMPLE_MANIFEST = (
    Path(__file__).resolve().parents[2]
    / "manifests"
    / "stable-1.0-backport.example.json"
)
PHASE_HANDOFF_SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "protected"
    / "stable_backport_phase_handoff.py"
)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


QUEUE_BINDING_PLACEHOLDER = _digest("0")


def _git(root: Path, *arguments: str) -> str:
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_AUTHOR_NAME": "Cryptad Test",
        "GIT_AUTHOR_EMAIL": "cryptad-test@example.invalid",
        "GIT_COMMITTER_NAME": "Cryptad Test",
        "GIT_COMMITTER_EMAIL": "cryptad-test@example.invalid",
        "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
        "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
    }
    return subprocess.run(
        ("git", *arguments),
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _commit(root: Path, relative: str, content: str, message: str) -> str:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    _git(root, "add", "--", relative)
    _git(root, "commit", "-m", message)
    return _git(root, "rev-parse", "HEAD")


def _policy(root: Path) -> tuple[Path, dict, str]:
    destination = (
        root
        / "tools"
        / "release-certification"
        / "stable-1.0-backport-release-train-policy.json"
    )
    destination.parent.mkdir(parents=True)
    shutil.copyfile(BACKPORT_POLICY, destination)
    value = read_json(destination)
    return destination, value, file_digest(destination)


def _transition_rows() -> list[dict]:
    states = ("submitted", "triaged", "accepted", "scheduled", "landed", "verified")
    rows = []
    prior = None
    for sequence, state in enumerate(states):
        rows.append(
            {
                "sequence": sequence,
                "from": prior,
                "to": state,
                "occurredAt": f"2026-01-{sequence + 1:02d}T00:00:00Z",
                "actorRole": "stable-triage-manager",
                "reasonCode": "policy-eligible",
                "evidenceDigest": _digest(str(sequence + 1)),
            }
        )
        prior = state
    return rows


def _evidence(
    predecessor: str,
    candidate: str,
    evidence_id: str,
    character: str,
) -> dict:
    return {
        "evidenceId": evidence_id,
        "digest": _digest(character),
        "policyDigest": file_digest(BACKPORT_POLICY),
        "queueDigest": QUEUE_BINDING_PLACEHOLDER,
        "generatedAt": EVIDENCE_GENERATED,
        "expiresAt": EVIDENCE_EXPIRES,
        "predecessorCommit": predecessor,
        "candidateCommit": candidate,
        "visibility": (
            "protected"
            if evidence_id
            in {
                "stable-backport.security-incident-scope",
                "stable-backport.clean-cherry-pick-review",
                "stable-backport.manual-conflict-review",
                "stable-backport.release-train-authorization",
                "stable-backport.post-release-reconciliation",
            }
            else "public"
        ),
    }


def _fix(
    inspector: GitInspector,
    source_commit: str,
    candidate_commit: str,
    *,
    classification: str = "compatible-bug-fix",
) -> dict:
    authorization_digest = _digest("a")
    actual = inspector.verify_inherited(
        source_commit, candidate_commit, authorization_digest
    )
    provenance = engine._provenance_dict(  # noqa: SLF001
        actual, "routine-release-candidate"
    )
    evidence_ids = {
        "compatible-bug-fix": (
            "stable-backport.affected-component-scope",
            "stable-backport.candidate-bound-tests",
            "stable-backport.compatibility",
        ),
        "platform-api-compatible-addition": (
            "stable-backport.platform-api-compatibility-window",
            "stable-backport.platform-api-stable-samples",
            "stable-backport.candidate-bound-tests",
        ),
        "platform-api-deprecation": (
            "stable-backport.platform-api-original-deprecation-clock",
            "stable-backport.platform-api-supported-consumer-coverage",
            "stable-backport.public-developer-guidance",
        ),
        "documentation-support-fix": (
            "stable-backport.docs-behavior-match",
            "stable-backport.public-support-redaction",
        ),
        "security-fix": (
            "stable-backport.security-incident-scope",
            "stable-backport.security-public-projection",
            "stable-backport.candidate-bound-tests",
        ),
        "stable-catalog-app-patch": (
            "stable-backport.catalog-app-compatibility",
            "stable-backport.catalog-app-review",
            "stable-backport.catalog-app-permission-delta",
            "stable-backport.app-data-migration",
            "stable-backport.app-data-backup-restore",
            "stable-backport.catalog-app-signing",
        ),
        "packaging-installer-fix": (
            "stable-backport.affected-package-keys",
            "stable-backport.exact-package-verification",
            "stable-backport.package-matrix",
        ),
        "release-tooling-fix": (
            "stable-backport.release-tooling-byte-truth",
            "stable-backport.release-authority-preservation",
            "stable-backport.tooling-security-boundaries",
        ),
    }[classification]
    predecessor_commit = inspector.inspect_commit(source_commit).parents[0]
    affected_scope = {
        "components": ["node-core"],
        "packageKeys": (
            ["linux-x86_64-deb"]
            if classification == "packaging-installer-fix"
            else []
        ),
        "appIds": (
            ["trust-graph"]
            if classification == "stable-catalog-app-patch"
            else []
        ),
        "platformApiIds": (
            ["platform.api.status"]
            if classification.startswith("platform-api-")
            else []
        ),
        "contentProfileIds": [],
        "dataSchemaIds": [],
        "affectedBuilds": ["300"],
    }
    value = {
        "schemaVersion": 1,
        "kind": "stable-1.0-fix-record",
        "stableMilestone": "1.0",
        "fixId": FIX_ID,
        "publicTitle": "Correct bounded request handling",
        "publicSummary": "Corrects request handling without changing stable formats.",
        "classification": classification,
        "disposition": "routine-maintenance",
        "releaseLane": "routine-maintenance",
        "severity": "moderate",
        "risk": "low",
        "affectedScope": affected_scope,
        "source": {
            "repositoryIdentity": "github.com/crypta-network/cryptad",
            "objectFormat": inspector.object_format,
            "sourceCommit": source_commit,
            "sourceBranchRole": "canonical-development",
        },
        "provenance": provenance,
        "security": None,
        "ownership": {
            "ownerRole": "stable-fix-owner",
            "reviewerRole": "stable-fix-reviewer",
            "authorizationDigest": authorization_digest,
        },
        "schedule": {
            "submittedAt": "2026-01-01T00:00:00Z",
            "decisionAt": "2026-01-03T00:00:00Z",
            "deadlineAt": "2026-02-01T00:00:00Z",
            "targetTrainId": "stable-train-301",
            "reviewAt": None,
            "rationale": "Eligible for the next authenticated maintenance successor.",
        },
        "evidence": [
            _evidence(
                predecessor_commit,
                candidate_commit,
                evidence_id,
                str(index + 1),
            )
            for index, evidence_id in enumerate(evidence_ids)
        ],
        "state": "verified",
        "stateTransitions": _transition_rows(),
        "supersedingFixId": None,
        "privateRecordDigest": None,
    }
    value["publicProjectionDigest"] = semantic_digest(
        {
            "fixId": value["fixId"],
            "classification": value["classification"],
            "publicSummary": value["publicSummary"],
        }
    )
    return value


def _security_fix(
    inspector: GitInspector,
    source_commit: str,
    candidate_commit: str,
    *,
    severity: str = "critical",
) -> dict:
    value = _fix(
        inspector,
        source_commit,
        candidate_commit,
        classification="security-fix",
    )
    value["disposition"] = (
        "security-hotfix" if severity == "critical" else "routine-maintenance"
    )
    value["releaseLane"] = value["disposition"]
    value["severity"] = severity
    private_digest = _digest("e")
    security = {
        "incidentOpaqueId": "incident-opaque-287",
        "advisoryOpaqueId": "advisory-opaque-287",
        "severity": severity,
        "disclosureState": "protected-embargoed",
        "publicSafeSummary": "A bounded security correction is available.",
        "privateRecordDigest": private_digest,
    }
    security["publicProjectionDigest"] = semantic_digest(
        {
            "fixId": value["fixId"],
            "incidentOpaqueId": security["incidentOpaqueId"],
            "advisoryOpaqueId": security["advisoryOpaqueId"],
            "severity": security["severity"],
            "disclosureState": security["disclosureState"],
            "publicSafeSummary": security["publicSafeSummary"],
        }
    )
    value["security"] = security
    value["privateRecordDigest"] = private_digest
    for sequence, transition in enumerate(value["stateTransitions"]):
        transition["occurredAt"] = (
            NOW + dt.timedelta(hours=sequence * 2 - 12)
        ).isoformat().replace("+00:00", "Z")
    value["schedule"]["submittedAt"] = value["stateTransitions"][0]["occurredAt"]
    value["schedule"]["decisionAt"] = value["stateTransitions"][2]["occurredAt"]
    predecessor = value["evidence"][0]["predecessorCommit"]
    value["evidence"].append(
        _evidence(
            predecessor,
            candidate_commit,
            "stable-backport.critical-operational-coverage",
            "f",
        )
    )
    return value


def _intake(policy_digest: str, fix: dict) -> dict:
    value = {
        "schemaVersion": 1,
        "kind": "stable-1.0-fix-intake",
        "generatedAt": GENERATED,
        "stableMilestone": "1.0",
        "policyDigest": policy_digest,
        "repositoryIdentity": "github.com/crypta-network/cryptad",
        "intakeId": "stable-intake-abcdefghijklmnop",
        "previousQueueDigest": None,
        "fixes": [fix],
        "obligations": [],
        "publicProjectionDigest": semantic_digest(
            {"fixIds": [fix["fixId"]], "obligations": []}
        ),
        "redaction": PASS_REDACTION,
    }
    value["intakeDigest"] = canonical_identity_digest(value, "intakeDigest")
    _bind_intake_evidence(
        value,
        None,
        policy_digest=policy_digest,
        candidate_commit=str(fix["provenance"]["candidateCommit"]),
    )
    return value


def _review_authorization(fix: dict, policy_digest: str) -> dict:
    provenance = fix["provenance"]
    mode = provenance["mode"]
    evidence_id = (
        "stable-backport.clean-cherry-pick-review"
        if mode == "clean-cherry-pick"
        else "stable-backport.manual-conflict-review"
    )
    reviewer_role = (
        "stable-backport-cherry-pick-reviewer"
        if mode == "clean-cherry-pick"
        else "stable-backport-conflict-reviewer"
    )
    review_evidence = next(
        row for row in fix["evidence"] if row["evidenceId"] == evidence_id
    )
    row = {
        "authorizationId": "stable-backport-review-" + "a" * 32,
        "fixId": fix["fixId"],
        "provenanceMode": mode,
        "reviewerRole": reviewer_role,
        "repositoryIdentity": "github.com/crypta-network/cryptad",
        "policyDigest": policy_digest,
        "sourceCommit": fix["source"]["sourceCommit"],
        "predecessorCommit": review_evidence["predecessorCommit"],
        "candidateCommit": provenance["candidateCommit"],
        "normalizedDiffEvidenceDigest": provenance[
            "normalizedDiffEvidenceDigest"
        ],
        "pathInventoryDigest": semantic_digest(
            {
                "conflictPaths": sorted(provenance["conflictPaths"]),
                "touchedPaths": sorted(provenance["touchedPaths"]),
            }
        ),
        "focusedTestEvidenceIds": provenance["focusedTestEvidenceIds"],
        "reviewEvidenceId": evidence_id,
        "producer": {
            "workflowIdentity": (
                "crypta-network/cryptad/.github/workflows/"
                "stable-1.0-backport-review-authorization.yml@" + "a" * 40
            ),
            "workflowCommit": "a" * 40,
            "runId": "287",
            "runAttempt": "1",
            "environment": "stable-1.0-backport-review",
            "operation": "authorize-provenance-review",
            "artifactName": (
                f"stable-1.0-backport-review-{fix['fixId']}-"
                f"{'a' * 40}"
            ),
        },
        "issuedAt": "2026-01-15T11:30:00Z",
        "expiresAt": "2026-01-16T11:30:00Z",
        "producerAuthenticated": True,
    }
    row["authorizationDigest"] = canonical_identity_digest(
        row, "authorizationDigest"
    )
    provenance["reviewerAuthorizationDigest"] = row["authorizationDigest"]
    fix["ownership"]["reviewerRole"] = reviewer_role
    fix["ownership"]["authorizationDigest"] = row["authorizationDigest"]
    review_evidence["digest"] = row["authorizationDigest"]
    return row


def _review_authorization_set(
    root: Path,
    authorization: dict,
    policy_digest: str,
) -> tuple[Path, dict, str]:
    value = {
        "schemaVersion": 1,
        "kind": "stable-1.0-backport-review-authorizations",
        "generatedAt": authorization["issuedAt"],
        "stableMilestone": "1.0",
        "repositoryIdentity": "github.com/crypta-network/cryptad",
        "policyDigest": policy_digest,
        "authorizations": [authorization],
        "authenticatedArtifacts": [
            {
                "fixId": authorization["fixId"],
                "runId": authorization["producer"]["runId"],
                "artifactName": authorization["producer"]["artifactName"],
                "artifactDigest": _digest("f"),
                "sourceCommit": authorization["producer"]["workflowCommit"],
                "workflowRef": authorization["producer"]["workflowIdentity"],
            }
        ],
        "redaction": PASS_REDACTION,
    }
    value["authorizationSetDigest"] = canonical_identity_digest(
        value, "authorizationSetDigest"
    )
    path = root / "inputs" / "review-authorizations.json"
    write_json(path, value)
    return path, value, file_digest(path)


def _bind_intake_evidence(
    intake: dict,
    previous_queue: dict | None,
    *,
    policy_digest: str,
    candidate_commit: str,
    latest_pointer_digest: str = _digest("b"),
    lifecycle_ledger_digest: str = _digest("d"),
) -> str:
    """Bind every evidence row to the queue's normalized self-identity."""

    for fix in intake.get("fixes", []):
        if not isinstance(fix, dict):
            continue
        for evidence in fix.get("evidence", []):
            if isinstance(evidence, dict):
                evidence["policyDigest"] = policy_digest
                evidence["queueDigest"] = QUEUE_BINDING_PLACEHOLDER
    intake["intakeDigest"] = canonical_identity_digest(intake, "intakeDigest")
    queue, _errors = build_queue(
        intake,
        previous_queue,
        policy_digest=policy_digest,
        latest_maintenance_pointer_digest=latest_pointer_digest,
        lifecycle_ledger_digest=lifecycle_ledger_digest,
        repository_identity="github.com/crypta-network/cryptad",
        candidate_commit=candidate_commit,
    )
    queue_digest = queue_identity_digest(queue)
    for fix in intake.get("fixes", []):
        if not isinstance(fix, dict):
            continue
        for evidence in fix.get("evidence", []):
            if isinstance(evidence, dict):
                evidence["queueDigest"] = queue_digest
    intake["intakeDigest"] = canonical_identity_digest(intake, "intakeDigest")
    return queue_digest


def _authorization(fixture: "Fixture", output: Path) -> dict:
    prepare = read_json(output / "stable-1.0-release-train-validation.json")
    plan = read_json(output / "stable-1.0-backport-plan.json")
    queue = read_json(output / "stable-1.0-release-train-queue.json")
    value = {
        "schemaVersion": 1,
        "kind": "stable-1.0-release-train-authorization",
        "stableMilestone": "1.0",
        "trainId": "stable-train-301",
        "release": {
            "releaseId": "stable-maintenance-301",
            "releaseClass": "maintenance",
            "buildVersion": "301",
            "tag": "v301",
        },
        "repositoryIdentity": "github.com/crypta-network/cryptad",
        "workflowIdentity": (
            "github.com/crypta-network/cryptad/.github/workflows/"
            "stable-1.0-backport-release-train.yml@" + fixture.candidate
        ),
        "policyDigest": fixture.policy_digest,
        "queueDigest": queue["queueDigest"],
        "planDigest": plan["planDigest"],
        "validationDigest": prepare["validationDigest"],
        "predecessorCommit": fixture.predecessor,
        "candidateCommit": fixture.candidate,
        "acceptedFixes": prepare["publicFixes"],
        "securityOpaqueIds": [],
        "allowedOperation": "candidate-handoff",
        "role": "stable-maintenance-train-manager",
        "scope": ["train:composition", "candidate:handoff"],
        "issuedAt": GENERATED,
        "expiresAt": "2026-01-15T13:00:00Z",
        "decision": "go",
        "redaction": PASS_REDACTION,
    }
    value["authorizationDigest"] = canonical_identity_digest(
        value, "authorizationDigest"
    )
    return value


def _publication_receipt(
    candidate_commit: str,
    validation_file_digest: str,
    authorization_digest: str,
) -> dict:
    asset_digest = _digest("1")
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-maintenance-publication-receipt",
        "generatedAt": GENERATED,
        "releaseId": "stable-maintenance-301",
        "buildVersion": "301",
        "releaseClass": "maintenance",
        "sourceCommit": candidate_commit,
        "githubReleasePageUri": (
            "https://github.com/crypta-network/cryptad/releases/tag/v301"
        ),
        "deploymentServicePublicUri": "https://deployment.crypta.network/observe",
        "latestPointerPublicUri": (
            "https://updates.crypta.network/maintenance/latest.json"
        ),
        "candidateIdentityDigest": _digest("2"),
        "productDigest": _digest("3"),
        "checksumsDigest": _digest("4"),
        "provenanceDigest": _digest("5"),
        "authorizationDigest": authorization_digest,
        "backportReleaseTrainDigest": validation_file_digest,
        "publicationPlanDigest": _digest("6"),
        "releaseNotesDigest": _digest("7"),
        "coreInfoDigest": _digest("8"),
        "coreUpdateReceiptDigest": _digest("9"),
        "successorBaselineDigest": _digest("a"),
        "releaseHistoryDigest": _digest("b"),
        "tag": {
            "name": "v301",
            "objectType": "annotated",
            "targetCommit": candidate_commit,
            "tagObjectDigest": _digest("c"),
            "operation": "created",
            "verificationStatus": "verified",
        },
        "githubRelease": {
            "releaseId": "github-release-301",
            "tag": "v301",
            "pageUri": (
                "https://github.com/crypta-network/cryptad/releases/tag/v301"
            ),
            "notesDigest": _digest("7"),
            "operation": "created",
            "verificationStatus": "verified",
        },
        "assets": [
            {
                "role": "product",
                "fileName": "cryptad-301.tar.gz",
                "digest": asset_digest,
                "sizeBytes": 1,
                "publicUri": (
                    "https://downloads.crypta.network/stable/cryptad-301.tar.gz"
                ),
                "operation": "created",
                "verificationStatus": "verified",
            }
        ],
        "stableCatalog": {
            "catalogId": "crypta-first-party",
            "revision": 301,
            "edition": 301,
            "digest": _digest("d"),
            "signatureDigest": _digest("e"),
            "publicUri": "https://catalog.crypta.network/stable/catalog.json",
            "signaturePublicUri": (
                "https://catalog.crypta.network/stable/catalog.json.sig"
            ),
            "mirrorSetDigest": _digest("f"),
            "rollbackStateDigest": _digest("0"),
            "operation": "created",
            "verificationStatus": "verified",
        },
        "coreUpdate": {
            "edition": 301,
            "descriptorDigest": _digest("1"),
            "publicUri": "https://updates.crypta.network/info/301/core-info.json",
            "packageMapDigest": _digest("2"),
            "operation": "created",
            "verificationStatus": "verified",
        },
        "workflow": {
            "repository": "crypta-network/cryptad",
            "runId": 287,
            "runAttempt": 1,
            "environment": "stable-1.0-maintenance-publication",
            "actor": "release-manager-1",
            "attestationDigest": _digest("3"),
        },
        "publicObservations": {
            "tag": "verified",
            "githubRelease": "verified",
            "assets": "verified",
            "artifactBase": "verified",
            "stableCatalog": "verified",
            "coreUpdate": "verified",
        },
        "publicationState": "publication-complete",
        "finalVerificationStatus": "pass",
        "failureCategory": None,
        "redaction": PASS_REDACTION,
    }


def _completion_handoff(
    completion: dict,
    completion_file_digest: str,
    validation: dict,
    validation_file_digest: str,
) -> dict:
    workflow_commit = "a" * 40
    value = {
        "schemaVersion": 1,
        "kind": "stable-1.0-release-train-completion-handoff",
        "generatedAt": GENERATED,
        "stableMilestone": "1.0",
        "repositoryIdentity": "github.com/crypta-network/cryptad",
        "trainId": completion["trainId"],
        "candidateCommit": completion["publicationCommit"],
        "producer": {
            "workflowIdentity": (
                "crypta-network/cryptad/.github/workflows/"
                "stable-1.0-backport-release-train.yml@" + workflow_commit
            ),
            "workflowCommit": workflow_commit,
            "runId": "287",
            "runAttempt": "1",
            "operation": "verify-release-completion",
            "evidenceSource": "actions-artifact",
            "evidenceDigest": _digest("e"),
            "artifactName": (
                "stable-1.0-backport-verify-release-completion-"
                f"{completion['release']['releaseId']}-"
                f"{completion['release']['buildVersion']}"
            ),
        },
        "completionFileDigest": completion_file_digest,
        "completionDigest": completion["completionDigest"],
        "validationFileDigest": validation_file_digest,
        "validationDigest": validation["validationDigest"],
        "queueDigest": completion["queueDigest"],
        "observedProtectedRefs": {
            "main": {
                "ref": "refs/heads/main",
                "tip": completion["mainMerge"]["protectedTip"],
            },
            "develop": {
                "ref": "refs/heads/develop",
                "tip": completion["developMerge"]["protectedTip"],
            },
        },
        "producerAuthenticated": True,
        "redaction": PASS_REDACTION,
    }
    value["handoffDigest"] = canonical_identity_digest(
        value, "handoffDigest"
    )
    return value


class Fixture:
    def __init__(self, root: Path, *, extra_unaccounted_commit: bool = False) -> None:
        self.root = root = root.resolve(strict=True)
        _git(root, "init", "-b", "develop")
        (root / "build.gradle.kts").write_text(
            'version = "301"\n',
            encoding="utf-8",
        )
        _git(root, "add", "--", "build.gradle.kts")
        self.predecessor = _commit(root, "node.txt", "base\n", "base")
        self.fix_commit = _commit(root, "node.txt", "base\nfix\n", "fix")
        self.candidate = self.fix_commit
        if extra_unaccounted_commit:
            self.candidate = _commit(
                root, "unrelated.txt", "unrelated\n", "unrelated cleanup"
            )
        self.policy_path, self.policy, self.policy_digest = _policy(root)
        lifecycle_policy_source = (
            Path(__file__).resolve().parents[2]
            / "stable-1.0-support-lifecycle-policy.json"
        )
        self.lifecycle_policy_path = (
            root
            / "tools"
            / "release-certification"
            / "stable-1.0-support-lifecycle-policy.json"
        )
        shutil.copyfile(lifecycle_policy_source, self.lifecycle_policy_path)
        inspector = GitInspector(
            root,
            expected_repository_identity="github.com/crypta-network/cryptad",
        )
        self.intake = _intake(
            self.policy_digest,
            _fix(inspector, self.fix_commit, self.candidate),
        )
        inputs = root / "inputs"
        inputs.mkdir()
        write_json(inputs / "intake.json", self.intake)
        for name in ("receipt", "pointer", "ledger", "descriptor"):
            write_json(inputs / f"{name}.json", {})
        for name in (
            "lifecycle-authorization",
            "lifecycle-plan",
            "lifecycle-receipt",
        ):
            write_json(inputs / f"{name}.json", {})
        write_json(
            inputs / "lifecycle-observation.json",
            {"generatedAt": GENERATED},
        )
        write_json(
            inputs / "baseline.json",
            {"kind": "stable-1.0-maintenance-baseline"},
        )
        self.current_context = self._context("evaluate")

    def write_intake(self, previous_queue: dict | None = None) -> None:
        _bind_intake_evidence(
            self.intake,
            previous_queue,
            policy_digest=self.policy_digest,
            candidate_commit=self.candidate,
        )
        write_json(self.root / "inputs" / "intake.json", self.intake)

    def _context(self, mode: str) -> RunContext:
        root = self.root
        inputs = {
            "stableBackportPolicy": self.policy_path.relative_to(root).as_posix(),
            "stableFixIntake": "inputs/intake.json",
            "predecessorPublicationReceipt": "inputs/receipt.json",
            "predecessorBaseline": "inputs/baseline.json",
            "latestPublishedMaintenancePointer": "inputs/pointer.json",
            "stableLifecyclePolicy": self.lifecycle_policy_path.relative_to(
                root
            ).as_posix(),
            "previousStableLifecycleLedger": "inputs/ledger.json",
            "previousStableLifecycleDescriptor": "inputs/descriptor.json",
            "previousStableLifecycleAuthorization": (
                "inputs/lifecycle-authorization.json"
            ),
            "previousStableLifecyclePublicationPlan": (
                "inputs/lifecycle-plan.json"
            ),
            "previousStableLifecyclePublicationReceipt": (
                "inputs/lifecycle-receipt.json"
            ),
            "stableLifecyclePublicObservationReceipt": (
                "inputs/lifecycle-observation.json"
            ),
        }
        manifest = RunManifest(
            path=root / "manifest.json",
            release=ReleaseSpec("stable-maintenance-301", "301", "stable-review"),
            output=OutputSpec(root / "out"),
            requirements={},
            inputs=inputs,
            policies={
                "releaseClass": "maintenance",
                "backportReleaseLane": "routine-maintenance",
                "candidateSourceBranch": "release/301",
                "candidateSourceCommit": self.candidate,
                "candidateSourceRef": f"commit:{self.candidate}",
                "candidateBaseCommit": self.predecessor,
                "developmentLineageCommit": self.predecessor,
                "expectedPredecessorBuild": "300",
            },
            execution={},
            commands={"stable-backport": {"mode": mode}},
        )
        return RunContext(
            workspace_root=root,
            run_root=root / "out" / "stable-maintenance-301",
            component="stable-backport",
            manifest=manifest,
        )

    def context(self, mode: str) -> RunContext:
        self.current_context = self._context(mode)
        return self.current_context


class StableBackportEngineTest(unittest.TestCase):
    def _run_context(
        self,
        fixture: Fixture,
        context: RunContext,
        *,
        lifecycle_observed_at: dt.datetime = NOW,
    ) -> tuple[int, Path]:
        (context.component_dir / "artifacts").mkdir(parents=True, exist_ok=True)
        with mock.patch.object(engine, "_now", return_value=NOW), mock.patch.object(
            engine,
            "_authenticate_predecessor",
            return_value=(
                fixture.predecessor,
                "300",
                _digest("b"),
                _digest("c"),
            ),
        ), mock.patch.object(
            engine,
            "_authenticate_lifecycle",
            return_value=(_digest("d"), {"300": "current-stable"}),
        ), mock.patch.object(
            engine,
            "_authenticate_lifecycle_authority",
            return_value=lifecycle_observed_at,
        ):
            code, summary, _report = engine.run(context)
        return code, summary.parent

    def _run(self, fixture: Fixture, mode: str = "evaluate") -> tuple[int, Path]:
        return self._run_context(fixture, fixture.context(mode))

    def test_evaluate_emits_deterministic_canonical_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            code, output = self._run(fixture)

            self.assertEqual(code, 0)
            expected = {
                "stable-1.0-fix-intake.json",
                "stable-1.0-backport-plan.json",
                "stable-1.0-backport-lineage.json",
                "stable-1.0-release-train-queue.json",
                "stable-1.0-release-train-queue-public.json",
                "stable-1.0-release-train-candidate.json",
                "stable-1.0-release-train-validation.json",
                "stable-1.0-release-train-validation-public.json",
                "stable-1.0-release-train-summary.json",
                "stable-1.0-release-train-report.md",
                "stable-1.0-release-train-checksums.txt",
                "stable-1.0-release-train-provenance.json",
                "redaction-report.json",
            }
            self.assertEqual({path.name for path in output.iterdir()}, expected)
            candidate = read_json(
                output / "stable-1.0-release-train-candidate.json"
            )
            self.assertEqual(
                candidate["developmentLineageCommit"], fixture.predecessor
            )
            self.assertIsNone(candidate["mainLineageCommit"])
            validation = read_json(
                output / "stable-1.0-release-train-validation.json"
            )
            self.assertEqual(validation["mode"], "evaluate")
            self.assertIsNone(validation["authorization"])
            self.assertEqual(validation["decision"], "go")
            self.assertEqual(validation["unaccountedCommitIds"], [])
            self.assertEqual(
                validate_schema(
                    validation,
                    "stable-1.0-release-train-validation-v1.schema.json",
                ),
                [],
            )
            self.assertFalse(
                read_json(output / "stable-1.0-release-train-summary.json")[
                    "sideEffectsPerformed"
                ]
            )
            public_queue = read_json(
                output / "stable-1.0-release-train-queue-public.json"
            )
            self.assertEqual(
                validate_schema(
                    public_queue,
                    "stable-1.0-release-train-queue-public-v1.schema.json",
                ),
                [],
            )
            self.assertNotIn("fixes", public_queue)
            self.assertNotIn("touchedPaths", str(public_queue))
            self.assertNotIn("privateRecordDigest", str(public_queue))
            self.assertNotIn("actorRole", str(public_queue))
            self.assertNotIn("occurredAt", str(public_queue))
            self.assertNotIn("reasonCode", str(public_queue))
            self.assertRegex(
                public_queue["intakeCompositionDigest"],
                r"^sha256:[0-9a-f]{64}$",
            )
            self.assertEqual(
                set(public_queue["fixEvolution"][0]),
                {"fixId", "transitionDigests"},
            )

    def test_evaluate_accepts_triaged_work_before_candidate_landing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            fix = fixture.intake["fixes"][0]
            fix["state"] = "accepted"
            fix["stateTransitions"] = fix["stateTransitions"][:3]
            fixture.write_intake()

            code, output = self._run(fixture, "evaluate")

            self.assertEqual(code, 0)
            validation = read_json(
                output / "stable-1.0-release-train-validation.json"
            )
            self.assertEqual(validation["decision"], "go")
            self.assertEqual(validation["includedFixIds"], [])
            self.assertEqual(validation["omittedFixIds"], [FIX_ID])
            self.assertEqual(validation["evidenceResults"], [])
            counts = read_json(
                output / "stable-1.0-release-train-summary.json"
            )["fixCounts"]
            self.assertEqual(counts["accepted"], 1)
            self.assertEqual(
                counts["total"],
                sum(value for key, value in counts.items() if key != "total"),
            )

    def test_prepare_rejects_landed_fix_until_candidate_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            fix = fixture.intake["fixes"][0]
            fix["state"] = "landed"
            fix["stateTransitions"] = fix["stateTransitions"][:5]
            fixture.write_intake()

            code, output = self._run(fixture, "prepare-candidate")

            self.assertEqual(code, 1)
            self.assertNotIn(
                "stable-1.0-release-train-validation.json",
                {path.name for path in output.iterdir()},
            )

    def test_prepare_preserves_evidence_identity_for_each_accepted_fix(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            fixture.candidate = _commit(
                fixture.root,
                "second.txt",
                "second fix\n",
                "second fix",
            )
            inspector = GitInspector(
                fixture.root,
                expected_repository_identity="github.com/crypta-network/cryptad",
            )
            first = _fix(
                inspector,
                fixture.fix_commit,
                fixture.candidate,
            )
            second = _fix(
                inspector,
                fixture.candidate,
                fixture.candidate,
            )
            second["fixId"] = "stable-fix-qrstuvwxyzabcdef"
            second["publicTitle"] = "Correct a second bounded request path"
            second["publicSummary"] = (
                "Corrects a distinct request path without changing stable formats."
            )
            second["publicProjectionDigest"] = semantic_digest(
                {
                    "fixId": second["fixId"],
                    "classification": second["classification"],
                    "publicSummary": second["publicSummary"],
                }
            )
            for index, evidence in enumerate(second["evidence"]):
                evidence["digest"] = _digest("abcdef"[index])
                evidence["predecessorCommit"] = fixture.predecessor
            fixture.intake = _intake(fixture.policy_digest, first)
            fixture.intake["fixes"].append(second)
            fixture.intake["publicProjectionDigest"] = semantic_digest(
                {
                    "fixIds": sorted(
                        [first["fixId"], second["fixId"]]
                    ),
                    "obligations": [],
                }
            )
            fixture.write_intake()

            code, output = self._run(fixture, "prepare-candidate")

            self.assertEqual(code, 0)
            validation = read_json(
                output / "stable-1.0-release-train-validation.json"
            )
            evidence_results = validation["evidenceResults"]
            subjects = [
                (row["fixId"], row["evidenceId"])
                for row in evidence_results
            ]
            self.assertEqual(subjects, sorted(subjects))
            self.assertEqual(len(subjects), len(set(subjects)))
            shared_rows = [
                row
                for row in evidence_results
                if row["evidenceId"]
                == "stable-backport.candidate-bound-tests"
            ]
            self.assertEqual(
                [row["fixId"] for row in shared_rows],
                sorted([first["fixId"], second["fixId"]]),
            )
            self.assertEqual(
                len({row["evidenceDigest"] for row in shared_rows}),
                2,
            )
            self.assertTrue(
                all(
                    row["generatedAt"] == EVIDENCE_GENERATED
                    and row["expiresAt"] == EVIDENCE_EXPIRES
                    and row["freshnessDeadlineAt"] == EVIDENCE_EXPIRES
                    for row in evidence_results
                )
            )

    def test_review_evidence_remains_bound_to_patch_commit_below_candidate_tip(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            patch_commit = "e" * 40
            candidate_tip = "f" * 40
            queue_digest = _digest("c")
            cases = (
                (
                    "clean-cherry-pick",
                    "stable-backport.clean-cherry-pick-review",
                    [],
                ),
                (
                    "manual-conflict-resolution",
                    "stable-backport.manual-conflict-review",
                    ["stable-backport.candidate-bound-tests"],
                ),
            )
            for mode, review_evidence_id, focused_ids in cases:
                with self.subTest(mode=mode):
                    evidence = [
                        _evidence(
                            fixture.predecessor,
                            patch_commit,
                            review_evidence_id,
                            "a",
                        ),
                        _evidence(
                            fixture.predecessor,
                            candidate_tip,
                            "stable-backport.compatibility",
                            "b",
                        ),
                    ]
                    if focused_ids:
                        evidence.append(
                            _evidence(
                                fixture.predecessor,
                                patch_commit,
                                focused_ids[0],
                                "d",
                            )
                        )
                    for row in evidence:
                        row["policyDigest"] = fixture.policy_digest
                        row["queueDigest"] = queue_digest
                    fix = {
                        "fixId": FIX_ID,
                        "provenance": {
                            "mode": mode,
                            "candidateCommit": patch_commit,
                            "focusedTestEvidenceIds": focused_ids,
                        },
                        "evidence": evidence,
                    }

                    results = engine._required_evidence(  # noqa: SLF001
                        [fix],
                        fixture.predecessor,
                        candidate_tip,
                        NOW,
                        dt.timedelta(days=14),
                        policy_digest=fixture.policy_digest,
                        queue_digest=queue_digest,
                        evidence_policy=fixture.policy["evidencePolicy"],
                        provenance_policy=fixture.policy["provenancePolicy"],
                    )

                    self.assertEqual(len(results), len(evidence))
                    self.assertTrue(all(row["candidateBound"] for row in results))

    def test_prepare_rejects_fix_scheduled_for_another_train(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            fixture.intake["fixes"][0]["schedule"][
                "targetTrainId"
            ] = "stable-train-999"
            fixture.write_intake()

            code, output = self._run(fixture, "prepare-candidate")

            self.assertEqual(code, 1)
            self.assertNotIn(
                "stable-1.0-release-train-validation.json",
                {path.name for path in output.iterdir()},
            )

    def test_prepare_rejects_false_source_object_format(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            fixture.intake["fixes"][0]["source"]["objectFormat"] = "sha256"
            fixture.write_intake()

            code, output = self._run(fixture, "prepare-candidate")

            self.assertEqual(code, 1)
            self.assertNotIn(
                "stable-1.0-backport-lineage.json",
                {path.name for path in output.iterdir()},
            )

    def test_prepare_rejects_evidence_from_another_policy_or_queue(self) -> None:
        for field in ("policyDigest", "queueDigest"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(Path(directory))
                if field == "policyDigest":
                    fixture.intake["fixes"][0]["evidence"][0][field] = _digest("f")
                else:
                    fixture.intake["fixes"][0][
                        "publicTitle"
                    ] = "Correct bounded response handling"
                fixture.intake["intakeDigest"] = canonical_identity_digest(
                    fixture.intake, "intakeDigest"
                )
                write_json(
                    fixture.root / "inputs" / "intake.json",
                    fixture.intake,
                )

                code, output = self._run(fixture, "prepare-candidate")

                self.assertEqual(code, 1)
                self.assertNotIn(
                    "stable-1.0-release-train-validation.json",
                    {path.name for path in output.iterdir()},
                )

    def test_authorization_cannot_predate_the_composition_it_approves(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            fixture.intake["generatedAt"] = "2026-01-15T10:00:00Z"
            fixture.write_intake()
            code, output = self._run(fixture, "prepare-candidate")
            self.assertEqual(code, 0)
            authorization = _authorization(fixture, output)
            authorization["issuedAt"] = "2026-01-15T10:30:00Z"
            authorization["authorizationDigest"] = canonical_identity_digest(
                authorization, "authorizationDigest"
            )
            write_json(
                fixture.root / "inputs" / "authorization.json",
                authorization,
            )
            context = fixture.context("validate-authorization")
            context.manifest.inputs["stableBackportAuthorization"] = (
                "inputs/authorization.json"
            )
            (context.component_dir / "artifacts").mkdir(
                parents=True, exist_ok=True
            )

            with mock.patch.object(
                engine, "_now", return_value=NOW
            ), mock.patch.object(
                engine,
                "_authenticate_predecessor",
                return_value=(
                    fixture.predecessor,
                    "300",
                    _digest("b"),
                    _digest("c"),
                ),
            ), mock.patch.object(
                engine,
                "_authenticate_lifecycle",
                return_value=(_digest("d"), {"300": "current-stable"}),
            ), mock.patch.object(
                engine,
                "_authenticate_lifecycle_authority",
                return_value=NOW - dt.timedelta(hours=2),
            ):
                code, summary, _report = engine.run(context)

            self.assertEqual(code, 1)
            self.assertNotIn(
                "stable-1.0-release-train-validation.json",
                {path.name for path in summary.parent.iterdir()},
            )

    def test_authorization_cannot_predate_protected_provenance_review(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            source_commit = fixture.fix_commit
            _git(
                fixture.root,
                "switch",
                "-c",
                "release-review",
                fixture.predecessor,
            )
            _git(fixture.root, "cherry-pick", "--no-commit", source_commit)
            _git(fixture.root, "commit", "-m", "reviewed fix backport")
            fixture.candidate = _git(fixture.root, "rev-parse", "HEAD")
            inspector = GitInspector(
                fixture.root,
                expected_repository_identity="github.com/crypta-network/cryptad",
            )
            provenance = inspector.verify_clean_cherry_pick(
                source_commit,
                fixture.candidate,
                fixture.candidate,
                _digest("a"),
                ["node.txt"],
            )
            fix = _fix(inspector, source_commit, source_commit)
            fix["provenance"] = engine._provenance_dict(  # noqa: SLF001
                provenance,
                "routine-release-candidate",
            )
            for evidence in fix["evidence"]:
                evidence["candidateCommit"] = fixture.candidate
            fix["evidence"].append(
                _evidence(
                    fixture.predecessor,
                    fixture.candidate,
                    "stable-backport.clean-cherry-pick-review",
                    "e",
                )
            )
            review_authorization = _review_authorization(
                fix,
                fixture.policy_digest,
            )
            review_path, _review_set, _review_digest = (
                _review_authorization_set(
                    fixture.root,
                    review_authorization,
                    fixture.policy_digest,
                )
            )
            fixture.intake = _intake(fixture.policy_digest, fix)
            fixture.intake["generatedAt"] = "2026-01-15T10:00:00Z"
            fixture.write_intake()

            prepare_context = fixture.context("prepare-candidate")
            prepare_context.manifest.inputs[
                "stableBackportReviewAuthorizations"
            ] = review_path.relative_to(fixture.root).as_posix()
            code, output = self._run_context(
                fixture,
                prepare_context,
                lifecycle_observed_at=NOW - dt.timedelta(hours=2),
            )
            self.assertEqual(code, 0)

            authorization = _authorization(fixture, output)
            authorization["issuedAt"] = "2026-01-15T11:15:00Z"
            authorization["authorizationDigest"] = canonical_identity_digest(
                authorization,
                "authorizationDigest",
            )
            write_json(
                fixture.root / "inputs" / "authorization.json",
                authorization,
            )
            validate_context = fixture.context("validate-authorization")
            validate_context.manifest.inputs.update(
                {
                    "stableBackportReviewAuthorizations": (
                        review_path.relative_to(fixture.root).as_posix()
                    ),
                    "stableBackportAuthorization": "inputs/authorization.json",
                }
            )

            code, output = self._run_context(
                fixture,
                validate_context,
                lifecycle_observed_at=NOW - dt.timedelta(hours=2),
            )

            self.assertEqual(code, 1)
            self.assertNotIn(
                "stable-1.0-release-train-validation.json",
                {path.name for path in output.iterdir()},
            )

    def test_non_genesis_train_requires_authenticated_previous_queue(self) -> None:
        baseline = {
            "kind": "stable-1.0-maintenance-successor-baseline",
            "releaseTrain": {
                "validationDigest": _digest("1"),
                "candidateCommit": "a" * 40,
            },
        }
        inputs = {
            "predecessorBaseline": (
                Path("/nonexistent/baseline.json"),
                baseline,
                _digest("2"),
            ),
            "previousStableBackportQueue": None,
            "previousStableBackportValidation": None,
        }

        with self.assertRaisesRegex(ValueError, "authenticated previous queue"):
            engine._authenticate_previous_queue(  # noqa: SLF001
                inputs,
                predecessor_commit="a" * 40,
                predecessor_build="300",
            )

    def test_non_genesis_train_rejects_tampered_evidence_queue_binding(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            queue, errors = build_queue(
                fixture.intake,
                None,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )
            self.assertEqual(errors, [])
            tampered_queue = copy.deepcopy(queue)
            tampered_queue["fixes"][0]["evidence"][0][
                "queueDigest"
            ] = _digest("f")
            self.assertEqual(
                queue_identity_digest(tampered_queue),
                tampered_queue["queueDigest"],
            )
            queue_path = fixture.root / "inputs" / "previous-queue.json"
            validation_path = (
                fixture.root / "inputs" / "previous-validation.json"
            )
            write_json(queue_path, tampered_queue)
            validation = {
                "mode": "validate-authorization",
                "decision": "go",
                "candidateCommit": fixture.candidate,
                "release": {"buildVersion": "301"},
                "queueDigest": tampered_queue["queueDigest"],
            }
            write_json(validation_path, validation)
            validation_digest = file_digest(validation_path)
            inputs = {
                "predecessorBaseline": (
                    Path("/nonexistent/baseline.json"),
                    {
                        "kind": "stable-1.0-maintenance-successor-baseline",
                        "releaseTrain": {
                            "validationDigest": validation_digest,
                            "candidateCommit": fixture.candidate,
                        },
                    },
                    _digest("2"),
                ),
                "previousStableBackportQueue": (
                    queue_path,
                    tampered_queue,
                    file_digest(queue_path),
                ),
                "previousStableBackportValidation": (
                    validation_path,
                    validation,
                    validation_digest,
                ),
            }

            with mock.patch.object(engine, "_schema_or_raise"):
                with self.assertRaisesRegex(
                    ValueError,
                    "not authenticated by the published predecessor",
                ):
                    engine._authenticate_previous_queue(  # noqa: SLF001
                        inputs,
                        predecessor_commit=fixture.candidate,
                        predecessor_build="301",
                    )

    def test_predecessor_authentication_uses_tag_object_and_ga_genesis_absence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            context = fixture.context("prepare-candidate")
            input_root = fixture.root / "inputs"
            train_digest = _digest("1")
            baseline = {
                "kind": "stable-1.0-maintenance-successor-baseline",
                "release": {
                    "releaseId": "stable-maintenance-300",
                    "buildVersion": "300",
                    "sourceCommit": fixture.predecessor,
                },
                "releaseTrain": {"validationDigest": train_digest},
            }
            receipt = {
                "kind": "stable-1.0-maintenance-publication-receipt",
                "buildVersion": "300",
                "sourceCommit": fixture.predecessor,
                "tag": {
                    "name": "v300",
                    "targetCommit": fixture.predecessor,
                },
                "publicationState": "publication-complete",
                "finalVerificationStatus": "pass",
            }
            baseline_path = input_root / "real-baseline.json"
            receipt_path = input_root / "real-receipt.json"
            write_json(baseline_path, baseline)
            write_json(receipt_path, receipt)
            baseline_digest = file_digest(baseline_path)
            receipt_digest = file_digest(receipt_path)
            pointer = {
                "kind": "stable-1.0-maintenance-latest-published",
                "releaseId": "stable-maintenance-300",
                "buildVersion": "300",
                "baselineDigest": baseline_digest,
                "publicationReceiptDigest": receipt_digest,
                "backportReleaseTrainDigest": train_digest,
                "status": "active",
            }
            pointer_path = input_root / "real-pointer.json"
            write_json(pointer_path, pointer)
            inputs = {
                "predecessorBaseline": (
                    baseline_path,
                    baseline,
                    baseline_digest,
                ),
                "predecessorPublicationReceipt": (
                    receipt_path,
                    receipt,
                    receipt_digest,
                ),
                "latestPublishedMaintenancePointer": (
                    pointer_path,
                    pointer,
                    file_digest(pointer_path),
                ),
            }
            inspector = GitInspector(
                fixture.root,
                expected_repository_identity="github.com/crypta-network/cryptad",
            )
            with mock.patch.object(engine, "_schema_or_raise"):
                authenticated = engine._authenticate_predecessor(  # noqa: SLF001
                    context, inputs, inspector, authenticate_chain=False
                )
            self.assertEqual(authenticated[0], fixture.predecessor)

            ga_baseline = copy.deepcopy(baseline)
            ga_baseline["kind"] = "stable-1.0-maintenance-baseline"
            ga_baseline.pop("releaseTrain")
            ga_receipt = copy.deepcopy(receipt)
            ga_receipt["kind"] = "stable-1.0-ga-publication-receipt"
            write_json(baseline_path, ga_baseline)
            write_json(receipt_path, ga_receipt)
            ga_inputs = {
                "predecessorBaseline": (
                    baseline_path,
                    ga_baseline,
                    file_digest(baseline_path),
                ),
                "predecessorPublicationReceipt": (
                    receipt_path,
                    ga_receipt,
                    file_digest(receipt_path),
                ),
                "latestPublishedMaintenancePointer": None,
            }
            with mock.patch.object(engine, "_schema_or_raise"):
                authenticated = engine._authenticate_predecessor(  # noqa: SLF001
                    context, ga_inputs, inspector, authenticate_chain=False
                )
            self.assertEqual(authenticated[0], fixture.predecessor)
            self.assertRegex(authenticated[2], r"^sha256:[0-9a-f]{64}$")

    def test_lifecycle_authority_requires_a_fresh_exact_public_observation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            context = fixture.context("prepare-candidate")
            lifecycle_policy_source = (
                Path(__file__).resolve().parents[2]
                / "stable-1.0-support-lifecycle-policy.json"
            )
            lifecycle_policy_path = (
                fixture.root
                / "tools"
                / "release-certification"
                / "stable-1.0-support-lifecycle-policy.json"
            )
            shutil.copyfile(lifecycle_policy_source, lifecycle_policy_path)
            lifecycle_inputs = {
                "stableLifecyclePolicy": lifecycle_policy_path.relative_to(
                    fixture.root
                ).as_posix(),
                "previousStableLifecycleAuthorization": (
                    "inputs/lifecycle-authorization.json"
                ),
                "previousStableLifecyclePublicationPlan": (
                    "inputs/lifecycle-plan.json"
                ),
                "previousStableLifecyclePublicationReceipt": (
                    "inputs/lifecycle-receipt.json"
                ),
                "stableLifecyclePublicObservationReceipt": (
                    "inputs/lifecycle-observation.json"
                ),
            }
            context.manifest.inputs.update(lifecycle_inputs)
            for name in ("authorization", "plan", "receipt"):
                write_json(
                    fixture.root / "inputs" / f"lifecycle-{name}.json",
                    {},
                )
            write_json(
                fixture.root / "inputs" / "lifecycle-observation.json",
                {"generatedAt": GENERATED},
            )
            authority_inputs = engine._load_inputs(context)  # noqa: SLF001

            with mock.patch.object(
                engine, "_schema_or_raise"
            ), mock.patch.object(
                engine, "authenticate_stable_ga_root", return_value=mock.Mock()
            ), mock.patch.object(
                engine, "authenticate_stable_predecessor", return_value=mock.Mock()
            ), mock.patch.object(
                engine, "authenticated_lifecycle_errors", return_value=[]
            ), mock.patch.object(
                engine,
                "public_lifecycle_observation_errors",
                return_value=["stale public lifecycle observation"],
            ):
                with self.assertRaisesRegex(
                    ValueError, "stale public lifecycle observation"
                ):
                    engine._authenticate_lifecycle_authority(  # noqa: SLF001
                        context,
                        authority_inputs,
                        release_class="maintenance",
                        now=NOW,
                        hotfix_scope=None,
                    )

            with mock.patch.object(
                engine, "_schema_or_raise"
            ), mock.patch.object(
                engine, "authenticate_stable_ga_root", return_value=mock.Mock()
            ), mock.patch.object(
                engine, "authenticate_stable_predecessor", return_value=mock.Mock()
            ), mock.patch.object(
                engine, "authenticated_lifecycle_errors", return_value=[]
            ), mock.patch.object(
                engine, "public_lifecycle_observation_errors", return_value=[]
            ) as observation_check:
                observed_at = engine._authenticate_lifecycle_authority(  # noqa: SLF001
                    context,
                    authority_inputs,
                    release_class="maintenance",
                    now=NOW,
                    hotfix_scope=None,
                )

            self.assertEqual(observed_at, NOW)
            observation_check.assert_called_once()

    def test_example_manifest_is_an_explicit_ga_genesis_train(self) -> None:
        example = read_json(EXAMPLE_MANIFEST)
        inputs = example["inputs"]

        self.assertEqual(
            inputs["predecessorPublicationReceipt"],
            inputs["stableGaPublicationReceipt"],
        )
        self.assertEqual(
            inputs["predecessorBaseline"],
            inputs["stableGaMaintenanceBaseline"],
        )
        self.assertNotIn("latestPublishedMaintenancePointer", inputs)
        self.assertNotIn("previousStableBackportQueue", inputs)
        self.assertNotIn("previousStableBackportValidation", inputs)
        self.assertIn("stableLifecyclePublicObservationReceipt", inputs)

    def test_prepare_then_exact_authorization_validates_candidate_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            code, output = self._run(fixture, "prepare-candidate")
            self.assertEqual(code, 0)
            authorization = _authorization(fixture, output)
            # A routine handoff must remain usable after the mandatory
            # 24-hour post-freeze soak. This 49-hour grant remains below the
            # policy's bounded 72-hour ceiling.
            authorization["expiresAt"] = "2026-01-17T13:00:00.250000+00:00"
            authorization["authorizationDigest"] = canonical_identity_digest(
                authorization, "authorizationDigest"
            )
            write_json(fixture.root / "inputs" / "authorization.json", authorization)
            context = fixture.context("validate-authorization")
            (context.component_dir / "artifacts").mkdir(parents=True, exist_ok=True)
            context.manifest.inputs["stableBackportAuthorization"] = (
                "inputs/authorization.json"
            )

            with mock.patch.object(engine, "_now", return_value=NOW), mock.patch.object(
                engine,
                "_authenticate_predecessor",
                return_value=(
                    fixture.predecessor,
                    "300",
                    _digest("b"),
                    _digest("c"),
                ),
            ), mock.patch.object(
                engine,
                "_authenticate_lifecycle",
                return_value=(_digest("d"), {"300": "current-stable"}),
            ), mock.patch.object(
                engine, "_authenticate_lifecycle_authority", return_value=NOW
            ):
                code, summary, _report = engine.run(context)

            self.assertEqual(code, 0)
            validation = read_json(
                summary.parent / "stable-1.0-release-train-validation.json"
            )
            self.assertEqual(validation["mode"], "validate-authorization")
            self.assertEqual(validation["authorization"]["status"], "valid")
            self.assertEqual(
                validation["authorization"]["expiresAt"],
                authorization["expiresAt"],
            )
            self.assertEqual(validation["decision"], "go")
            self.assertEqual(
                validate_schema(authorization, AUTHORIZATION_SCHEMA), []
            )

    def test_completion_verifies_publication_and_exact_no_ff_reconciliation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            code, output = self._run(fixture, "prepare-candidate")
            self.assertEqual(code, 0)
            authorization = _authorization(fixture, output)
            authorization_path = fixture.root / "inputs" / "authorization.json"
            write_json(authorization_path, authorization)

            context = fixture.context("validate-authorization")
            context.manifest.inputs["stableBackportAuthorization"] = (
                "inputs/authorization.json"
            )
            (context.component_dir / "artifacts").mkdir(parents=True, exist_ok=True)
            with mock.patch.object(engine, "_now", return_value=NOW), mock.patch.object(
                engine,
                "_authenticate_predecessor",
                return_value=(
                    fixture.predecessor,
                    "300",
                    _digest("b"),
                    _digest("c"),
                ),
            ), mock.patch.object(
                engine,
                "_authenticate_lifecycle",
                return_value=(_digest("d"), {"300": "current-stable"}),
            ), mock.patch.object(
                engine, "_authenticate_lifecycle_authority", return_value=NOW
            ):
                code, summary, _report = engine.run(context)
            self.assertEqual(code, 0)
            authorized_validation_path = (
                summary.parent / "stable-1.0-release-train-validation.json"
            )
            validation_file_digest = file_digest(authorized_validation_path)
            frozen_validation_path = (
                fixture.root / "inputs" / "frozen-validation.json"
            )
            shutil.copyfile(authorized_validation_path, frozen_validation_path)

            _git(fixture.root, "branch", "main", fixture.predecessor)
            _git(fixture.root, "switch", "main")
            _git(
                fixture.root,
                "merge",
                "--no-ff",
                "--no-edit",
                fixture.candidate,
            )
            main_merge = _git(fixture.root, "rev-parse", "HEAD")
            _git(fixture.root, "branch", "-f", "develop", fixture.predecessor)
            _git(fixture.root, "switch", "develop")
            develop_tip = _commit(
                fixture.root,
                "develop.txt",
                "continued development\n",
                "continued development",
            )
            _git(
                fixture.root,
                "merge",
                "--no-ff",
                "--no-edit",
                fixture.candidate,
            )
            develop_merge = _git(fixture.root, "rev-parse", "HEAD")
            inspector = GitInspector(
                fixture.root,
                expected_repository_identity="github.com/crypta-network/cryptad",
            )
            main_evidence = engine._merge_evidence_dict(  # noqa: SLF001
                inspector.verify_no_ff_merge(
                    merge_commit=main_merge,
                    first_parent=fixture.predecessor,
                    merged_tip=fixture.candidate,
                    protected_ref="refs/heads/main",
                    protected_tip=main_merge,
                    expected_protected_ref="refs/heads/main",
                    workflow_attestation_digest=(
                        inspector.reconciliation_attestation_digest(
                            protected_ref="refs/heads/main",
                            protected_tip=main_merge,
                            merge_commit=main_merge,
                            first_parent=fixture.predecessor,
                            merged_tip=fixture.candidate,
                        )
                    ),
                )
            )
            develop_evidence = engine._merge_evidence_dict(  # noqa: SLF001
                inspector.verify_no_ff_merge(
                    merge_commit=develop_merge,
                    first_parent=develop_tip,
                    merged_tip=fixture.candidate,
                    protected_ref="refs/heads/develop",
                    protected_tip=develop_merge,
                    expected_protected_ref="refs/heads/develop",
                    workflow_attestation_digest=(
                        inspector.reconciliation_attestation_digest(
                            protected_ref="refs/heads/develop",
                            protected_tip=develop_merge,
                            merge_commit=develop_merge,
                            first_parent=develop_tip,
                            merged_tip=fixture.candidate,
                        )
                    ),
                )
            )
            receipt = _publication_receipt(
                fixture.candidate,
                validation_file_digest,
                authorization["authorizationDigest"],
            )
            receipt_path = fixture.root / "inputs" / "publication-receipt.json"
            write_json(receipt_path, receipt)
            completion = {
                "schemaVersion": 1,
                "kind": "stable-1.0-release-train-completion",
                "generatedAt": GENERATED,
                "stableMilestone": "1.0",
                "trainId": "stable-train-301",
                "release": authorization["release"],
                "policyDigest": fixture.policy_digest,
                "queueDigest": read_json(
                    output / "stable-1.0-release-train-queue.json"
                )["queueDigest"],
                "validationDigest": validation_file_digest,
                "authorizationDigest": authorization["authorizationDigest"],
                "publicationReceiptDigest": file_digest(receipt_path),
                "publicationCommit": fixture.candidate,
                "tag": "v301",
                "lifecycleState": "pending-activation",
                "lifecycleReceiptDigest": None,
                "lifecycleLedgerDigest": None,
                "lifecycleDescriptorDigest": None,
                "mainMerge": main_evidence,
                "developMerge": develop_evidence,
                "hotfixPresentInDevelop": True,
                "reconciliationStatus": "verified",
                "reconciliationObligations": [],
                "carriedObligationIds": [],
                "status": "complete",
                "redaction": PASS_REDACTION,
            }
            completion["completionDigest"] = canonical_identity_digest(
                completion, "completionDigest"
            )
            completion_path = fixture.root / "inputs" / "completion.json"
            write_json(completion_path, completion)

            context = fixture.context("verify-release-completion")
            context.manifest.inputs.update(
                {
                    "stableBackportAuthorization": "inputs/authorization.json",
                    "stableBackportFrozenValidation": (
                        "inputs/frozen-validation.json"
                    ),
                    "stableBackportCompletionEvidence": "inputs/completion.json",
                    "stableMaintenancePublicationReceipt": (
                        "inputs/publication-receipt.json"
                    ),
                }
            )
            (context.component_dir / "artifacts").mkdir(parents=True, exist_ok=True)
            with mock.patch.object(
                engine, "_now", return_value=NOW + dt.timedelta(hours=48)
            ), mock.patch.object(
                engine,
                "_authenticate_predecessor",
                return_value=(
                    fixture.predecessor,
                    "300",
                    _digest("b"),
                    _digest("c"),
                ),
            ), mock.patch.object(
                engine,
                "_authenticate_lifecycle",
                return_value=(_digest("d"), {"300": "current-stable"}),
            ), mock.patch.object(
                engine, "_authenticate_lifecycle_authority", return_value=NOW
            ):
                code, summary, _report = engine.run(context)

            self.assertEqual(
                code,
                0,
                read_json(summary).get("blockers", []),
            )
            emitted = read_json(
                summary.parent / "stable-1.0-release-train-completion.json"
            )
            self.assertEqual(emitted["completionDigest"], completion["completionDigest"])

            _git(
                fixture.root,
                "switch",
                "-c",
                "manual-develop-reconciliation",
                fixture.predecessor,
            )
            manual_develop_tip = _commit(
                fixture.root,
                "node.txt",
                "base\ndevelop context\n",
                "conflicting develop context",
            )
            with self.assertRaises(subprocess.CalledProcessError):
                _git(
                    fixture.root,
                    "merge",
                    "--no-ff",
                    "--no-edit",
                    fixture.candidate,
                )
            manual_develop_merge = _commit(
                fixture.root,
                "node.txt",
                "base\ndevelop context\n",
                "manual reconciliation retaining develop context",
            )
            manual_develop_evidence = {
                "mergeCommit": manual_develop_merge,
                "firstParent": manual_develop_tip,
                "mergedTip": fixture.candidate,
                "protectedRef": "refs/heads/develop",
                "protectedTip": manual_develop_merge,
                "parentCount": 2,
                "graphVerified": True,
                "workflowAttestationDigest": (
                    inspector.reconciliation_attestation_digest(
                        protected_ref="refs/heads/develop",
                        protected_tip=manual_develop_merge,
                        merge_commit=manual_develop_merge,
                        first_parent=manual_develop_tip,
                        merged_tip=fixture.candidate,
                    )
                ),
            }
            with self.assertRaisesRegex(
                engine.NonAutomaticMergeResolutionError,
                "non-automatic content resolution",
            ) as manual_error:
                inspector.verify_no_ff_merge(
                    merge_commit=manual_develop_merge,
                    first_parent=manual_develop_tip,
                    merged_tip=fixture.candidate,
                    protected_ref="refs/heads/develop",
                    protected_tip=manual_develop_merge,
                    expected_protected_ref="refs/heads/develop",
                    workflow_attestation_digest=manual_develop_evidence[
                        "workflowAttestationDigest"
                    ],
                )
            manual_completion = copy.deepcopy(completion)
            main_obligation = engine._reconciliation_obligation(  # noqa: SLF001
                completion=manual_completion,
                evidence=manual_error.exception.evidence,
                resolution_paths=manual_error.exception.resolution_paths,
                role="main",
                lane="routine-maintenance",
                source_fix_ids=[FIX_ID],
                reconciliation_policy=fixture.policy[
                    "postReleaseReconciliation"
                ],
            )
            hotfix_obligation = engine._reconciliation_obligation(  # noqa: SLF001
                completion=manual_completion,
                evidence=manual_error.exception.evidence,
                resolution_paths=manual_error.exception.resolution_paths,
                role="develop",
                lane="security-hotfix",
                source_fix_ids=[FIX_ID],
                reconciliation_policy=fixture.policy[
                    "postReleaseReconciliation"
                ],
            )
            self.assertEqual(
                main_obligation["obligationType"],
                "post-release-main-merge",
            )
            self.assertEqual(
                hotfix_obligation["obligationType"],
                "hotfix-develop-merge-back",
            )
            manual_completion["developMerge"] = manual_develop_evidence
            manual_completion["completionDigest"] = canonical_identity_digest(
                manual_completion,
                "completionDigest",
            )
            manual_completion_path = (
                fixture.root / "inputs" / "manual-completion.json"
            )
            write_json(manual_completion_path, manual_completion)
            manual_context = fixture.context("verify-release-completion")
            manual_context.manifest.inputs.update(
                {
                    "stableBackportAuthorization": "inputs/authorization.json",
                    "stableBackportFrozenValidation": (
                        "inputs/frozen-validation.json"
                    ),
                    "stableBackportCompletionEvidence": (
                        "inputs/manual-completion.json"
                    ),
                    "stableMaintenancePublicationReceipt": (
                        "inputs/publication-receipt.json"
                    ),
                }
            )
            (manual_context.component_dir / "artifacts").mkdir(
                parents=True,
                exist_ok=True,
            )
            with mock.patch.object(
                engine, "_now", return_value=NOW + dt.timedelta(hours=48)
            ), mock.patch.object(
                engine,
                "_authenticate_predecessor",
                return_value=(
                    fixture.predecessor,
                    "300",
                    _digest("b"),
                    _digest("c"),
                ),
            ), mock.patch.object(
                engine,
                "_authenticate_lifecycle",
                return_value=(_digest("d"), {"300": "current-stable"}),
            ), mock.patch.object(
                engine, "_authenticate_lifecycle_authority", return_value=NOW
            ):
                manual_code, manual_summary, manual_report = engine.run(
                    manual_context
                )

            self.assertEqual(
                manual_code,
                0,
                read_json(manual_summary).get("blockers", []),
            )
            normalized_completion = read_json(
                manual_summary.parent
                / "stable-1.0-release-train-completion.json"
            )
            obligation_id = "stable-reconciliation-301-develop"
            self.assertEqual(
                normalized_completion["carriedObligationIds"],
                [obligation_id],
            )
            self.assertEqual(
                normalized_completion["reconciliationStatus"],
                "content-review-required",
            )
            self.assertEqual(
                normalized_completion["reconciliationObligations"],
                [
                    {
                        "obligationId": obligation_id,
                        "obligationType": "post-release-develop-merge",
                        "sourceTrainId": "stable-train-301",
                        "sourceFixIds": [FIX_ID],
                        "status": "open",
                        "generatedAt": GENERATED,
                        "resolvedAt": None,
                        "evidenceDigest": normalized_completion[
                            "reconciliationObligations"
                        ][0]["evidenceDigest"],
                    }
                ],
            )
            self.assertEqual(
                normalized_completion["completionDigest"],
                canonical_identity_digest(
                    normalized_completion,
                    "completionDigest",
                ),
            )
            self.assertEqual(
                validate_schema(
                    normalized_completion,
                    "stable-1.0-release-train-completion-v1.schema.json",
                ),
                [],
            )
            self.assertIn(
                obligation_id,
                manual_report.read_text(encoding="utf-8"),
            )
            self.assertEqual(
                manual_completion["reconciliationObligations"],
                [],
            )
            inherited_follow_up = "hotfix-follow-up-300"
            retained_completion = copy.deepcopy(completion)
            retained_completion["carriedObligationIds"] = [
                inherited_follow_up
            ]
            retained_completion["completionDigest"] = canonical_identity_digest(
                retained_completion,
                "completionDigest",
            )
            engine._verify_completion_release_and_reconciliation(  # noqa: SLF001
                retained_completion,
                receipt,
                file_digest(receipt_path),
                inspector=inspector,
                release=authorization["release"],
                train_id="stable-train-301",
                lane="security-hotfix",
                policy_digest=fixture.policy_digest,
                queue_digest=completion["queueDigest"],
                validation_file_digest=validation_file_digest,
                authorization_digest=authorization[
                    "authorizationDigest"
                ],
                candidate_commit=fixture.candidate,
                expected_carried_obligation_ids=[inherited_follow_up],
                source_fix_ids=[FIX_ID],
                reconciliation_policy=fixture.policy[
                    "postReleaseReconciliation"
                ],
            )
            with self.assertRaisesRegex(
                ValueError,
                "exact permitted carried obligations",
            ):
                engine._verify_completion_release_and_reconciliation(  # noqa: SLF001
                    completion,
                    receipt,
                    file_digest(receipt_path),
                    inspector=inspector,
                    release=authorization["release"],
                    train_id="stable-train-301",
                    lane="security-hotfix",
                    policy_digest=fixture.policy_digest,
                    queue_digest=completion["queueDigest"],
                    validation_file_digest=validation_file_digest,
                    authorization_digest=authorization[
                        "authorizationDigest"
                    ],
                    candidate_commit=fixture.candidate,
                    expected_carried_obligation_ids=[inherited_follow_up],
                    source_fix_ids=[FIX_ID],
                    reconciliation_policy=fixture.policy[
                        "postReleaseReconciliation"
                    ],
                )
            self.assertFalse(
                read_json(summary.parent / "stable-1.0-release-train-summary.json")[
                    "sideEffectsPerformed"
                ]
            )

    def test_unaccounted_candidate_commit_fails_closed_without_success_artifacts(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory), extra_unaccounted_commit=True)
            code, output = self._run(fixture, "prepare-candidate")

            self.assertEqual(code, 1)
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {
                    "stable-1.0-release-train-summary.json",
                    "stable-1.0-release-train-report.md",
                    "redaction-report.json",
                },
            )
            summary = read_json(
                output / "stable-1.0-release-train-summary.json"
            )
            self.assertEqual(summary["decision"], "no-go")
            self.assertFalse(summary["sideEffectsPerformed"])

    def test_critical_security_hotfix_emits_only_digest_bound_public_projection(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            inspector = GitInspector(
                fixture.root,
                expected_repository_identity="github.com/crypta-network/cryptad",
            )
            security_fix = _security_fix(
                inspector,
                fixture.fix_commit,
                fixture.candidate,
            )
            security_fix["provenance"][
                "candidateBranchRole"
            ] = "security-hotfix-candidate"
            fixture.intake = _intake(fixture.policy_digest, security_fix)
            fixture.write_intake()
            context = fixture.context("prepare-candidate")
            context.manifest.policies.update(
                {
                    "releaseClass": "security-hotfix",
                    "backportReleaseLane": "security-hotfix",
                    "candidateSourceBranch": "hotfix/301",
                }
            )
            context.manifest.policies.pop("developmentLineageCommit")
            context.manifest.policies["mainLineageCommit"] = fixture.predecessor
            (context.component_dir / "artifacts").mkdir(parents=True, exist_ok=True)
            with mock.patch.object(engine, "_now", return_value=NOW), mock.patch.object(
                engine,
                "_authenticate_predecessor",
                return_value=(
                    fixture.predecessor,
                    "300",
                    _digest("b"),
                    _digest("c"),
                ),
            ), mock.patch.object(
                engine,
                "_authenticate_lifecycle",
                return_value=(_digest("d"), {"300": "current-stable"}),
            ), mock.patch.object(
                engine, "_authenticate_lifecycle_authority", return_value=NOW
            ):
                code, summary, _report = engine.run(context)

            self.assertEqual(code, 0)
            candidate = read_json(
                summary.parent / "stable-1.0-release-train-candidate.json"
            )
            self.assertIsNone(candidate["developmentLineageCommit"])
            self.assertEqual(
                candidate["mainLineageCommit"], fixture.predecessor
            )
            validation = read_json(
                summary.parent / "stable-1.0-release-train-validation.json"
            )
            public_validation = read_json(
                summary.parent / "stable-1.0-release-train-validation-public.json"
            )
            public_fix = validation["publicFixes"][0]
            self.assertEqual(public_fix["classification"], "security-fix")
            self.assertEqual(public_fix["severity"], "critical")
            self.assertEqual(
                public_fix["disclosureState"],
                "protected-embargoed",
            )
            self.assertEqual(
                public_fix["securityPublicProjectionDigest"],
                security_fix["security"]["publicProjectionDigest"],
            )
            protected = "stable-backport.security-incident-scope"
            self.assertIn(protected, str(validation["evidenceResults"]))
            self.assertNotIn(protected, str(public_validation["evidenceResults"]))
            self.assertEqual(
                public_validation["authoritativeValidationDigest"],
                validation["validationDigest"],
            )
            self.assertEqual(
                public_validation["authoritativeValidationFileDigest"],
                file_digest(
                    summary.parent
                    / "stable-1.0-release-train-validation.json"
                ),
            )
            self.assertEqual(
                validate_schema(
                    public_validation,
                    "stable-1.0-release-train-validation-public-v1.schema.json",
                ),
                [],
            )
            self.assertNotIn(
                security_fix["privateRecordDigest"],
                (summary.parent / "stable-1.0-release-train-report.md").read_text(
                    encoding="utf-8"
                ),
            )

    def test_security_hotfix_carries_one_inherited_follow_up_but_not_two(
        self,
    ) -> None:
        def run_with_follow_ups(count: int) -> int:
            with tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(Path(directory))
                inspector = GitInspector(
                    fixture.root,
                    expected_repository_identity=(
                        "github.com/crypta-network/cryptad"
                    ),
                )
                security_fix = _security_fix(
                    inspector,
                    fixture.fix_commit,
                    fixture.candidate,
                )
                security_fix["provenance"][
                    "candidateBranchRole"
                ] = "security-hotfix-candidate"
                previous_intake = _intake(
                    fixture.policy_digest,
                    security_fix,
                )
                obligations = [
                    {
                        "obligationId": f"hotfix-follow-up-30{index}",
                        "obligationType": "hotfix-follow-up",
                        "sourceTrainId": f"stable-train-30{index}",
                        "sourceFixIds": [FIX_ID],
                        "status": "open",
                        "generatedAt": GENERATED,
                        "resolvedAt": None,
                        "evidenceDigest": _digest(str(index)),
                    }
                    for index in range(count)
                ]
                previous_intake["obligations"] = obligations
                previous_intake["publicProjectionDigest"] = semantic_digest(
                    {
                        "fixIds": [FIX_ID],
                        "obligations": [
                            {
                                "obligationId": row["obligationId"],
                                "status": "open",
                            }
                            for row in obligations
                        ],
                    }
                )
                _bind_intake_evidence(
                    previous_intake,
                    None,
                    policy_digest=fixture.policy_digest,
                    candidate_commit=fixture.candidate,
                )
                previous_queue, queue_errors = build_queue(
                    previous_intake,
                    None,
                    policy_digest=fixture.policy_digest,
                    latest_maintenance_pointer_digest=_digest("b"),
                    lifecycle_ledger_digest=_digest("d"),
                    repository_identity="github.com/crypta-network/cryptad",
                    candidate_commit=fixture.candidate,
                )
                self.assertEqual(queue_errors, [])
                fixture.intake = copy.deepcopy(previous_intake)
                fixture.intake["intakeId"] = "stable-intake-bcdefghijklmnopq"
                fixture.intake["previousQueueDigest"] = previous_queue[
                    "queueDigest"
                ]
                fixture.write_intake(previous_queue)
                context = fixture.context("prepare-candidate")
                context.manifest.policies.update(
                    {
                        "releaseClass": "security-hotfix",
                        "backportReleaseLane": "security-hotfix",
                        "candidateSourceBranch": "hotfix/301",
                    }
                )
                context.manifest.policies.pop("developmentLineageCommit")
                context.manifest.policies["mainLineageCommit"] = fixture.predecessor
                (context.component_dir / "artifacts").mkdir(
                    parents=True,
                    exist_ok=True,
                )
                with mock.patch.object(
                    engine, "_now", return_value=NOW
                ), mock.patch.object(
                    engine,
                    "_authenticate_predecessor",
                    return_value=(
                        fixture.predecessor,
                        "300",
                        _digest("b"),
                        _digest("c"),
                    ),
                ), mock.patch.object(
                    engine,
                    "_authenticate_lifecycle",
                    return_value=(_digest("d"), {"300": "current-stable"}),
                ), mock.patch.object(
                    engine,
                    "_authenticate_previous_queue",
                    return_value=previous_queue,
                ), mock.patch.object(
                    engine, "_authenticate_lifecycle_authority", return_value=NOW
                ):
                    code, _summary, _report = engine.run(context)
                return code

        self.assertEqual(run_with_follow_ups(1), 0)
        self.assertEqual(run_with_follow_ups(2), 1)


class StableBackportPolicyAndQueueTest(unittest.TestCase):
    def test_summary_fix_counts_account_for_every_closed_state(self) -> None:
        fixes = [{"state": state} for state in FIX_STATES]

        counts = engine._fix_counts(fixes)  # noqa: SLF001

        self.assertEqual(counts["total"], len(FIX_STATES))
        self.assertEqual(
            counts["total"],
            sum(value for key, value in counts.items() if key != "total"),
        )
        for state in FIX_STATES:
            self.assertEqual(counts[state], 1)

    def test_closed_vocabulary_and_policy_are_exact(self) -> None:
        policy = read_json(
            Path(__file__).resolve().parents[2]
            / "stable-1.0-backport-release-train-policy.json"
        )
        self.assertEqual(policy_errors(policy), [])
        self.assertEqual(policy["classifications"], list(CLASSIFICATIONS))
        self.assertEqual(policy["dispositions"], list(DISPOSITIONS))
        self.assertEqual(policy["fixStates"], list(FIX_STATES))
        self.assertEqual(policy["provenanceModes"], list(PROVENANCE_MODES))
        self.assertEqual(
            policy["provenancePolicy"]["clean-cherry-pick"][
                "reviewEvidenceId"
            ],
            "stable-backport.clean-cherry-pick-review",
        )
        self.assertEqual(
            policy["provenancePolicy"]["manual-conflict-resolution"][
                "reviewEvidenceId"
            ],
            "stable-backport.manual-conflict-review",
        )
        self.assertEqual(
            policy["authorization"]["cleanCherryPickReviewerRole"],
            "stable-backport-cherry-pick-reviewer",
        )
        self.assertEqual(
            policy["queuePolicy"][
                "securityHotfixAllowedCarriedObligationTypes"
            ],
            ["hotfix-follow-up"],
        )
        self.assertEqual(
            policy["queuePolicy"]["securityHotfixMaximumCarriedFollowUps"],
            1,
        )
        self.assertTrue(
            policy["queuePolicy"][
                "publicationCreatedFollowUpBaselineBindingRequired"
            ]
        )
        for classification, eligibility in policy[
            "classificationEligibility"
        ].items():
            if classification == "security-fix":
                continue
            self.assertNotIn(
                "security-hotfix",
                eligibility["allowedDispositions"],
            )
            self.assertNotIn("security-hotfix", eligibility["allowedLanes"])
        self.assertFalse(policy["noFork"]["parallelStableBranchesAllowed"])

    def test_publication_created_follow_up_is_seeded_from_predecessor_baseline(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            inspector = GitInspector(
                fixture.root,
                expected_repository_identity="github.com/crypta-network/cryptad",
            )
            security_fix = _security_fix(
                inspector,
                fixture.fix_commit,
                fixture.candidate,
            )
            previous_intake = _intake(fixture.policy_digest, security_fix)
            previous_queue, previous_errors = build_queue(
                previous_intake,
                None,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )
            self.assertEqual(previous_errors, [])
            obligation_digest = _digest("9")
            obligation = {
                "obligationId": "hotfix-follow-up-301",
                "obligationType": "hotfix-follow-up",
                "sourceTrainId": "stable-train-301",
                "sourceFixIds": [FIX_ID],
                "status": "open",
                "generatedAt": GENERATED,
                "resolvedAt": None,
                "evidenceDigest": obligation_digest,
            }
            current_intake = copy.deepcopy(previous_intake)
            current_intake["intakeId"] = "stable-intake-bcdefghijklmnopq"
            current_intake["previousQueueDigest"] = previous_queue["queueDigest"]
            current_intake["obligations"] = [obligation]
            current_intake["publicProjectionDigest"] = semantic_digest(
                {
                    "fixIds": [FIX_ID],
                    "obligations": [
                        {
                            "obligationId": obligation["obligationId"],
                            "status": "open",
                        }
                    ],
                }
            )
            _bind_intake_evidence(
                current_intake,
                previous_queue,
                policy_digest=fixture.policy_digest,
                candidate_commit=fixture.candidate,
            )
            current_queue, current_errors = build_queue(
                current_intake,
                previous_queue,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )
            self.assertEqual(current_errors, [])
            baseline = {
                "hotfixFollowUp": {
                    "status": "open",
                    "generatedAt": GENERATED,
                    "obligationDigest": obligation_digest,
                    "blocksRoutineMaintenance": True,
                    "obligatedBuildVersion": "301",
                }
            }

            permitted, errors = permitted_carried_obligation_ids(
                current_queue,
                previous_queue,
                lane="security-hotfix",
                policy=fixture.policy,
                predecessor_baseline=baseline,
            )

            self.assertEqual(errors, [])
            self.assertEqual(permitted, ["hotfix-follow-up-301"])
            _permitted, missing_errors = permitted_carried_obligation_ids(
                previous_queue,
                previous_queue,
                lane="security-hotfix",
                policy=fixture.policy,
                predecessor_baseline=baseline,
            )
            self.assertTrue(
                any("absent from the release-train queue" in row for row in missing_errors),
                missing_errors,
            )
            closed_baseline = copy.deepcopy(baseline)
            closed_baseline["hotfixFollowUp"]["status"] = "closed"
            closed_baseline["hotfixFollowUp"]["closureEvidenceDigest"] = _digest("7")
            closed_baseline["hotfixFollowUp"]["blocksRoutineMaintenance"] = False
            _permitted, closed_errors = permitted_carried_obligation_ids(
                previous_queue,
                previous_queue,
                lane="security-hotfix",
                policy=fixture.policy,
                predecessor_baseline=closed_baseline,
            )
            self.assertEqual(closed_errors, [])
            substituted_baseline = copy.deepcopy(baseline)
            substituted_baseline["hotfixFollowUp"]["obligationDigest"] = _digest("8")
            _permitted, errors = permitted_carried_obligation_ids(
                current_queue,
                previous_queue,
                lane="security-hotfix",
                policy=fixture.policy,
                predecessor_baseline=substituted_baseline,
            )
            self.assertTrue(
                any("authenticated by the predecessor baseline" in row for row in errors),
                errors,
            )

    def test_manual_conflict_requires_bound_reviewer_and_focused_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            fix = copy.deepcopy(fixture.intake["fixes"][0])
            candidate = "f" * 40
            reviewer_digest = _digest("e")
            provenance = fix["provenance"]
            provenance.update(
                {
                    "mode": "manual-conflict-resolution",
                    "candidateCommit": candidate,
                    "mergeBaseCommit": fixture.predecessor,
                    "sourceBaseCommit": fixture.predecessor,
                    "targetBaseCommit": "e" * 40,
                    "conflictPaths": ["node.txt"],
                    "normalizedDiffEvidenceDigest": _digest("d"),
                    "reviewerAuthorizationDigest": reviewer_digest,
                    "focusedTestEvidenceIds": [
                        "stable-backport.candidate-bound-tests"
                    ],
                    "noUnrelatedFeatureChange": True,
                }
            )
            for evidence in fix["evidence"]:
                evidence["candidateCommit"] = candidate
            review_evidence = _evidence(
                fixture.predecessor,
                candidate,
                "stable-backport.manual-conflict-review",
                "e",
            )
            review_evidence["visibility"] = "protected"
            fix["evidence"].append(review_evidence)
            fix["ownership"].update(
                {
                    "reviewerRole": "stable-backport-conflict-reviewer",
                    "authorizationDigest": reviewer_digest,
                }
            )
            authorization = _review_authorization(
                fix, fixture.policy_digest
            )
            authorizations = {FIX_ID: authorization}

            valid_errors = fix_record_errors(
                fix,
                fixture.policy,
                now=NOW,
                review_authorizations=authorizations,
            )

            self.assertEqual(valid_errors, [])

            wrong_role = copy.deepcopy(fix)
            wrong_role["ownership"]["reviewerRole"] = "stable-fix-reviewer"
            self.assertTrue(
                any(
                    "configured reviewer role" in error
                    for error in fix_record_errors(
                        wrong_role,
                        fixture.policy,
                        now=NOW,
                        review_authorizations=authorizations,
                    )
                )
            )

            invented_authorization = copy.deepcopy(fix)
            invented_authorization["provenance"][
                "reviewerAuthorizationDigest"
            ] = _digest("f")
            self.assertTrue(
                any(
                    "review authorization digest" in error
                    for error in fix_record_errors(
                        invented_authorization,
                        fixture.policy,
                        now=NOW,
                        review_authorizations=authorizations,
                    )
                )
            )

            missing_focused_test = copy.deepcopy(fix)
            missing_focused_test["provenance"]["focusedTestEvidenceIds"] = [
                "stable-backport.unbound-focused-test"
            ]
            self.assertTrue(
                any(
                    "focused test evidence" in error
                    for error in fix_record_errors(
                        missing_focused_test,
                        fixture.policy,
                        now=NOW,
                        review_authorizations=authorizations,
                    )
                )
            )

    def test_clean_cherry_pick_requires_bound_reviewer_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            fix = copy.deepcopy(fixture.intake["fixes"][0])
            candidate = "f" * 40
            reviewer_digest = _digest("e")
            provenance = fix["provenance"]
            provenance.update(
                {
                    "mode": "clean-cherry-pick",
                    "candidateCommit": candidate,
                    "stablePatchId": "e" * 40,
                    "candidateTreeOid": "d" * 40,
                    "candidateTreeDigest": _digest("c"),
                    "candidateDiffDigest": _digest("b"),
                    "normalizedDiffEvidenceDigest": _digest("a"),
                    "reviewerAuthorizationDigest": reviewer_digest,
                }
            )
            for evidence in fix["evidence"]:
                evidence["candidateCommit"] = candidate
            review_evidence = _evidence(
                fixture.predecessor,
                candidate,
                "stable-backport.clean-cherry-pick-review",
                "e",
            )
            review_evidence["visibility"] = "protected"
            fix["evidence"].append(review_evidence)
            fix["ownership"].update(
                {
                    "reviewerRole": "stable-backport-cherry-pick-reviewer",
                    "authorizationDigest": reviewer_digest,
                }
            )
            authorization = _review_authorization(
                fix, fixture.policy_digest
            )
            authorizations = {FIX_ID: authorization}

            self.assertEqual(
                fix_record_errors(
                    fix,
                    fixture.policy,
                    now=NOW,
                    review_authorizations=authorizations,
                ),
                [],
            )
            self.assertTrue(
                any(
                    "authenticated protected review authorization" in error
                    for error in fix_record_errors(
                        fix,
                        fixture.policy,
                        now=NOW,
                    )
                )
            )
            loaded = _review_authorization_set(
                fixture.root,
                authorization,
                fixture.policy_digest,
            )
            self.assertEqual(
                engine._authenticate_review_authorizations(  # noqa: SLF001
                    loaded,
                    intake={"fixes": [fix]},
                    policy=fixture.policy,
                    policy_digest=fixture.policy_digest,
                    now=NOW,
                ),
                authorizations,
            )
            expiring_fix = copy.deepcopy(fix)
            expiring_authorization = copy.deepcopy(authorization)
            expiring_authorization["expiresAt"] = (
                NOW.isoformat().replace("+00:00", "Z")
            )
            expiring_authorization["authorizationDigest"] = (
                canonical_identity_digest(
                    expiring_authorization,
                    "authorizationDigest",
                )
            )
            expiring_digest = expiring_authorization[
                "authorizationDigest"
            ]
            expiring_fix["provenance"][
                "reviewerAuthorizationDigest"
            ] = expiring_digest
            expiring_fix["ownership"]["authorizationDigest"] = (
                expiring_digest
            )
            next(
                row
                for row in expiring_fix["evidence"]
                if row["evidenceId"]
                == "stable-backport.clean-cherry-pick-review"
            )["digest"] = expiring_digest
            expiring_set = _review_authorization_set(
                fixture.root,
                expiring_authorization,
                fixture.policy_digest,
            )
            with self.assertRaisesRegex(
                ValueError,
                "not bound to an exact protected reviewer authorization",
            ):
                engine._authenticate_review_authorizations(  # noqa: SLF001
                    expiring_set,
                    intake={"fixes": [expiring_fix]},
                    policy=fixture.policy,
                    policy_digest=fixture.policy_digest,
                    now=NOW,
                )

            invented_authorization = copy.deepcopy(fix)
            invented_authorization["provenance"][
                "reviewerAuthorizationDigest"
            ] = _digest("f")
            self.assertTrue(
                any(
                    "review authorization digest" in error
                    for error in fix_record_errors(
                        invented_authorization,
                        fixture.policy,
                        now=NOW,
                        review_authorizations=authorizations,
                    )
                )
            )

            wrong_role = copy.deepcopy(fix)
            wrong_role["ownership"]["reviewerRole"] = "stable-fix-reviewer"
            self.assertTrue(
                any(
                    "configured reviewer role" in error
                    for error in fix_record_errors(
                        wrong_role,
                        fixture.policy,
                        now=NOW,
                        review_authorizations=authorizations,
                    )
                )
            )

            missing_review = copy.deepcopy(fix)
            missing_review["evidence"] = [
                row
                for row in missing_review["evidence"]
                if row["evidenceId"]
                != "stable-backport.clean-cherry-pick-review"
            ]
            self.assertTrue(
                any(
                    "protected review evidence" in error
                    for error in fix_record_errors(
                        missing_review,
                        fixture.policy,
                        now=NOW,
                        review_authorizations=authorizations,
                    )
                )
            )

    def test_obligation_timestamps_cannot_claim_future_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            future = (NOW + dt.timedelta(hours=1)).isoformat().replace(
                "+00:00", "Z"
            )
            base_obligation = {
                "obligationId": "reconcile-develop-301",
                "obligationType": "post-release-develop-merge",
                "sourceTrainId": "stable-train-301",
                "sourceFixIds": [FIX_ID],
                "status": "open",
                "generatedAt": future,
                "resolvedAt": None,
                "evidenceDigest": _digest("d"),
            }

            future_creation = copy.deepcopy(fixture.intake)
            future_creation["obligations"] = [base_obligation]
            future_creation["publicProjectionDigest"] = semantic_digest(
                {
                    "fixIds": [FIX_ID],
                    "obligations": [
                        {
                            "obligationId": base_obligation["obligationId"],
                            "status": "open",
                        }
                    ],
                }
            )
            creation_errors = intake_errors(
                future_creation,
                fixture.policy,
                policy_digest=fixture.policy_digest,
                repository_identity="github.com/crypta-network/cryptad",
                now=NOW,
            )
            self.assertTrue(
                any(
                    "generation time is future-dated" in error
                    for error in creation_errors
                )
            )

            future_resolution = copy.deepcopy(future_creation)
            obligation = future_resolution["obligations"][0]
            obligation["generatedAt"] = GENERATED
            obligation["status"] = "resolved"
            obligation["resolvedAt"] = future
            future_resolution["publicProjectionDigest"] = semantic_digest(
                {
                    "fixIds": [FIX_ID],
                    "obligations": [
                        {
                            "obligationId": obligation["obligationId"],
                            "status": "resolved",
                        }
                    ],
                }
            )
            resolution_errors = intake_errors(
                future_resolution,
                fixture.policy,
                policy_digest=fixture.policy_digest,
                repository_identity="github.com/crypta-network/cryptad",
                now=NOW,
            )
            self.assertTrue(
                any(
                    "resolution time is future-dated" in error
                    for error in resolution_errors
                )
            )

    def test_released_state_cannot_appear_without_prior_queue_and_completion(
        self,
    ) -> None:
        policy = read_json(
            Path(__file__).resolve().parents[2]
            / "stable-1.0-backport-release-train-policy.json"
        )
        with self.assertRaisesRegex(ValueError, "authenticated prior queue"):
            engine._authenticate_released_transitions(  # noqa: SLF001
                {
                    "fixes": [
                        {
                            "fixId": "stable-fix-" + "a" * 16,
                            "state": "released",
                        }
                    ]
                },
                None,
                None,
                None,
                None,
                None,
                policy,
                mock.Mock(),
                NOW,
            )

    def test_released_fix_requires_authenticated_publication_and_merges(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            publication_tip = _commit(
                fixture.root,
                "release-notes.md",
                "Stable maintenance metadata.\n",
                "release metadata",
            )
            _git(fixture.root, "branch", "release-tip", publication_tip)
            _git(fixture.root, "branch", "main", fixture.predecessor)
            _git(fixture.root, "switch", "main")
            _git(
                fixture.root,
                "merge",
                "--no-ff",
                "--no-edit",
                "release-tip",
            )
            main_merge = _git(fixture.root, "rev-parse", "HEAD")
            _git(fixture.root, "branch", "-f", "develop", fixture.predecessor)
            _git(fixture.root, "switch", "develop")
            develop_tip = _commit(
                fixture.root,
                "develop.txt",
                "continued development\n",
                "continued development",
            )
            _git(
                fixture.root,
                "merge",
                "--no-ff",
                "--no-edit",
                "release-tip",
            )
            develop_merge = _git(fixture.root, "rev-parse", "HEAD")
            inspector = GitInspector(
                fixture.root,
                expected_repository_identity="github.com/crypta-network/cryptad",
            )
            main_evidence = engine._merge_evidence_dict(  # noqa: SLF001
                inspector.verify_no_ff_merge(
                    merge_commit=main_merge,
                    first_parent=fixture.predecessor,
                    merged_tip=publication_tip,
                    protected_ref="refs/heads/main",
                    protected_tip=main_merge,
                    expected_protected_ref="refs/heads/main",
                    workflow_attestation_digest=(
                        inspector.reconciliation_attestation_digest(
                            protected_ref="refs/heads/main",
                            protected_tip=main_merge,
                            merge_commit=main_merge,
                            first_parent=fixture.predecessor,
                            merged_tip=publication_tip,
                        )
                    ),
                )
            )
            develop_evidence = engine._merge_evidence_dict(  # noqa: SLF001
                inspector.verify_no_ff_merge(
                    merge_commit=develop_merge,
                    first_parent=develop_tip,
                    merged_tip=publication_tip,
                    protected_ref="refs/heads/develop",
                    protected_tip=develop_merge,
                    expected_protected_ref="refs/heads/develop",
                    workflow_attestation_digest=(
                        inspector.reconciliation_attestation_digest(
                            protected_ref="refs/heads/develop",
                            protected_tip=develop_merge,
                            merge_commit=develop_merge,
                            first_parent=develop_tip,
                            merged_tip=publication_tip,
                        )
                    ),
                )
            )
            release = {
                "releaseId": "stable-maintenance-301",
                "releaseClass": "maintenance",
                "buildVersion": "301",
                "tag": "v301",
            }
            queue_digest = _digest("1")
            authorization_digest = _digest("3")
            prior_fix = copy.deepcopy(fixture.intake["fixes"][0])
            previous_validation = engine._build_validation(  # noqa: SLF001
                generated_at=GENERATED,
                mode="validate-authorization",
                train_id="stable-train-301",
                release=release,
                policy_digest=fixture.policy_digest,
                queue_digest=queue_digest,
                plan_digest=_digest("2"),
                candidate_digest=_digest("4"),
                predecessor_commit=fixture.predecessor,
                candidate_commit=publication_tip,
                accepted=[prior_fix],
                deferred=[],
                evidence_results=[],
                unaccounted=[],
                state=engine.ValidationState(),
                authorization={
                    "authorizationDigest": authorization_digest,
                    "status": "valid",
                    "expiresAt": EVIDENCE_EXPIRES,
                    "role": "stable-maintenance-train-manager",
                },
            )
            validation_path = fixture.root / "inputs" / "prior-validation.json"
            write_json(validation_path, previous_validation)
            validation_file_digest = file_digest(validation_path)
            receipt = _publication_receipt(
                publication_tip,
                validation_file_digest,
                authorization_digest,
            )
            receipt_path = fixture.root / "inputs" / "prior-receipt.json"
            write_json(receipt_path, receipt)
            completion = {
                "schemaVersion": 1,
                "kind": "stable-1.0-release-train-completion",
                "generatedAt": GENERATED,
                "stableMilestone": "1.0",
                "trainId": "stable-train-301",
                "release": release,
                "policyDigest": fixture.policy_digest,
                "queueDigest": queue_digest,
                "validationDigest": validation_file_digest,
                "authorizationDigest": authorization_digest,
                "publicationReceiptDigest": file_digest(receipt_path),
                "publicationCommit": publication_tip,
                "tag": "v301",
                "lifecycleState": "pending-activation",
                "lifecycleReceiptDigest": None,
                "lifecycleLedgerDigest": None,
                "lifecycleDescriptorDigest": None,
                "mainMerge": main_evidence,
                "developMerge": develop_evidence,
                "hotfixPresentInDevelop": True,
                "reconciliationStatus": "verified",
                "reconciliationObligations": [],
                "carriedObligationIds": [],
                "status": "complete",
                "redaction": PASS_REDACTION,
            }
            completion["completionDigest"] = canonical_identity_digest(
                completion, "completionDigest"
            )
            completion_path = fixture.root / "inputs" / "completion-transition.json"
            write_json(completion_path, completion)
            completion_file_digest = file_digest(completion_path)
            released_fix = {
                "fixId": FIX_ID,
                "state": "released",
                "provenance": {"candidateCommit": fixture.fix_commit},
                "schedule": {"targetTrainId": "stable-train-301"},
                "evidence": [
                    {
                        "evidenceId": "stable-backport.release-completion",
                        "digest": completion_file_digest,
                        "predecessorCommit": fixture.predecessor,
                        "candidateCommit": publication_tip,
                        "generatedAt": GENERATED,
                    }
                ],
                "stateTransitions": [
                    {
                        "to": "released",
                        "evidenceDigest": completion_file_digest,
                        "occurredAt": GENERATED,
                    }
                ],
            }
            released_intake = {
                "generatedAt": GENERATED,
                "fixes": [released_fix],
            }
            inspector = GitInspector(
                fixture.root,
                expected_repository_identity="github.com/crypta-network/cryptad",
            )
            previous_queue = {
                "queueDigest": completion["queueDigest"],
                "fixes": [prior_fix],
                "obligations": [],
                "carriedObligationIds": [],
            }
            completion_handoff = _completion_handoff(
                completion,
                completion_file_digest,
                previous_validation,
                validation_file_digest,
            )
            handoff_path = fixture.root / "inputs" / "completion-handoff.json"
            write_json(handoff_path, completion_handoff)
            handoff_loaded = (handoff_path, completion_handoff, file_digest(handoff_path))
            previous_validation_loaded = (
                validation_path, previous_validation, validation_file_digest
            )
            receipt_loaded = (receipt_path, receipt, file_digest(receipt_path))
            def authenticate_released(
                intake: dict[str, object], handoff=handoff_loaded
            ) -> None:
                engine._authenticate_released_transitions(  # noqa: SLF001
                    intake,
                    previous_queue,
                    (completion_path, completion, completion_file_digest),
                    handoff,
                    previous_validation_loaded,
                    receipt_loaded,
                    fixture.policy, inspector, NOW,
                )
            with self.assertRaisesRegex(ValueError, "protected-workflow completion handoff"):
                authenticate_released(released_intake, None)
            authenticate_released(released_intake)
            for event_path in (
                ("generatedAt",),
                ("fixes", 0, "evidence", 0, "generatedAt"),
                ("fixes", 0, "stateTransitions", 0, "occurredAt"),
            ):
                with self.subTest(backdated_event=event_path):
                    backdated = copy.deepcopy(released_intake)
                    target: object = backdated
                    for segment in event_path[:-1]:
                        target = target[segment]  # type: ignore[index]
                    target[event_path[-1]] = "2026-01-15T11:59:59Z"  # type: ignore[index]
                    with self.assertRaisesRegex(
                        ValueError,
                        "released fix transition predates authenticated "
                        "publication completion",
                    ):
                        authenticate_released(backdated)

            _git(
                fixture.root,
                "switch",
                "-c",
                "manual-successor-reconciliation",
                fixture.predecessor,
            )
            manual_parent = _commit(
                fixture.root,
                "node.txt",
                "base\nsuccessor context\n",
                "successor develop context",
            )
            with self.assertRaises(subprocess.CalledProcessError):
                _git(
                    fixture.root,
                    "merge",
                    "--no-ff",
                    "--no-edit",
                    publication_tip,
                )
            manual_merge = _commit(
                fixture.root,
                "node.txt",
                "base\nsuccessor context\n",
                "manual successor reconciliation",
            )
            manual_completion = copy.deepcopy(completion)
            manual_completion["developMerge"] = {
                "mergeCommit": manual_merge,
                "firstParent": manual_parent,
                "mergedTip": publication_tip,
                "protectedRef": "refs/heads/develop",
                "protectedTip": manual_merge,
                "parentCount": 2,
                "graphVerified": True,
                "workflowAttestationDigest": (
                    inspector.reconciliation_attestation_digest(
                        protected_ref="refs/heads/develop",
                        protected_tip=manual_merge,
                        merge_commit=manual_merge,
                        first_parent=manual_parent,
                        merged_tip=publication_tip,
                    )
                ),
            }
            manual_completion["completionDigest"] = canonical_identity_digest(
                manual_completion,
                "completionDigest",
            )
            normalized_completion = (
                engine._verify_completion_release_and_reconciliation(  # noqa: SLF001
                    manual_completion,
                    receipt,
                    file_digest(receipt_path),
                    inspector=inspector,
                    release=release,
                    train_id="stable-train-301",
                    lane="routine-maintenance",
                    policy_digest=fixture.policy_digest,
                    queue_digest=queue_digest,
                    validation_file_digest=validation_file_digest,
                    authorization_digest=authorization_digest,
                    candidate_commit=publication_tip,
                    expected_carried_obligation_ids=[],
                    source_fix_ids=[FIX_ID],
                    reconciliation_policy=fixture.policy[
                        "postReleaseReconciliation"
                    ],
                )
            )
            manual_completion_path = (
                fixture.root / "inputs" / "manual-transition-completion.json"
            )
            write_json(manual_completion_path, normalized_completion)
            manual_completion_file_digest = file_digest(manual_completion_path)
            manual_released_fix = copy.deepcopy(released_fix)
            manual_released_fix["evidence"][0][
                "digest"
            ] = manual_completion_file_digest
            manual_released_fix["stateTransitions"][-1][
                "evidenceDigest"
            ] = manual_completion_file_digest
            manual_handoff = _completion_handoff(
                normalized_completion,
                manual_completion_file_digest,
                previous_validation,
                validation_file_digest,
            )
            manual_handoff_path = (
                fixture.root / "inputs" / "manual-transition-handoff.json"
            )
            write_json(manual_handoff_path, manual_handoff)
            current_intake = {
                "generatedAt": GENERATED,
                "fixes": [manual_released_fix],
                "obligations": normalized_completion[
                    "reconciliationObligations"
                ],
            }
            engine._authenticate_released_transitions(  # noqa: SLF001
                current_intake,
                previous_queue,
                (
                    manual_completion_path,
                    normalized_completion,
                    manual_completion_file_digest,
                ),
                (
                    manual_handoff_path,
                    manual_handoff,
                    file_digest(manual_handoff_path),
                ),
                (validation_path, previous_validation, validation_file_digest),
                (receipt_path, receipt, file_digest(receipt_path)),
                fixture.policy,
                inspector,
                NOW,
            )
            with self.assertRaisesRegex(
                ValueError,
                "omits an exact completion-created reconciliation obligation",
            ):
                engine._authenticate_released_transitions(  # noqa: SLF001
                    {
                        "generatedAt": GENERATED,
                        "fixes": [manual_released_fix],
                        "obligations": [],
                    },
                    previous_queue,
                    (
                        manual_completion_path,
                        normalized_completion,
                        manual_completion_file_digest,
                    ),
                    (
                        manual_handoff_path,
                        manual_handoff,
                        file_digest(manual_handoff_path),
                    ),
                    (
                        validation_path,
                        previous_validation,
                        validation_file_digest,
                    ),
                    (receipt_path, receipt, file_digest(receipt_path)),
                    fixture.policy,
                    inspector,
                    NOW,
                )
            for invalid_predecessor in (None, publication_tip):
                invalid_binding = copy.deepcopy(released_fix)
                invalid_binding["evidence"][0][
                    "predecessorCommit"
                ] = invalid_predecessor
                with self.subTest(
                    predecessor=invalid_predecessor
                ), self.assertRaisesRegex(ValueError, "exact completion artifact"):
                    engine._authenticate_released_transitions(  # noqa: SLF001
                        {
                            "generatedAt": GENERATED,
                            "fixes": [invalid_binding],
                        },
                        previous_queue,
                        (
                            completion_path,
                            completion,
                            completion_file_digest,
                        ),
                        handoff_loaded,
                        (
                            validation_path,
                            previous_validation,
                            validation_file_digest,
                        ),
                        (receipt_path, receipt, file_digest(receipt_path)),
                        fixture.policy,
                        inspector,
                        NOW,
                    )
            durable_handoff = copy.deepcopy(completion_handoff)
            durable_handoff["producer"].update(
                {
                    "operation": "reauthenticate-predecessor-completion",
                    "evidenceSource": "protected-input-bundle",
                    "evidenceDigest": _digest("f"),
                }
            )
            durable_handoff["producer"].pop("artifactName")
            durable_handoff["handoffDigest"] = canonical_identity_digest(
                durable_handoff, "handoffDigest"
            )
            durable_handoff_path = (
                fixture.root / "inputs" / "durable-completion-handoff.json"
            )
            write_json(durable_handoff_path, durable_handoff)
            engine._authenticate_released_transitions(  # noqa: SLF001
                released_intake,
                previous_queue,
                (completion_path, completion, completion_file_digest),
                (
                    durable_handoff_path,
                    durable_handoff,
                    file_digest(durable_handoff_path),
                ),
                (
                    validation_path,
                    previous_validation,
                    validation_file_digest,
                ),
                (receipt_path, receipt, file_digest(receipt_path)),
                fixture.policy,
                inspector,
                NOW,
            )
            off_branch_handoff = copy.deepcopy(completion_handoff)
            off_branch_handoff["observedProtectedRefs"]["main"][
                "tip"
            ] = publication_tip
            off_branch_handoff["handoffDigest"] = canonical_identity_digest(
                off_branch_handoff, "handoffDigest"
            )
            off_branch_path = (
                fixture.root / "inputs" / "off-branch-completion-handoff.json"
            )
            write_json(off_branch_path, off_branch_handoff)
            with self.assertRaisesRegex(
                ValueError, "protected branch reconciliation"
            ):
                engine._authenticate_released_transitions(  # noqa: SLF001
                    released_intake,
                    previous_queue,
                    (completion_path, completion, completion_file_digest),
                    (
                        off_branch_path,
                        off_branch_handoff,
                        file_digest(off_branch_path),
                    ),
                    (
                        validation_path,
                        previous_validation,
                        validation_file_digest,
                    ),
                    (receipt_path, receipt, file_digest(receipt_path)),
                    fixture.policy,
                    inspector,
                    NOW,
                )

            superseded_fix = copy.deepcopy(prior_fix)
            superseded_fix["state"] = "superseded"
            superseded_fix["supersedingFixId"] = (
                "stable-fix-bcdefghijklmnopq"
            )
            superseded_fix["stateTransitions"].append(
                {
                    "sequence": len(superseded_fix["stateTransitions"]),
                    "from": "verified",
                    "to": "superseded",
                    "occurredAt": GENERATED,
                    "actorRole": "stable-triage-manager",
                    "reasonCode": "replacement-reviewed",
                    "evidenceDigest": _digest("f"),
                }
            )
            with self.assertRaisesRegex(
                ValueError, "transition from verified to released"
            ):
                engine._authenticate_released_transitions(  # noqa: SLF001
                    {
                        "generatedAt": GENERATED,
                        "fixes": [superseded_fix],
                    },
                    previous_queue,
                    (completion_path, completion, completion_file_digest),
                    handoff_loaded,
                    (validation_path, previous_validation, validation_file_digest),
                    (receipt_path, receipt, file_digest(receipt_path)),
                    fixture.policy,
                    inspector,
                    NOW,
                )

            duplicate_merge = copy.deepcopy(completion)
            duplicate_merge["developMerge"] = copy.deepcopy(main_evidence)
            duplicate_merge["developMerge"]["protectedRef"] = (
                "refs/heads/develop"
            )
            duplicate_merge["developMerge"]["workflowAttestationDigest"] = (
                inspector.reconciliation_attestation_digest(
                    protected_ref="refs/heads/develop",
                    protected_tip=main_merge,
                    merge_commit=main_merge,
                    first_parent=fixture.predecessor,
                    merged_tip=publication_tip,
                )
            )
            duplicate_merge["completionDigest"] = canonical_identity_digest(
                duplicate_merge, "completionDigest"
            )
            duplicate_path = fixture.root / "inputs" / "duplicate-merge.json"
            write_json(duplicate_path, duplicate_merge)
            duplicate_handoff = _completion_handoff(
                duplicate_merge,
                file_digest(duplicate_path),
                previous_validation,
                validation_file_digest,
            )
            duplicate_handoff_path = (
                fixture.root / "inputs" / "duplicate-completion-handoff.json"
            )
            write_json(duplicate_handoff_path, duplicate_handoff)
            with self.assertRaisesRegex(ValueError, "reconciliation identities"):
                engine._authenticate_released_transitions(  # noqa: SLF001
                    released_intake,
                    previous_queue,
                    (
                        duplicate_path,
                        duplicate_merge,
                        file_digest(duplicate_path),
                    ),
                    (
                        duplicate_handoff_path,
                        duplicate_handoff,
                        file_digest(duplicate_handoff_path),
                    ),
                    (validation_path, previous_validation, validation_file_digest),
                    (receipt_path, receipt, file_digest(receipt_path)),
                    fixture.policy,
                    inspector,
                    NOW,
                )

            with self.assertRaisesRegex(
                ValueError, "transition from verified to released"
            ):
                engine._authenticate_released_transitions(  # noqa: SLF001
                    released_intake,
                    {
                        "queueDigest": completion["queueDigest"],
                        "fixes": [],
                        "obligations": [],
                        "carriedObligationIds": [],
                    },
                    (completion_path, completion, completion_file_digest),
                    handoff_loaded,
                    (validation_path, previous_validation, validation_file_digest),
                    (receipt_path, receipt, file_digest(receipt_path)),
                    fixture.policy,
                    inspector,
                    NOW,
                )
            omitted_validation = copy.deepcopy(previous_validation)
            omitted_validation["includedFixIds"] = []
            omitted_validation["validationDigest"] = canonical_identity_digest(
                omitted_validation, "validationDigest"
            )
            omitted_path = fixture.root / "inputs" / "omitted-validation.json"
            write_json(omitted_path, omitted_validation)
            omitted_handoff = _completion_handoff(
                completion,
                completion_file_digest,
                omitted_validation,
                file_digest(omitted_path),
            )
            omitted_handoff_path = (
                fixture.root / "inputs" / "omitted-completion-handoff.json"
            )
            write_json(omitted_handoff_path, omitted_handoff)
            with self.assertRaisesRegex(ValueError, "prior authorized validation"):
                engine._authenticate_released_transitions(  # noqa: SLF001
                    released_intake,
                    previous_queue,
                    (completion_path, completion, completion_file_digest),
                    (
                        omitted_handoff_path,
                        omitted_handoff,
                        file_digest(omitted_handoff_path),
                    ),
                    (
                        omitted_path,
                        omitted_validation,
                        file_digest(omitted_path),
                    ),
                    (receipt_path, receipt, file_digest(receipt_path)),
                    fixture.policy,
                    inspector,
                    NOW,
                )

            forged = copy.deepcopy(completion)
            forged["mainMerge"]["mergeCommit"] = "a" * 40
            forged["mainMerge"]["protectedTip"] = "a" * 40
            forged["completionDigest"] = canonical_identity_digest(
                forged, "completionDigest"
            )
            forged_path = fixture.root / "inputs" / "forged-completion.json"
            write_json(forged_path, forged)
            forged_handoff = _completion_handoff(
                forged,
                file_digest(forged_path),
                previous_validation,
                validation_file_digest,
            )
            forged_handoff_path = (
                fixture.root / "inputs" / "forged-completion-handoff.json"
            )
            write_json(forged_handoff_path, forged_handoff)
            with self.assertRaisesRegex(
                (ValueError, engine.GitInspectionError),
                "commit|merge|reconciliation|identity",
            ):
                engine._authenticate_released_transitions(  # noqa: SLF001
                    released_intake,
                    previous_queue,
                    (forged_path, forged, file_digest(forged_path)),
                    (
                        forged_handoff_path,
                        forged_handoff,
                        file_digest(forged_handoff_path),
                    ),
                    (
                        validation_path,
                        previous_validation,
                        validation_file_digest,
                    ),
                    (receipt_path, receipt, file_digest(receipt_path)),
                    fixture.policy,
                    inspector,
                    NOW,
                )

    def test_classification_evidence_is_policy_driven(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            inspector = GitInspector(
                fixture.root,
                expected_repository_identity="github.com/crypta-network/cryptad",
            )
            fix = _fix(inspector, fixture.fix_commit, fixture.candidate)
            fix["evidence"] = fix["evidence"][:-1]

            errors = fix_record_errors(fix, fixture.policy, now=NOW)

            self.assertTrue(
                any("classification evidence" in error for error in errors),
                errors,
            )

    def test_platform_api_addition_and_deprecation_require_exact_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            inspector = GitInspector(
                fixture.root,
                expected_repository_identity="github.com/crypta-network/cryptad",
            )
            for classification in (
                "platform-api-compatible-addition",
                "platform-api-deprecation",
            ):
                with self.subTest(classification=classification):
                    fix = _fix(
                        inspector,
                        fixture.fix_commit,
                        fixture.candidate,
                        classification=classification,
                    )
                    self.assertEqual(
                        fix_record_errors(fix, fixture.policy, now=NOW), []
                    )
                    fix["affectedScope"]["platformApiIds"] = []
                    self.assertTrue(
                        any(
                            "exact API scope" in error
                            for error in fix_record_errors(
                                fix, fixture.policy, now=NOW
                            )
                        )
                    )

    def test_security_fix_binds_embargo_projection_severity_and_lane(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            inspector = GitInspector(
                fixture.root,
                expected_repository_identity="github.com/crypta-network/cryptad",
            )
            fix = _security_fix(
                inspector,
                fixture.fix_commit,
                fixture.candidate,
            )
            self.assertEqual(fix_record_errors(fix, fixture.policy, now=NOW), [])

            wrong_lane = copy.deepcopy(fix)
            wrong_lane["disposition"] = "routine-maintenance"
            wrong_lane["releaseLane"] = "routine-maintenance"
            self.assertTrue(
                any(
                    "wrong lane" in error
                    for error in fix_record_errors(
                        wrong_lane, fixture.policy, now=NOW
                    )
                )
            )

            noncritical = _security_fix(
                inspector,
                fixture.fix_commit,
                fixture.candidate,
                severity="high",
            )
            noncritical["disposition"] = "security-hotfix"
            noncritical["releaseLane"] = "security-hotfix"
            self.assertTrue(
                any(
                    "noncritical" in error
                    for error in fix_record_errors(
                        noncritical, fixture.policy, now=NOW
                    )
                )
            )

            substituted = copy.deepcopy(fix)
            substituted["security"]["publicProjectionDigest"] = _digest("f")
            self.assertTrue(
                any(
                    "public security projection" in error
                    for error in fix_record_errors(
                        substituted, fixture.policy, now=NOW
                    )
                )
            )

            leaked = copy.deepcopy(fix)
            leaked["security"]["publicSafeSummary"] = (
                "See https://private.example.invalid/incidents/287"
            )
            self.assertTrue(fix_record_errors(leaked, fixture.policy, now=NOW))

    def test_policy_protected_evidence_cannot_claim_public_visibility(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            inspector = GitInspector(
                fixture.root,
                expected_repository_identity="github.com/crypta-network/cryptad",
            )
            fix = _security_fix(
                inspector,
                fixture.fix_commit,
                fixture.candidate,
            )
            incident_evidence = next(
                row
                for row in fix["evidence"]
                if row["evidenceId"]
                == "stable-backport.security-incident-scope"
            )
            incident_evidence["visibility"] = "public"

            errors = fix_record_errors(fix, fixture.policy, now=NOW)

            self.assertTrue(
                any("policy-protected evidence as public" in row for row in errors),
                errors,
            )

    def test_overdue_critical_deferral_remains_a_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            inspector = GitInspector(
                fixture.root,
                expected_repository_identity="github.com/crypta-network/cryptad",
            )
            fix = _security_fix(
                inspector,
                fixture.fix_commit,
                fixture.candidate,
            )
            fix["disposition"] = "deferred"
            fix["releaseLane"] = None
            fix["state"] = "deferred"
            fix["stateTransitions"] = fix["stateTransitions"][:3]
            fix["stateTransitions"].append(
                {
                    "sequence": 3,
                    "from": "accepted",
                    "to": "deferred",
                    "occurredAt": "2026-01-15T06:00:00Z",
                    "actorRole": "stable-security-decision-manager",
                    "reasonCode": "bounded-security-decision",
                    "evidenceDigest": _digest("d"),
                }
            )
            fix["schedule"]["deadlineAt"] = None
            fix["schedule"]["decisionAt"] = "2026-01-15T06:00:00Z"
            fix["schedule"]["reviewAt"] = "2026-01-15T11:00:00Z"
            fix["evidence"].append(
                _evidence(
                    fixture.predecessor,
                    fixture.candidate,
                    "stable-backport.critical-deferral-security-decision",
                    "e",
                )
            )
            mismatched_decision_errors = fix_record_errors(
                fix, fixture.policy, now=NOW
            )
            self.assertTrue(
                any(
                    "bounded security decision" in error
                    for error in mismatched_decision_errors
                ),
                mismatched_decision_errors,
            )
            fix["evidence"][-1]["digest"] = _digest("d")

            overdue_errors = fix_record_errors(
                fix, fixture.policy, now=NOW
            )

            self.assertTrue(
                any("bounded security decision" in row for row in overdue_errors),
                overdue_errors,
            )
            future_review = copy.deepcopy(fix)
            future_review["schedule"]["reviewAt"] = "2026-01-15T13:00:00Z"
            self.assertEqual(
                fix_record_errors(future_review, fixture.policy, now=NOW),
                [],
            )
            reset_clock = copy.deepcopy(fix)
            reset_clock["schedule"]["decisionAt"] = "2026-01-15T12:00:00Z"
            reset_clock["schedule"]["reviewAt"] = "2026-01-16T12:00:00Z"
            reset_errors = fix_record_errors(
                reset_clock, fixture.policy, now=NOW
            )
            self.assertTrue(
                any("bounded security decision" in row for row in reset_errors),
                reset_errors,
            )

    def test_completed_critical_deferral_retains_time_and_evidence_gates(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            inspector = GitInspector(
                fixture.root,
                expected_repository_identity="github.com/crypta-network/cryptad",
            )
            fix = _security_fix(
                inspector,
                fixture.fix_commit,
                fixture.candidate,
            )
            states = (
                "submitted",
                "triaged",
                "accepted",
                "deferred",
                "triaged",
                "accepted",
                "scheduled",
                "landed",
                "verified",
            )

            def set_history(
                hours: tuple[int, ...],
                transition_states: tuple[str, ...] = states,
            ) -> None:
                fix["stateTransitions"] = []
                prior = None
                for sequence, (state, hour) in enumerate(
                    zip(transition_states, hours, strict=True)
                ):
                    fix["stateTransitions"].append(
                        {
                            "sequence": sequence,
                            "from": prior,
                            "to": state,
                            "occurredAt": (
                                NOW + dt.timedelta(hours=hour)
                            ).isoformat().replace("+00:00", "Z"),
                            "actorRole": (
                                "stable-security-decision-manager"
                                if state == "deferred"
                                else "stable-triage-manager"
                            ),
                            "reasonCode": (
                                "bounded-security-decision"
                                if state == "deferred"
                                else "policy-eligible"
                            ),
                            "evidenceDigest": (
                                _digest("d")
                                if state == "deferred"
                                else _digest(str(sequence + 1))
                            ),
                        }
                    )
                    prior = state
                fix["schedule"]["submittedAt"] = fix["stateTransitions"][0][
                    "occurredAt"
                ]
                fix["schedule"]["decisionAt"] = fix["stateTransitions"][2][
                    "occurredAt"
                ]

            set_history((-60, -58, -56, -55, -20, -18, -16, -14, -12))

            missing_decision_errors = fix_record_errors(
                fix, fixture.policy, now=NOW
            )

            self.assertTrue(
                any(
                    "bounded security decision" in error
                    for error in missing_decision_errors
                ),
                missing_decision_errors,
            )
            fix["evidence"].append(
                _evidence(
                    fixture.predecessor,
                    fixture.candidate,
                    "stable-backport.critical-deferral-security-decision",
                    "d",
                )
            )

            overdue_errors = fix_record_errors(
                fix, fixture.policy, now=NOW
            )

            self.assertTrue(
                any(
                    "critical-deferral policy window" in error
                    for error in overdue_errors
                ),
                overdue_errors,
            )
            set_history((-60, -58, -56, -55, -32, -30, -28, -26, -24))
            self.assertEqual(
                fix_record_errors(fix, fixture.policy, now=NOW),
                [],
            )
            repeated_states = (
                "submitted",
                "triaged",
                "accepted",
                "deferred",
                "triaged",
                "accepted",
                "deferred",
                "triaged",
                "accepted",
                "scheduled",
                "landed",
                "verified",
            )
            set_history(
                (-80, -78, -76, -75, -52, -50, -49, -14, -12, -10, -8, -6),
                repeated_states,
            )
            repeated_errors = fix_record_errors(
                fix, fixture.policy, now=NOW
            )
            self.assertTrue(
                any(
                    "critical-deferral policy window" in error
                    for error in repeated_errors
                ),
                repeated_errors,
            )

    def test_deferred_state_cannot_retain_release_lane_routing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            inspector = GitInspector(
                fixture.root,
                expected_repository_identity="github.com/crypta-network/cryptad",
            )
            routine = _fix(
                inspector,
                fixture.fix_commit,
                fixture.candidate,
            )
            routine["state"] = "deferred"
            routine["stateTransitions"] = routine["stateTransitions"][:3]
            routine["stateTransitions"].append(
                {
                    "sequence": 3,
                    "from": "accepted",
                    "to": "deferred",
                    "occurredAt": "2026-01-15T06:00:00Z",
                    "actorRole": "stable-triage-manager",
                    "reasonCode": "needs-more-evidence",
                    "evidenceDigest": _digest("d"),
                }
            )
            routine["schedule"]["reviewAt"] = None

            routine_errors = fix_record_errors(
                routine, fixture.policy, now=NOW
            )

            self.assertTrue(
                any(
                    "deferred state contradicts its disposition" in row
                    for row in routine_errors
                ),
                routine_errors,
            )
            self.assertTrue(
                any(
                    "lacks owner, rationale, or review time" in row
                    for row in routine_errors
                ),
                routine_errors,
            )

            critical = _security_fix(
                inspector,
                fixture.fix_commit,
                fixture.candidate,
            )
            critical["state"] = "deferred"
            critical["stateTransitions"] = critical["stateTransitions"][:3]
            critical["stateTransitions"].append(
                {
                    "sequence": 3,
                    "from": "accepted",
                    "to": "deferred",
                    "occurredAt": "2026-01-15T06:00:00Z",
                    "actorRole": "stable-security-decision-manager",
                    "reasonCode": "needs-more-evidence",
                    "evidenceDigest": _digest("e"),
                }
            )
            critical["schedule"]["reviewAt"] = None

            critical_errors = fix_record_errors(
                critical, fixture.policy, now=NOW
            )

            self.assertTrue(
                any(
                    "deferred state contradicts its disposition" in row
                    for row in critical_errors
                ),
                critical_errors,
            )
            self.assertTrue(
                any(
                    "lacks a bounded security decision" in row
                    for row in critical_errors
                ),
                critical_errors,
            )

    def test_unresolved_critical_rejection_and_supersession_remain_nonwaivable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            inspector = GitInspector(
                fixture.root,
                expected_repository_identity="github.com/crypta-network/cryptad",
            )
            rejected = _security_fix(
                inspector,
                fixture.fix_commit,
                fixture.candidate,
            )
            rejected["state"] = "rejected"
            rejected["stateTransitions"] = rejected["stateTransitions"][:2]
            rejected["stateTransitions"].append(
                {
                    "sequence": 2,
                    "from": "triaged",
                    "to": "rejected",
                    "occurredAt": "2026-01-15T04:00:00Z",
                    "actorRole": "stable-security-decision-manager",
                    "reasonCode": "not-reproducible",
                    "evidenceDigest": _digest("d"),
                }
            )
            rejected_intake = _intake(fixture.policy_digest, rejected)
            self.assertEqual(
                intake_errors(
                    rejected_intake,
                    fixture.policy,
                    policy_digest=fixture.policy_digest,
                    repository_identity="github.com/crypta-network/cryptad",
                    now=NOW,
                ),
                [],
            )
            rejected_queue, queue_errors = build_queue(
                rejected_intake,
                None,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )
            self.assertEqual(queue_errors, [])
            self.assertEqual(rejected_queue["criticalFixIds"], [FIX_ID])

            superseded = _security_fix(
                inspector,
                fixture.fix_commit,
                fixture.candidate,
            )
            superseded["state"] = "superseded"
            superseded["supersedingFixId"] = (
                "stable-fix-zzzzzzzzzzzzzzzz"
            )
            superseded["stateTransitions"].append(
                {
                    "sequence": len(superseded["stateTransitions"]),
                    "from": "verified",
                    "to": "superseded",
                    "occurredAt": GENERATED,
                    "actorRole": "stable-security-decision-manager",
                    "reasonCode": "replacement-reviewed",
                    "evidenceDigest": _digest("e"),
                }
            )
            replacement = _security_fix(
                inspector,
                fixture.fix_commit,
                fixture.candidate,
                severity="high",
            )
            replacement["fixId"] = superseded["supersedingFixId"]
            replacement["provenance"]["candidateCommit"] = "e" * 40
            for evidence in replacement["evidence"]:
                evidence["candidateCommit"] = "e" * 40
            replacement["publicProjectionDigest"] = semantic_digest(
                {
                    "fixId": replacement["fixId"],
                    "classification": replacement["classification"],
                    "publicSummary": replacement["publicSummary"],
                }
            )
            replacement["security"]["publicProjectionDigest"] = semantic_digest(
                {
                    "fixId": replacement["fixId"],
                    "incidentOpaqueId": replacement["security"][
                        "incidentOpaqueId"
                    ],
                    "advisoryOpaqueId": replacement["security"][
                        "advisoryOpaqueId"
                    ],
                    "severity": replacement["security"]["severity"],
                    "disclosureState": replacement["security"][
                        "disclosureState"
                    ],
                    "publicSafeSummary": replacement["security"][
                        "publicSafeSummary"
                    ],
                }
            )
            superseded_intake = _intake(
                fixture.policy_digest, superseded
            )
            superseded_intake["fixes"].append(replacement)
            superseded_intake["publicProjectionDigest"] = semantic_digest(
                {
                    "fixIds": [
                        superseded["fixId"],
                        replacement["fixId"],
                    ],
                    "obligations": [],
                }
            )
            _bind_intake_evidence(
                superseded_intake,
                None,
                policy_digest=fixture.policy_digest,
                candidate_commit=fixture.candidate,
            )

            replacement_errors = intake_errors(
                superseded_intake,
                fixture.policy,
                policy_digest=fixture.policy_digest,
                repository_identity="github.com/crypta-network/cryptad",
                now=NOW,
            )

            self.assertTrue(
                any(
                    "incident- and severity-equivalent replacement" in row
                    for row in replacement_errors
                ),
                replacement_errors,
            )

    def test_critical_supersession_chain_must_terminate_without_a_cycle(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            inspector = GitInspector(
                fixture.root,
                expected_repository_identity="github.com/crypta-network/cryptad",
            )
            first = _security_fix(
                inspector,
                fixture.fix_commit,
                fixture.candidate,
            )
            second = copy.deepcopy(first)
            second["fixId"] = "stable-fix-qrstuvwxyzabcdef"
            second["provenance"]["candidateCommit"] = "e" * 40
            for evidence in second["evidence"]:
                evidence["candidateCommit"] = "e" * 40
            for row, replacement_id, character in (
                (first, second["fixId"], "e"),
                (second, first["fixId"], "f"),
            ):
                row["state"] = "superseded"
                row["supersedingFixId"] = replacement_id
                row["stateTransitions"].append(
                    {
                        "sequence": len(row["stateTransitions"]),
                        "from": "verified",
                        "to": "superseded",
                        "occurredAt": GENERATED,
                        "actorRole": "stable-security-decision-manager",
                        "reasonCode": "replacement-reviewed",
                        "evidenceDigest": _digest(character),
                    }
                )
                row["publicProjectionDigest"] = semantic_digest(
                    {
                        "fixId": row["fixId"],
                        "classification": row["classification"],
                        "publicSummary": row["publicSummary"],
                    }
                )
                row["security"]["publicProjectionDigest"] = semantic_digest(
                    {
                        "fixId": row["fixId"],
                        "incidentOpaqueId": row["security"]["incidentOpaqueId"],
                        "advisoryOpaqueId": row["security"]["advisoryOpaqueId"],
                        "severity": row["security"]["severity"],
                        "disclosureState": row["security"]["disclosureState"],
                        "publicSafeSummary": row["security"]["publicSafeSummary"],
                    }
                )
            intake = _intake(fixture.policy_digest, first)
            intake["fixes"].append(second)
            intake["publicProjectionDigest"] = semantic_digest(
                {
                    "fixIds": sorted([first["fixId"], second["fixId"]]),
                    "obligations": [],
                }
            )
            _bind_intake_evidence(
                intake,
                None,
                policy_digest=fixture.policy_digest,
                candidate_commit=fixture.candidate,
            )

            errors = intake_errors(
                intake,
                fixture.policy,
                policy_digest=fixture.policy_digest,
                repository_identity="github.com/crypta-network/cryptad",
                now=NOW,
            )

            self.assertTrue(
                any("supersession chain is cyclic" in row for row in errors),
                errors,
            )

    def test_critical_security_transition_windows_use_recorded_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            inspector = GitInspector(
                fixture.root,
                expected_repository_identity="github.com/crypta-network/cryptad",
            )
            valid = _security_fix(
                inspector,
                fixture.fix_commit,
                fixture.candidate,
            )
            self.assertEqual(
                fix_record_errors(valid, fixture.policy, now=NOW),
                [],
            )
            for delayed_stage, expected_label in (
                ("intake", "intake-to-triage"),
                ("triage", "triage-to-decision"),
                ("accepted", "accepted-to-scheduled"),
            ):
                with self.subTest(stage=delayed_stage):
                    late = copy.deepcopy(valid)
                    start = NOW - dt.timedelta(hours=72)
                    triaged = start + dt.timedelta(
                        hours=5 if delayed_stage == "intake" else 2
                    )
                    accepted = triaged + dt.timedelta(
                        hours=9 if delayed_stage == "triage" else 2
                    )
                    scheduled = accepted + dt.timedelta(
                        hours=13 if delayed_stage == "accepted" else 2
                    )
                    times = (
                        start,
                        triaged,
                        accepted,
                        scheduled,
                        scheduled + dt.timedelta(hours=2),
                        scheduled + dt.timedelta(hours=4),
                    )
                    for transition, occurred_at in zip(
                        late["stateTransitions"], times, strict=True
                    ):
                        transition["occurredAt"] = (
                            occurred_at.isoformat().replace("+00:00", "Z")
                        )
                    late["schedule"]["submittedAt"] = late["stateTransitions"][0][
                        "occurredAt"
                    ]
                    late["schedule"]["decisionAt"] = late["stateTransitions"][2][
                        "occurredAt"
                    ]

                    errors = fix_record_errors(late, fixture.policy, now=NOW)

                    self.assertTrue(
                        any(expected_label in error for error in errors),
                        errors,
                    )

            for label, states, hours, expected_label in (
                (
                    "reentered-accepted",
                    (
                        "submitted",
                        "triaged",
                        "accepted",
                        "deferred",
                        "triaged",
                        "accepted",
                        "scheduled",
                        "landed",
                        "verified",
                    ),
                    (-30, -28, -26, -25, -24, -22, -5, -4, -3),
                    "accepted-to-scheduled",
                ),
                (
                    "open-accepted",
                    ("submitted", "triaged", "accepted"),
                    (-20, -18, -13),
                    "accepted-to-scheduled",
                ),
            ):
                with self.subTest(stage=label):
                    late = copy.deepcopy(valid)
                    late["stateTransitions"] = []
                    prior = None
                    for sequence, (state, hour) in enumerate(
                        zip(states, hours, strict=True)
                    ):
                        late["stateTransitions"].append(
                            {
                                "sequence": sequence,
                                "from": prior,
                                "to": state,
                                "occurredAt": (
                                    NOW + dt.timedelta(hours=hour)
                                ).isoformat().replace("+00:00", "Z"),
                                "actorRole": "stable-triage-manager",
                                "reasonCode": "policy-eligible",
                                "evidenceDigest": _digest(str(sequence + 1)),
                            }
                        )
                        prior = state
                    late["state"] = states[-1]
                    late["schedule"]["submittedAt"] = late[
                        "stateTransitions"
                    ][0]["occurredAt"]
                    late["schedule"]["decisionAt"] = late[
                        "stateTransitions"
                    ][2]["occurredAt"]

                    errors = fix_record_errors(late, fixture.policy, now=NOW)

                    self.assertTrue(
                        any(expected_label in error for error in errors),
                        errors,
                    )

    def test_component_specific_stable_fix_classes_bind_required_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            inspector = GitInspector(
                fixture.root,
                expected_repository_identity="github.com/crypta-network/cryptad",
            )
            for classification in (
                "stable-catalog-app-patch",
                "packaging-installer-fix",
                "release-tooling-fix",
                "documentation-support-fix",
            ):
                with self.subTest(classification=classification):
                    fix = _fix(
                        inspector,
                        fixture.fix_commit,
                        fixture.candidate,
                        classification=classification,
                    )
                    self.assertEqual(
                        fix_record_errors(fix, fixture.policy, now=NOW),
                        [],
                    )

    def test_breaking_and_unsupported_work_cannot_enter_stable_lane(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            inspector = GitInspector(
                fixture.root,
                expected_repository_identity="github.com/crypta-network/cryptad",
            )
            for classification in ("breaking-change", "unsupported-feature-change"):
                with self.subTest(classification=classification):
                    fix = _fix(inspector, fixture.fix_commit, fixture.candidate)
                    fix["classification"] = classification
                    self.assertTrue(
                        any(
                            "never eligible" in error or "not eligible" in error
                            for error in fix_record_errors(
                                fix, fixture.policy, now=NOW
                            )
                        )
                    )

    def test_unresolved_fix_cannot_disappear_from_next_queue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            first, errors = build_queue(
                fixture.intake,
                None,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )
            self.assertEqual(errors, [])
            next_intake = copy.deepcopy(fixture.intake)
            next_intake["previousQueueDigest"] = first["queueDigest"]
            next_intake["fixes"] = []
            next_intake["intakeDigest"] = canonical_identity_digest(
                next_intake, "intakeDigest"
            )

            _second, errors = build_queue(
                next_intake,
                first,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )

            self.assertTrue(any("omitted" in error for error in errors), errors)

    def test_rejected_disposition_requires_rejected_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            inspector = GitInspector(
                fixture.root,
                expected_repository_identity="github.com/crypta-network/cryptad",
            )
            for state, transition_count in (
                ("accepted", 3),
                ("landed", 5),
                ("verified", 6),
            ):
                with self.subTest(state=state):
                    fix = _fix(
                        inspector,
                        fixture.fix_commit,
                        fixture.candidate,
                    )
                    fix["state"] = state
                    fix["stateTransitions"] = fix["stateTransitions"][
                        :transition_count
                    ]
                    fix["disposition"] = "rejected"
                    fix["releaseLane"] = None

                    errors = fix_record_errors(
                        fix, fixture.policy, now=NOW
                    )

                    self.assertTrue(
                        any(
                            "rejected routing without entering rejected state"
                            in error
                            for error in errors
                        ),
                        errors,
                    )

            rejected = _fix(
                inspector,
                fixture.fix_commit,
                fixture.candidate,
            )
            rejected["stateTransitions"] = rejected["stateTransitions"][:3]
            rejected["stateTransitions"].append(
                {
                    "sequence": 3,
                    "from": "accepted",
                    "to": "rejected",
                    "occurredAt": "2026-01-07T00:00:00Z",
                    "actorRole": "stable-triage-manager",
                    "reasonCode": "policy-ineligible",
                    "evidenceDigest": _digest("f"),
                }
            )
            rejected["state"] = "rejected"
            rejected["disposition"] = "rejected"
            rejected["releaseLane"] = None
            self.assertEqual(
                fix_record_errors(rejected, fixture.policy, now=NOW),
                [],
            )
    def test_evaluated_queue_allows_only_committed_append_only_evolution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            evaluated_intake = copy.deepcopy(fixture.intake)
            evaluated_fix = evaluated_intake["fixes"][0]
            evaluated_fix["state"] = "accepted"
            evaluated_fix["stateTransitions"] = evaluated_fix[
                "stateTransitions"
            ][:3]
            _bind_intake_evidence(
                evaluated_intake,
                None,
                policy_digest=fixture.policy_digest,
                candidate_commit=fixture.predecessor,
            )
            evaluated_queue, evaluated_errors = build_queue(
                evaluated_intake,
                None,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.predecessor,
            )
            prepared_intake = copy.deepcopy(fixture.intake)
            _bind_intake_evidence(
                prepared_intake,
                None,
                policy_digest=fixture.policy_digest,
                candidate_commit=fixture.candidate,
            )
            prepared_queue, prepared_errors = build_queue(
                prepared_intake,
                None,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )
            self.assertEqual(evaluated_errors, [])
            self.assertEqual(prepared_errors, [])
            evaluated_public = engine._public_queue(  # noqa: SLF001
                evaluated_queue
            )
            prepared_public = engine._public_queue(  # noqa: SLF001
                prepared_queue
            )

            self.assertEqual(
                phase_intake_composition_digest(evaluated_queue),
                phase_intake_composition_digest(prepared_queue),
            )
            self.assertEqual(
                public_phase_evolution_errors(
                    evaluated_public, prepared_public
                ),
                [],
            )
            evaluated_path = fixture.root / "evaluated-public-queue.json"
            prepared_path = fixture.root / "prepared-public-queue.json"
            write_json(evaluated_path, evaluated_public)
            write_json(prepared_path, prepared_public)
            verified = subprocess.run(
                (
                    "python3",
                    str(PHASE_HANDOFF_SCRIPT),
                    "--evaluated-queue",
                    str(evaluated_path),
                    "--prepared-queue",
                    str(prepared_path),
                ),
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)

            rewritten_history = copy.deepcopy(prepared_public)
            rewritten_history["fixEvolution"][0]["transitionDigests"][0] = (
                _digest("f")
            )
            history_errors = public_phase_evolution_errors(
                evaluated_public, rewritten_history
            )
            self.assertTrue(
                any("rewrote evaluated transition history" in row for row in history_errors),
                history_errors,
            )

            changed_composition = copy.deepcopy(prepared_queue)
            changed_composition["fixes"][0]["affectedScope"]["components"] = [
                "unrelated-component"
            ]
            composition_errors = public_phase_evolution_errors(
                evaluated_public,
                engine._public_queue(changed_composition),  # noqa: SLF001
            )
            self.assertTrue(
                any("intakeCompositionDigest" in row for row in composition_errors),
                composition_errors,
            )
            obligation = {
                "obligationId": "reconcile-develop-301",
                "obligationType": "post-release-develop-merge",
                "sourceTrainId": "stable-train-301",
                "sourceFixIds": [FIX_ID],
                "status": "open",
                "generatedAt": GENERATED,
                "resolvedAt": None,
                "evidenceDigest": _digest("d"),
            }
            evaluated_with_obligation = copy.deepcopy(evaluated_queue)
            evaluated_with_obligation["obligations"] = [obligation]
            prepared_with_obligation = copy.deepcopy(prepared_queue)
            prepared_with_obligation["obligations"] = [
                copy.deepcopy(obligation)
            ]
            evaluated_obligation_public = engine._public_queue(  # noqa: SLF001
                evaluated_with_obligation
            )
            prepared_obligation_public = engine._public_queue(  # noqa: SLF001
                prepared_with_obligation
            )
            self.assertEqual(
                public_phase_evolution_errors(
                    evaluated_obligation_public,
                    prepared_obligation_public,
                ),
                [],
            )

            prepared_with_obligation["obligations"][0][
                "sourceTrainId"
            ] = "stable-train-999"
            source_train_errors = public_phase_evolution_errors(
                evaluated_obligation_public,
                engine._public_queue(  # noqa: SLF001
                    prepared_with_obligation
                ),
            )
            self.assertTrue(
                any(
                    "intakeCompositionDigest" in row
                    for row in source_train_errors
                ),
                source_train_errors,
            )

    def test_superseding_fix_identity_is_immutable_across_queue_versions(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            previous_intake = copy.deepcopy(fixture.intake)
            previous_fix = previous_intake["fixes"][0]
            previous_fix["state"] = "superseded"
            previous_fix["supersedingFixId"] = (
                "stable-fix-bbbbbbbbbbbbbbbb"
            )
            previous_fix["stateTransitions"].append(
                {
                    "sequence": len(previous_fix["stateTransitions"]),
                    "from": "verified",
                    "to": "superseded",
                    "occurredAt": "2026-01-07T00:00:00Z",
                    "actorRole": "stable-triage-manager",
                    "reasonCode": "replacement-reviewed",
                    "evidenceDigest": _digest("f"),
                }
            )
            _bind_intake_evidence(
                previous_intake,
                None,
                policy_digest=fixture.policy_digest,
                candidate_commit=fixture.candidate,
            )
            previous_queue, previous_errors = build_queue(
                previous_intake,
                None,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )
            self.assertEqual(previous_errors, [])
            successor_intake = copy.deepcopy(previous_intake)
            successor_intake["previousQueueDigest"] = previous_queue[
                "queueDigest"
            ]
            successor_intake["fixes"][0]["supersedingFixId"] = (
                "stable-fix-cccccccccccccccc"
            )
            _bind_intake_evidence(
                successor_intake,
                previous_queue,
                policy_digest=fixture.policy_digest,
                candidate_commit=fixture.candidate,
            )

            _successor_queue, successor_errors = build_queue(
                successor_intake,
                previous_queue,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )

            self.assertTrue(
                any(
                    "rewrites immutable supersedingFixId provenance" in error
                    for error in successor_errors
                ),
                successor_errors,
            )

    def test_omitted_terminal_fix_carries_with_successor_queue_binding(
        self,
    ) -> None:
        for terminal_state in ("released", "rejected", "superseded"):
            with self.subTest(terminal_state=terminal_state):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = Fixture(Path(directory))
                    terminal_intake = copy.deepcopy(fixture.intake)
                    terminal_fix = terminal_intake["fixes"][0]
                    if terminal_state == "rejected":
                        terminal_fix["stateTransitions"] = terminal_fix[
                            "stateTransitions"
                        ][:3]
                        terminal_fix["disposition"] = "rejected"
                        terminal_fix["releaseLane"] = None
                    terminal_fix["stateTransitions"].append(
                        {
                            "sequence": len(terminal_fix["stateTransitions"]),
                            "from": terminal_fix["stateTransitions"][-1]["to"],
                            "to": terminal_state,
                            "occurredAt": "2026-01-07T00:00:00Z",
                            "actorRole": "stable-release-manager",
                            "reasonCode": "terminal-state-authenticated",
                            "evidenceDigest": _digest("f"),
                        }
                    )
                    terminal_fix["state"] = terminal_state
                    if terminal_state == "superseded":
                        terminal_fix["supersedingFixId"] = (
                            "stable-fix-bbbbbbbbbbbbbbbb"
                        )
                    _bind_intake_evidence(
                        terminal_intake,
                        None,
                        policy_digest=fixture.policy_digest,
                        candidate_commit=fixture.candidate,
                    )
                    terminal_queue, errors = build_queue(
                        terminal_intake,
                        None,
                        policy_digest=fixture.policy_digest,
                        latest_maintenance_pointer_digest=_digest("b"),
                        lifecycle_ledger_digest=_digest("d"),
                        repository_identity="github.com/crypta-network/cryptad",
                        candidate_commit=fixture.candidate,
                    )
                    self.assertEqual(errors, [])
                    predecessor_snapshot = copy.deepcopy(terminal_queue)

                    successor_intake = copy.deepcopy(terminal_intake)
                    successor_intake["previousQueueDigest"] = terminal_queue[
                        "queueDigest"
                    ]
                    successor_intake["fixes"] = []
                    successor_intake["publicProjectionDigest"] = semantic_digest(
                        {"fixIds": [], "obligations": []}
                    )
                    successor_intake["intakeDigest"] = canonical_identity_digest(
                        successor_intake, "intakeDigest"
                    )
                    successor_queue, errors = build_queue(
                        successor_intake,
                        terminal_queue,
                        policy_digest=fixture.policy_digest,
                        latest_maintenance_pointer_digest=_digest("b"),
                        lifecycle_ledger_digest=_digest("d"),
                        repository_identity="github.com/crypta-network/cryptad",
                        candidate_commit=fixture.candidate,
                    )

                    self.assertEqual(errors, [])
                    self.assertEqual(terminal_queue, predecessor_snapshot)
                    self.assertEqual(len(successor_queue["fixes"]), 1)
                    self.assertEqual(
                        successor_queue["fixes"][0]["state"], terminal_state
                    )
                    self.assertEqual(
                        queue_identity_digest(successor_queue),
                        successor_queue["queueDigest"],
                    )
                    self.assertTrue(
                        all(
                            evidence["queueDigest"]
                            == successor_queue["queueDigest"]
                            for evidence in successor_queue["fixes"][0][
                                "evidence"
                            ]
                        )
                    )

    def test_post_release_obligation_carries_until_evidence_resolves_it(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            first, errors = build_queue(
                fixture.intake,
                None,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )
            self.assertEqual(errors, [])
            open_obligation = {
                "obligationId": "reconcile-develop-301",
                "obligationType": "post-release-develop-merge",
                "sourceTrainId": "stable-train-301",
                "sourceFixIds": [FIX_ID],
                "status": "open",
                "generatedAt": GENERATED,
                "resolvedAt": None,
                "evidenceDigest": _digest("d"),
            }
            second_intake = copy.deepcopy(fixture.intake)
            second_intake["previousQueueDigest"] = first["queueDigest"]
            second_intake["obligations"] = [open_obligation]
            second_intake["publicProjectionDigest"] = semantic_digest(
                {
                    "fixIds": [FIX_ID],
                    "obligations": [
                        {
                            "obligationId": open_obligation["obligationId"],
                            "status": "open",
                        }
                    ],
                }
            )
            _bind_intake_evidence(
                second_intake,
                first,
                policy_digest=fixture.policy_digest,
                candidate_commit=fixture.candidate,
            )
            second, errors = build_queue(
                second_intake,
                first,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )
            self.assertEqual(errors, [])
            self.assertEqual(
                second["carriedObligationIds"],
                ["reconcile-develop-301"],
            )
            self.assertEqual(second["status"], "blocked")

            omitted = copy.deepcopy(fixture.intake)
            omitted["previousQueueDigest"] = second["queueDigest"]
            _bind_intake_evidence(
                omitted,
                second,
                policy_digest=fixture.policy_digest,
                candidate_commit=fixture.candidate,
            )
            _omitted_queue, errors = build_queue(
                omitted,
                second,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )
            self.assertTrue(any("open obligation" in error for error in errors))

            resolved_intake = copy.deepcopy(second_intake)
            resolved_intake["previousQueueDigest"] = second["queueDigest"]
            resolved = resolved_intake["obligations"][0]
            resolved["status"] = "resolved"
            resolved["resolvedAt"] = "2026-01-15T12:00:00Z"
            resolved["evidenceDigest"] = _digest("e")
            resolved_intake["publicProjectionDigest"] = semantic_digest(
                {
                    "fixIds": [FIX_ID],
                    "obligations": [
                        {
                            "obligationId": resolved["obligationId"],
                            "status": "resolved",
                        }
                    ],
                }
            )
            _bind_intake_evidence(
                resolved_intake,
                second,
                policy_digest=fixture.policy_digest,
                candidate_commit=fixture.candidate,
            )
            resolved_queue, errors = build_queue(
                resolved_intake,
                second,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )
            self.assertEqual(errors, [])
            self.assertEqual(resolved_queue["carriedObligationIds"], [])
            self.assertEqual(resolved_queue["status"], "ready")



if __name__ == "__main__":
    unittest.main()
