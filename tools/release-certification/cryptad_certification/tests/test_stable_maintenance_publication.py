"""Offline tests for the protected Stable 1.0 maintenance publication adapter."""

from __future__ import annotations

import contextlib
import copy
import dataclasses
import datetime as dt
import hashlib
import importlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Mapping
import unittest
from unittest import mock

from cryptad_certification.engines import (
    stable_1_0_maintenance,
    stable_1_0_maintenance_artifacts,
)
from cryptad_certification.engines.stable_1_0_maintenance_core import (
    _receipt_identity as engine_receipt_identity,
    stable_catalog_verification_identity,
)
from cryptad_certification.engines.stable_1_0_rc_core import ValidationState
from cryptad_certification.tests.support import release_train_evidence_result
from cryptad_certification.tests.test_stable_maintenance import (
    _candidate,
    _context,
    _digest,
    _evidence,
)


SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "protected"
    / "stable_maintenance_publication.py"
)
SPEC = importlib.util.spec_from_file_location(
    "stable_maintenance_publication_under_test", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
publication = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = publication
SPEC.loader.exec_module(publication)


NOW = dt.datetime(2026, 7, 18, 12, 0, tzinfo=dt.timezone.utc)
RELEASE_ID = "stable-1-0-maintenance-301"
BUILD = "301"
COMMIT = "a" * 40
POINTER = "sha256:" + "b" * 64
PREVIOUS_BASELINE = "sha256:" + "c" * 64
PREVIOUS_LINEAGE = "sha256:" + "d" * 64
GA_BASELINE = "sha256:" + "e" * 64
GA_RECEIPT = "sha256:" + "f" * 64
CATALOG_SECRET = "USK@protected-catalog-insert-material"
CORE_UPDATE_SECRET = "USK@protected-core-update-insert-material"
MAINTENANCE_STATE_SECRET = "protected-maintenance-state-credential"
PUBLIC_PACKAGE_CHK = (
    "CHK@"
    + "A" * 43
    + ","
    + "B" * 43
    + ","
    + "C" * 7
    + "/cryptad-301.exe"
)


def digest(character: str) -> str:
    return "sha256:" + hashlib.sha256(character.encode("utf-8")).hexdigest()


def timestamp(value: dt.datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def train_evidence_freshness() -> dict[str, str]:
    deadline = NOW + dt.timedelta(hours=1)
    return {
        "generatedAt": timestamp(NOW),
        "expiresAt": timestamp(deadline),
        "freshnessDeadlineAt": timestamp(deadline),
    }


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value))


def file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def semantic_digest(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def seal_backport_handoff(
    validation: dict[str, object], authorization: dict[str, object]
) -> None:
    """Recompute the exact protected handoff bindings after a test mutation."""

    validation.pop("validationDigest", None)
    validation["mode"] = "prepare-candidate"
    validation["authorization"] = None
    authorization["release"] = copy.deepcopy(validation["release"])
    authorization["validationDigest"] = semantic_digest(validation)
    authorization["acceptedFixes"] = copy.deepcopy(validation["publicFixes"])
    authorization["securityOpaqueIds"] = sorted(
        {
            row["incidentOpaqueId"]
            for row in validation["publicFixes"]
            if isinstance(row, Mapping)
            and isinstance(row.get("incidentOpaqueId"), str)
        }
    )
    authorization.pop("authorizationDigest", None)
    authorization["authorizationDigest"] = semantic_digest(authorization)
    validation["mode"] = "validate-authorization"
    validation["authorization"] = {
        "authorizationDigest": authorization["authorizationDigest"],
        "status": "valid",
        "expiresAt": authorization["expiresAt"],
        "role": authorization["role"],
    }
    validation["validationDigest"] = semantic_digest(validation)


def redaction() -> dict[str, object]:
    return {"status": "pass", "findingCount": 0, "findings": []}


def apps() -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for index, app_id in enumerate(
        (
            "queue-manager",
            "publisher",
            "site-publisher",
            "profile-publisher",
            "social-inbox",
            "feed-reader",
            "trust-graph",
        ),
        start=1,
    ):
        result.append(
            {
                "appId": app_id,
                "version": f"301.{index}",
                "channel": "stable",
                "supportLevel": "local-rc" if app_id == "trust-graph" else "maintained",
                "bundleDigest": digest(str(index)),
                "reviewReceiptDigest": digest(chr(96 + index)),
                "appSigningKeyId": f"app-key-{index}",
                "reviewerKeyId": f"reviewer-key-{index}",
                "manifestDigest": digest(chr(103 + index)),
                "permissionSetDigest": digest(chr(110 + index)),
                "appDataSchemaVersion": 1,
                "supportMetadataDigest": digest(chr(80 + index)),
            }
        )
    return result


def profiles() -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for index, profile_id in enumerate(
        (
            "crypta.profile.v1",
            "crypta.feed.snapshot.v1",
            "crypta.trust.statement.v1",
            "crypta.social.message.v1",
            "crypta.social.outbox.v1",
        ),
        start=1,
    ):
        result.append(
            {
                "profileId": profile_id,
                "version": 1,
                "status": "stable",
                "descriptorDigest": digest(str(index)),
                "canonicalizationRulesDigest": digest(chr(102 + index)),
                "maximumSizePolicyDigest": digest(chr(107 + index)),
                "signaturePayloadRulesDigest": digest(chr(112 + index)),
            }
        )
    return result


class StableMaintenanceReleaseNotesTest(unittest.TestCase):
    def test_rejected_backport_train_is_not_reported_as_passing_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = _context(root)
            candidate = _candidate(root)
            state = ValidationState()
            state.block(
                "stable-maintenance.backport-release-train",
                "stable-maintenance.backport-release-train",
                "The candidate-bound release train was rejected.",
                "Regenerate the exact candidate-bound train.",
            )

            validation = stable_1_0_maintenance._validation(  # noqa: SLF001
                context=context,
                state=state,
                mode="validate-only",
                candidate=candidate,
                lineage_digest=_digest("0"),
                comparison_digest=_digest("1"),
                evidence=_evidence(),
                evidence_digest=_digest("2"),
                core_info_digest=_digest("3"),
                checksums_digest=_digest("4"),
                provenance_digest=_digest("5"),
                pending_lifecycle_transition_digest=_digest("6"),
                backport_release_train_digest=_digest("7"),
                backport_release_train_authenticated=False,
                authorization_digest=_digest("8"),
                authorization_valid=False,
                publication_state="validated",
            )

            self.assertEqual(validation["decision"], "no-go")
            self.assertFalse(
                any(
                    row.get("evidenceId")
                    == "stable-maintenance.backport-release-train"
                    for row in validation["evidenceResults"]
                )
            )
            self.assertTrue(
                any(
                    blocker.get("category")
                    == "stable-maintenance.backport-release-train"
                    for blocker in validation["blockers"]
                )
            )

    def test_train_rows_include_authenticated_public_fix_summaries(self) -> None:
        public_summary = (
            "Corrects request handling without changing stable contracts."
        )
        public_security_summary = (
            "A bounded security correction is available."
        )
        notes = stable_1_0_maintenance_artifacts.render_release_notes(
            RELEASE_ID,
            BUILD,
            "security-hotfix",
            "300",
            {
                "changeScope": {
                    "incidentId": "incident-opaque-287",
                    "publicUserVisibleFixes": [],
                },
                "platformApi": {
                    "baselineName": "platform-api-1.0",
                    "currentContractVersion": "19",
                },
                "stableCatalog": {
                    "catalogId": "stable",
                    "edition": "2",
                    "revision": "301",
                },
                "limitations": {
                    "addedCount": 0,
                    "resolvedCount": 0,
                    "unchangedCount": 0,
                },
                "packages": [],
            },
            "validated",
            [
                {
                    "fixId": "stable-fix-0000000000000301",
                    "classification": "security-fix",
                    "publicSummary": public_summary,
                    "affectedComponentSummary": "node-core",
                    "provenanceMode": "inherited",
                    "lineageDigest": digest("train-lineage"),
                    "advisoryOpaqueId": "advisory-opaque-287",
                    "publicSecuritySummary": public_security_summary,
                    "disclosureState": "protected-embargoed",
                }
            ],
            [],
            digest("train-validation"),
        )

        self.assertIn(f"summary: {public_summary}", notes)
        self.assertIn(
            f"security summary: {public_security_summary}",
            notes,
        )
        self.assertNotIn("advisory advisory-opaque-287", notes)


class BundleFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.legacy = root / "component" / "artifacts" / "legacy"
        self.legacy.mkdir(parents=True)
        self.product = self.legacy / "cryptad-stable-301.tar.gz"
        self.package = self.legacy / "cryptad-301.exe"
        self.catalog = self.legacy / "first-party-stable.properties"
        self.catalog_signature = self.legacy / "first-party-stable.properties.sig"
        self.product.write_bytes(b"exact product bytes\n")
        self.package.write_bytes(b"exact windows package bytes\n")
        self.catalog.write_bytes(b"catalog.version=301\n")
        self.catalog_signature.write_bytes(b"detached catalog signature bytes\n")

        package_row = {
            "packageKey": "amd64.exe",
            "fileName": self.package.name,
            "digest": file_digest(self.package),
            "sizeBytes": self.package.stat().st_size,
            "publicChk": PUBLIC_PACKAGE_CHK,
            "storeUrl": None,
        }
        self.platform_api = {
            "baselineName": "1.0",
            "baselineDigest": digest("platform-baseline"),
            "baselineContractVersion": 1,
            "currentContractVersion": 2,
            "currentContractDigest": digest("platform-contract"),
            "stableSurfaceDigest": digest("platform-surface"),
            "compatibilityWindowPolicyDigest": digest("platform-window"),
            "deprecationHistoryDigest": semantic_digest([]),
            "deprecationHistory": [],
        }
        self.stable_catalog = {
            "fileName": self.catalog.name,
            "sizeBytes": self.catalog.stat().st_size,
            "signatureFileName": self.catalog_signature.name,
            "signatureSizeBytes": self.catalog_signature.stat().st_size,
            "catalogId": "crypta-first-party",
            "channel": "stable",
            "revision": 301,
            "edition": 301,
            "digest": file_digest(self.catalog),
            "signatureDigest": file_digest(self.catalog_signature),
            "signingKeyId": "catalog-key-2026",
        }
        self.first_party_apps = apps()
        self.content_profiles = profiles()
        self.limitations = {
            "knownLimitationsDigest": semantic_digest({"limitationIds": []}),
            "deltaDigest": semantic_digest(
                {
                    "predecessorIds": [],
                    "addedIds": [],
                    "resolvedIds": [],
                    "unchangedIds": [],
                    "currentIds": [],
                }
            ),
            "addedCount": 0,
            "resolvedCount": 0,
            "unchangedCount": 0,
            "addedIds": [],
            "resolvedIds": [],
            "unchangedIds": [],
            "changesReviewed": True,
            "noHiddenLimitations": True,
        }
        self.security = {
            "advisoryDigest": digest("security-advisory"),
            "denylistDigest": digest("security-denylist"),
        }
        self.support = {
            "supportLevelDigest": digest("support-level"),
            "diagnosticsEvidenceDigest": digest("support-diagnostics"),
        }
        self.legacy_boundaries = {
            "pluginRuntime": "removed",
            "inCorePluginApi": "removed",
            "legacyAdminMutationRoutes": "disabled",
            "fproxyBrowse": "retained",
            "contentFiltering": "retained",
            "emergencyFallbackRoutes": "retained",
        }
        self.authenticated_inputs = self.root / "authenticated-inputs"
        self.authenticated_inputs.mkdir()
        self.source = {
            "branch": f"release/{BUILD}",
            "ref": f"commit:{COMMIT}",
            "commit": COMMIT,
            "baseBranch": "develop",
            "baseCommit": "9" * 40,
            "clean": True,
            "treeState": "clean",
            "branchHeadVerified": True,
            "immutableRefVerified": True,
            "currentPublishedMainBaseVerified": False,
            "sourceTreeDigest": digest("source-tree"),
        }
        self.toolchain = {
            "javaVersion": "25.0.3",
            "javaMajorVersion": 25,
            "gradleVersion": "9.0",
            "gradleWrapperDigest": digest("gradle-wrapper"),
            "dependencyVerificationDigest": digest("dependency-verification"),
            "dependencyVerificationStatus": "pass",
            "buildLogicDigest": digest("build-logic"),
            "buildTasks": ["assembleCryptadDist", "jpackageInstallerCryptad"],
            "productionSigning": True,
            "testSigning": False,
        }
        self.candidate_input = {
            "schemaVersion": 1,
            "kind": "stable-1.0-maintenance-candidate-input",
            "generatedAt": timestamp(NOW),
            "stableMilestone": "1.0",
            "releaseId": RELEASE_ID,
            "buildVersion": BUILD,
            "releaseClass": "maintenance",
            "source": self.source,
            "toolchain": self.toolchain,
            "product": {
                "fileName": self.product.name,
                "digest": file_digest(self.product),
                "sizeBytes": self.product.stat().st_size,
                "frozenAt": timestamp(NOW),
            },
            "packages": [package_row],
            "platformApi": self.platform_api,
            "stableCatalog": self.stable_catalog,
            "firstPartyApps": self.first_party_apps,
            "contentFormatProfiles": self.content_profiles,
            "limitations": self.limitations,
            "security": self.security,
            "support": self.support,
            "legacyBoundaries": self.legacy_boundaries,
            "redaction": redaction(),
        }
        self.candidate_input_path = (
            self.authenticated_inputs / "maintenance-candidate-input.json"
        )
        write_json(self.candidate_input_path, self.candidate_input)
        self.ga_baseline = {
            "schemaVersion": 1,
            "kind": "stable-1.0-maintenance-baseline",
            "limitations": {"known": []},
            "securityBaseline": {"status": "stable"},
            "supportBaseline": {"status": "stable"},
            "redaction": redaction(),
        }
        self.ga_baseline_path = (
            self.authenticated_inputs / "stable-ga-maintenance-baseline.json"
        )
        write_json(self.ga_baseline_path, self.ga_baseline)
        self.predecessor_baseline_path = (
            self.authenticated_inputs / "predecessor-maintenance-baseline.json"
        )
        write_json(self.predecessor_baseline_path, self.ga_baseline)
        self.ga_baseline_digest = file_digest(self.ga_baseline_path)
        catalog_verification = stable_catalog_verification_identity(
            self.stable_catalog, digest("catalog-trust-registry")
        )
        catalog_verification_digest = semantic_digest(catalog_verification)
        freeze_assets = [
            {
                "role": "product",
                "fileName": self.product.name,
                "digest": file_digest(self.product),
                "sizeBytes": self.product.stat().st_size,
                "packageKey": None,
                "os": None,
                "arch": None,
                "producerArchitecture": None,
                "packageType": None,
                "publicAsset": True,
                "signingStatus": "pass",
                "signingReceiptDigest": digest("product-signing-receipt"),
                "notarizationStatus": "not-applicable",
                "notarizationReceiptDigest": None,
            },
            {
                "role": "package",
                "fileName": self.package.name,
                "digest": file_digest(self.package),
                "sizeBytes": self.package.stat().st_size,
                "packageKey": "amd64.exe",
                "os": "windows",
                "arch": "amd64",
                "producerArchitecture": "amd64",
                "packageType": "exe",
                "publicAsset": True,
                "signingStatus": "pass",
                "signingReceiptDigest": digest("package-signing-receipt"),
                "notarizationStatus": "not-applicable",
                "notarizationReceiptDigest": None,
            },
            {
                "role": "stable-catalog",
                "fileName": self.catalog.name,
                "digest": file_digest(self.catalog),
                "sizeBytes": self.catalog.stat().st_size,
                "packageKey": None,
                "os": None,
                "arch": None,
                "producerArchitecture": None,
                "packageType": None,
                "publicAsset": True,
                "signingStatus": "pass",
                "signingReceiptDigest": catalog_verification_digest,
                "notarizationStatus": "not-applicable",
                "notarizationReceiptDigest": None,
            },
            {
                "role": "stable-catalog-signature",
                "fileName": self.catalog_signature.name,
                "digest": file_digest(self.catalog_signature),
                "sizeBytes": self.catalog_signature.stat().st_size,
                "packageKey": None,
                "os": None,
                "arch": None,
                "producerArchitecture": None,
                "packageType": None,
                "publicAsset": True,
                "signingStatus": "pass",
                "signingReceiptDigest": catalog_verification_digest,
                "notarizationStatus": "not-applicable",
                "notarizationReceiptDigest": None,
            },
        ]
        self.candidate_freeze = {
            "schemaVersion": 1,
            "kind": "stable-1.0-maintenance-candidate-freeze",
            "generatedAt": timestamp(NOW),
            "frozenAt": timestamp(NOW),
            "stableMilestone": "1.0",
            "releaseId": RELEASE_ID,
            "buildVersion": BUILD,
            "releaseClass": "maintenance",
            "source": self.source,
            "toolchain": self.toolchain,
            "producer": {
                "system": "github-actions",
                "repository": "crypta-network/cryptad",
                "workflowPath": ".github/workflows/stable-1.0-maintenance-release.yml",
                "workflowCommit": COMMIT,
                "runId": "30101",
                "runAttempt": 1,
                "runnerEnvironment": "github-hosted",
                "producerIdentityReceiptDigest": digest("producer-identity"),
                "sourceRefReceiptDigest": digest("source-ref-receipt"),
                "buildReceiptDigest": digest("build-receipt"),
                "authenticationStatus": "pass",
            },
            "predecessorObservation": {
                "releaseId": "stable-1-0-ga-300",
                "buildVersion": "300",
                "productDigest": digest("8"),
                "baselineDigest": self.ga_baseline_digest,
                "publicationReceiptDigest": GA_RECEIPT,
                "latestPublishedPointerDigest": POINTER,
                "observedAt": timestamp(NOW),
                "status": "latest-published",
            },
            "stableCatalogVerification": catalog_verification,
            "buildCount": 1,
            "rebuildPerformed": False,
            "checksumsDigest": digest("candidate-checksums"),
            "assets": freeze_assets,
            "assetSetDigest": semantic_digest(
                sorted(freeze_assets, key=lambda row: str(row["fileName"]))
            ),
            "redaction": redaction(),
        }
        self.candidate_freeze_path = (
            self.authenticated_inputs / "maintenance-candidate-freeze.json"
        )
        write_json(self.candidate_freeze_path, self.candidate_freeze)
        self.candidate_input["candidateFreezeDigest"] = file_digest(
            self.candidate_freeze_path
        )
        write_json(self.candidate_input_path, self.candidate_input)
        self.evidence = {
            "schemaVersion": 1,
            "kind": "stable-1.0-maintenance-evidence",
            "releaseId": RELEASE_ID,
            "buildVersion": BUILD,
            "releaseClass": "maintenance",
            "candidateProductDigest": file_digest(self.product),
            "candidateFreezeDigest": file_digest(self.candidate_freeze_path),
            "windowClass": "normal",
            "evidenceRows": [
                {"evidenceId": "stable-maintenance.installation-packaging"},
                {"evidenceId": "stable-maintenance.security"},
            ],
            "redaction": redaction(),
        }
        self.evidence_path = self.authenticated_inputs / "maintenance-evidence.json"
        write_json(self.evidence_path, self.evidence)
        self.candidate = {
            "schemaVersion": 1,
            "kind": "stable-1.0-maintenance-candidate",
            "generatedAt": timestamp(NOW),
            "stableMilestone": "1.0",
            "releaseId": RELEASE_ID,
            "buildVersion": BUILD,
            "releaseClass": "maintenance",
            "source": self.source,
            "toolchain": self.toolchain,
            "product": {
                "fileName": self.product.name,
                "sizeBytes": self.product.stat().st_size,
                "digest": file_digest(self.product),
            },
            "packages": [package_row],
            "candidateInputDigest": file_digest(self.candidate_input_path),
            "candidateFreezeDigest": file_digest(self.candidate_freeze_path),
            "frozenAt": timestamp(NOW),
            "platformApiDigest": semantic_digest(self.platform_api),
            "stableCatalogDigest": semantic_digest(self.stable_catalog),
            "firstPartyAppsDigest": semantic_digest(self.first_party_apps),
            "contentProfilesDigest": semantic_digest(self.content_profiles),
            "knownLimitationsDigest": semantic_digest(self.limitations),
            "securityDigest": semantic_digest(self.security),
            "supportDigest": semantic_digest(self.support),
            "legacyBoundariesDigest": semantic_digest(self.legacy_boundaries),
            "builtOnce": True,
            "rebuildPerformedAfterFreeze": False,
            "redaction": redaction(),
        }
        self.candidate_path = self.legacy / "stable-1.0-maintenance-candidate.json"
        write_json(self.candidate_path, self.candidate)
        self.candidate_digest = semantic_digest(self.candidate)

        self.lineage = {
            "schemaVersion": 1,
            "kind": "stable-1.0-maintenance-lineage",
            "generatedAt": timestamp(NOW),
            "stableMilestone": "1.0",
            "gaRoot": {
                "releaseId": "stable-1-0-ga-300",
                "buildVersion": "300",
                "tag": "v300",
                "sourceCommit": "9" * 40,
                "productDigest": digest("8"),
                "maintenanceBaselineDigest": self.ga_baseline_digest,
                "publicationReceiptDigest": GA_RECEIPT,
                "publicationState": "publication-complete",
            },
            "predecessor": {
                "releaseId": "stable-1-0-ga-300",
                "buildVersion": "300",
                "tag": "v300",
                "sourceCommit": "9" * 40,
                "productDigest": digest("8"),
                "releaseClass": "stable-ga",
                "publicationReceiptDigest": GA_RECEIPT,
                "successorBaselineDigest": None,
                "hotfixFollowUpClosureDigest": None,
                "publicationState": "publication-complete",
            },
            "candidate": {
                "releaseId": RELEASE_ID,
                "buildVersion": BUILD,
                "tag": f"v{BUILD}",
                "sourceBranch": f"release/{BUILD}",
                "sourceRef": f"commit:{COMMIT}",
                "sourceCommit": COMMIT,
                "releaseClass": "maintenance",
            },
            "chainDepth": 1,
            "previousLineageDigest": PREVIOUS_LINEAGE,
            "latestPublishedPointerDigest": POINTER,
            "noGap": True,
            "noFork": True,
            "status": "pass",
            "redaction": redaction(),
        }
        self.lineage_path = self.legacy / "stable-1.0-maintenance-lineage.json"
        write_json(self.lineage_path, self.lineage)

        self.backport_release_train_validation = {
            "schemaVersion": 1,
            "kind": "stable-1.0-release-train-validation",
            "generatedAt": timestamp(NOW),
            "stableMilestone": "1.0",
            "mode": "prepare-candidate",
            "trainId": "stable-train-maintenance-301",
            "release": {
                "releaseId": RELEASE_ID,
                "buildVersion": BUILD,
                "releaseClass": "maintenance",
                "tag": f"v{BUILD}",
            },
            "policyDigest": file_digest(
                Path(__file__).resolve().parents[2]
                / "stable-1.0-backport-release-train-policy.json"
            ),
            "queueDigest": digest("backport-queue"),
            "planDigest": digest("backport-plan"),
            "candidateDigest": digest("backport-candidate-artifact"),
            "predecessorCommit": "9" * 40,
            "candidateCommit": COMMIT,
            "hotfixFollowUpClosureDigest": self.lineage["predecessor"][
                "hotfixFollowUpClosureDigest"
            ],
            "requiredFixIds": ["stable-fix-0000000000000301"],
            "includedFixIds": ["stable-fix-0000000000000301"],
            "authorizationRequired": True,
            "authorization": None,
            "publicFixes": [
                {
                    "fixId": "stable-fix-0000000000000301",
                    "classification": "compatible-bug-fix",
                    "severity": "moderate",
                    "publicSummary": "Updater package selection remains compatible.",
                    "affectedComponentSummary": "Updater package selection.",
                    "provenanceMode": "inherited",
                    "lineageDigest": digest("train-lineage"),
                    "publicProjectionDigest": digest("train-fix-projection"),
                    "incidentOpaqueId": None,
                    "advisoryOpaqueId": None,
                    "publicSecuritySummary": None,
                    "securityPublicProjectionDigest": None,
                    "disclosureState": None,
                }
            ],
            "evidenceResults": [
                {
                    "fixId": "stable-fix-0000000000000301",
                    "evidenceId": "stable-backport.candidate-coverage",
                    "status": "pass",
                    "evidenceDigest": digest("train-evidence"),
                    **train_evidence_freshness(),
                    "candidateBound": True,
                    "predecessorBound": True,
                    "fresh": True,
                }
            ],
            "blockers": [],
            "omittedFixIds": [],
            "deferredFixIds": [],
            "unaccountedCommitIds": [],
            "decision": "go",
            "redaction": redaction(),
        }
        train_public_fix = self.backport_release_train_validation["publicFixes"][0]
        train_public_fix["publicProjectionDigest"] = semantic_digest(
            {
                "fixId": train_public_fix["fixId"],
                "classification": train_public_fix["classification"],
                "publicSummary": train_public_fix["publicSummary"],
            }
        )
        prepare_validation_digest = semantic_digest(
            self.backport_release_train_validation
        )
        self.backport_release_train_authorization = {
            "schemaVersion": 1,
            "kind": "stable-1.0-release-train-authorization",
            "stableMilestone": "1.0",
            "trainId": self.backport_release_train_validation["trainId"],
            "release": self.backport_release_train_validation["release"],
            "repositoryIdentity": "github.com/crypta-network/cryptad",
            "workflowIdentity": (
                "github.com/crypta-network/cryptad/.github/workflows/"
                f"stable-1.0-backport-release-train.yml@{COMMIT}"
            ),
            "policyDigest": self.backport_release_train_validation[
                "policyDigest"
            ],
            "queueDigest": self.backport_release_train_validation["queueDigest"],
            "planDigest": self.backport_release_train_validation["planDigest"],
            "validationDigest": prepare_validation_digest,
            "predecessorCommit": "9" * 40,
            "candidateCommit": COMMIT,
            "acceptedFixes": self.backport_release_train_validation[
                "publicFixes"
            ],
            "securityOpaqueIds": [],
            "allowedOperation": "candidate-handoff",
            "role": "stable-maintenance-train-manager",
            "scope": ["train:composition", "candidate:handoff"],
            "issuedAt": timestamp(NOW - dt.timedelta(minutes=30)),
            "expiresAt": timestamp(NOW + dt.timedelta(hours=1)),
            "decision": "go",
            "redaction": redaction(),
        }
        self.backport_release_train_authorization[
            "authorizationDigest"
        ] = semantic_digest(self.backport_release_train_authorization)
        self.backport_release_train_authorization_path = (
            self.authenticated_inputs
            / publication.BACKPORT_RELEASE_TRAIN_AUTHORIZATION_FILE
        )
        write_json(
            self.backport_release_train_authorization_path,
            self.backport_release_train_authorization,
        )
        self.backport_release_train_validation["mode"] = "validate-authorization"
        self.backport_release_train_validation["authorization"] = {
            "authorizationDigest": self.backport_release_train_authorization[
                "authorizationDigest"
            ],
            "status": "valid",
            "expiresAt": self.backport_release_train_authorization["expiresAt"],
            "role": self.backport_release_train_authorization["role"],
        }
        self.backport_release_train_validation["validationDigest"] = semantic_digest(
            self.backport_release_train_validation
        )
        self.backport_release_train_validation_path = (
            self.authenticated_inputs
            / publication.BACKPORT_RELEASE_TRAIN_VALIDATION_FILE
        )
        write_json(
            self.backport_release_train_validation_path,
            self.backport_release_train_validation,
        )
        self.backport_release_train_digest = file_digest(
            self.backport_release_train_validation_path
        )

        self.core_info = {
            "version": BUILD,
            "release_page_url": f"https://github.com/crypta-network/cryptad/releases/tag/v{BUILD}",
            "packages": {
                "amd64.exe": {
                    "chk": package_row["publicChk"],
                    "size": package_row["sizeBytes"],
                }
            },
        }
        self.core_info_path = self.legacy / "core-info.json"
        write_json(self.core_info_path, self.core_info)
        self.notes_path = self.legacy / "stable-1.0-maintenance-release-notes.md"
        self.notes_path.write_text("# Stable 1.0 maintenance build 301\n", encoding="utf-8")
        self.known_path = self.legacy / "stable-1.0-maintenance-known-limitations.json"
        write_json(
            self.known_path,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-maintenance-known-limitations-delta",
                "redaction": redaction(),
            },
        )
        self.checksums_path = self.legacy / "stable-1.0-maintenance-checksums.txt"
        self.checksums_path.write_text(
            f"{file_digest(self.product).removeprefix('sha256:')}  {self.product.name}\n",
            encoding="utf-8",
        )
        self.provenance = {
            "schemaVersion": 1,
            "kind": "stable-1.0-maintenance-provenance",
            "generatedAt": timestamp(NOW),
            "releaseId": RELEASE_ID,
            "buildVersion": BUILD,
            "releaseClass": "maintenance",
            "candidateIdentityDigest": self.candidate_digest,
            "candidateFreezeDigest": file_digest(self.candidate_freeze_path),
            "candidateProductDigest": file_digest(self.product),
            "lineageDigest": file_digest(self.lineage_path),
            "predecessorBaselineDigest": file_digest(self.predecessor_baseline_path),
            "evidenceDigest": file_digest(self.evidence_path),
            "policyDigest": digest("maintenance-policy"),
            "backportReleaseTrainDigest": self.backport_release_train_digest,
            "redaction": redaction(),
        }
        self.provenance_path = self.legacy / "stable-1.0-maintenance-provenance.json"
        write_json(self.provenance_path, self.provenance)
        self.comparison_path = self.legacy / "stable-1.0-maintenance-comparison.json"
        write_json(
            self.comparison_path,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-maintenance-comparison",
                "releaseId": RELEASE_ID,
                "redaction": redaction(),
            },
        )

        self.authorization = {
            "schemaVersion": 1,
            "kind": "stable-1.0-maintenance-authorization",
            "authorizationId": "maintenance-301-authorization",
            "releaseId": RELEASE_ID,
            "buildVersion": BUILD,
            "releaseClass": "maintenance",
            "candidateIdentityDigest": self.candidate_digest,
            "gaBaselineDigest": self.ga_baseline_digest,
            "predecessorIdentityDigest": semantic_digest(
                {
                    "releaseId": self.lineage["predecessor"]["releaseId"],
                    "buildVersion": self.lineage["predecessor"]["buildVersion"],
                    "sourceCommit": self.lineage["predecessor"]["sourceCommit"],
                    "productDigest": self.lineage["predecessor"]["productDigest"],
                    "baselineDigest": file_digest(self.predecessor_baseline_path),
                }
            ),
            "predecessorProductDigest": digest("8"),
            "predecessorPublicationReceiptDigest": GA_RECEIPT,
            "candidateFreezeDigest": file_digest(self.candidate_freeze_path),
            "productDigest": file_digest(self.product),
            "checksumsDigest": file_digest(self.checksums_path),
            "provenanceDigest": file_digest(self.provenance_path),
            "comparisonDigest": file_digest(self.comparison_path),
            "evidenceDigest": file_digest(self.evidence_path),
            "coreInfoDigest": file_digest(self.core_info_path),
            "stableCatalogDigest": file_digest(self.catalog),
            "knownLimitationsDeltaDigest": digest("3"),
            "releaseNotesDigest": file_digest(self.notes_path),
            "publicationTargetsDigest": digest("2"),
            "backportReleaseTrainDigest": self.backport_release_train_digest,
            "allowedPublicationScopes": list(publication.AUTHORIZATION_SCOPES),
            "acceptedWarningIds": [],
            "role": "stable-maintenance-release-manager",
            "approverIdentity": "release-manager-1",
            "authorizedAt": timestamp(NOW),
            "expiresAt": timestamp(NOW + dt.timedelta(days=365)),
            "decision": "go",
            "status": "approved",
            "hotfixIncidentId": None,
            "hotfixPolicyAuthorizationDigest": None,
            "hotfixShortenedEvidenceIds": [],
            "hotfixFollowUpObligationDigest": None,
            "redaction": redaction(),
        }
        self.authorization_path = (
            self.legacy / "stable-1.0-maintenance-authorization-summary.json"
        )
        write_json(self.authorization_path, self.authorization)

        self.core_plan = {
            "schemaVersion": 1,
            "kind": "cryptad-core-update-publication-plan",
            "generatedAt": timestamp(NOW),
            "releaseId": RELEASE_ID,
            "buildVersion": BUILD,
            "releaseClass": "maintenance",
            "candidateIdentityDigest": self.candidate_digest,
            "descriptorDigest": file_digest(self.core_info_path),
            "descriptorSizeBytes": self.core_info_path.stat().st_size,
            "packageMapDigest": semantic_digest(self.core_info["packages"]),
            "edition": int(BUILD),
            "publicFetchUri": f"https://updates.crypta.network/info/{BUILD}",
            "protectedInsertInputName": publication.PRIVATE_INPUT_ENV,
            "authorizationDigest": file_digest(self.authorization_path),
            "publicationTargetDigest": digest("2"),
            "preInsertionConflictStatus": "clear",
            "sideEffectsPerformed": False,
            "redaction": redaction(),
        }
        self.core_plan_path = self.legacy / "core-update-publication-plan.json"
        write_json(self.core_plan_path, self.core_plan)

        asset_rows: list[dict[str, object]] = []
        role_paths = (
            ("product", self.product),
            ("package", self.package),
            ("release-notes", self.notes_path),
            ("known-limitations", self.known_path),
            ("checksums", self.checksums_path),
            ("provenance", self.provenance_path),
            ("authorization", self.authorization_path),
            ("core-info", self.core_info_path),
            ("stable-catalog", self.catalog),
            ("stable-catalog-signature", self.catalog_signature),
        )
        for role, path in role_paths:
            asset_rows.append(
                {
                    "role": role,
                    "fileName": path.name,
                    "digest": file_digest(path),
                    "sizeBytes": path.stat().st_size,
                    "publicUri": f"https://downloads.crypta.network/stable/{path.name}",
                }
            )
        self.plan = {
            "schemaVersion": 1,
            "kind": "stable-1.0-maintenance-publication-plan",
            "generatedAt": timestamp(NOW),
            "releaseId": RELEASE_ID,
            "buildVersion": BUILD,
            "releaseClass": "maintenance",
            "sourceBranch": f"release/{BUILD}",
            "sourceCommit": COMMIT,
            "expectedTag": f"v{BUILD}",
            "githubReleasePageUri": f"https://github.com/crypta-network/cryptad/releases/tag/v{BUILD}",
            "artifactBaseUri": "https://downloads.crypta.network/stable/",
            "deploymentServicePublicUri": "https://deployment.crypta.network/stable/observe",
            "latestPointerPublicUri": "https://state.crypta.network/stable/latest.json",
            "candidateIdentityDigest": self.candidate_digest,
            "productDigest": file_digest(self.product),
            "checksumsDigest": file_digest(self.checksums_path),
            "provenanceDigest": file_digest(self.provenance_path),
            "authorizationDigest": file_digest(self.authorization_path),
            "backportReleaseTrainDigest": self.backport_release_train_digest,
            "releaseNotesDigest": file_digest(self.notes_path),
            "coreInfoDigest": file_digest(self.core_info_path),
            "stableCatalogDigest": file_digest(self.catalog),
            "knownLimitationsDeltaDigest": digest("3"),
            "publicationTargetsDigest": digest("2"),
            "assets": asset_rows,
            "stableCatalogTarget": {
                "catalogId": "crypta-first-party",
                "channel": "stable",
                "revision": 301,
                "edition": 301,
                "digest": file_digest(self.catalog),
                "signatureDigest": file_digest(self.catalog_signature),
                "publicUri": "https://catalog.crypta.network/stable/catalog.properties",
                "signaturePublicUri": "https://catalog.crypta.network/stable/first-party-stable.properties.sig",
                "mirrorUris": ["https://mirror.crypta.network/stable/catalog.properties"],
                "rollbackUri": "https://catalog.crypta.network/stable/history/300/catalog.properties",
                "mirrorSetDigest": digest("1"),
                "rollbackStateDigest": digest("0"),
            },
            "coreUpdateTarget": {
                "edition": int(BUILD),
                "descriptorDigest": file_digest(self.core_info_path),
                "publicUri": self.core_plan["publicFetchUri"],
                "protectedInsertInputName": publication.PRIVATE_INPUT_ENV,
            },
            "sideEffectsPerformed": False,
            "publicationState": "publication-authorized",
            "redaction": redaction(),
        }
        self.plan_path = self.legacy / "stable-1.0-maintenance-publication-plan.json"
        write_json(self.plan_path, self.plan)

    def load(self) -> publication.PublicationBundle:
        with mock.patch.object(publication, "_utcnow", return_value=NOW):
            return publication._load_bundle(self.root)

    def material(self, operation: str = "created") -> publication.VerificationMaterial:
        bundle = self.load()
        plan = bundle.plan
        assets = [
            {
                **dict(row),
                "operation": operation,
                "verificationStatus": "verified",
            }
            for row in plan["assets"]
        ]
        core_receipt = {
            "schemaVersion": 1,
            "kind": "cryptad-core-update-publication-receipt",
            "generatedAt": timestamp(NOW),
            "releaseId": RELEASE_ID,
            "buildVersion": BUILD,
            "releaseClass": "maintenance",
            "candidateIdentityDigest": self.candidate_digest,
            "publicationPlanDigest": file_digest(self.core_plan_path),
            "descriptorDigest": file_digest(self.core_info_path),
            "descriptorSizeBytes": self.core_info_path.stat().st_size,
            "packageMapDigest": semantic_digest(self.core_info["packages"]),
            "edition": int(BUILD),
            "publicFetchUri": self.core_plan["publicFetchUri"],
            "operation": operation,
            "fetchedDescriptorDigest": file_digest(self.core_info_path),
            "referencedPackages": [
                {
                    "packageKey": "amd64.exe",
                    "candidateAssetDigest": file_digest(self.package),
                    "candidateAssetSizeBytes": self.package.stat().st_size,
                    "publicReference": PUBLIC_PACKAGE_CHK,
                    "verificationStatus": "pass",
                }
            ],
            "conflictStatus": "clear",
            "verificationStatus": "pass",
            "publicationState": "publication-complete",
            "redaction": redaction(),
        }
        receipt = {
            "schemaVersion": 1,
            "kind": "stable-1.0-maintenance-publication-receipt",
            "generatedAt": timestamp(NOW),
            "releaseId": RELEASE_ID,
            "buildVersion": BUILD,
            "releaseClass": "maintenance",
            "sourceCommit": COMMIT,
            "githubReleasePageUri": plan["githubReleasePageUri"],
            "deploymentServicePublicUri": plan["deploymentServicePublicUri"],
            "latestPointerPublicUri": plan["latestPointerPublicUri"],
            "candidateIdentityDigest": self.candidate_digest,
            "productDigest": file_digest(self.product),
            "checksumsDigest": file_digest(self.checksums_path),
            "provenanceDigest": file_digest(self.provenance_path),
            "authorizationDigest": file_digest(self.authorization_path),
            "backportReleaseTrainDigest": self.backport_release_train_digest,
            "publicationPlanDigest": file_digest(self.plan_path),
            "releaseNotesDigest": file_digest(self.notes_path),
            "coreInfoDigest": file_digest(self.core_info_path),
            "coreUpdateReceiptDigest": (
                "sha256:" + hashlib.sha256(canonical_bytes(core_receipt)).hexdigest()
            ),
            "successorBaselineDigest": digest("0"),
            "releaseHistoryDigest": digest("0"),
            "tag": {
                "name": f"v{BUILD}",
                "objectType": "annotated",
                "targetCommit": COMMIT,
                "tagObjectDigest": digest("1"),
                "operation": operation,
                "verificationStatus": "verified",
            },
            "githubRelease": {
                "releaseId": "github-release-301",
                "tag": f"v{BUILD}",
                "pageUri": f"https://github.com/crypta-network/cryptad/releases/tag/v{BUILD}",
                "notesDigest": file_digest(self.notes_path),
                "operation": operation,
                "verificationStatus": "verified",
            },
            "assets": assets,
            "stableCatalog": {
                "catalogId": "crypta-first-party",
                "revision": 301,
                "edition": 301,
                "digest": file_digest(self.catalog),
                "signatureDigest": self.stable_catalog["signatureDigest"],
                "publicUri": "https://catalog.crypta.network/stable/catalog.properties",
                "signaturePublicUri": "https://catalog.crypta.network/stable/first-party-stable.properties.sig",
                "mirrorSetDigest": digest("1"),
                "rollbackStateDigest": digest("0"),
                "operation": operation,
                "verificationStatus": "verified",
            },
            "coreUpdate": {
                "edition": int(BUILD),
                "descriptorDigest": file_digest(self.core_info_path),
                "publicUri": self.core_plan["publicFetchUri"],
                "packageMapDigest": semantic_digest(self.core_info["packages"]),
                "operation": operation,
                "verificationStatus": "verified",
            },
            "workflow": {
                "repository": "crypta-network/cryptad",
                "runId": 1234,
                "runAttempt": 1,
                "environment": "stable-1.0-maintenance-publication",
                "actor": "release-manager-1",
                "attestationDigest": digest("3"),
            },
            "publicObservations": {target: "verified" for target in publication.TARGETS},
            "publicationState": "publication-complete",
            "finalVerificationStatus": "pass",
            "failureCategory": None,
            "redaction": redaction(),
        }
        receipt_identity = publication._receipt_identity(receipt)
        history = {
            "schemaVersion": 1,
            "kind": "stable-1.0-maintenance-history-entry",
            "generatedAt": timestamp(NOW),
            "stableMilestone": "1.0",
            "releaseId": RELEASE_ID,
            "buildVersion": BUILD,
            "tag": f"v{BUILD}",
            "sourceCommit": COMMIT,
            "releaseClass": "maintenance",
            "chainDepth": 1,
            "gaBaselineDigest": self.ga_baseline_digest,
            "previousBaselineDigest": file_digest(self.predecessor_baseline_path),
            "previousLineageDigest": PREVIOUS_LINEAGE,
            "candidateIdentityDigest": self.candidate_digest,
            "productDigest": file_digest(self.product),
            "publicationReceiptIdentityDigest": receipt_identity,
            "coreInfoDigest": file_digest(self.core_info_path),
            "evidenceDigest": file_digest(self.evidence_path),
            "backportReleaseTrainDigest": self.backport_release_train_digest,
            "status": "published-and-verified",
            "redaction": redaction(),
        }
        history_digest = "sha256:" + hashlib.sha256(canonical_bytes(history)).hexdigest()
        history_rows = [
            {
                "chainDepth": 0,
                "releaseId": "stable-1-0-ga-300",
                "buildVersion": "300",
                "tag": "v300",
                "sourceCommit": "9" * 40,
                "releaseClass": "stable-ga",
                "productDigest": digest("8"),
                "baselineIdentityDigest": self.ga_baseline_digest,
                "publicationReceiptIdentityDigest": GA_RECEIPT,
                "previousLineageDigest": PREVIOUS_LINEAGE,
            },
            {
                "chainDepth": 1,
                "releaseId": RELEASE_ID,
                "buildVersion": BUILD,
                "tag": f"v{BUILD}",
                "sourceCommit": COMMIT,
                "releaseClass": "maintenance",
                "productDigest": file_digest(self.product),
                "baselineIdentityDigest": digest("a"),
                "publicationReceiptIdentityDigest": receipt_identity,
                "previousLineageDigest": PREVIOUS_LINEAGE,
            },
        ]
        successor = {
            "schemaVersion": 2,
            "kind": "stable-1.0-maintenance-successor-baseline",
            "generatedAt": timestamp(NOW),
            "stableMilestone": "1.0",
            "status": "published",
            "gaRoot": {
                "releaseId": "stable-1-0-ga-300",
                "buildVersion": "300",
                "tag": "v300",
                "sourceCommit": "9" * 40,
                "productDigest": digest("8"),
                "maintenanceBaselineDigest": self.ga_baseline_digest,
                "publicationReceiptDigest": GA_RECEIPT,
            },
            "previousBaselineDigest": file_digest(self.predecessor_baseline_path),
            "chainDepth": 1,
            "previousLineageDigest": PREVIOUS_LINEAGE,
            "lineage": {
                "gaBaselineDigest": self.ga_baseline_digest,
                "gaPublicationReceiptDigest": GA_RECEIPT,
                "chainDepth": 1,
                "lineageDigest": semantic_digest(history_rows),
                "history": history_rows,
            },
            "publication": {
                "receiptIdentityDigest": receipt_identity,
                "publicationState": "publication-complete",
                "verificationStatus": "pass",
            },
            "release": {
                "releaseId": RELEASE_ID,
                "buildVersion": BUILD,
                "tag": f"v{BUILD}",
                "sourceCommit": COMMIT,
                "releaseClass": "maintenance",
                "productDigest": file_digest(self.product),
                "publicationReceiptIdentityDigest": receipt_identity,
                "checksumsDigest": file_digest(self.checksums_path),
                "provenanceDigest": file_digest(self.provenance_path),
                "coreInfoDigest": file_digest(self.core_info_path),
            },
            "platformApi": self.platform_api,
            "stableCatalog": {
                "catalogId": "crypta-first-party",
                "channel": "stable",
                "revision": 301,
                "edition": 301,
                "digest": file_digest(self.catalog),
                "signatureFileName": self.catalog_signature.name,
                "signatureSizeBytes": self.catalog_signature.stat().st_size,
                "signatureDigest": self.stable_catalog["signatureDigest"],
                "signingKeyId": "catalog-key-2026",
            },
            "firstPartyApps": self.first_party_apps,
            "contentFormatProfiles": self.content_profiles,
            "limitations": {
                "currentDigest": self.limitations["knownLimitationsDigest"],
                "currentIds": [],
                "gaBaselineDigest": semantic_digest(self.ga_baseline["limitations"]),
                "predecessorDigest": semantic_digest(self.ga_baseline["limitations"]),
            },
            "security": {
                "currentDigest": semantic_digest(self.security),
                "gaBaselineDigest": semantic_digest(self.ga_baseline["securityBaseline"]),
                "predecessorDigest": semantic_digest(self.ga_baseline["securityBaseline"]),
            },
            "support": {
                "currentDigest": semantic_digest(self.support),
                "gaBaselineDigest": semantic_digest(self.ga_baseline["supportBaseline"]),
                "predecessorDigest": semantic_digest(self.ga_baseline["supportBaseline"]),
            },
            "legacyBoundaries": self.legacy_boundaries,
            "evidenceWindowPolicy": {
                "windowClass": "normal",
                "policyDigest": self.provenance["policyDigest"],
                "requiredEvidenceDigest": semantic_digest(
                    sorted(row["evidenceId"] for row in self.evidence["evidenceRows"])
                ),
                "completedEvidenceDigest": file_digest(self.evidence_path),
            },
            "hotfixFollowUp": {
                "status": "not-required",
                "generatedAt": timestamp(NOW),
                "obligationDigest": None,
                "deadline": None,
                "closureEvidenceDigest": None,
                "blocksRoutineMaintenance": False,
            },
            "releaseTrain": {
                "validationDigest": self.backport_release_train_digest,
                "requiredEvidenceId": "stable-maintenance.backport-release-train",
                "candidateCommit": COMMIT,
                "predecessorCommit": "9" * 40,
                "unresolvedObligationsCarried": False,
            },
            "releaseHistoryDigest": history_digest,
            "redaction": redaction(),
        }
        history_rows[1]["baselineIdentityDigest"] = publication._successor_identity(
            successor
        )
        successor["lineage"]["lineageDigest"] = semantic_digest(history_rows)
        receipt["successorBaselineDigest"] = (
            "sha256:" + hashlib.sha256(canonical_bytes(successor)).hexdigest()
        )
        receipt["releaseHistoryDigest"] = history_digest
        return publication.VerificationMaterial(receipt, core_receipt, successor, history)


class FakeOperations:
    def __init__(
        self,
        material: publication.VerificationMaterial,
        *,
        target_status: str = "absent",
        predecessor: str | None = POINTER,
        fail_target: str | None = None,
    ) -> None:
        self.material = material
        self.targets = {target: target_status for target in publication.TARGETS}
        self.predecessor = predecessor
        self.latest_candidate: str | None = None
        self.fail_target = fail_target
        self.observe_calls = 0
        self.publish_calls: list[str] = []
        self.publish_input_purposes: list[tuple[str, str | None]] = []
        self.publish_input_values: list[tuple[str, str | None]] = []
        self.activate_calls = 0
        self.activation_input_purpose: str | None = None
        self.activation_input_value: str | None = None
        self.activation_pointer_bytes: bytes | None = None
        self.activation_pointer_digest_override: str | None = None
        self.pointer = publication.PointerSnapshot(
            "observed", POINTER, PREVIOUS_BASELINE, digest("0")
        )

    def observe_public_state(
        self, request: publication.PublicationRequest
    ) -> publication.PublicSnapshot:
        self.observe_calls += 1
        return publication.PublicSnapshot(
            self.predecessor, dict(self.targets), self.latest_candidate
        )

    def publish_target(
        self,
        target: str,
        request: publication.PublicationRequest,
        protected_input: publication.SecretMaterial | None,
    ) -> None:
        self.publish_calls.append(target)
        self.publish_input_purposes.append(
            (target, protected_input.purpose if protected_input else None)
        )
        self.publish_input_values.append(
            (target, protected_input.value if protected_input else None)
        )
        if target == self.fail_target:
            raise RuntimeError(
                protected_input.value if protected_input else CORE_UPDATE_SECRET
            )
        self.targets[target] = "matching"
        if all(value == "matching" for value in self.targets.values()):
            self.latest_candidate = request.candidate_identity_digest

    def verify_publication(
        self, request: publication.PublicationRequest
    ) -> publication.VerificationMaterial:
        return self.material

    def observe_latest_pointer(
        self, request: publication.ActivationRequest
    ) -> publication.PointerSnapshot:
        return self.pointer

    def activate_latest(
        self,
        request: publication.ActivationRequest,
        protected_input: publication.SecretMaterial,
    ) -> None:
        self.activate_calls += 1
        self.activation_input_purpose = protected_input.purpose
        self.activation_input_value = protected_input.value
        self.activation_pointer_bytes = request.activated_pointer_bytes
        self.pointer = publication.PointerSnapshot(
            "observed",
            self.activation_pointer_digest_override
            or request.activated_pointer_digest,
            request.successor_digest,
            str(request.receipt["candidateIdentityDigest"]),
        )


class StableMaintenancePublicationTest(unittest.TestCase):
    def test_maintenance_handoff_rejects_expired_candidate_evidence(self) -> None:
        evidence = release_train_evidence_result(
            "stable-fix-abcdefghijklmnop",
            "stable-backport.candidate-bound-tests",
            digest("train-evidence"),
            NOW - dt.timedelta(hours=2),
        )
        evidence["expiresAt"] = timestamp(NOW - dt.timedelta(minutes=1))
        evidence["freshnessDeadlineAt"] = evidence["expiresAt"]

        errors = stable_1_0_maintenance._release_train_evidence_freshness_errors(  # noqa: SLF001
            [evidence], now=NOW, maximum_age=dt.timedelta(days=14)
        )

        self.assertTrue(errors)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="stable-maintenance-publication-test-"
        )
        self.addCleanup(self.temporary.cleanup)
        now_patch = mock.patch.object(publication, "_utcnow", return_value=NOW)
        now_patch.start()
        self.addCleanup(now_patch.stop)
        self.root = Path(self.temporary.name)
        self.fixture = BundleFixture(self.root / "bundle")

    def operations(
        self,
        *,
        status: str = "absent",
        operation: str = "created",
        fail_target: str | None = None,
    ) -> FakeOperations:
        operations = FakeOperations(
            self.fixture.material(operation),
            target_status=status,
            fail_target=fail_target,
        )
        if status == "absent":
            operations.targets["artifactBase"] = "matching"
        return operations

    @staticmethod
    def protected_inputs() -> publication.PublicationProtectedInputs:
        return publication.PublicationProtectedInputs(
            publication.SecretMaterial("stable-catalog", CATALOG_SECRET),
            publication.SecretMaterial("core-update", CORE_UPDATE_SECRET),
        )

    @staticmethod
    def maintenance_state_input() -> publication.SecretMaterial:
        return publication.SecretMaterial(
            "maintenance-state", MAINTENANCE_STATE_SECRET
        )

    def test_bundle_authenticates_exact_backport_release_train(self) -> None:
        bundle = self.fixture.load()

        self.assertNotEqual(
            bundle.backport_release_train_validation["candidateDigest"],
            bundle.plan["candidateIdentityDigest"],
        )
        self.assertEqual(
            file_digest(bundle.backport_release_train_validation_path),
            self.fixture.backport_release_train_digest,
        )
        self.assertEqual(
            bundle.plan["backportReleaseTrainDigest"],
            self.fixture.backport_release_train_digest,
        )
        self.assertEqual(
            bundle.authorization["backportReleaseTrainDigest"],
            self.fixture.backport_release_train_digest,
        )
        self.assertEqual(
            bundle.backport_release_train_authorization[
                "authorizationDigest"
            ],
            bundle.backport_release_train_validation["authorization"][
                "authorizationDigest"
            ],
        )

    def test_train_authorization_expiry_is_frozen_at_maintenance_handoff(
        self,
    ) -> None:
        validation = copy.deepcopy(
            self.fixture.backport_release_train_validation
        )
        authorization = copy.deepcopy(
            self.fixture.backport_release_train_authorization
        )
        validation["generatedAt"] = timestamp(NOW - dt.timedelta(hours=1))
        evidence_result = validation["evidenceResults"][0]
        evidence_result["generatedAt"] = validation["generatedAt"]
        evidence_result["expiresAt"] = timestamp(NOW + dt.timedelta(hours=4))
        evidence_result["freshnessDeadlineAt"] = evidence_result["expiresAt"]
        seal_backport_handoff(validation, authorization)
        publication_time = NOW + dt.timedelta(hours=2)

        publication._validate_backport_release_train(  # noqa: SLF001
            validation,
            authorization,
            plan=self.fixture.plan,
            lineage=self.fixture.lineage,
            candidate_scope={},
            handoff_at=NOW,
            now=publication_time,
        )
        with self.assertRaisesRegex(
            publication.AdapterError,
            "backport-release-train-binding-mismatch",
        ):
            publication._validate_backport_release_train(  # noqa: SLF001
                validation,
                authorization,
                plan=self.fixture.plan,
                lineage=self.fixture.lineage,
                candidate_scope={},
                handoff_at=publication_time,
                now=publication_time,
            )

    def test_protected_boundary_preserves_per_fix_evidence_identity(
        self,
    ) -> None:
        validation = copy.deepcopy(
            self.fixture.backport_release_train_validation
        )
        authorization = copy.deepcopy(
            self.fixture.backport_release_train_authorization
        )
        first_public_fix = validation["publicFixes"][0]
        second_public_fix = copy.deepcopy(first_public_fix)
        second_public_fix["fixId"] = "stable-fix-0000000000000302"
        second_public_fix["publicSummary"] = (
            "A second updater package correction remains compatible."
        )
        second_public_fix["lineageDigest"] = digest(
            "second-train-lineage"
        )
        second_public_fix["publicProjectionDigest"] = semantic_digest(
            {
                "fixId": second_public_fix["fixId"],
                "classification": second_public_fix["classification"],
                "publicSummary": second_public_fix["publicSummary"],
            }
        )
        validation["requiredFixIds"] = sorted(
            [first_public_fix["fixId"], second_public_fix["fixId"]]
        )
        validation["includedFixIds"] = list(validation["requiredFixIds"])
        validation["publicFixes"] = sorted(
            [first_public_fix, second_public_fix],
            key=lambda row: row["fixId"],
        )
        validation["evidenceResults"].append(
            {
                "fixId": second_public_fix["fixId"],
                "evidenceId": "stable-backport.candidate-coverage",
                "status": "pass",
                "evidenceDigest": digest("second-train-evidence"),
                **train_evidence_freshness(),
                "candidateBound": True,
                "predecessorBound": True,
                "fresh": True,
            }
        )
        validation["evidenceResults"].sort(
            key=lambda row: (row["fixId"], row["evidenceId"])
        )
        seal_backport_handoff(validation, authorization)

        publication._validate_backport_release_train(  # noqa: SLF001
            validation,
            authorization,
            plan=self.fixture.plan,
            lineage=self.fixture.lineage,
            candidate_scope={},
            handoff_at=NOW,
            now=NOW,
        )

    def test_bundle_rejects_substituted_or_expired_backport_release_train(
        self,
    ) -> None:
        mutations = (
            lambda value: value.__setitem__("candidateCommit", "f" * 40),
            lambda value: value.__setitem__(
                "hotfixFollowUpClosureDigest",
                digest("substituted-follow-up-closure"),
            ),
            lambda value: value["authorization"].__setitem__(
                "role", "stable-security-train-manager"
            ),
            lambda value: value["authorization"].__setitem__(
                "expiresAt", "2020-01-01T00:00:00Z"
            ),
        )
        original = copy.deepcopy(self.fixture.backport_release_train_validation)
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                changed = copy.deepcopy(original)
                mutate(changed)
                changed["validationDigest"] = semantic_digest(
                    {
                        key: item
                        for key, item in changed.items()
                        if key != "validationDigest"
                    }
                )
                write_json(
                    self.fixture.backport_release_train_validation_path,
                    changed,
                )

                with self.assertRaisesRegex(
                    publication.AdapterError,
                    "backport-release-train-binding-mismatch",
                ):
                    self.fixture.load()
                write_json(
                    self.fixture.backport_release_train_validation_path,
                    original,
                )

    def test_bundle_rejects_substituted_full_backport_authorization(self) -> None:
        changed = copy.deepcopy(
            self.fixture.backport_release_train_authorization
        )
        changed["candidateCommit"] = "f" * 40
        changed["authorizationDigest"] = semantic_digest(
            {
                key: item
                for key, item in changed.items()
                if key != "authorizationDigest"
            }
        )
        changed_validation = copy.deepcopy(
            self.fixture.backport_release_train_validation
        )
        changed_validation["authorization"]["authorizationDigest"] = changed[
            "authorizationDigest"
        ]
        changed_validation["validationDigest"] = semantic_digest(
            {
                key: item
                for key, item in changed_validation.items()
                if key != "validationDigest"
            }
        )
        write_json(
            self.fixture.backport_release_train_authorization_path,
            changed,
        )
        write_json(
            self.fixture.backport_release_train_validation_path,
            changed_validation,
        )

        with self.assertRaisesRegex(
            publication.AdapterError,
            "backport-release-train-binding-mismatch",
        ):
            self.fixture.load()

    def test_protected_boundary_rejects_stale_backport_release_train(self) -> None:
        validation = copy.deepcopy(
            self.fixture.backport_release_train_validation
        )
        authorization = copy.deepcopy(
            self.fixture.backport_release_train_authorization
        )
        validation["generatedAt"] = timestamp(
            NOW - dt.timedelta(days=14, seconds=1)
        )
        seal_backport_handoff(validation, authorization)

        with self.assertRaisesRegex(
            publication.AdapterError,
            "backport-release-train-binding-mismatch",
        ):
            publication._validate_backport_release_train(  # noqa: SLF001
                validation,
                authorization,
                plan=self.fixture.plan,
                lineage=self.fixture.lineage,
                candidate_scope={},
                handoff_at=NOW,
                now=NOW,
            )

    def test_protected_boundary_rejects_expired_candidate_evidence(self) -> None:
        validation = copy.deepcopy(
            self.fixture.backport_release_train_validation
        )
        authorization = copy.deepcopy(
            self.fixture.backport_release_train_authorization
        )
        evidence_result = validation["evidenceResults"][0]
        evidence_result["generatedAt"] = timestamp(
            NOW - dt.timedelta(hours=2)
        )
        evidence_result["expiresAt"] = timestamp(
            NOW - dt.timedelta(minutes=1)
        )
        evidence_result["freshnessDeadlineAt"] = evidence_result["expiresAt"]
        seal_backport_handoff(validation, authorization)

        with self.assertRaisesRegex(
            publication.AdapterError,
            "backport-release-train-binding-mismatch",
        ):
            publication._validate_backport_release_train(  # noqa: SLF001
                validation,
                authorization,
                plan=self.fixture.plan,
                lineage=self.fixture.lineage,
                candidate_scope={},
                handoff_at=NOW,
                now=NOW,
            )

    def test_protected_boundary_binds_hotfix_train_to_candidate_scope(
        self,
    ) -> None:
        validation = copy.deepcopy(
            self.fixture.backport_release_train_validation
        )
        authorization = copy.deepcopy(
            self.fixture.backport_release_train_authorization
        )
        plan = copy.deepcopy(self.fixture.plan)
        plan["releaseClass"] = "security-hotfix"
        validation["release"]["releaseClass"] = "security-hotfix"
        public_fix = validation["publicFixes"][0]
        public_fix.update(
            {
                "classification": "security-fix",
                "severity": "critical",
                "incidentOpaqueId": "incident-opaque-287",
                "advisoryOpaqueId": "advisory-opaque-287",
                "publicSecuritySummary": (
                    "A bounded security correction is available."
                ),
                "disclosureState": "protected-embargoed",
            }
        )
        public_fix["publicProjectionDigest"] = semantic_digest(
            {
                "fixId": public_fix["fixId"],
                "classification": public_fix["classification"],
                "publicSummary": public_fix["publicSummary"],
            }
        )
        public_fix["securityPublicProjectionDigest"] = semantic_digest(
            {
                "fixId": public_fix["fixId"],
                "incidentOpaqueId": public_fix["incidentOpaqueId"],
                "advisoryOpaqueId": public_fix["advisoryOpaqueId"],
                "severity": public_fix["severity"],
                "disclosureState": public_fix["disclosureState"],
                "publicSafeSummary": public_fix["publicSecuritySummary"],
            }
        )
        incident_scope_digest = digest("hotfix-incident-scope")
        validation["evidenceResults"].append(
            {
                "fixId": public_fix["fixId"],
                "evidenceId": "stable-backport.security-incident-scope",
                "status": "pass",
                "evidenceDigest": incident_scope_digest,
                **train_evidence_freshness(),
                "candidateBound": True,
                "predecessorBound": True,
                "fresh": True,
            }
        )
        authorization["role"] = "stable-security-train-manager"
        seal_backport_handoff(validation, authorization)
        matching_scope = {
            "incidentId": public_fix["advisoryOpaqueId"],
            "severity": "critical",
            "hotfixPolicyAuthorizationDigest": incident_scope_digest,
        }

        publication._validate_backport_release_train(  # noqa: SLF001
            validation,
            authorization,
            plan=plan,
            lineage=self.fixture.lineage,
            candidate_scope=matching_scope,
            handoff_at=NOW,
            now=NOW,
        )
        stale_validation = copy.deepcopy(validation)
        stale_authorization = copy.deepcopy(authorization)
        stale_validation["generatedAt"] = timestamp(
            NOW - dt.timedelta(hours=24, seconds=1)
        )
        seal_backport_handoff(stale_validation, stale_authorization)
        with self.assertRaisesRegex(
            publication.AdapterError,
            "backport-release-train-binding-mismatch",
        ):
            publication._validate_backport_release_train(  # noqa: SLF001
                stale_validation,
                stale_authorization,
                plan=plan,
                lineage=self.fixture.lineage,
                candidate_scope=matching_scope,
                handoff_at=NOW,
                now=NOW,
            )
        mismatches = (
            {"incidentId": "advisory-opaque-other"},
            {"hotfixPolicyAuthorizationDigest": digest("other-scope")},
        )
        for mismatch in mismatches:
            with self.subTest(mismatch=mismatch):
                candidate_scope = {**matching_scope, **mismatch}
                with self.assertRaisesRegex(
                    publication.AdapterError,
                    "backport-release-train-binding-mismatch",
                ):
                    publication._validate_backport_release_train(  # noqa: SLF001
                        validation,
                        authorization,
                        plan=plan,
                        lineage=self.fixture.lineage,
                        candidate_scope=candidate_scope,
                        handoff_at=NOW,
                        now=NOW,
                    )

    def test_protected_boundary_rejects_noncritical_security_hotfix_train(
        self,
    ) -> None:
        validation = copy.deepcopy(
            self.fixture.backport_release_train_validation
        )
        authorization = copy.deepcopy(
            self.fixture.backport_release_train_authorization
        )
        plan = copy.deepcopy(self.fixture.plan)
        plan["releaseClass"] = "security-hotfix"
        validation["release"]["releaseClass"] = "security-hotfix"
        public_fix = validation["publicFixes"][0]
        public_fix.update(
            {
                "classification": "security-fix",
                "severity": "high",
                "incidentOpaqueId": "incident-opaque-287",
                "advisoryOpaqueId": "advisory-opaque-287",
                "publicSecuritySummary": "A bounded security correction is available.",
                "disclosureState": "protected-embargoed",
            }
        )
        public_fix["publicProjectionDigest"] = semantic_digest(
            {
                "fixId": public_fix["fixId"],
                "classification": public_fix["classification"],
                "publicSummary": public_fix["publicSummary"],
            }
        )
        public_fix["securityPublicProjectionDigest"] = semantic_digest(
            {
                "fixId": public_fix["fixId"],
                "incidentOpaqueId": public_fix["incidentOpaqueId"],
                "advisoryOpaqueId": public_fix["advisoryOpaqueId"],
                "severity": public_fix["severity"],
                "disclosureState": public_fix["disclosureState"],
                "publicSafeSummary": public_fix["publicSecuritySummary"],
            }
        )
        prepare_validation = copy.deepcopy(validation)
        prepare_validation["mode"] = "prepare-candidate"
        prepare_validation["authorization"] = None
        prepare_validation.pop("validationDigest", None)
        authorization.update(
            {
                "release": validation["release"],
                "validationDigest": semantic_digest(prepare_validation),
                "acceptedFixes": validation["publicFixes"],
                "securityOpaqueIds": [public_fix["incidentOpaqueId"]],
                "role": "stable-security-train-manager",
            }
        )
        authorization["authorizationDigest"] = semantic_digest(
            {
                key: item
                for key, item in authorization.items()
                if key != "authorizationDigest"
            }
        )
        validation["authorization"] = {
            "authorizationDigest": authorization["authorizationDigest"],
            "status": "valid",
            "expiresAt": authorization["expiresAt"],
            "role": authorization["role"],
        }
        validation["validationDigest"] = semantic_digest(
            {
                key: item
                for key, item in validation.items()
                if key != "validationDigest"
            }
        )

        with self.assertRaisesRegex(
            publication.AdapterError,
            "backport-release-train-binding-mismatch",
        ):
            publication._validate_backport_release_train(  # noqa: SLF001
                validation,
                authorization,
                plan=plan,
                lineage=self.fixture.lineage,
                candidate_scope={},
                handoff_at=NOW,
                now=NOW,
            )

    def test_bundle_rejects_release_train_digest_claim_substitution(self) -> None:
        changed_plan = copy.deepcopy(self.fixture.plan)
        changed_plan["backportReleaseTrainDigest"] = digest("substituted-train")
        write_json(self.fixture.plan_path, changed_plan)

        with self.assertRaisesRegex(
            publication.AdapterError, "authorization-binding-mismatch"
        ):
            self.fixture.load()

    def test_successor_history_and_pointer_bind_the_exact_release_train(
        self,
    ) -> None:
        bundle = self.fixture.load()
        material = self.fixture.material()
        pointer = publication._activated_latest_pointer(
            material.successor_baseline,
            digest("successor"),
            material.maintenance_receipt,
            digest("receipt"),
            digest("history"),
        )
        self.assertEqual(
            pointer["backportReleaseTrainDigest"],
            self.fixture.backport_release_train_digest,
        )

        changed_successor = copy.deepcopy(material.successor_baseline)
        changed_successor["releaseTrain"]["validationDigest"] = digest(
            "substituted-train"
        )
        changed_material = publication.VerificationMaterial(
            material.maintenance_receipt,
            material.core_update_receipt,
            changed_successor,
            material.history_entry,
        )
        with self.assertRaisesRegex(
            publication.AdapterError, "successor-baseline-binding-mismatch"
        ):
            publication._validate_verification_material(changed_material, bundle)

    def activation_authorization(
        self,
        successor_path: Path,
        history_path: Path,
        receipt_path: Path,
        *,
        now: dt.datetime = NOW,
    ) -> Path:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        authorization = {
            "schemaVersion": 1,
            "kind": "stable-1.0-maintenance-activation-authorization",
            "generatedAt": timestamp(now),
            "authorizationId": "activation-12345-1",
            "authority": "github-protected-environment",
            "protectedEnvironment": "stable-1.0-maintenance-publication",
            "workflowRepository": publication.SOURCE_REPOSITORY,
            "workflowRunId": "12345",
            "workflowRunAttempt": 1,
            "sourceCommit": receipt["sourceCommit"],
            "releaseId": receipt["releaseId"],
            "buildVersion": receipt["buildVersion"],
            "releaseClass": receipt["releaseClass"],
            "candidateIdentityDigest": receipt["candidateIdentityDigest"],
            "publicationReceiptDigest": file_digest(receipt_path),
            "successorBaselineDigest": file_digest(successor_path),
            "historyDigest": file_digest(history_path),
            "originalAuthorizationDigest": file_digest(
                self.fixture.authorization_path
            ),
            "expectedCurrentPointerDigest": POINTER,
            "allowedScope": "successor-baseline:activate",
            "authorizedAt": timestamp(now),
            "expiresAt": timestamp(now + dt.timedelta(minutes=30)),
            "status": "approved",
            "redaction": redaction(),
        }
        path = self.root / f"{receipt_path.stem}-activation-authorization.json"
        write_json(path, authorization)
        return path

    @staticmethod
    def backend_source(lazy_dependency: str | None = None) -> str:
        lazy_import = ""
        lazy_result = "return 'authenticated-site'"
        if lazy_dependency is not None:
            lazy_import = f"import {lazy_dependency}\n        "
            lazy_result = f"return {lazy_dependency}.ORIGIN"
        return (
            "class Backend:\n"
            "    def observe_public_state(self, request):\n"
            f"        {lazy_import}{lazy_result}\n"
            "    def publish_target(self, target, request, protected_input):\n"
            "        return None\n"
            "    def verify_publication(self, request):\n"
            "        return None\n"
            "    def observe_latest_pointer(self, request):\n"
            "        return None\n"
            "    def activate_latest(self, request, protected_input):\n"
            "        return None\n"
            "def factory():\n"
            "    return Backend()\n"
        )

    def test_backend_loader_rejects_unscrubbed_target_credentials(self) -> None:
        environment = {
            publication.BACKEND_FACTORY_ENV: "reviewed_backend:factory",
            publication.BACKEND_SITE_ENV: str(self.root.resolve()),
            publication.CATALOG_INPUT_ENV: CATALOG_SECRET,
        }

        with self.assertRaisesRegex(
            publication.AdapterError,
            "protected-input-environment-not-scrubbed",
        ):
            publication._load_backend(environment)

    def test_backend_loader_uses_authenticated_site_instead_of_checkout_shadow(
        self,
    ) -> None:
        site = self.root / "authenticated-site"
        checkout = self.root / "candidate-checkout"
        site.mkdir()
        checkout.mkdir()
        module_name = "stable_maintenance_reviewed_backend_direct"
        (site / f"{module_name}.py").write_text(
            self.backend_source(), encoding="utf-8"
        )
        (checkout / f"{module_name}.py").write_text(
            "raise RuntimeError('candidate checkout backend executed')\n",
            encoding="utf-8",
        )
        original_path = list(sys.path)
        sys.path.insert(0, str(checkout))
        try:
            backend = publication._load_backend(
                {
                    publication.BACKEND_FACTORY_ENV: f"{module_name}:factory",
                    publication.BACKEND_SITE_ENV: str(site.resolve()),
                }
            )
            self.assertEqual(
                "authenticated-site", backend.observe_public_state(None)
            )
            loaded = sys.modules[module_name]
            self.assertTrue(
                Path(loaded.__file__).resolve().is_relative_to(site.resolve())
            )
        finally:
            sys.path[:] = original_path
            sys.modules.pop(module_name, None)

    def test_backend_lazy_import_replaces_preloaded_checkout_shadow(self) -> None:
        site = self.root / "authenticated-lazy-site"
        checkout = self.root / "candidate-lazy-checkout"
        site.mkdir()
        checkout.mkdir()
        module_name = "stable_maintenance_reviewed_backend_lazy"
        dependency_name = "stable_maintenance_reviewed_backend_dependency"
        (site / f"{module_name}.py").write_text(
            self.backend_source(dependency_name), encoding="utf-8"
        )
        (site / f"{dependency_name}.py").write_text(
            "ORIGIN = 'authenticated-site'\n", encoding="utf-8"
        )
        (checkout / f"{dependency_name}.py").write_text(
            "ORIGIN = 'candidate-checkout'\n", encoding="utf-8"
        )
        original_path = list(sys.path)
        sys.path.insert(0, str(checkout))
        try:
            shadow = importlib.import_module(dependency_name)
            self.assertEqual("candidate-checkout", shadow.ORIGIN)
            backend = publication._load_backend(
                {
                    publication.BACKEND_FACTORY_ENV: f"{module_name}:factory",
                    publication.BACKEND_SITE_ENV: str(site.resolve()),
                }
            )
            self.assertEqual(
                "authenticated-site", backend.observe_public_state(None)
            )
            loaded = sys.modules[dependency_name]
            self.assertTrue(
                Path(loaded.__file__).resolve().is_relative_to(site.resolve())
            )
        finally:
            sys.path[:] = original_path
            sys.modules.pop(module_name, None)
            sys.modules.pop(dependency_name, None)

    def test_backend_loader_requires_explicit_authenticated_site(self) -> None:
        with self.assertRaisesRegex(
            publication.AdapterError,
            "protected-publication-backend-site-not-authenticated",
        ):
            publication._load_backend(
                {publication.BACKEND_FACTORY_ENV: "reviewed_backend:factory"}
            )

    def test_preflight_requires_prestaged_artifact_base(self) -> None:
        absent = self.operations()
        absent.targets["artifactBase"] = "absent"
        outcome = publication.preflight(
            self.fixture.root, POINTER, absent, now=NOW
        )
        self.assertFalse(outcome.passed)
        self.assertEqual("absent", outcome.artifact["publicState"])
        self.assertEqual(
            "artifact-base-not-prestaged", outcome.artifact["failureCategory"]
        )
        self.assertEqual([], absent.publish_calls)

        matching = self.operations(status="matching", operation="verified-existing")
        matching.latest_candidate = self.fixture.candidate_digest
        outcome = publication.preflight(
            self.fixture.root, POINTER, matching, now=NOW
        )
        self.assertTrue(outcome.passed)
        self.assertEqual("matching-existing", outcome.artifact["publicState"])

    def test_preflight_records_conflict_partial_and_unavailable_state(self) -> None:
        for target_status, expected in (
            ("conflict", "conflict"),
            ("unavailable", "unavailable"),
        ):
            with self.subTest(target_status=target_status):
                operations = self.operations(status=target_status)
                outcome = publication.preflight(
                    self.fixture.root, POINTER, operations, now=NOW
                )
                self.assertFalse(outcome.passed)
                self.assertEqual(expected, outcome.artifact["publicState"])
                self.assertFalse(outcome.artifact["sideEffectsPerformed"])

        resumable = self.operations()
        outcome = publication.preflight(self.fixture.root, POINTER, resumable, now=NOW)
        self.assertTrue(outcome.passed)
        self.assertEqual("resumable-prefix", outcome.artifact["publicState"])

        operations = self.operations()
        operations.targets["githubRelease"] = "matching"
        outcome = publication.preflight(self.fixture.root, POINTER, operations, now=NOW)
        self.assertFalse(outcome.passed)
        self.assertEqual("partial", outcome.artifact["publicState"])

    def test_duplicate_json_and_mutated_frozen_asset_fail_closed(self) -> None:
        self.fixture.plan_path.write_text(
            '{"schemaVersion":1,"schemaVersion":1}\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(publication.AdapterError, "duplicate-json-field"):
            self.fixture.load()

        replacement = BundleFixture(self.root / "mutated-bundle")
        replacement.product.write_bytes(b"changed after authorization\n")
        with self.assertRaisesRegex(
            publication.AdapterError, "publication-plan-asset-byte-mismatch"
        ):
            replacement.load()

        replaced_signature = BundleFixture(self.root / "mutated-catalog-signature")
        replaced_signature.catalog_signature.write_bytes(
            b"changed detached catalog signature after authorization\n"
        )
        with self.assertRaisesRegex(
            publication.AdapterError, "publication-plan-asset-byte-mismatch"
        ):
            replaced_signature.load()

    def test_substituted_candidate_freeze_record_fails_closed(self) -> None:
        replacement = BundleFixture(self.root / "substituted-freeze-bundle")
        replacement.candidate_freeze["producer"]["runAttempt"] = 2
        write_json(replacement.candidate_freeze_path, replacement.candidate_freeze)

        with self.assertRaisesRegex(
            publication.AdapterError, "authenticated-candidate-input-binding-mismatch"
        ):
            replacement.load()

    def test_publish_revalidates_before_every_target_and_writes_exact_receipts(self) -> None:
        operations = self.operations()
        source_ref_checks: list[str] = []
        receipt = self.root / "publication-receipt.json"
        core_receipt = self.root / "core-receipt.json"
        outcome = publication.publish_or_verify_exact(
            self.fixture.root,
            POINTER,
            operations,
            self.protected_inputs(),
            lambda record: source_ref_checks.append(
                str(record.plan["sourceCommit"])
            ),
            receipt,
            core_receipt,
            now=lambda: NOW,
        )
        self.assertTrue(outcome.passed)
        self.assertEqual(list(publication.TARGETS[1:]), operations.publish_calls)
        self.assertEqual([COMMIT] * len(publication.TARGETS[1:]), source_ref_checks)
        self.assertEqual(
            [
                ("tag", None),
                ("githubRelease", None),
                ("assets", None),
                ("stableCatalog", "stable-catalog"),
                ("coreUpdate", "core-update"),
            ],
            operations.publish_input_purposes,
        )
        self.assertEqual(
            [
                ("tag", None),
                ("githubRelease", None),
                ("assets", None),
                ("stableCatalog", CATALOG_SECRET),
                ("coreUpdate", CORE_UPDATE_SECRET),
            ],
            operations.publish_input_values,
        )
        self.assertEqual(len(publication.TARGETS) + 1, operations.observe_calls)
        for path, value in outcome.artifacts.items():
            publication._write_canonical(
                path,
                value,
                (
                    self.protected_inputs().stable_catalog,
                    self.protected_inputs().core_update,
                ),
            )
            encoded = path.read_text(encoding="utf-8")
            self.assertNotIn(CATALOG_SECRET, encoded)
            self.assertNotIn(CORE_UPDATE_SECRET, encoded)
        self.assertEqual(
            "publication-complete", json.loads(receipt.read_text())["publicationState"]
        )

    def test_publish_resumes_only_an_exact_matching_target_prefix(self) -> None:
        operations = self.operations(fail_target="assets")
        receipt = self.root / "resumed-publication-receipt.json"
        core_receipt = self.root / "resumed-core-receipt.json"

        failed = publication.publish_or_verify_exact(
            self.fixture.root,
            POINTER,
            operations,
            self.protected_inputs(),
            lambda _record: None,
            receipt,
            core_receipt,
            now=lambda: NOW,
        )

        self.assertFalse(failed.passed)
        self.assertEqual(
            ["tag", "githubRelease", "assets"],
            operations.publish_calls,
        )
        self.assertEqual(
            "resumable-prefix",
            publication._public_state_class(
                publication.PublicSnapshot(POINTER, dict(operations.targets))
            ),
        )

        operations.fail_target = None
        operations.publish_calls.clear()
        resumed = publication.publish_or_verify_exact(
            self.fixture.root,
            POINTER,
            operations,
            self.protected_inputs(),
            lambda _record: None,
            receipt,
            core_receipt,
            now=lambda: NOW,
        )

        self.assertTrue(resumed.passed)
        self.assertEqual(
            ["assets", "stableCatalog", "coreUpdate"],
            operations.publish_calls,
        )

    def test_exact_matching_publication_is_idempotent_and_has_no_mutation(self) -> None:
        operations = self.operations(status="matching", operation="verified-existing")
        operations.latest_candidate = self.fixture.candidate_digest
        outcome = publication.publish_or_verify_exact(
            self.fixture.root,
            POINTER,
            operations,
            self.protected_inputs(),
            lambda _record: None,
            self.root / "receipt.json",
            self.root / "core.json",
            now=lambda: NOW,
        )
        self.assertTrue(outcome.passed)
        self.assertEqual([], operations.publish_calls)
        self.assertEqual(
            "verified-existing",
            outcome.artifacts[self.root / "receipt.json"]["tag"]["operation"],
        )

    def test_mid_publication_failure_records_truthful_partial_state_without_secret(self) -> None:
        operations = self.operations(fail_target="stableCatalog")
        receipt_path = self.root / "partial.json"
        outcome = publication.publish_or_verify_exact(
            self.fixture.root,
            POINTER,
            operations,
            self.protected_inputs(),
            lambda _record: None,
            receipt_path,
            self.root / "core-partial.json",
            now=lambda: NOW,
        )
        self.assertFalse(outcome.passed)
        audit_path = publication._failure_audit_path(receipt_path)
        self.assertNotIn(receipt_path, outcome.artifacts)
        self.assertNotIn(self.root / "core-partial.json", outcome.artifacts)
        audit = outcome.artifacts[audit_path]
        self.assertEqual(
            "stable-1.0-maintenance-publication-failure-audit", audit["kind"]
        )
        self.assertEqual("publication-partial", audit["publicationState"])
        self.assertEqual("matching", audit["observedPublicState"]["tag"])
        self.assertEqual("absent", audit["observedPublicState"]["stableCatalog"])
        self.assertTrue(audit["sideEffectsMayHaveOccurred"])
        self.assertEqual(
            ["tag", "githubRelease", "assets", "stableCatalog"],
            audit["attemptedTargets"],
        )
        self.assertEqual(
            ["artifactBase", "tag", "githubRelease", "assets"],
            audit["completedTargets"],
        )
        self.assertEqual(
            ["tag", "githubRelease", "assets", "stableCatalog"],
            operations.publish_calls,
        )
        encoded = canonical_bytes(audit).decode("utf-8")
        self.assertNotIn(CATALOG_SECRET, encoded)
        self.assertNotIn(CORE_UPDATE_SECRET, encoded)

    def test_failed_observation_retains_attempted_and_completed_mutations(self) -> None:
        class ObservationUnavailableAfterFailure(FakeOperations):
            def observe_public_state(
                self, request: publication.PublicationRequest
            ) -> publication.PublicSnapshot:
                if self.fail_target in self.publish_calls:
                    raise RuntimeError("public observation unavailable")
                return super().observe_public_state(request)

        operations = ObservationUnavailableAfterFailure(
            self.fixture.material(), fail_target="githubRelease"
        )
        operations.targets["artifactBase"] = "matching"
        receipt_path = self.root / "unavailable-after-mutation.json"

        outcome = publication.publish_or_verify_exact(
            self.fixture.root,
            POINTER,
            operations,
            self.protected_inputs(),
            lambda _record: None,
            receipt_path,
            self.root / "unavailable-after-mutation-core.json",
            now=lambda: NOW,
        )

        self.assertFalse(outcome.passed)
        audit = outcome.artifacts[publication._failure_audit_path(receipt_path)]
        self.assertEqual("publication-partial", audit["publicationState"])
        self.assertEqual(
            {target: "unavailable" for target in publication.TARGETS},
            audit["observedPublicState"],
        )
        self.assertEqual(
            ["tag", "githubRelease"], audit["attemptedTargets"]
        )
        self.assertEqual(["artifactBase", "tag"], audit["completedTargets"])
        self.assertTrue(audit["sideEffectsMayHaveOccurred"])

    def test_authorization_expiry_blocks_first_mutation(self) -> None:
        operations = self.operations()
        outcome = publication.publish_or_verify_exact(
            self.fixture.root,
            POINTER,
            operations,
            self.protected_inputs(),
            lambda _record: None,
            self.root / "expired.json",
            self.root / "expired-core.json",
            now=lambda: NOW + dt.timedelta(days=730),
        )
        self.assertFalse(outcome.passed)
        self.assertEqual([], operations.publish_calls)

    def test_authorization_expiring_during_ref_check_blocks_first_mutation(self) -> None:
        operations = self.operations()
        expired = NOW + dt.timedelta(days=730)
        times = iter((NOW, NOW, expired, expired))

        outcome = publication.publish_or_verify_exact(
            self.fixture.root,
            POINTER,
            operations,
            self.protected_inputs(),
            lambda _record: None,
            self.root / "expired-after-ref.json",
            self.root / "expired-after-ref-core.json",
            now=lambda: next(times),
        )

        self.assertFalse(outcome.passed)
        self.assertEqual([], operations.publish_calls)
        audit = outcome.artifacts[
            publication._failure_audit_path(self.root / "expired-after-ref.json")
        ]
        self.assertEqual(
            "authorization-expired-before-mutation", audit["failureCategory"]
        )

    def test_remote_source_ref_verifier_authenticates_exact_head_without_leaking_token(
        self,
    ) -> None:
        token = "github-protected-source-ref-token"
        requests: list[object] = []

        class Response:
            status = 200

            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *_arguments: object) -> None:
                return None

            @staticmethod
            def read(_size: int) -> bytes:
                return json.dumps(
                    {
                        "ref": f"refs/heads/release/{BUILD}",
                        "object": {"type": "commit", "sha": COMMIT},
                    }
                ).encode("utf-8")

        def open_source_ref(request: object, *, timeout: int) -> Response:
            self.assertEqual(30, timeout)
            requests.append(request)
            return Response()

        revalidator = publication._make_remote_source_ref_revalidator(
            publication.SOURCE_REPOSITORY,
            f"release/{BUILD}",
            COMMIT,
            publication.GITHUB_TOKEN_ENV,
            {publication.GITHUB_TOKEN_ENV: token},
            opener=open_source_ref,
        )

        revalidator(self.fixture.load())

        self.assertEqual(1, len(requests))
        self.assertEqual(
            f"Bearer {token}", requests[0].get_header("Authorization")
        )

    def test_workflow_publish_and_activation_use_literal_source_ref_token_contract(
        self,
    ) -> None:
        workflow = (
            SCRIPT.parents[3]
            / ".github/workflows/stable-1.0-maintenance-release.yml"
        ).read_text(encoding="utf-8")

        def step(name: str) -> str:
            marker = f"      - name: {name}"
            start = workflow.index(marker)
            end = workflow.find("\n      - name:", start + len(marker))
            return workflow[start:] if end == -1 else workflow[start:end]

        publish_call_site = step("Publish or idempotently verify exact bytes")
        self.assertIn(
            "GITHUB_TOKEN: ${{ secrets.LEUMOR_GITHUB_TOKEN }}", publish_call_site
        )
        self.assertNotIn("GITHUB_TOKEN: ${{ github.token }}", publish_call_site)
        self.assertIn("--github-token-env GITHUB_TOKEN", publish_call_site)
        self.assertNotIn("--github-token-env GH_TOKEN", publish_call_site)

        activation_call_site = step("Compare-and-swap latest-published pointer")
        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", activation_call_site)
        self.assertIn("--github-token-env GITHUB_TOKEN", activation_call_site)
        self.assertNotIn("--github-token-env GH_TOKEN", activation_call_site)
        self.assertEqual(2, workflow.count("--github-token-env GITHUB_TOKEN"))
        self.assertNotIn("--github-token-env GH_TOKEN", workflow)

    def test_remote_source_ref_movement_blocks_first_publication_target(self) -> None:
        operations = self.operations()

        def moved(_record: object) -> None:
            raise publication.AdapterError("remote-source-ref-moved")

        outcome = publication.publish_or_verify_exact(
            self.fixture.root,
            POINTER,
            operations,
            self.protected_inputs(),
            moved,
            self.root / "moved-ref-receipt.json",
            self.root / "moved-ref-core.json",
            now=lambda: NOW,
        )

        self.assertFalse(outcome.passed)
        self.assertEqual([], operations.publish_calls)
        audit = outcome.artifacts[
            publication._failure_audit_path(self.root / "moved-ref-receipt.json")
        ]
        self.assertEqual("remote-source-ref-moved", audit["failureCategory"])

    def test_independent_verification_is_read_only_and_emits_successor_records(self) -> None:
        operations = self.operations(status="matching")
        operations.latest_candidate = self.fixture.candidate_digest
        paths = [
            self.root / name
            for name in ("receipt", "core", "successor", "history")
        ]
        outcome = publication.verify_public_state(
            self.fixture.root, operations, *paths
        )
        self.assertTrue(outcome.passed)
        self.assertEqual([], operations.publish_calls)
        self.assertEqual(set(paths), set(outcome.artifacts))
        self.assertEqual(
            "stable-1.0-maintenance-successor-baseline",
            outcome.artifacts[paths[2]]["kind"],
        )

    def test_publication_receipt_identity_matches_the_engine_contract(self) -> None:
        receipt = dict(self.fixture.material().maintenance_receipt)

        self.assertEqual(
            engine_receipt_identity(receipt), publication._receipt_identity(receipt)
        )

    def test_verified_receipt_cannot_substitute_authorized_public_topology(self) -> None:
        for field in (
            "githubReleasePageUri",
            "deploymentServicePublicUri",
            "latestPointerPublicUri",
        ):
            with self.subTest(field=field):
                material = self.fixture.material()
                receipt = copy.deepcopy(material.maintenance_receipt)
                receipt[field] = f"https://substituted.example.com/{field}"
                replaced = publication.VerificationMaterial(
                    receipt,
                    material.core_update_receipt,
                    material.successor_baseline,
                    material.history_entry,
                )
                with self.assertRaisesRegex(
                    publication.AdapterError,
                    "maintenance-publication-receipt-mismatch",
                ):
                    publication._validate_verification_material(
                        replaced, self.fixture.load()
                    )

    def test_independent_verification_rejects_provider_successor_surface_drift(self) -> None:
        material = self.fixture.material()
        successor = copy.deepcopy(material.successor_baseline)
        successor["platformApi"]["currentContractDigest"] = digest(
            "provider-substituted-contract"
        )
        operations = FakeOperations(
            publication.VerificationMaterial(
                material.maintenance_receipt,
                material.core_update_receipt,
                successor,
                material.history_entry,
            ),
            target_status="matching",
        )
        operations.latest_candidate = self.fixture.candidate_digest
        paths = [self.root / name for name in ("receipt", "core", "successor", "history")]

        outcome = publication.verify_public_state(
            self.fixture.root, operations, *paths
        )

        self.assertFalse(outcome.passed)
        self.assertEqual([], operations.publish_calls)
        audit_path = publication._failure_audit_path(paths[0])
        self.assertEqual(
            "successor-baseline-binding-mismatch",
            outcome.artifacts[audit_path]["failureCategory"],
        )
        self.assertNotIn(paths[0], outcome.artifacts)
        self.assertNotIn(paths[2], outcome.artifacts)

    def test_independent_verification_rejects_unverified_github_release(self) -> None:
        for status in ("conflict", "unavailable"):
            with self.subTest(status=status):
                material = self.fixture.material()
                receipt = copy.deepcopy(material.maintenance_receipt)
                receipt["githubRelease"]["verificationStatus"] = status
                operations = FakeOperations(
                    publication.VerificationMaterial(
                        receipt,
                        material.core_update_receipt,
                        material.successor_baseline,
                        material.history_entry,
                    ),
                    target_status="matching",
                )
                operations.latest_candidate = self.fixture.candidate_digest
                paths = [
                    self.root / f"{status}-{name}"
                    for name in ("receipt", "core", "successor", "history")
                ]

                outcome = publication.verify_public_state(
                    self.fixture.root, operations, *paths
                )

                self.assertFalse(outcome.passed)
                self.assertEqual([], operations.publish_calls)
                audit_path = publication._failure_audit_path(paths[0])
                self.assertEqual(
                    "maintenance-publication-receipt-mismatch",
                    outcome.artifacts[audit_path]["failureCategory"],
                )
                self.assertNotIn(paths[0], outcome.artifacts)
                self.assertNotIn(paths[2], outcome.artifacts)

    def test_successor_verification_carries_inherited_hotfix_obligation(self) -> None:
        material = self.fixture.material()
        inherited = {
            "status": "open",
            "generatedAt": timestamp(NOW - dt.timedelta(days=1)),
            "obligationDigest": digest("inherited-hotfix-obligation"),
            "deadline": timestamp(NOW + dt.timedelta(days=6)),
            "closureEvidenceDigest": None,
            "blocksRoutineMaintenance": True,
            "obligatedReleaseId": "stable-1-0-hotfix-300",
            "obligatedBuildVersion": "300",
            "obligatedProductDigest": digest("obligated-product"),
            "obligatedCandidateIdentityDigest": digest("obligated-candidate"),
            "obligatedCandidateFreezeDigest": digest("obligated-freeze"),
            "obligatedCandidateFrozenAt": timestamp(NOW - dt.timedelta(days=3)),
            "obligatedPredecessorBuild": "299",
            "obligatedPredecessorProductDigest": digest("obligated-predecessor"),
            "authorizationDigest": digest("obligated-authorization"),
        }
        bundle = self.fixture.load()
        bundle = dataclasses.replace(
            bundle,
            predecessor_baseline={
                **bundle.predecessor_baseline,
                "hotfixFollowUp": inherited,
            },
        )
        successor = copy.deepcopy(material.successor_baseline)
        successor["hotfixFollowUp"] = dict(inherited)
        successor["releaseTrain"]["unresolvedObligationsCarried"] = True
        successor["lineage"]["history"][-1]["baselineIdentityDigest"] = (
            publication._successor_identity(successor)
        )
        successor["lineage"]["lineageDigest"] = semantic_digest(
            successor["lineage"]["history"]
        )
        history_digest = "sha256:" + hashlib.sha256(
            canonical_bytes(material.history_entry)
        ).hexdigest()

        publication._validate_successor(
            successor,
            material.history_entry,
            history_digest,
            bundle,
            publication._receipt_identity(material.maintenance_receipt),
        )
        successor["hotfixFollowUp"] = {
            "status": "not-required",
            "generatedAt": timestamp(NOW),
            "obligationDigest": None,
            "deadline": None,
            "closureEvidenceDigest": None,
            "blocksRoutineMaintenance": False,
        }

        with self.assertRaises(publication.AdapterError) as raised:
            publication._validate_successor(
                successor,
                material.history_entry,
                history_digest,
                bundle,
                publication._receipt_identity(material.maintenance_receipt),
            )

        self.assertEqual("successor-baseline-binding-mismatch", raised.exception.code)

    def test_successor_verification_carries_overdue_hotfix_obligation(self) -> None:
        inherited = {
            "status": "overdue",
            "generatedAt": timestamp(NOW - dt.timedelta(days=10)),
            "obligationDigest": digest("overdue-hotfix-obligation"),
            "deadline": timestamp(NOW - dt.timedelta(days=3)),
            "closureEvidenceDigest": None,
            "blocksRoutineMaintenance": True,
            "obligatedReleaseId": "stable-1-0-hotfix-300",
            "obligatedBuildVersion": "300",
            "obligatedProductDigest": digest("obligated-product"),
            "obligatedCandidateIdentityDigest": digest("obligated-candidate"),
            "obligatedCandidateFreezeDigest": digest("obligated-freeze"),
            "obligatedCandidateFrozenAt": timestamp(NOW - dt.timedelta(days=10)),
            "obligatedPredecessorBuild": "299",
            "obligatedPredecessorProductDigest": digest("obligated-predecessor"),
            "authorizationDigest": digest("obligated-authorization"),
        }
        bundle = self.fixture.load()
        bundle = dataclasses.replace(
            bundle,
            predecessor_baseline={
                **bundle.predecessor_baseline,
                "hotfixFollowUp": inherited,
            },
        )

        self.assertEqual(
            inherited,
            publication._expected_successor_follow_up(bundle),
        )

    def test_successor_verification_applies_authenticated_closure_overlay(self) -> None:
        base_bundle = self.fixture.load()
        inherited = {
            "status": "open",
            "generatedAt": timestamp(NOW - dt.timedelta(days=2)),
            "obligationDigest": digest("closed-hotfix-obligation"),
            "deadline": timestamp(NOW + dt.timedelta(days=5)),
            "closureEvidenceDigest": None,
            "blocksRoutineMaintenance": True,
            "obligatedReleaseId": "stable-1-0-hotfix-300",
            "obligatedBuildVersion": "300",
            "obligatedProductDigest": digest("closed-product"),
            "obligatedCandidateIdentityDigest": digest("closed-candidate"),
            "obligatedCandidateFreezeDigest": digest("closed-freeze"),
            "obligatedCandidateFrozenAt": timestamp(NOW - dt.timedelta(days=3)),
            "obligatedPredecessorBuild": "299",
            "obligatedPredecessorProductDigest": digest("closed-predecessor"),
            "authorizationDigest": digest("closed-authorization"),
        }
        receipt_file_digest = digest("closed-publication-receipt")
        receipt_identity_digest = digest("closed-publication-receipt-identity")
        predecessor_baseline = {
            **self.fixture.ga_baseline,
            "publication": {"receiptIdentityDigest": receipt_identity_digest},
            "hotfixFollowUp": inherited,
        }
        predecessor_path = self.root / "closed-predecessor-baseline.json"
        write_json(predecessor_path, predecessor_baseline)
        closure = {
            "schemaVersion": 1,
            "kind": "stable-1.0-hotfix-follow-up-closure",
            "generatedAt": timestamp(NOW),
            "closedAt": timestamp(NOW),
            "status": "closed",
            "releaseId": inherited["obligatedReleaseId"],
            "buildVersion": inherited["obligatedBuildVersion"],
            "releaseClass": "security-hotfix",
            "productDigest": inherited["obligatedProductDigest"],
            "candidateIdentityDigest": inherited["obligatedCandidateIdentityDigest"],
            "predecessorBuild": inherited["obligatedPredecessorBuild"],
            "predecessorProductDigest": inherited[
                "obligatedPredecessorProductDigest"
            ],
            "successorBaselineDigest": file_digest(predecessor_path),
            "publicationReceiptDigest": receipt_file_digest,
            "publicationReceiptIdentityDigest": receipt_identity_digest,
            "authorizationDigest": inherited["authorizationDigest"],
            "latestPublishedPointerDigest": POINTER,
            "obligationDigest": inherited["obligationDigest"],
            "fullEvidenceDigest": digest("closed-full-evidence"),
            "owner": "stable-security-team",
            "approver": "stable-security-release-manager",
            "redaction": redaction(),
        }
        closure_path = (
            self.fixture.authenticated_inputs / publication.FOLLOW_UP_CLOSURE_FILE
        )
        write_json(closure_path, closure)
        lineage = copy.deepcopy(self.fixture.lineage)
        lineage["predecessor"].update(
            {
                "publicationReceiptDigest": receipt_file_digest,
                "successorBaselineDigest": file_digest(predecessor_path),
                "hotfixFollowUpClosureDigest": file_digest(closure_path),
            }
        )
        lineage["latestPublishedPointerDigest"] = POINTER

        loaded_path, loaded_closure = publication._load_follow_up_closure(
            self.fixture.authenticated_inputs,
            lineage,
            predecessor_baseline,
            predecessor_path,
        )
        bundle = dataclasses.replace(
            base_bundle,
            lineage=lineage,
            predecessor_baseline_path=predecessor_path,
            predecessor_baseline=predecessor_baseline,
            follow_up_closure_path=loaded_path,
            follow_up_closure=loaded_closure,
        )

        expected = publication._expected_successor_follow_up(bundle)

        self.assertEqual("not-required", expected["status"])
        self.assertFalse(expected["blocksRoutineMaintenance"])
        self.assertIsNone(expected["obligationDigest"])

        substituted_closure = copy.deepcopy(closure)
        substituted_closure["predecessorBuild"] = "298"
        write_json(closure_path, substituted_closure)
        substituted_lineage = copy.deepcopy(lineage)
        substituted_lineage["predecessor"]["hotfixFollowUpClosureDigest"] = (
            file_digest(closure_path)
        )
        with self.assertRaises(publication.AdapterError) as raised:
            publication._load_follow_up_closure(
                self.fixture.authenticated_inputs,
                substituted_lineage,
                predecessor_baseline,
                predecessor_path,
            )
        self.assertEqual(
            "hotfix-follow-up-closure-binding-mismatch", raised.exception.code
        )

        write_json(closure_path, closure)
        closure["fullEvidenceDigest"] = digest("tampered-full-evidence")
        write_json(closure_path, closure)
        with self.assertRaises(publication.AdapterError) as raised:
            publication._load_follow_up_closure(
                self.fixture.authenticated_inputs,
                lineage,
                predecessor_baseline,
                predecessor_path,
            )
        self.assertEqual(
            "hotfix-follow-up-closure-digest-mismatch", raised.exception.code
        )

    def test_verification_rejects_duplicate_failed_asset_observation(self) -> None:
        material = self.fixture.material()
        receipt = copy.deepcopy(material.maintenance_receipt)
        duplicate = dict(receipt["assets"][0])
        duplicate["operation"] = "partial"
        duplicate["verificationStatus"] = "conflict"
        receipt["assets"].append(duplicate)

        with self.assertRaises(publication.AdapterError) as raised:
            publication._validate_verification_material(
                publication.VerificationMaterial(
                    receipt,
                    material.core_update_receipt,
                    material.successor_baseline,
                    material.history_entry,
                ),
                self.fixture.load(),
            )

        self.assertEqual(
            "maintenance-publication-receipt-mismatch", raised.exception.code
        )

    def test_verification_rejects_duplicate_failed_core_package_observation(self) -> None:
        material = self.fixture.material()
        core_receipt = copy.deepcopy(material.core_update_receipt)
        duplicate = dict(core_receipt["referencedPackages"][0])
        duplicate["verificationStatus"] = "fail"
        core_receipt["referencedPackages"].append(duplicate)
        receipt = copy.deepcopy(material.maintenance_receipt)
        receipt["coreUpdateReceiptDigest"] = (
            "sha256:" + hashlib.sha256(canonical_bytes(core_receipt)).hexdigest()
        )

        with self.assertRaises(publication.AdapterError) as raised:
            publication._validate_verification_material(
                publication.VerificationMaterial(
                    receipt,
                    core_receipt,
                    material.successor_baseline,
                    material.history_entry,
                ),
                self.fixture.load(),
            )

        self.assertEqual(
            "core-update-publication-receipt-mismatch", raised.exception.code
        )

    def test_activation_rejects_receipt_for_a_different_release_train(self) -> None:
        material = self.fixture.material()
        receipt = copy.deepcopy(material.maintenance_receipt)
        history = copy.deepcopy(material.history_entry)
        successor = copy.deepcopy(material.successor_baseline)
        receipt["backportReleaseTrainDigest"] = digest("different-train")
        receipt_identity = publication._receipt_identity(receipt)
        history["publicationReceiptIdentityDigest"] = receipt_identity
        successor["publication"]["receiptIdentityDigest"] = receipt_identity
        successor["release"]["publicationReceiptIdentityDigest"] = receipt_identity
        successor["lineage"]["history"][-1][
            "publicationReceiptIdentityDigest"
        ] = receipt_identity
        successor_path = self.root / "successor-wrong-train.json"
        history_path = self.root / "history-wrong-train.json"
        receipt_path = self.root / "receipt-wrong-train.json"
        write_json(history_path, history)
        successor["releaseHistoryDigest"] = file_digest(history_path)
        write_json(successor_path, successor)
        receipt["successorBaselineDigest"] = file_digest(successor_path)
        receipt["releaseHistoryDigest"] = file_digest(history_path)
        write_json(receipt_path, receipt)

        with self.assertRaisesRegex(
            publication.AdapterError,
            "baseline-activation-input-binding-mismatch",
        ):
            publication._load_activation_request(  # noqa: SLF001
                successor_path,
                history_path,
                receipt_path,
                self.fixture.authorization_path,
                self.activation_authorization(
                    successor_path, history_path, receipt_path
                ),
                POINTER,
            )

    def test_activation_is_compare_and_swap_and_idempotent(self) -> None:
        material = self.fixture.material()
        successor_path = self.root / "successor.json"
        history_path = self.root / "history.json"
        receipt_path = self.root / "receipt.json"
        write_json(successor_path, material.successor_baseline)
        write_json(history_path, material.history_entry)
        write_json(receipt_path, material.maintenance_receipt)
        operations = self.operations()
        activation_path = self.root / "activation.json"
        outcome = publication.activate_latest_baseline(
            successor_path,
            history_path,
            receipt_path,
            self.fixture.authorization_path,
            self.activation_authorization(successor_path, history_path, receipt_path),
            POINTER,
            operations,
            self.maintenance_state_input(),
            lambda _record: None,
            activation_path,
            now=NOW,
        )
        self.assertTrue(outcome.passed)
        self.assertEqual(1, operations.activate_calls)
        self.assertEqual("maintenance-state", operations.activation_input_purpose)
        self.assertEqual(MAINTENANCE_STATE_SECRET, operations.activation_input_value)
        self.assertEqual("activated", outcome.artifacts[activation_path]["pointerUpdate"])
        expected_pointer = {
            "schemaVersion": 1,
            "kind": "stable-1.0-maintenance-latest-published",
            "generatedAt": material.successor_baseline["generatedAt"],
            "releaseId": RELEASE_ID,
            "buildVersion": BUILD,
            "releaseClass": "maintenance",
            "baselineDigest": file_digest(successor_path),
            "baselineIdentityDigest": publication._successor_identity(
                material.successor_baseline
            ),
            "publicationReceiptDigest": file_digest(receipt_path),
            "publicationReceiptIdentityDigest": publication._receipt_identity(
                material.maintenance_receipt
            ),
            "lineageDigest": material.successor_baseline["lineage"]["lineageDigest"],
            "historyDigest": file_digest(history_path),
            "backportReleaseTrainDigest": self.fixture.backport_release_train_digest,
            "compareAndSwapPredecessorBaselineDigest": material.successor_baseline[
                "previousBaselineDigest"
            ],
            "status": "active",
            "redaction": redaction(),
        }
        expected_pointer_bytes = canonical_bytes(expected_pointer)
        expected_pointer_digest = (
            "sha256:" + hashlib.sha256(expected_pointer_bytes).hexdigest()
        )
        self.assertEqual(expected_pointer_bytes, operations.activation_pointer_bytes)
        self.assertEqual(expected_pointer_digest, operations.pointer.pointer_digest)
        self.assertEqual(
            expected_pointer_digest,
            outcome.artifacts[activation_path]["expectedActivatedPointerDigest"],
        )
        self.assertEqual(
            expected_pointer_digest,
            outcome.artifacts[activation_path]["observedPointerDigest"],
        )

        idempotent_path = self.root / "activation-idempotent.json"
        outcome = publication.activate_latest_baseline(
            successor_path,
            history_path,
            receipt_path,
            self.fixture.authorization_path,
            self.activation_authorization(successor_path, history_path, receipt_path),
            POINTER,
            operations,
            self.maintenance_state_input(),
            lambda _record: None,
            idempotent_path,
            now=NOW,
        )
        self.assertTrue(outcome.passed)
        self.assertEqual(1, operations.activate_calls)
        self.assertEqual(
            "verified-existing", outcome.artifacts[idempotent_path]["operation"]
        )
        self.assertEqual(
            expected_pointer_digest,
            outcome.artifacts[idempotent_path]["observedPointerDigest"],
        )

    def test_activation_rejects_inexact_pointer_bytes_after_mutation(self) -> None:
        material = self.fixture.material()
        successor_path = self.root / "successor-inexact-pointer.json"
        history_path = self.root / "history-inexact-pointer.json"
        receipt_path = self.root / "receipt-inexact-pointer.json"
        write_json(successor_path, material.successor_baseline)
        write_json(history_path, material.history_entry)
        write_json(receipt_path, material.maintenance_receipt)
        operations = self.operations()
        operations.activation_pointer_digest_override = digest("inexact-pointer")
        activation_path = self.root / "activation-inexact-pointer.json"

        outcome = publication.activate_latest_baseline(
            successor_path,
            history_path,
            receipt_path,
            self.fixture.authorization_path,
            self.activation_authorization(successor_path, history_path, receipt_path),
            POINTER,
            operations,
            self.maintenance_state_input(),
            lambda _record: None,
            activation_path,
            now=NOW,
        )

        self.assertFalse(outcome.passed)
        self.assertEqual(1, operations.activate_calls)
        self.assertEqual(
            "latest-pointer-post-activation-mismatch",
            outcome.artifacts[activation_path]["failureCategory"],
        )
        self.assertEqual("partial", outcome.artifacts[activation_path]["operation"])
        self.assertEqual(
            digest("inexact-pointer"),
            outcome.artifacts[activation_path]["observedPointerDigest"],
        )
        self.assertNotEqual(
            outcome.artifacts[activation_path]["expectedActivatedPointerDigest"],
            outcome.artifacts[activation_path]["observedPointerDigest"],
        )

    def test_activation_rejects_inexact_preexisting_active_pointer(self) -> None:
        material = self.fixture.material()
        successor_path = self.root / "successor-inexact-existing.json"
        history_path = self.root / "history-inexact-existing.json"
        receipt_path = self.root / "receipt-inexact-existing.json"
        write_json(successor_path, material.successor_baseline)
        write_json(history_path, material.history_entry)
        write_json(receipt_path, material.maintenance_receipt)
        operations = self.operations()
        operations.pointer = publication.PointerSnapshot(
            "observed",
            digest("inexact-existing-pointer"),
            file_digest(successor_path),
            self.fixture.candidate_digest,
        )
        activation_path = self.root / "activation-inexact-existing.json"

        outcome = publication.activate_latest_baseline(
            successor_path,
            history_path,
            receipt_path,
            self.fixture.authorization_path,
            self.activation_authorization(successor_path, history_path, receipt_path),
            POINTER,
            operations,
            self.maintenance_state_input(),
            lambda _record: None,
            activation_path,
            now=NOW,
        )

        self.assertFalse(outcome.passed)
        self.assertEqual(0, operations.activate_calls)
        self.assertEqual(
            "latest-pointer-compare-and-swap-conflict",
            outcome.artifacts[activation_path]["failureCategory"],
        )
        self.assertEqual(
            digest("inexact-existing-pointer"),
            outcome.artifacts[activation_path]["observedPointerDigest"],
        )

    def test_activation_pointer_conflict_never_mutates(self) -> None:
        material = self.fixture.material()
        successor_path = self.root / "successor.json"
        history_path = self.root / "history.json"
        receipt_path = self.root / "receipt.json"
        write_json(successor_path, material.successor_baseline)
        write_json(history_path, material.history_entry)
        write_json(receipt_path, material.maintenance_receipt)
        operations = self.operations()
        operations.pointer = publication.PointerSnapshot(
            "observed", digest("1"), PREVIOUS_BASELINE, digest("2")
        )
        activation_path = self.root / "activation-conflict.json"
        outcome = publication.activate_latest_baseline(
            successor_path,
            history_path,
            receipt_path,
            self.fixture.authorization_path,
            self.activation_authorization(successor_path, history_path, receipt_path),
            POINTER,
            operations,
            self.maintenance_state_input(),
            lambda _record: None,
            activation_path,
            now=NOW,
        )
        self.assertFalse(outcome.passed)
        self.assertEqual(0, operations.activate_calls)
        self.assertEqual(
            "latest-pointer-compare-and-swap-conflict",
            outcome.artifacts[activation_path]["failureCategory"],
        )

    def test_activation_rejects_authorization_substituted_after_publication(self) -> None:
        material = self.fixture.material()
        successor_path = self.root / "successor-auth-substitution.json"
        history_path = self.root / "history-auth-substitution.json"
        receipt_path = self.root / "receipt-auth-substitution.json"
        authorization_path = self.root / "authorization-substitution.json"
        write_json(successor_path, material.successor_baseline)
        write_json(history_path, material.history_entry)
        write_json(receipt_path, material.maintenance_receipt)
        substituted = copy.deepcopy(self.fixture.authorization)
        substituted["approverIdentity"] = "replacement-release-manager"
        write_json(authorization_path, substituted)

        with self.assertRaises(publication.AdapterError) as raised:
            publication.activate_latest_baseline(
                successor_path,
                history_path,
                receipt_path,
                authorization_path,
                self.activation_authorization(
                    successor_path, history_path, receipt_path
                ),
                POINTER,
                self.operations(),
                self.maintenance_state_input(),
                lambda _record: None,
                self.root / "activation-auth-substitution.json",
                now=NOW,
            )

        self.assertEqual(
            "baseline-activation-input-binding-mismatch", raised.exception.code
        )

    def test_activation_authorization_expiry_blocks_pointer_mutation(self) -> None:
        material = self.fixture.material()
        successor_path = self.root / "successor-expiring-auth.json"
        history_path = self.root / "history-expiring-auth.json"
        receipt_path = self.root / "receipt-expiring-auth.json"
        write_json(successor_path, material.successor_baseline)
        write_json(history_path, material.history_entry)
        write_json(receipt_path, material.maintenance_receipt)
        operations = self.operations()
        times = iter((NOW, NOW + dt.timedelta(days=730)))
        activation_path = self.root / "activation-expiring-auth.json"

        outcome = publication.activate_latest_baseline(
            successor_path,
            history_path,
            receipt_path,
            self.fixture.authorization_path,
            self.activation_authorization(successor_path, history_path, receipt_path),
            POINTER,
            operations,
            self.maintenance_state_input(),
            lambda _record: None,
            activation_path,
            now=lambda: next(times),
        )

        self.assertFalse(outcome.passed)
        self.assertEqual(0, operations.activate_calls)
        self.assertEqual(
            "activation-authorization-expired",
            outcome.artifacts[activation_path]["failureCategory"],
        )

    def test_expired_activation_authorization_cannot_accept_idempotent_state(self) -> None:
        material = self.fixture.material()
        successor_path = self.root / "successor-idempotent-expired.json"
        history_path = self.root / "history-idempotent-expired.json"
        receipt_path = self.root / "receipt-idempotent-expired.json"
        write_json(successor_path, material.successor_baseline)
        write_json(history_path, material.history_entry)
        write_json(receipt_path, material.maintenance_receipt)
        operations = self.operations()
        request = publication._load_activation_request(
            successor_path,
            history_path,
            receipt_path,
            self.fixture.authorization_path,
            self.activation_authorization(successor_path, history_path, receipt_path),
            POINTER,
        )
        operations.pointer = publication.PointerSnapshot(
            "observed",
            request.activated_pointer_digest,
            file_digest(successor_path),
            self.fixture.candidate_digest,
        )
        activation_path = self.root / "activation-idempotent-expired.json"

        outcome = publication.activate_latest_baseline(
            successor_path,
            history_path,
            receipt_path,
            self.fixture.authorization_path,
            self.activation_authorization(successor_path, history_path, receipt_path),
            POINTER,
            operations,
            self.maintenance_state_input(),
            lambda _record: None,
            activation_path,
            now=NOW + dt.timedelta(days=730),
        )

        self.assertFalse(outcome.passed)
        self.assertEqual(0, operations.activate_calls)
        self.assertEqual(
            "activation-authorization-expired",
            outcome.artifacts[activation_path]["failureCategory"],
        )

    def test_renewed_activation_authorization_can_finalize_published_release(self) -> None:
        material = self.fixture.material()
        successor_path = self.root / "successor-renewed-activation.json"
        history_path = self.root / "history-renewed-activation.json"
        receipt_path = self.root / "receipt-renewed-activation.json"
        write_json(successor_path, material.successor_baseline)
        write_json(history_path, material.history_entry)
        write_json(receipt_path, material.maintenance_receipt)
        activation_time = NOW + dt.timedelta(days=730)
        activation_path = self.root / "activation-renewed.json"
        operations = self.operations()

        outcome = publication.activate_latest_baseline(
            successor_path,
            history_path,
            receipt_path,
            self.fixture.authorization_path,
            self.activation_authorization(
                successor_path,
                history_path,
                receipt_path,
                now=activation_time,
            ),
            POINTER,
            operations,
            self.maintenance_state_input(),
            lambda _record: None,
            activation_path,
            now=activation_time,
        )

        self.assertTrue(outcome.passed)
        self.assertEqual(1, operations.activate_calls)
        self.assertEqual("activated", outcome.artifacts[activation_path]["pointerUpdate"])
        self.assertEqual(
            file_digest(self.fixture.authorization_path),
            outcome.artifacts[activation_path]["authorizationDigest"],
        )
        self.assertEqual(
            file_digest(
                self.activation_authorization(
                    successor_path,
                    history_path,
                    receipt_path,
                    now=activation_time,
                )
            ),
            outcome.artifacts[activation_path]["activationAuthorizationDigest"],
        )

    def test_cli_rejects_local_pr_and_self_test_contexts(self) -> None:
        arguments = self.preflight_arguments(self.root / "preflight.json")
        operations = self.operations()
        for environment in (
            {},
            self.workflow_environment(GITHUB_EVENT_NAME="pull_request"),
            self.workflow_environment(CRYPTAD_SELF_TEST="1"),
        ):
            with self.subTest(environment=environment):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    code = publication.main(
                        arguments, operations=operations, environ=environment
                    )
                self.assertEqual(1, code)
                self.assertIn("protected-workflow-context-required", stderr.getvalue())
        self.assertEqual([], operations.publish_calls)

    def test_cli_accepts_exact_preflight_contract_and_never_serializes_secret(self) -> None:
        output = self.root / "preflight.json"
        operations = self.operations()
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = publication.main(
                self.preflight_arguments(output),
                operations=operations,
                environ=self.workflow_environment(),
            )
        self.assertEqual(0, code, stderr.getvalue())
        encoded = output.read_text(encoding="utf-8")
        self.assertNotIn(CATALOG_SECRET, encoded)
        self.assertNotIn(CORE_UPDATE_SECRET, encoded)
        self.assertNotIn(MAINTENANCE_STATE_SECRET, encoded)
        self.assertEqual("pass", json.loads(output.read_text())["status"])

    def test_cli_provider_exception_cannot_disclose_secret(self) -> None:
        operations = self.operations(fail_target="tag")
        receipt = self.root / "receipt.json"
        core = self.root / "core.json"
        arguments = self.publication_arguments(receipt, core)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = publication.main(
                arguments,
                operations=operations,
                source_ref_revalidator=lambda _record: None,
                environ=self.workflow_environment(),
            )
        self.assertEqual(1, code)
        audit = receipt.with_name(publication.FAILURE_AUDIT_FILE)
        self.assertFalse(receipt.exists())
        self.assertFalse(core.exists())
        self.assertTrue(audit.is_file())
        for protected_value in (CATALOG_SECRET, CORE_UPDATE_SECRET):
            self.assertNotIn(protected_value, stderr.getvalue())
            self.assertNotIn(protected_value, audit.read_text(encoding="utf-8"))

    def test_cli_isolates_target_credentials_from_backend_and_ambient_environment(
        self,
    ) -> None:
        protected_names = (
            publication.CATALOG_INPUT_ENV,
            publication.CORE_UPDATE_INPUT_ENV,
        )

        class EnvironmentAuditingOperations(FakeOperations):
            def __init__(self, fixture: BundleFixture) -> None:
                super().__init__(fixture.material(), target_status="absent")
                self.targets["artifactBase"] = "matching"
                self.ambient_observations: list[
                    tuple[str, tuple[str | None, str | None]]
                ] = []

            def capture(self, operation: str) -> None:
                self.ambient_observations.append(
                    (operation, tuple(os.environ.get(name) for name in protected_names))
                )

            def observe_public_state(
                self, request: publication.PublicationRequest
            ) -> publication.PublicSnapshot:
                self.capture("observe")
                return super().observe_public_state(request)

            def publish_target(
                self,
                target: str,
                request: publication.PublicationRequest,
                protected_input: publication.SecretMaterial | None,
            ) -> None:
                self.capture(f"publish:{target}")
                super().publish_target(target, request, protected_input)

            def verify_publication(
                self, request: publication.PublicationRequest
            ) -> publication.VerificationMaterial:
                self.capture("verify")
                return super().verify_publication(request)

        operations = EnvironmentAuditingOperations(self.fixture)
        loader_environments: list[dict[str, str]] = []
        loader_ambient: list[tuple[str | None, str | None]] = []

        def load_backend(environment: Mapping[str, str]) -> FakeOperations:
            loader_environments.append(dict(environment))
            loader_ambient.append(
                tuple(os.environ.get(name) for name in protected_names)
            )
            return operations

        receipt = self.root / "isolated-receipt.json"
        core_receipt = self.root / "isolated-core-receipt.json"
        ambient = {
            publication.CATALOG_INPUT_ENV: CATALOG_SECRET,
            publication.CORE_UPDATE_INPUT_ENV: CORE_UPDATE_SECRET,
        }
        with mock.patch.dict(os.environ, ambient, clear=False), mock.patch.object(
            publication, "_load_backend", side_effect=load_backend
        ):
            code = publication.main(
                self.publication_arguments(receipt, core_receipt),
                source_ref_revalidator=lambda _record: None,
                environ=self.workflow_environment(),
            )

            self.assertEqual(0, code)
            self.assertTrue(all(name not in os.environ for name in protected_names))

        self.assertEqual([(None, None)], loader_ambient)
        self.assertTrue(
            all(name not in loader_environments[0] for name in protected_names)
        )
        self.assertTrue(operations.ambient_observations)
        self.assertTrue(
            all(
                values == (None, None)
                for _operation, values in operations.ambient_observations
            )
        )
        self.assertEqual(
            [
                ("tag", None),
                ("githubRelease", None),
                ("assets", None),
                ("stableCatalog", "stable-catalog"),
                ("coreUpdate", "core-update"),
            ],
            operations.publish_input_purposes,
        )
        self.assertEqual(
            [
                ("tag", None),
                ("githubRelease", None),
                ("assets", None),
                ("stableCatalog", CATALOG_SECRET),
                ("coreUpdate", CORE_UPDATE_SECRET),
            ],
            operations.publish_input_values,
        )

    def test_cli_requires_each_target_specific_protected_input(self) -> None:
        for missing_name in (
            publication.CATALOG_INPUT_ENV,
            publication.CORE_UPDATE_INPUT_ENV,
        ):
            with self.subTest(missing_name=missing_name):
                operations = self.operations()
                environment = self.workflow_environment()
                del environment[missing_name]
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    code = publication.main(
                        self.publication_arguments(
                            self.root / f"{missing_name}-receipt.json",
                            self.root / f"{missing_name}-core.json",
                        ),
                        operations=operations,
                        environ=environment,
                    )
                self.assertEqual(1, code)
                self.assertEqual([], operations.publish_calls)
                self.assertIn("protected-input-not-materialized", stderr.getvalue())

    def test_cli_requires_distinct_maintenance_state_activation_input(self) -> None:
        material = self.fixture.material()
        successor = self.root / "activation-successor.json"
        history = self.root / "activation-history.json"
        receipt = self.root / "activation-publication-receipt.json"
        write_json(successor, material.successor_baseline)
        write_json(history, material.history_entry)
        write_json(receipt, material.maintenance_receipt)
        operations = self.operations()
        environment = self.workflow_environment(GITHUB_JOB="activate-latest-baseline")
        del environment[publication.MAINTENANCE_STATE_INPUT_ENV]
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr):
            code = publication.main(
                self.activation_arguments(successor, history, receipt),
                operations=operations,
                environ=environment,
            )

        self.assertEqual(1, code)
        self.assertEqual(0, operations.activate_calls)
        self.assertIn("protected-input-not-materialized", stderr.getvalue())

    def workflow_environment(self, **overrides: str) -> dict[str, str]:
        environment = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": "crypta-network/cryptad",
            "GITHUB_WORKFLOW_REF": (
                "crypta-network/cryptad/.github/workflows/"
                "stable-1.0-maintenance-release.yml@refs/heads/release/301"
            ),
            "GITHUB_JOB": "protected-publication",
            "GITHUB_REF": "refs/heads/release/301",
            publication.CATALOG_INPUT_ENV: CATALOG_SECRET,
            publication.CORE_UPDATE_INPUT_ENV: CORE_UPDATE_SECRET,
            publication.MAINTENANCE_STATE_INPUT_ENV: MAINTENANCE_STATE_SECRET,
            publication.GITHUB_TOKEN_ENV: "github-protected-token-material",
        }
        environment.update(overrides)
        return environment

    def preflight_arguments(self, output: Path) -> list[str]:
        return [
            "--mode",
            "preflight-only",
            "--bundle",
            str(self.fixture.root),
            "--no-protected-inputs",
            "--expected-predecessor-pointer-digest",
            POINTER,
            "--check-latest-predecessor",
            "--check-authorization-expiry",
            "--check-exact-freeze-bytes",
            "--check-tag-release-artifact-catalog-and-updater-conflicts",
            "--idempotency",
            "exact-match-only",
            "--conflict-action",
            "fail",
            "--no-side-effects",
            "--out",
            str(output),
        ]

    def publication_arguments(self, receipt: Path, core: Path) -> list[str]:
        return [
            "--mode",
            "publish-or-verify-exact",
            "--bundle",
            str(self.fixture.root),
            "--catalog-input-env",
            publication.CATALOG_INPUT_ENV,
            "--core-update-input-env",
            publication.CORE_UPDATE_INPUT_ENV,
            "--expected-predecessor-pointer-digest",
            POINTER,
            "--expected-source-repository",
            publication.SOURCE_REPOSITORY,
            "--expected-source-branch",
            f"release/{BUILD}",
            "--expected-source-commit",
            COMMIT,
            "--github-token-env",
            publication.GITHUB_TOKEN_ENV,
            "--recheck-remote-source-ref",
            "--revalidate-before-each-mutation",
            "--idempotency",
            "exact-match-only",
            "--conflict-action",
            "fail",
            "--partial-state-action",
            "record-only",
            "--forbid-overwrite",
            "--forbid-delete-recovery",
            "--receipt",
            str(receipt),
            "--core-update-receipt",
            str(core),
        ]

    def activation_arguments(
        self, successor: Path, history: Path, receipt: Path
    ) -> list[str]:
        return [
            "--mode",
            "activate-latest-baseline",
            "--maintenance-state-input-env",
            publication.MAINTENANCE_STATE_INPUT_ENV,
            "--expected-current-pointer-digest",
            POINTER,
            "--expected-source-repository",
            publication.SOURCE_REPOSITORY,
            "--expected-source-branch",
            f"release/{BUILD}",
            "--expected-source-commit",
            COMMIT,
            "--github-token-env",
            publication.GITHUB_TOKEN_ENV,
            "--recheck-remote-source-ref",
            "--successor-baseline",
            str(successor),
            "--history-entry",
            str(history),
            "--publication-receipt",
            str(receipt),
            "--authorization",
            str(self.fixture.authorization_path),
            "--activation-authorization",
            str(self.activation_authorization(successor, history, receipt)),
            "--check-authorization-expiry",
            "--compare-and-swap",
            "--forbid-overwrite-on-conflict",
            "--verify-after-activation",
            "--activation-receipt",
            str(self.root / "activation-receipt.json"),
        ]


if __name__ == "__main__":
    unittest.main()
