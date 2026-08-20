"""Deterministic adversarial tests for provider-distinct Stable rebuild evidence."""

from __future__ import annotations

import copy
import hashlib
import os
import re
import stat
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from cryptad_certification.cli import build_parser
from cryptad_certification.io import read_json, write_json
from cryptad_certification.schema_validation import validate_schema

from ..engines import stable_1_0_independent_reproducibility as engine
from ..engines.stable_1_0_supply_chain_core import (
    canonical_json_bytes,
    file_digest,
    semantic_digest,
    sha256_digest,
)
from ..engines.stable_1_0_supply_chain_sbom import build_sbom_binding, build_spdx
from .test_stable_supply_chain import SOURCE_COMMIT, SupplyChainFixture


REPOSITORY = Path(__file__).resolve().parents[4]
RELEASE_ROOT = REPOSITORY / "tools/release-certification"
EXAMPLE_PATH = (
    RELEASE_ROOT
    / "manifests/stable-1.0-independent-reproducibility.example.json"
)
POLICY_PATH = RELEASE_ROOT / "stable-1.0-independent-reproducibility-policy.json"
SUPPLY_CHAIN_POLICY_PATH = RELEASE_ROOT / "stable-1.0-supply-chain-policy.json"
WORKFLOW_PATH = (
    REPOSITORY / ".github/workflows/stable-1.0-independent-reproducibility.yml"
)
PROTECTED_RELEASE_DOC_PATH = (
    REPOSITORY / "docs/stable-1.0-protected-release-execution.md"
)


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


class StableIndependentReproducibilityTests(unittest.TestCase):
    """Exercise the PR-292 contract, archive, identity, and workflow boundaries."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.example = read_json(EXAMPLE_PATH)
        self.policy = read_json(POLICY_PATH)
        self.supply_chain_policy = read_json(SUPPLY_CHAIN_POLICY_PATH)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _authority(label: str) -> dict[str, object]:
        return {
            "providerProfileId": f"{label}-profile",
            "providerProfileDigest": _digest(f"{label}-profile"),
            "authorityIdentity": {
                "providerId": f"{label}.provider.invalid",
                "controlPlaneId": f"{label}.control-plane.invalid",
                "trustDomainId": f"{label}.trust-domain.invalid",
                "organizationId": f"{label}-organization",
                "accountId": f"{label}-account",
                "projectId": f"{label}-project",
                "executorControllerId": f"{label}-executor-controller",
            },
            "pipelineIdentity": {
                "definitionId": f"{label}-pipeline",
                "immutableRevision": _digest(f"{label}-pipeline-revision"),
                "runId": f"{label}-run",
                "runAttempt": 1,
                "jobId": f"{label}-job",
            },
            "artifactAttestation": {
                "bundleDigest": _digest(f"{label}-attestation-bundle"),
                "statementDigest": _digest(f"{label}-attestation-statement"),
                "verificationStatus": "fixture-only",
            },
            "workloadIdentity": {"claimsDigest": _digest(f"{label}-claims")},
        }

    def _independence_contract(self) -> dict[str, object]:
        return {
            "expectedVerifierAuthority": {
                "requireProviderDistinct": True,
                "requireControlPlaneDistinct": True,
                "requireTrustDomainDistinct": True,
                "requireOrganizationDistinct": True,
            }
        }

    def _kit_inputs(self) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
        contract = copy.deepcopy(self.example)
        source_commit = "a" * 40
        contract["repository"].update(
            {
                "sourceCommit": source_commit,
                "sourceRef": f"commit:{source_commit}",
                "sourceTreeDigest": _digest("source-tree"),
                "authenticatedSourceArchive": {
                    "origin": (
                        "https://codeload.github.com/crypta-network/cryptad/zip/"
                        + source_commit
                    ),
                    "digest": _digest("source-archive"),
                    "format": "source-zip",
                },
            }
        )
        contract["evaluationTime"] = "2026-01-01T00:00:00Z"
        for field in (
            "artifactDigest",
            "freezeDigest",
            "freezeFileDigest",
            "productDigest",
            "subjectInventoryDigest",
        ):
            contract["selectedRc"][field] = _digest(f"candidate-{field}")
        contract["authenticatedInputs"]["subjectInventoryDigest"] = contract[
            "selectedRc"
        ]["subjectInventoryDigest"]

        direct_inputs = []
        for name, immutability in (
            ("gradle-wrapper-distribution", "versioned-url"),
            ("seedrefs-source-archive", "immutable-git-archive"),
            ("tanuki-wrapper-delta-pack", "immutable-release-asset"),
            ("windows-wrapper-amd64", "immutable-release-asset"),
            ("windows-wrapper-arm64", "immutable-release-asset"),
        ):
            direct_inputs.append(
                {
                    "name": name,
                    "digest": _digest(name),
                    "origin": f"https://downloads.example.com/{name}",
                    "immutabilityClass": immutability,
                }
            )
        documents = {
            "buildMaterials": {
                "materialsDigest": _digest("materials"),
                "directInputs": direct_inputs,
                "jdk": {
                    "vendor": "Eclipse Adoptium",
                    "version": "25.0.1",
                    "build": "25.0.1+8",
                },
                "gradle": {
                    "version": "9.1.0",
                    "distributionDigest": _digest("gradle-distribution"),
                    "wrapperJarDigest": _digest("gradle-wrapper-jar"),
                    "wrapperPropertiesDigest": _digest("gradle-wrapper-properties"),
                    "verificationMetadataDigest": _digest("verification-metadata"),
                    "verificationKeyringDigest": _digest("verification-keyring"),
                    "repositoryConfigurationDigest": _digest("repository-configuration"),
                    "pluginResolutionDigest": _digest("plugin-resolution"),
                    "buildLogicDigest": _digest("build-logic"),
                },
            },
            "resolutionSnapshot": {"snapshotDigest": _digest("resolution-snapshot")},
        }
        return contract, documents

    @staticmethod
    def _write_zip(
        path: Path,
        rows: list[tuple[str, bytes, int, int]],
        *,
        timestamp: tuple[int, int, int, int, int, int] = (1980, 1, 1, 0, 0, 0),
    ) -> None:
        with zipfile.ZipFile(path, "w") as archive:
            for name, content, mode, compression in rows:
                info = zipfile.ZipInfo(name)
                info.date_time = timestamp
                info.create_system = 3
                info.external_attr = mode << 16
                info.compress_type = compression
                archive.writestr(info, content)

    def _summary_fixture(self) -> dict[str, object]:
        producer = self._authority("producer")
        verifier = self._authority("verifier")
        independence, errors = engine._independence_evaluation(  # noqa: SLF001
            producer,
            verifier,
            self._independence_contract(),
        )
        self.assertEqual([], errors)
        summary = {
            "schemaVersion": 1,
            "kind": "stable-1.0-independent-reproducibility-summary",
            "releaseId": self.example["release"]["id"],
            "buildVersion": self.example["release"]["integerBuild"],
            "tag": self.example["release"]["tag"],
            "sourceCommit": self.example["repository"]["sourceCommit"],
            "sourceRef": self.example["repository"]["sourceRef"],
            "selectedRc": self.example["selectedRc"],
            "stableSupplyChainPolicyDigest": self.example["policies"][
                "stableSupplyChainPolicyDigest"
            ],
            "independentReproducibilityPolicyDigest": self.policy["policyDigest"],
            "executionContractDigest": self.example["executionContractDigest"],
            "verifierKitDigest": _digest("kit"),
            "componentInventoryDigest": _digest("components"),
            "subjectInventoryDigest": self.example["authenticatedInputs"][
                "subjectInventoryDigest"
            ],
            "buildMaterialsDigest": self.example["authenticatedInputs"][
                "buildMaterialsDigest"
            ],
            "resolutionSnapshotDigest": self.example["authenticatedInputs"][
                "resolutionSnapshotDigest"
            ],
            "primaryBuilderReceiptDigest": _digest("primary-receipt"),
            "primaryAuthorityAttestationDigest": _digest("primary-attestation"),
            "externalBuilderReceiptDigest": _digest("external-receipt"),
            "externalAuthorityAttestationDigest": _digest("external-attestation"),
            "externalOutputManifestDigest": _digest("output-manifest"),
            "externalOutputBundleDigest": _digest("output-bundle"),
            "comparisonPlanDigest": _digest("comparison-plan"),
            "reproducibilityResultDigest": _digest("comparison-result"),
            "providerIndependence": independence,
            "subjectCoverage": {
                "requiredSubjectCount": 1,
                "comparedSubjectCount": 1,
                "missingSubjectKeys": [],
                "extraSubjectKeys": [],
                "complete": True,
            },
            "coordinator": None,
            "timing": {
                "kitPreparedAt": None,
                "externalBuildStartedAt": None,
                "externalBuildCompletedAt": None,
                "externalOutputsSealedAt": None,
                "externalReceiptAuthenticatedAt": None,
                "candidateInputsAvailableAt": None,
                "comparisonCompletedAt": None,
            },
            "operationMode": "compare",
            "lifecycleState": "comparison-complete",
            "status": "pending",
            "comparisonStatus": "pass",
            "evidenceClassification": "fixture",
            "fixture": True,
            "selfTest": False,
            "operational": False,
            "publicVerification": "not-performed",
            "blockers": [],
            "redaction": {
                "status": "pass",
                "credentialsExcluded": True,
                "privateUrisExcluded": True,
                "absolutePathsExcluded": True,
                "rawContentExcluded": True,
                "candidateBytesExcludedFromVerifierKit": True,
                "sideEffectsPerformed": False,
            },
            "generatedAt": "2026-01-01T00:00:00Z",
            "summaryDigest": _digest("placeholder"),
        }
        summary["summaryDigest"] = semantic_digest(summary, "summaryDigest")
        return summary

    def test_execution_contract_schema_when_unknown_field_added_expect_rejection(self) -> None:
        errors = validate_schema(
            self.example,
            engine.CONTRACT_SCHEMA,
        )
        changed = copy.deepcopy(self.example)
        changed["unexpected"] = True

        changed_errors = validate_schema(changed, engine.CONTRACT_SCHEMA)

        self.assertEqual([], errors)
        self.assertTrue(any("unknown field unexpected" in error for error in changed_errors))

    def test_policy_when_external_adapter_is_only_a_template_expect_operational_gate_closed(self) -> None:
        adapter = next(
            row
            for row in self.policy["attestationAdapters"]
            if row["adapterId"] == "external-oidc-dsse-v1"
        )
        profile = next(
            row
            for row in self.policy["providerProfiles"]
            if row["profileId"] == "generic-external-oidc-template-v1"
        )

        self.assertFalse(adapter["operationalAllowed"])
        self.assertFalse(profile["operationalAllowed"])
        self.assertNotIn(
            adapter["adapterId"],
            engine._IMPLEMENTED_OPERATIONAL_EXTERNAL_ADAPTERS,  # noqa: SLF001
        )
        self.assertEqual(
            adapter["adapterDigest"], semantic_digest(adapter, "adapterDigest")
        )
        self.assertEqual(
            profile["profileDigest"], semantic_digest(profile, "profileDigest")
        )

    def test_verifier_recipe_when_apps_are_packaged_expect_no_signing_authority(self) -> None:
        unsigned_task = ":packageUnsignedFirstPartyAppsForIndependentReproducibility"
        forbidden_fragments = (
            "signFirstPartyApps",
            "verifyFirstPartyApps",
            "packageFirstPartyApps",
        )
        expected_tasks = self.policy["requiredBuildTasks"]
        partition_tasks = self.policy["requiredExecutionTasks"]

        self.assertIn(unsigned_task, expected_tasks)
        self.assertEqual([":dist", unsigned_task], partition_tasks["portable-apps"])
        self.assertEqual(expected_tasks, self.example["buildRecipe"]["buildTasks"])
        self.assertEqual(
            partition_tasks["portable-apps"],
            next(
                row["taskSet"]
                for row in self.example["buildRecipe"]["executionPartitions"]
                if row["executionId"] == "portable-apps"
            ),
        )
        serialized_tasks = "\n".join(
            [
                *expected_tasks,
                *(task for tasks in partition_tasks.values() for task in tasks),
            ]
        )
        self.assertFalse(
            any(fragment in serialized_tasks for fragment in forbidden_fragments),
            serialized_tasks,
        )
        app_outputs = [
            row
            for row in self.example["buildRecipe"]["expectedOutputs"]
            if row["subjectKey"].startswith("app-")
        ]
        self.assertEqual(7, len(app_outputs))
        self.assertTrue(
            all(
                row["reproducibilityClass"] == "normalized-payload-identical"
                and row["normalizationRuleId"]
                == "crypta-app-signature-envelope-v1"
                for row in app_outputs
            )
        )

    def test_strict_json_when_duplicate_key_present_expect_rejection(self) -> None:
        duplicate = self.root / "duplicate.json"
        duplicate.write_text('{"releaseId":"one","releaseId":"two"}\n', encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "duplicate field"):
            read_json(duplicate)

    def test_execution_digest_when_phase_fields_change_expect_immutable_value(self) -> None:
        original = engine.execution_contract_digest(self.example)
        phase_change = copy.deepcopy(self.example)
        phase_change["operationMode"] = "closeout"
        phase_change["evaluationTime"] = "2030-01-01T00:00:00Z"
        phase_change["lifecycleState"] = "blocked"
        immutable_change = copy.deepcopy(self.example)
        immutable_change["repository"]["sourceCommit"] = "f" * 40

        self.assertEqual(self.example["executionContractDigest"], original)
        self.assertEqual(original, engine.execution_contract_digest(phase_change))
        self.assertNotEqual(original, engine.execution_contract_digest(immutable_change))

    def test_contract_when_requested_mode_differs_expect_closed_rejection(self) -> None:
        errors = engine._contract_errors(  # noqa: SLF001
            self.example,
            "closeout",
            self.policy,
            self.supply_chain_policy,
        )

        self.assertIn(
            "execution contract operation mode differs from the requested operation",
            errors,
        )
        self.assertIn(
            "execution contract lifecycle state is invalid for the requested operation",
            errors,
        )

    def test_receipt_projection_when_compare_is_requested_expect_phase_compatible(self) -> None:
        comparison = copy.deepcopy(self.example)
        comparison["verifierKit"] = {}
        for field in (
            "builderReceipt",
            "authorityAttestation",
            "rawArtifactAttestationBundle",
            "verificationTranscript",
            "outputManifest",
            "outputBundle",
        ):
            comparison["externalBuild"][field] = {}
        for field in (
            "primaryBuilderReceipt",
            "primaryAuthorityAttestation",
            "candidateSubjectBundle",
        ):
            comparison["comparison"][field] = {}
        comparison["operationMode"] = "compare"
        comparison["lifecycleState"] = "external-build-sealed"
        receipt = copy.deepcopy(comparison)
        receipt["operationMode"] = "verify-external-receipt"
        for field in (
            "primaryBuilderReceipt",
            "primaryAuthorityAttestation",
            "candidateSubjectBundle",
            "comparisonPlan",
            "reproducibilityResult",
        ):
            receipt["comparison"][field] = None

        comparison_errors = engine._phase_binding_errors(  # noqa: SLF001
            comparison,
            "compare",
        )
        receipt_errors = engine._phase_binding_errors(  # noqa: SLF001
            receipt,
            "verify-external-receipt",
        )

        self.assertEqual([], comparison_errors)
        self.assertEqual([], receipt_errors)
        self.assertEqual(
            engine.execution_contract_digest(comparison),
            engine.execution_contract_digest(receipt),
        )

    def test_contract_when_planned_phase_exposes_external_evidence_expect_rejection(self) -> None:
        changed = copy.deepcopy(self.example)
        changed["externalBuild"]["builderReceipt"] = {
            "path": "external/receipt.json",
            "sha256": _digest("external-receipt-file"),
            "schema": engine.BUILDER_RECEIPT_SCHEMA,
            "size": 0,
        }

        errors = engine._contract_errors(  # noqa: SLF001
            changed,
            "prepare-verifier-kit",
            self.policy,
            self.supply_chain_policy,
        )

        self.assertIn(
            "planned execution contract already exposes an external build",
            errors,
        )

    def test_independence_when_provider_distinct_expect_all_required_checks_pass(self) -> None:
        evaluation, errors = engine._independence_evaluation(  # noqa: SLF001
            self._authority("producer"),
            self._authority("verifier"),
            self._independence_contract(),
        )

        self.assertEqual([], errors)
        self.assertEqual("pass", evaluation["status"])
        self.assertTrue(
            all(row["status"] == "pass" for row in evaluation["checks"])
        )
        self.assertEqual(
            semantic_digest(evaluation, "evaluationDigest"),
            evaluation["evaluationDigest"],
        )

    def test_independence_when_identity_reused_expect_closed_rejection(self) -> None:
        cases = (
            ("provider", ("authorityIdentity", "providerId"), "same provider"),
            ("control-plane", ("authorityIdentity", "controlPlaneId"), "same control plane"),
            ("trust-domain", ("authorityIdentity", "trustDomainId"), "same trust domain"),
            ("organization", ("authorityIdentity", "organizationId"), "same organization"),
            ("account", ("authorityIdentity", "accountId"), "same organization or provider account"),
            ("artifact", ("artifactAttestation", "bundleDigest"), "reuse an artifact attestation"),
        )
        producer = self._authority("producer")
        for name, (section, field), message in cases:
            with self.subTest(case=name):
                verifier = self._authority("verifier")
                verifier[section][field] = producer[section][field]

                evaluation, errors = engine._independence_evaluation(  # noqa: SLF001
                    producer,
                    verifier,
                    self._independence_contract(),
                )

                self.assertEqual("fail", evaluation["status"])
                self.assertTrue(any(message in error for error in errors), errors)

    def test_independence_when_run_or_workflow_reused_expect_rejection(self) -> None:
        producer = self._authority("producer")
        for name, pipeline_field, message in (
            ("run", "runId", "reuse a build identity"),
            ("workflow", "definitionId", "relabeled as an external verifier"),
        ):
            with self.subTest(case=name):
                verifier = self._authority("verifier")
                verifier["authorityIdentity"]["providerId"] = producer[
                    "authorityIdentity"
                ]["providerId"]
                verifier["pipelineIdentity"][pipeline_field] = producer[
                    "pipelineIdentity"
                ][pipeline_field]

                evaluation, errors = engine._independence_evaluation(  # noqa: SLF001
                    producer,
                    verifier,
                    self._independence_contract(),
                )

                self.assertEqual("fail", evaluation["status"])
                self.assertTrue(any(message in error for error in errors), errors)

    def test_verifier_kit_when_prepared_expect_exact_source_and_no_candidate_oracle(self) -> None:
        contract, documents = self._kit_inputs()

        kit = engine._build_verifier_kit(  # noqa: SLF001
            contract,
            self.policy,
            self.supply_chain_policy,
            documents,
        )
        encoded = canonical_json_bytes(kit).decode("utf-8")

        self.assertEqual(contract["repository"]["sourceCommit"], kit["sourceCommit"])
        self.assertEqual(contract["repository"]["sourceRef"], kit["sourceRef"])
        self.assertEqual(contract["repository"]["sourceCommit"], kit["sourceArchive"]["commit"])
        self.assertEqual(
            contract["executionContractDigest"], kit["executionContractDigest"]
        )
        for field in (
            "artifactDigest",
            "freezeDigest",
            "freezeFileDigest",
            "productDigest",
            "subjectInventoryDigest",
        ):
            self.assertNotIn(contract["selectedRc"][field], encoded)
        self.assertNotIn("candidateSubjectBundle", encoded)

    def test_candidate_free_subject_projection_when_primary_bytes_change_expect_stable_digest(
        self,
    ) -> None:
        contract, _documents = self._kit_inputs()
        partition = contract["buildRecipe"]["executionPartitions"][0]
        outputs = contract["buildRecipe"]["expectedOutputs"]
        candidate_rows = [
            {
                **row,
                "digest": _digest(f"candidate-{row['subjectKey']}"),
                "size": index + 1,
                "payloadManifestDigest": _digest(f"payload-{row['subjectKey']}"),
            }
            for index, row in enumerate(outputs)
        ]

        projection = engine.candidate_free_subject_projection(
            outputs, partition["subjectKeys"]
        )
        changed_candidate_rows = copy.deepcopy(candidate_rows)
        changed_candidate_rows[0]["digest"] = _digest("different-candidate-bytes")
        repeated = engine.candidate_free_subject_projection(
            outputs, partition["subjectKeys"]
        )

        self.assertEqual(projection, repeated)
        self.assertEqual(
            [
                "fileName",
                "normalizationRuleId",
                "reproducibilityClass",
                "subjectKey",
            ],
            sorted(projection[0]),
        )
        self.assertNotEqual(
            sha256_digest(canonical_json_bytes(candidate_rows)),
            sha256_digest(canonical_json_bytes(projection)),
        )
        self.assertNotEqual(candidate_rows, changed_candidate_rows)
        self.assertNotIn(
            changed_candidate_rows[0]["digest"],
            canonical_json_bytes(projection).decode("utf-8"),
        )
        with self.assertRaisesRegex(ValueError, "subject keys are not canonical"):
            engine.candidate_free_subject_projection(
                outputs, list(reversed(partition["subjectKeys"]))
            )

    def test_verifier_kit_when_execution_digest_missing_expect_schema_rejection(self) -> None:
        contract, documents = self._kit_inputs()
        kit = engine._build_verifier_kit(  # noqa: SLF001
            contract,
            self.policy,
            self.supply_chain_policy,
            documents,
        )
        kit.pop("executionContractDigest")

        errors = validate_schema(kit, engine.VERIFIER_KIT_SCHEMA)

        self.assertTrue(
            any("omits required field executionContractDigest" in error for error in errors),
            errors,
        )

    def test_verifier_kit_when_execution_digest_substituted_expect_rejection(self) -> None:
        contract, documents = self._kit_inputs()
        kit = engine._build_verifier_kit(  # noqa: SLF001
            contract,
            self.policy,
            self.supply_chain_policy,
            documents,
        )
        kit["executionContractDigest"] = _digest("substituted-execution-contract")
        kit["kitDigest"] = semantic_digest(kit, "kitDigest")
        kit_path = self.root / "substituted-kit.json"
        write_json(kit_path, kit)
        contract["verifierKit"] = {
            "path": kit_path.name,
            "sha256": file_digest(kit_path),
            "schema": engine.VERIFIER_KIT_SCHEMA,
            "size": kit_path.stat().st_size,
        }

        _loaded, errors = engine._load_kit(  # noqa: SLF001
            self.root,
            contract,
            self.policy,
            self.supply_chain_policy,
            documents,
        )

        self.assertIn("verifier kit execution-contract digest differs", errors)

    def test_comparison_view_when_payload_manifest_binds_stale_package_expect_rejection(self) -> None:
        extracted = self.root / "extracted"
        destination = self.root / "comparison"
        subject = extracted / "subjects/cryptad.deb"
        payload_path = extracted / "payload-manifests/linux.amd64.deb.json"
        subject.parent.mkdir(parents=True)
        payload_path.parent.mkdir(parents=True)
        subject.write_bytes(b"current-package")
        payload = {
            "subjectKey": "linux.amd64.deb",
            "publishedSubjectDigest": _digest("stale-package"),
            "manifestDigest": "sha256:" + "0" * 64,
        }
        payload["manifestDigest"] = semantic_digest(payload, "manifestDigest")
        write_json(payload_path, payload)
        receipt = {
            "subjects": [
                {
                    "subjectKey": "linux.amd64.deb",
                    "fileName": "cryptad.deb",
                    "digest": file_digest(subject),
                    "size": subject.stat().st_size,
                    "payloadManifestDigest": payload["manifestDigest"],
                }
            ]
        }

        _, manifest_root, errors = engine._stage_comparison_view(  # noqa: SLF001
            extracted,
            receipt,
            destination,
        )

        self.assertEqual(
            ["payload manifest binds different published package bytes for linux.amd64.deb"],
            errors,
        )
        self.assertFalse((manifest_root / "linux.amd64.deb.json").exists())

    def test_prepare_mode_when_complete_authenticated_inputs_expect_deterministic_kit(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="independent-prepare-", dir=build_root
        ) as temporary:
            root = Path(temporary)
            fixture = SupplyChainFixture(root / "fixture")
            spdx = build_spdx(
                fixture.release,
                fixture.policy,
                fixture.components,
                fixture.subjects,
            )
            sbom_binding = build_sbom_binding(
                fixture.release,
                spdx,
                fixture.components,
                fixture.subjects,
            )
            documents = {
                "buildMaterials": (
                    fixture.materials,
                    "stable-1.0-build-materials-v1.schema.json",
                ),
                "resolutionSnapshot": (
                    fixture.snapshot,
                    "stable-1.0-resolved-dependency-snapshot-v1.schema.json",
                ),
                "componentInventory": (
                    fixture.components,
                    "stable-1.0-component-inventory-v1.schema.json",
                ),
                "subjectInventory": (
                    fixture.subjects,
                    "stable-1.0-release-subject-inventory-v1.schema.json",
                ),
                "sbomBinding": (
                    sbom_binding,
                    "stable-1.0-sbom-binding-v1.schema.json",
                ),
            }
            contract = copy.deepcopy(self.example)
            contract["evaluationTime"] = "2026-01-01T00:00:00Z"
            contract["repository"].update(
                {
                    "sourceCommit": SOURCE_COMMIT,
                    "sourceRef": f"commit:{SOURCE_COMMIT}",
                    "sourceTreeDigest": fixture.materials["source"]["treeDigest"],
                    "authenticatedSourceArchive": {
                        "origin": (
                            "https://codeload.github.com/crypta-network/cryptad/zip/"
                            + SOURCE_COMMIT
                        ),
                        "digest": _digest("authenticated-source-archive"),
                        "format": "source-zip",
                    },
                    "canonicalCommitEpoch": fixture.materials[
                        "canonicalBuildEpoch"
                    ],
                }
            )
            contract["release"].update(
                {
                    "id": fixture.release["releaseId"],
                    "integerBuild": fixture.release["buildVersion"],
                    "tag": fixture.release["tag"],
                }
            )
            contract["selectedRc"].update(
                {
                    "workflowCommit": SOURCE_COMMIT,
                    "subjectInventoryDigest": fixture.subjects[
                        "subjectInventoryDigest"
                    ],
                }
            )
            contract["selectedRc"]["supplyChain"]["workflowCommit"] = SOURCE_COMMIT
            contract["authenticatedInputs"].update(
                {
                    "componentInventoryDigest": fixture.components[
                        "inventoryDigest"
                    ],
                    "subjectInventoryDigest": fixture.subjects[
                        "subjectInventoryDigest"
                    ],
                    "buildMaterialsDigest": fixture.materials[
                        "materialsDigest"
                    ],
                    "resolutionSnapshotDigest": fixture.snapshot[
                        "snapshotDigest"
                    ],
                    "sbomDigest": sbom_binding["sbomDigest"],
                }
            )
            direct_inputs = [
                {
                    **row,
                    "verificationMechanism": (
                        "gradle-wrapper-checksum"
                        if row["name"] == "gradle-wrapper-distribution"
                        else "sha256-before-use"
                    ),
                }
                for row in fixture.materials["directInputs"]
            ]
            contract["authenticatedInputs"]["directInputsDigest"] = sha256_digest(
                canonical_json_bytes(direct_inputs)
            )
            contract["buildRecipe"].update(
                {
                    "canonicalEnvironment": {
                        "locale": fixture.materials["environment"]["locale"],
                        "timezone": fixture.materials["environment"]["timezone"],
                        "encoding": fixture.materials["environment"]["encoding"],
                        "sourceDateEpoch": fixture.materials[
                            "canonicalBuildEpoch"
                        ],
                    },
                    "jdkIdentityDigest": sha256_digest(
                        canonical_json_bytes(fixture.materials["jdk"])
                    ),
                    "gradleIdentityDigest": sha256_digest(
                        canonical_json_bytes(fixture.materials["gradle"])
                    ),
                }
            )
            inventory_by_key = {
                row["subjectKey"]: row for row in fixture.subjects["subjects"]
            }
            for output in contract["buildRecipe"]["expectedOutputs"]:
                output["fileName"] = inventory_by_key[output["subjectKey"]][
                    "fileName"
                ]
            for name, (value, schema) in documents.items():
                path = root / f"{name}.json"
                write_json(path, value)
                contract["authenticatedInputFiles"][name] = {
                    "path": path.relative_to(REPOSITORY).as_posix(),
                    "sha256": file_digest(path),
                    "schema": schema,
                    "size": path.stat().st_size,
                }
            contract["executionContractDigest"] = engine.execution_contract_digest(
                contract
            )
            contract_path = root / "execution.json"
            write_json(contract_path, contract)
            first_output = root / "first"
            second_output = root / "second"

            runner_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
            with mock.patch.object(
                engine, "_runner_utc_now", return_value=runner_time
            ):
                first_status = engine.run(
                    REPOSITORY,
                    contract_path.relative_to(REPOSITORY),
                    "prepare-verifier-kit",
                    first_output.relative_to(REPOSITORY),
                )
                second_status = engine.run(
                    REPOSITORY,
                    contract_path.relative_to(REPOSITORY),
                    "prepare-verifier-kit",
                    second_output.relative_to(REPOSITORY),
                )

            self.assertEqual(0, first_status)
            self.assertEqual(0, second_status)
            self.assertEqual(
                (first_output / engine.KIT_FILE).read_bytes(),
                (second_output / engine.KIT_FILE).read_bytes(),
            )

    def test_runner_clock_when_evaluation_is_rewound_expect_rejection(self) -> None:
        contract, _documents = self._kit_inputs()
        runner_time = datetime(2026, 1, 4, tzinfo=timezone.utc)

        errors = engine._runner_clock_errors(  # noqa: SLF001
            contract,
            self.policy,
            runner_time,
        )

        self.assertEqual(
            ["execution evaluation time differs from the runner clock"], errors
        )

    def test_runner_clock_when_evaluation_is_within_policy_skew_expect_acceptance(self) -> None:
        contract, _documents = self._kit_inputs()
        runner_time = datetime(2026, 1, 1, 0, 5, tzinfo=timezone.utc)

        errors = engine._runner_clock_errors(  # noqa: SLF001
            contract,
            self.policy,
            runner_time,
        )

        self.assertEqual([], errors)

    def test_verifier_kit_when_evaluated_at_expiry_expect_stale(self) -> None:
        contract, documents = self._kit_inputs()
        kit = engine._build_verifier_kit(  # noqa: SLF001
            contract,
            self.policy,
            self.supply_chain_policy,
            documents,
        )
        kit_path = self.root / "kit.json"
        write_json(kit_path, kit)
        contract["verifierKit"] = {
            "path": kit_path.name,
            "sha256": file_digest(kit_path),
            "schema": engine.VERIFIER_KIT_SCHEMA,
            "size": kit_path.stat().st_size,
        }
        contract["evaluationTime"] = kit["expiresAt"]

        loaded, errors = engine._load_kit(  # noqa: SLF001
            self.root,
            contract,
            self.policy,
            self.supply_chain_policy,
            documents,
        )

        self.assertEqual(kit, loaded)
        self.assertIn("verifier kit is not fresh at execution evaluation time", errors)

    def test_archive_name_when_private_or_unsafe_expect_rejection(self) -> None:
        for name in (
            "../escape",
            "/absolute",
            "subjects/../../escape",
            "subjects/._artifact",
            "__MACOSX/artifact",
            "subjects/.DS_Store",
            "subjects\\artifact",
        ):
            with self.subTest(name=name):
                self.assertFalse(engine._safe_archive_name(name))  # noqa: SLF001

    def test_confined_input_when_absolute_symlink_or_hardlink_expect_rejection(self) -> None:
        regular = self.root / "regular.json"
        regular.write_text("{}\n", encoding="utf-8")
        symlink = self.root / "symlink.json"
        symlink.symlink_to(regular)
        hardlink = self.root / "hardlink.json"
        os.link(regular, hardlink)

        with self.assertRaisesRegex(ValueError, "repository-relative"):
            engine._confined_file(  # noqa: SLF001
                self.root, regular.resolve(), "absolute fixture"
            )
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            engine._confined_file(  # noqa: SLF001
                self.root, symlink.name, "symlink fixture"
            )
        with self.assertRaisesRegex(ValueError, "hard-link"):
            engine._confined_file(  # noqa: SLF001
                self.root, regular.name, "hardlink fixture"
            )

    def test_output_directory_when_ancestor_is_symlink_expect_rejection(self) -> None:
        destination = self.root / "actual-output"
        destination.mkdir()
        alias = self.root / "output-alias"
        alias.symlink_to(destination, target_is_directory=True)

        with self.assertRaisesRegex(ValueError, "symbolic-link component"):
            engine._output_directory(  # noqa: SLF001
                self.root,
                Path("output-alias/nested"),
            )

        self.assertFalse((destination / "nested").exists())

    def test_protected_runbook_when_listing_closeout_members_expect_exact_contract(self) -> None:
        document = PROTECTED_RELEASE_DOC_PATH.read_text(encoding="utf-8")
        section = document[
            document.index("The retained closeout artifact must contain") :
            document.index("Closeout authenticates the coordinator")
        ]

        members = re.findall(r"^- `([^`]+)`[.;]$", section, re.MULTILINE)

        self.assertEqual(
            [
                "stable-1.0-independent-reproducibility-summary.json",
                "stable-1.0-selected-rc-supply-chain-coordinate.json",
                "stable-1.0-primary-builder-receipt.json",
                "stable-1.0-primary-authority-attestation.json",
                "stable-1.0-independent-builder-receipt.json",
                "stable-1.0-independent-builder-attestation.json",
                "stable-1.0-independent-output-manifest.json",
                "stable-1.0-independent-raw-artifact-attestation.bundle",
                "stable-1.0-independent-attestation-verification-transcript.json",
                "stable-1.0-rebuild-comparison-plan.json",
                "stable-1.0-reproducibility-report.json",
            ],
            members,
        )

    def test_subject_bundle_when_closed_stored_zip_expect_exact_extraction(self) -> None:
        bundle = self.root / "closed.zip"
        self._write_zip(
            bundle,
            [
                ("payload-manifests/amd64.deb.json", b"{}", stat.S_IFREG | 0o644, zipfile.ZIP_STORED),
                ("subjects/cryptad.jar", b"jar", stat.S_IFREG | 0o644, zipfile.ZIP_STORED),
            ],
        )
        destination = self.root / "extracted"

        errors = engine._extract_bundle(  # noqa: SLF001
            bundle,
            destination,
            self.policy,
            {"payload-manifests/amd64.deb.json", "subjects/cryptad.jar"},
        )

        self.assertEqual([], errors)
        self.assertEqual(b"jar", (destination / "subjects/cryptad.jar").read_bytes())

    def test_subject_bundle_when_casefold_collision_expect_rejection(self) -> None:
        bundle = self.root / "casefold.zip"
        self._write_zip(
            bundle,
            [
                ("subjects/A.jar", b"one", stat.S_IFREG | 0o644, zipfile.ZIP_STORED),
                ("subjects/a.jar", b"two", stat.S_IFREG | 0o644, zipfile.ZIP_STORED),
            ],
        )

        errors = engine._extract_bundle(  # noqa: SLF001
            bundle,
            self.root / "casefold-output",
            self.policy,
            {"subjects/A.jar", "subjects/a.jar"},
        )

        self.assertIn("subject bundle has a case-folding or Unicode name collision", errors)

    def test_subject_bundle_when_link_or_special_member_expect_rejection(self) -> None:
        for name, mode in (
            ("symlink", stat.S_IFLNK | 0o777),
            ("fifo", stat.S_IFIFO | 0o644),
        ):
            with self.subTest(case=name):
                bundle = self.root / f"{name}.zip"
                member = f"subjects/{name}"
                self._write_zip(
                    bundle,
                    [(member, b"unsafe", mode, zipfile.ZIP_STORED)],
                )

                errors = engine._extract_bundle(  # noqa: SLF001
                    bundle,
                    self.root / f"{name}-output",
                    self.policy,
                    {member},
                )

                self.assertIn(
                    "subject bundle contains an ambiguous link or creator identity",
                    errors,
                )

    def test_zip_difference_when_metadata_and_content_change_expect_bounded_classes(self) -> None:
        first = self.root / "first.zip"
        second = self.root / "second.zip"
        self._write_zip(
            first,
            [
                ("a.txt", b"line\r\n", stat.S_IFREG | 0o644, zipfile.ZIP_STORED),
                ("b.txt", b"same", stat.S_IFREG | 0o644, zipfile.ZIP_STORED),
            ],
        )
        self._write_zip(
            second,
            [
                ("b.txt", b"same", stat.S_IFREG | 0o755, zipfile.ZIP_DEFLATED),
                ("a.txt", b"line\n", stat.S_IFREG | 0o755, zipfile.ZIP_DEFLATED),
            ],
            timestamp=(2026, 1, 1, 0, 0, 0),
        )

        classes = engine._zip_difference_classes(first, second)  # noqa: SLF001

        self.assertIn("archive-member-ordering-drift", classes)
        self.assertIn("archive-timestamp-drift", classes)
        self.assertIn("owner-group-or-mode-drift", classes)
        self.assertIn("compression-parameter-drift", classes)
        self.assertIn("line-ending-or-encoding-drift", classes)

    def test_difference_report_when_unknown_difference_expect_fail_closed_count(self) -> None:
        result = {
            "resultDigest": _digest("result"),
            "comparisons": [
                {
                    "subjectKey": "cryptad-core",
                    "status": "fail",
                    "differences": ["unexpected comparator output"],
                }
            ],
        }
        plan = {
            "planDigest": _digest("plan"),
            "comparisons": [
                {"subjectKey": "cryptad-core", "fileName": "cryptad.jar"}
            ],
        }

        report = engine._difference_report(  # noqa: SLF001
            result,
            plan,
            self.root / "primary",
            self.root / "verifier",
        )

        self.assertEqual(1, report["unknownDifferenceCount"])
        self.assertEqual(
            ["unknown-or-unexplained-difference"],
            report["rows"][0]["classifications"],
        )

    def test_failure_report_when_recipe_drifts_expect_bounded_classifications(self) -> None:
        report = engine._failure_report(  # noqa: SLF001
            [
                "external source tree identity differs",
                "external resolution snapshot differs",
                "external Gradle toolchain differs",
                "external task set differs",
                "external canonical environment differs",
            ]
        )

        self.assertEqual("fail", report["status"])
        self.assertEqual(
            [
                "dependency-resolution-drift",
                "environment-drift",
                "source-tree-drift",
                "task-set-drift",
                "toolchain-drift",
            ],
            report["differenceClassifications"],
        )
        self.assertEqual(
            report["reportDigest"], semantic_digest(report, "reportDigest")
        )

    def test_summary_when_member_tampered_expect_digest_rejection(self) -> None:
        summary = self._summary_fixture()
        self.assertEqual([], validate_schema(summary, engine.SUMMARY_SCHEMA))
        summary["externalBuilderReceiptDigest"] = _digest("substituted-receipt")

        errors = engine.independent_summary_errors(summary)

        self.assertIn("independent reproducibility summary self-digest differs", errors)

    def test_summary_when_fixture_claims_operational_expect_rejection(self) -> None:
        summary = self._summary_fixture()
        summary.update(
            {
                "status": "independently-reproduced",
                "lifecycleState": "independently-reproduced",
                "evidenceClassification": "authenticated-external-provider",
                "operational": True,
            }
        )
        summary["summaryDigest"] = semantic_digest(summary, "summaryDigest")

        errors = engine.independent_summary_errors(summary)

        self.assertIn(
            "fixture, self-test, or uncoordinated evidence cannot be operational",
            errors,
        )

    def test_cli_when_independent_command_selected_expect_closed_modes(self) -> None:
        parser = build_parser()

        parsed = parser.parse_args(
            [
                "stable-independent-reproducibility",
                "--mode",
                "prepare-verifier-kit",
                "--execution-contract",
                "contract.json",
            ]
        )

        self.assertEqual("stable-independent-reproducibility", parsed.command)
        self.assertEqual("prepare-verifier-kit", parsed.mode)
        self.assertEqual(Path("contract.json"), parsed.execution_contract)

    def test_workflow_when_reviewed_expect_minimal_nonpublication_boundary(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        uses = re.findall(r"^\s*uses:\s*([^\s#]+)", workflow, re.MULTILINE)

        self.assertIn("permissions: {}", workflow)
        self.assertIn(
            "environment: stable-1.0-independent-reproducibility-external-receipt",
            workflow,
        )
        self.assertTrue(uses)
        self.assertTrue(all(re.search(r"@[0-9a-f]{40}$", use) for use in uses), uses)
        self.assertNotIn("${{ secrets.", workflow)
        self.assertEqual(3, workflow.count("          ref: ${{ github.sha }}"))
        self.assertNotIn("          ref: ${{ inputs.source_commit }}", workflow)
        self.assertIn('|| "$GITHUB_SHA" != "$INPUT_SOURCE_COMMIT"', workflow)
        self.assertIn("authenticated_inputs_coordinates", workflow)
        self.assertIn("verifier_kit_coordinates", workflow)
        self.assertIn("primary_subject_bundle_coordinates", workflow)
        self.assertIn(
            "build/independent-reproducibility-inputs/execution/"
            "stable-1.0-independent-reproducibility-execution.json",
            workflow,
        )
        self.assertNotIn(
            "${{ runner.temp }}/stable-1.0-independent-reproducibility-execution.json",
            workflow,
        )

        prepare = workflow[
            workflow.index("  prepare-verifier-kit:") :
            workflow.index("  authenticate-and-compare:")
        ]
        prepare_permissions = prepare[
            prepare.index("    permissions:") : prepare.index("    steps:")
        ]
        self.assertIn("      actions: read", prepare_permissions)
        self.assertIn("      contents: read", prepare_permissions)
        self.assertNotIn("write", prepare_permissions)
        prepare_invocation = prepare[
            prepare.index("- name: Generate verifier kit without candidate product bytes") :
            prepare.index("- name: Upload the bounded verifier kit")
        ]
        self.assertIn(".evaluationTime = $evaluationTime", prepare_invocation)
        self.assertLess(
            prepare_invocation.index("date -u +'%Y-%m-%dT%H:%M:%SZ'"),
            prepare_invocation.index("--mode prepare-verifier-kit"),
        )

        recipe_authentication_steps = re.findall(
            r"- name: Authenticate exact candidate-byte-free recipe-input coordinates"
            r"(?P<body>.*?)- name: Download authenticated recipe inputs",
            workflow,
            re.DOTALL,
        )
        self.assertEqual(2, len(recipe_authentication_steps))
        for step in recipe_authentication_steps:
            self.assertIn("attempt_started=\"$(jq -er .run_started_at", step)
            self.assertIn("attempt_updated=\"$(jq -er .updated_at", step)
            self.assertIn("and .[0].created_at >= $started", step)
            self.assertIn("and .[0].created_at <= $updated", step)

        coordinator = workflow[
            workflow.index("  authenticate-and-compare:") :
            workflow.index("  retain-failure-closeout:")
        ]
        self.assertNotIn(
            ".evaluationTime = $evaluationTime",
            coordinator[
                coordinator.index("- name: Bind phase-local protected coordinator identity") :
                coordinator.index(
                    "- name: Authenticate exact candidate-byte-free verifier-kit coordinates"
                )
            ],
        )
        self.assertEqual(
            4,
            workflow.count("date -u +'%Y-%m-%dT%H:%M:%SZ'"),
        )
        kit = coordinator.index("Download the exact candidate-byte-free verifier kit")
        external = coordinator.index("Download the sealed external rebuild bundle")
        authenticate = coordinator.index(
            "Authenticate sealed external receipt before candidate access"
        )
        primary = coordinator.index(
            "Download primary supply-chain evidence only after external receipt authentication"
        )
        primary_subjects = coordinator.index(
            "Download primary subject bundle only after external receipt authentication"
        )
        selected = coordinator.index(
            "Download selected RC only after external receipt authentication"
        )
        self.assertLess(kit, external)
        self.assertLess(external, authenticate)
        self.assertLess(authenticate, primary)
        self.assertLess(authenticate, primary_subjects)
        self.assertLess(authenticate, selected)
        receipt_step = coordinator[
            coordinator.index("- name: Authenticate sealed external receipt before candidate access") :
            coordinator.index(
                "- name: Authenticate exact primary supply-chain coordinates after external sealing"
            )
        ]
        self.assertIn(
            "stable-1.0-independent-reproducibility-receipt-phase.json",
            receipt_step,
        )
        self.assertIn('.operationMode = "verify-external-receipt"', receipt_step)
        for binding in (
            "primaryBuilderReceipt",
            "primaryAuthorityAttestation",
            "candidateSubjectBundle",
            "comparisonPlan",
            "reproducibilityResult",
        ):
            self.assertIn(f".comparison.{binding} = null", receipt_step)
        self.assertIn('--execution-contract "$RECEIPT_CONTRACT_PATH"', receipt_step)
        self.assertNotIn('--execution-contract "$CONTRACT_PATH"', receipt_step)
        self.assertLess(
            receipt_step.index("date -u +'%Y-%m-%dT%H:%M:%SZ'"),
            receipt_step.index("--mode verify-external-receipt"),
        )
        compare_step = coordinator[
            coordinator.index("- name: Compare with the existing Stable comparison authority") :
            coordinator.index("- name: Produce protected operational closeout")
        ]
        self.assertIn("if: inputs.operation == 'compare'", compare_step)
        self.assertNotIn("inputs.operation == 'closeout'", compare_step)
        self.assertIn(".evaluationTime = $evaluationTime", compare_step)
        self.assertLess(
            compare_step.index("date -u +'%Y-%m-%dT%H:%M:%SZ'"),
            compare_step.index("--mode compare"),
        )
        closeout_step = coordinator[
            coordinator.index("- name: Produce protected operational closeout") :
            coordinator.index("- name: Upload authenticated external receipt")
        ]
        self.assertIn(".evaluationTime = $evaluationTime", closeout_step)
        self.assertLess(
            closeout_step.index("date -u +'%Y-%m-%dT%H:%M:%SZ'"),
            closeout_step.index("--mode closeout"),
        )
        for prohibited in (
            "contents: write",
            "packages: write",
            "id-token: write",
            "gh release create",
            "git push",
            "git tag",
        ):
            self.assertNotIn(prohibited, workflow)

    def test_workflow_when_comparing_expect_external_seal_before_candidate_access(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        receipt = workflow.index("Authenticate sealed external receipt before candidate access")
        primary = workflow.index(
            "Authenticate exact primary supply-chain coordinates after external sealing"
        )
        candidate = workflow.index(
            "Download selected RC only after external receipt authentication"
        )
        comparison = workflow.index("Compare with the existing Stable comparison authority")

        self.assertLess(receipt, primary)
        self.assertLess(primary, candidate)
        self.assertLess(candidate, comparison)

    def test_workflow_when_importing_external_evidence_expect_exact_six_file_boundary(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        match = re.search(
            r"expected = \{\s*Path\(contract\[\"externalBuild\"\]\[field\]\[\"path\"\]\)"
            r"\.name\s*for field in \((?P<fields>.*?)\)\s*\}",
            workflow,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        fields = re.findall(r'"([A-Za-z]+)"', match.group("fields"))

        self.assertEqual(
            [
                "builderReceipt",
                "authorityAttestation",
                "rawArtifactAttestationBundle",
                "verificationTranscript",
                "outputManifest",
                "outputBundle",
            ],
            fields,
        )
        self.assertIn("if len(expected) != 6", workflow)


if __name__ == "__main__":
    unittest.main()
