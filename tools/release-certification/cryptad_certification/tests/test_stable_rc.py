"""Offline self-tests for Stable 1.0 RC freeze and artifact security invariants."""

from __future__ import annotations

import copy
import json
import tarfile
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cryptad_certification.engines import (
    production_beta_release,
    stable_1_0_rc,
    stable_1_0_rc_artifacts,
    stable_1_0_rc_freeze,
)
from cryptad_certification.engines.stable_1_0_rc_artifacts import (
    create_deterministic_archive,
    render_release_notes,
    verify_deterministic_archive,
    write_named_checksums,
)
from cryptad_certification.engines.stable_1_0_rc_core import (
    REQUIRED_PIPELINE_STAGES,
    SAME_RUN_INPUT_KEYS,
    SUPPORTING_VERIFIER_FILES,
    LoadedInput,
    SourceIdentity,
    ValidationState,
    ecosystem_matrix_is_promotable,
    explicit_production_classification_errors,
    freshness_error,
    load_candidate_inputs,
    load_raw_input,
    placeholder_findings,
    release_certification_is_promotable,
    semantic_digest,
    validate_catalog_operations,
    validate_live_inputs,
    validate_production_beta,
)
from cryptad_certification.engines.stable_1_0_rc_freeze import (
    assemble_freeze,
    build_limitations_freeze,
    compare_freezes,
    freeze_content_digest,
    merge_accepted_exception_history,
    producer_identity_digest,
    producer_identity_digests,
    stable_surface_is_exact,
    validate_exception_collection,
    validate_freeze_shape,
)
from cryptad_certification.engines.stable_1_0_readiness_policy import safe_limitation
from cryptad_certification.redaction import scan_value


def _freeze() -> dict[str, object]:
    def digest(character: str) -> str:
        return "sha256:" + character * 64

    app_ids = (
        "publisher",
        "queue-manager",
        "site-publisher",
        "profile-publisher",
        "social-inbox",
        "feed-reader",
        "trust-graph",
    )
    profile_ids = (
        "crypta.profile.v1",
        "crypta.feed.snapshot.v1",
        "crypta.trust.statement.v1",
        "crypta.social.message.v1",
        "crypta.social.outbox.v1",
    )
    apps = [
        {
            "appId": app_id,
            "version": "283",
            "channel": "stable",
            "supportStatus": "supported",
            "deprecationStatus": "none",
            "supportLevel": "maintained",
            "replacementAppId": None,
            "bundleDigest": digest("1"),
            "bundleSizeBytes": 1024,
            "appSigningKeyId": "app-production-2026",
            "reviewReceiptDigest": digest("2"),
            "reviewerKeyId": "reviewer-production-2026",
            "manifestDigest": digest("3"),
            "declaredPermissionSetDigest": digest("4"),
            "targetApiStability": "stable",
            "apiCompatibilityResult": "pass",
            "apiCompatibilityEvidenceDigest": digest("5"),
            "appDataSchemaVersion": 1,
            "migrationReadiness": "pass",
            "backupRestore": "supported",
            "betaReadinessEvidenceDigest": digest("6"),
            "supportMetadataDigest": digest("7"),
            "supportUri": "https://github.com/crypta-network/cryptad/issues",
            "redactedDiagnosticsReadiness": "redacted-summary-only",
            "allowedStableLimitationId": None,
        }
        for app_id in app_ids
    ]
    profiles = [
        {
            "profileId": profile_id,
            "version": 1,
            "status": "stable",
            "descriptorDigest": digest("8"),
            "canonicalizationRulesDigest": digest("9"),
            "maximumSizePolicy": {
                "documentBytes": 65536,
                "signedPayloadBytes": 32768,
            },
            "signaturePayloadRules": {
                "signed": True,
                "signingDomain": "crypta.stable-1.0",
            },
            "parserValidatorCompatibilityEvidenceDigest": digest("a"),
        }
        for profile_id in profile_ids
    ]
    value: dict[str, object] = {
        "schemaVersion": 1,
        "kind": "stable-1.0-rc-freeze",
        "stableMilestone": "1.0",
        "candidate": {
            "releaseId": "stable-rc-283",
            "buildVersion": "283",
            "sourceCommit": "a" * 40,
            "sourceRef": "commit:" + "a" * 40,
            "sourceProvenanceDigest": digest("b"),
            "generationTool": "stable-1.0-rc",
            "generationToolVersion": 1,
            "productionBetaSummaryDigest": digest("c"),
            "productionDistributionDigest": digest("c"),
            "stableReadinessSummaryDigest": digest("d"),
            "releaseCertificationSummaryDigest": digest("e"),
            "goNoGoSummaryDigest": digest("f"),
            "ecosystemMatrixDigest": digest("0"),
            "releaseHistoryDigest": digest("1"),
            "previousCandidateDigest": digest("2"),
            "liveNetworkDigest": digest("3"),
            "multiNodeSoakDigest": digest("4"),
            "networkScaleSoakDigest": digest("5"),
            "securityDrillDigest": digest("6"),
            "thirdPartyIntakeDigest": digest("7"),
            "catalogOperationsDigest": digest("8"),
        },
        "platformApi": {
            "baselineName": "1.0",
            "baselineContractVersion": 23,
            "baselineDigest": digest("9"),
            "currentContractVersion": 23,
            "currentContractDigest": digest("a"),
            "compatibilityWindowPolicyDigest": digest("b"),
            "stableCapabilityCount": 12,
            "stableEndpointCount": 34,
            "experimentalCapabilityCount": 2,
            "experimentalEndpointCount": 3,
            "stableBreakingChangeVerification": "pass",
            "verificationReportDigest": digest("c"),
        },
        "stableCatalog": {
            "catalogId": "crypta-first-party",
            "channel": "stable",
            "catalogVersion": 5,
            "edition": 7,
            "revision": 7,
            "catalogDigest": digest("d"),
            "signatureDigest": digest("e"),
            "signatureAliasDigest": digest("f"),
            "catalogSigningKeyId": "catalog-production-2026",
            "artifactTimestamp": "2026-07-14T00:00:00Z",
            "keyRotationStatus": {"status": "complete", "compromised": False},
            "primaryHealth": {
                "status": "pass",
                "signatureVerified": True,
                "revision": 7,
                "digest": digest("d"),
            },
            "mirrorHealth": [
                {
                    "status": "pass",
                    "signatureVerified": True,
                    "revision": 7,
                    "digest": digest("d"),
                    "transportFallbackOnly": True,
                }
            ],
            "verifiedRollback": {
                "status": "pass",
                "signatureVerified": True,
                "revision": 6,
                "digest": digest("0"),
            },
            "securityAdvisoryCount": 0,
            "denylistCount": 0,
            "orderedEntries": [{"appId": app_id, "version": "283"} for app_id in app_ids],
        },
        "firstPartyApps": apps,
        "contentFormatProfiles": profiles,
        "limitationsAndPolicy": {
            "stableReadinessPolicyDigest": digest("1"),
            "allowedLimitations": [],
            "allowedLimitationsDigest": semantic_digest([]),
            "allowedLimitationCount": 0,
            "disallowedLimitationCount": 0,
            "betaOnlyLimitationCount": 0,
            "publicBetaKnownIssuesDigest": digest("2"),
            "stableKnownLimitationsDigest": digest("3"),
            "securityDrillSummaryDigest": digest("4"),
            "legacyPluginAdminFreezeEvidenceDigest": digest("5"),
            "supportFeedbackReadinessEvidenceDigest": digest("6"),
        },
        "acceptedFreezeExceptions": [],
    }
    value["contentDigest"] = freeze_content_digest(value)
    return value


def _exception(before: str, after: str) -> dict[str, object]:
    now = datetime.now(timezone.utc)
    return {
        "exceptionId": "freeze-blocker-283",
        "releaseId": "stable-rc-283",
        "buildVersion": "283",
        "affectedSection": "firstPartyApps",
        "affectedItem": "publisher",
        "beforeDigest": before,
        "afterDigest": after,
        "reason": "Correct a release-blocking app bundle defect.",
        "issueKind": "blocker",
        "issueReference": "CRYPTA-283",
        "owner": "release-owner",
        "approver": "release-approver",
        "createdAt": (now - timedelta(minutes=1)).isoformat(),
        "expiresAt": (now + timedelta(hours=1)).isoformat(),
        "requiredRerunScope": ["freeze-generation", "packaging", "stable-rc-final-gates"],
        "finalVerificationResult": "pass",
    }


def _collection(record: dict[str, object]) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-rc-freeze-exceptions",
        "authorizationRole": "stable-release-manager",
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
        "exceptions": [record],
    }


def _production_summary() -> dict[str, object]:
    return {
        "status": "pass",
        "promotionReady": True,
        "nonRelease": False,
        "fixtureOnly": False,
        "simulatedOnly": False,
        "releaseId": "stable-rc-283",
        "version": "283",
        "signingProfile": {
            "kind": "production",
            "generatedTestKeys": False,
            "privateKeyMaterialIncluded": False,
        },
        "workspaceStatusKnown": True,
        "dirtyWorkspace": False,
        "pipelineStages": {stage: {"status": "pass"} for stage in REQUIRED_PIPELINE_STAGES},
    }


def _catalog_operations() -> dict[str, object]:
    now = datetime.now(timezone.utc).isoformat()
    digest = "sha256:" + "a" * 64
    health = {"status": "pass", "signatureVerified": True, "revision": 7, "digest": digest}
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-rc-catalog-operations",
        "generatedAt": now,
        "artifactTimestamp": now,
        "releaseId": "stable-rc-283",
        "buildVersion": "283",
        "sourceCommit": "a" * 40,
        "status": "pass",
        "fixtureOnly": False,
        "simulatedOnly": False,
        "nonRelease": False,
        "catalogId": "crypta-first-party",
        "channel": "stable",
        "revision": 7,
        "catalogDigest": digest,
        "signatureDigest": "sha256:" + "b" * 64,
        "signingKeyId": "catalog-production-2026",
        "keyRotation": {"status": "complete", "compromised": False},
        "primary": copy.deepcopy(health),
        "mirrors": [{**health, "transportFallbackOnly": True}],
        "rollback": {"status": "pass", "signatureVerified": True, "revision": 6, "digest": "sha256:" + "c" * 64},
        "advisoryCount": 0,
        "denylistCount": 0,
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }


def _readiness_summary(mutation: str) -> dict[str, object]:
    summary: dict[str, object] = {
        "schemaVersion": 1,
        "kind": "stable-1.0-readiness",
        "tool": "stable-1.0-readiness",
        "releaseId": "stable-rc-283",
        "status": "fail" if mutation == "not-ready" else "pass",
        "decision": "not-ready" if mutation == "not-ready" else "ready",
        "stableReady": mutation != "not-ready",
        "blockerCount": 0,
        "warningCount": 0,
        "allowedLimitationCount": 0,
        "disallowedLimitationCount": 0,
        "blockers": [],
        "warnings": [],
        "allowedLimitations": [],
        "disallowedLimitations": [],
        "domains": [],
        "evidence": [],
        "redaction": {"status": "pass", "findingCount": 0, "criticalFindingCount": 0, "findings": []},
    }
    if mutation == "wrong-release":
        summary["releaseId"] = "another-candidate"
    return summary


class StableRcFreezeTest(unittest.TestCase):
    def test_candidate_built_launcher_is_selected_for_the_host_platform(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            launchers = root / "build/crypta-app-launcher/bin"
            launchers.mkdir(parents=True)
            posix = launchers / "crypta-app"
            batch = launchers / "crypta-app.bat"
            posix.write_text("#!/bin/sh\n", encoding="utf-8")
            batch.write_text("@echo off\r\n", encoding="utf-8")

            with (
                mock.patch.object(stable_1_0_rc_freeze.platform, "system", return_value="Linux"),
                mock.patch.object(stable_1_0_rc_freeze.os, "access", return_value=True),
            ):
                self.assertEqual(posix.resolve(), stable_1_0_rc_freeze.find_crypta_app(root))
            with mock.patch.object(
                stable_1_0_rc_freeze.platform,
                "system",
                return_value="Windows",
            ):
                self.assertEqual(batch.resolve(), stable_1_0_rc_freeze.find_crypta_app(root))

    def test_candidate_built_posix_launcher_must_be_executable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            launcher = root / "build/crypta-app-launcher/bin/crypta-app"
            launcher.parent.mkdir(parents=True)
            launcher.write_text("#!/bin/sh\n", encoding="utf-8")

            with (
                mock.patch.object(stable_1_0_rc_freeze.platform, "system", return_value="Linux"),
                mock.patch.object(stable_1_0_rc_freeze.os, "access", return_value=False),
                self.assertRaisesRegex(ValueError, "not executable"),
            ):
                stable_1_0_rc_freeze.find_crypta_app(root)

    def test_candidate_loader_rejects_every_external_same_run_override(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for key in SAME_RUN_INPUT_KEYS:
                with self.subTest(key=key):
                    context = SimpleNamespace(
                        workspace_root=root,
                        manifest=SimpleNamespace(inputs={key: f"{key}.json"}),
                    )
                    with self.assertRaisesRegex(ValueError, rf"inputs\.{key}"):
                        load_candidate_inputs(context, root)

    def test_candidate_loader_rejects_symlinked_embedded_evidence_parents(self) -> None:
        for linked_parent in ("evidence", "reports"):
            with self.subTest(linked_parent=linked_parent), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                native_root = root / "native"
                native_root.mkdir()
                outside = root / "outside"
                outside.mkdir()
                if linked_parent == "evidence":
                    (outside / "app-platform-smoke.json").write_text("{}\n", encoding="utf-8")
                    (native_root / "evidence").symlink_to(outside, target_is_directory=True)
                else:
                    evidence = native_root / "evidence"
                    evidence.mkdir()
                    (evidence / "app-platform-smoke.json").write_text("{}\n", encoding="utf-8")
                    (evidence / "ecosystem-certification-matrix.json").write_text(
                        "{}\n", encoding="utf-8"
                    )
                    (outside / "go-no-go-dashboard.json").write_text("{}\n", encoding="utf-8")
                    (native_root / "reports").symlink_to(outside, target_is_directory=True)
                context = SimpleNamespace(
                    workspace_root=root,
                    manifest=SimpleNamespace(inputs={}),
                )
                production = LoadedInput(
                    "productionBeta",
                    root / "summary.json",
                    {"status": "pass"},
                    "sha256:" + "1" * 64,
                )

                with (
                    mock.patch(
                        "cryptad_certification.engines.stable_1_0_rc_core.load_existing_input",
                        return_value=production,
                    ),
                    self.assertRaisesRegex(ValueError, "symlink"),
                ):
                    load_candidate_inputs(context, native_root)

    def test_freeze_schema_closed_objects_and_local_references_are_well_formed(self) -> None:
        root = Path(__file__).resolve().parents[4]
        schema = json.loads(
            (root / "tools/release-certification/schemas/stable-1.0-rc-freeze-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        definitions = schema["$defs"]

        def assert_schema_node(node: object, path: str) -> None:
            if isinstance(node, dict):
                reference = node.get("$ref")
                if isinstance(reference, str) and reference.startswith("#/$defs/"):
                    self.assertIn(reference.removeprefix("#/$defs/"), definitions, path)
                if node.get("type") == "object" and node.get("additionalProperties") is False:
                    required = node.get("required", [])
                    properties = node.get("properties", {})
                    self.assertTrue(set(required).issubset(properties), path)
                for key, value in node.items():
                    assert_schema_node(value, f"{path}.{key}")
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    assert_schema_node(value, f"{path}[{index}]")

        assert_schema_node(schema, "$")
        self.assertIn("limitationsAndPolicy", definitions)
        self.assertIn(
            "parserValidatorCompatibilityEvidenceDigest",
            definitions["contentProfile"]["properties"],
        )

    def test_catalog_operations_reject_uncontracted_fields_before_freezing(self) -> None:
        catalog_operations = _catalog_operations()
        catalog_operations["primary"]["latencyMs"] = 12  # type: ignore[index]
        catalog_operations["mirrors"][0]["region"] = "test-region"  # type: ignore[index]
        catalog_operations["rollback"]["attemptCount"] = 1  # type: ignore[index]
        state = ValidationState()

        validate_catalog_operations(
            catalog_operations,
            "stable-rc-283",
            "283",
            datetime.now(timezone.utc),
            state,
        )

        frozen = stable_1_0_rc_freeze._catalog_operations_freeze(catalog_operations)  # noqa: SLF001

        self.assertTrue(state.blockers)
        summaries = " ".join(str(blocker["summary"]) for blocker in state.blockers)
        self.assertIn("unknown field latencyMs", summaries)
        self.assertIn("unknown field region", summaries)
        self.assertIn("unknown field attemptCount", summaries)
        self.assertEqual({"status", "compromised"}, set(frozen["keyRotationStatus"]))
        self.assertEqual(
            {"status", "signatureVerified", "revision", "digest"},
            set(frozen["primaryHealth"]),
        )
        self.assertEqual(
            {"status", "signatureVerified", "revision", "digest", "transportFallbackOnly"},
            set(frozen["mirrorHealth"][0]),
        )
        self.assertEqual(
            {"status", "signatureVerified", "revision", "digest"},
            set(frozen["verifiedRollback"]),
        )

    def test_catalog_operations_accept_a_verified_distinct_prior_revision(self) -> None:
        state = ValidationState()

        validate_catalog_operations(
            _catalog_operations(),
            "stable-rc-283",
            "283",
            datetime.now(timezone.utc),
            state,
        )

        self.assertEqual([], state.blockers)

    def test_catalog_operations_reject_non_production_classification(self) -> None:
        catalog_operations = _catalog_operations()
        catalog_operations["nonProduction"] = True
        state = ValidationState()

        validate_catalog_operations(
            catalog_operations,
            "stable-rc-283",
            "283",
            datetime.now(timezone.utc),
            state,
        )

        self.assertTrue(
            any("unknown field nonProduction" in blocker["summary"] for blocker in state.blockers)
        )

    def test_catalog_artifact_timestamp_must_precede_operations_evidence(self) -> None:
        catalog_operations = _catalog_operations()
        catalog_operations["generatedAt"] = "2026-07-14T00:00:00Z"
        catalog_operations["artifactTimestamp"] = "2026-07-15T00:00:00Z"
        state = ValidationState()

        validate_catalog_operations(
            catalog_operations,
            "stable-rc-283",
            "283",
            datetime(2026, 7, 15, 12, tzinfo=timezone.utc),
            state,
        )

        self.assertTrue(
            any(
                "artifactTimestamp cannot be later than generatedAt" in blocker["summary"]
                for blocker in state.blockers
            )
        )

    def test_catalog_rollback_must_bind_a_distinct_older_revision(self) -> None:
        cases = (
            (7, "sha256:" + "a" * 64, "precede"),
            (8, "sha256:" + "c" * 64, "precede"),
            (6, "sha256:" + "a" * 64, "distinct prior"),
        )
        for revision, digest, expected in cases:
            with self.subTest(revision=revision, digest=digest):
                catalog_operations = _catalog_operations()
                catalog_operations["rollback"]["revision"] = revision  # type: ignore[index]
                catalog_operations["rollback"]["digest"] = digest  # type: ignore[index]
                state = ValidationState()

                validate_catalog_operations(
                    catalog_operations,
                    "stable-rc-283",
                    "283",
                    datetime.now(timezone.utc),
                    state,
                )

                self.assertTrue(
                    any(expected in blocker["summary"] for blocker in state.blockers),
                    state.blockers,
                )

    def test_platform_api_freeze_rejects_symlinked_compatibility_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            contracts = root / "docs/platform-api/contracts"
            contracts.mkdir(parents=True)
            (contracts / "platform-api-1.0-baseline.json").write_text("{}\n", encoding="utf-8")
            outside = root / "outside-policy.md"
            outside.write_text("# External policy\n", encoding="utf-8")
            (root / "docs/platform-api-compatibility-support-window.md").symlink_to(outside)
            context = SimpleNamespace(workspace_root=root)

            with self.assertRaisesRegex(ValueError, "symlink"):
                stable_1_0_rc_freeze.build_platform_api_freeze(
                    context,
                    root / "native",
                    root / "output",
                    ValidationState(),
                )

    def test_same_run_producer_identities_exclude_only_execution_volatility(self) -> None:
        digest_one = "sha256:" + "1" * 64
        digest_two = "sha256:" + "2" * 64

        def inputs(
            generated_at: str,
            digest: str,
            duration: int,
            temporary_suffix: str,
        ) -> dict[str, LoadedInput]:
            values = {
                key: {"status": "pass", "generatedAt": generated_at}
                for key in SAME_RUN_INPUT_KEYS
            }
            values["productionBeta"]["startedAt"] = generated_at
            values["productionBeta"]["commands"] = [
                {
                    "name": "gradle-build",
                    "args": [
                        "<path>/python3",
                        "--out-dir",
                        (
                            "<workdir>/cryptad-production-beta-"
                            f"{temporary_suffix}/release-certification"
                        ),
                        "--app-platform-summary",
                        (
                            "<workdir>\\cryptad-production-beta-"
                            f"{temporary_suffix}\\release-certification\\"
                            "app-platform-smoke\\summary.json"
                        ),
                    ],
                    "exit_code": 0,
                    "duration_ms": duration,
                    "stdout_tail": "BUILD SUCCESSFUL in a volatile duration",
                    "stderr_tail": "",
                }
            ]
            values["stableReadiness"]["inputs"] = {
                reference: {"status": "present", "sha256": digest}
                for reference in stable_1_0_rc_freeze.STABLE_READINESS_SAME_RUN_REFERENCES
            }
            values["productionBeta"]["materializedInput"] = (
                "<workdir>/cryptad-production-beta-"
                f"{temporary_suffix}/release-certification/inputs/third-party.json"
            )
            return {
                key: LoadedInput(key, Path(f"{key}.json"), value, digest)
                for key, value in values.items()
            }

        first = inputs("2026-07-14T00:00:00Z", digest_one, 1, "t3hwetmy")
        second = inputs("2026-07-14T00:05:00Z", digest_two, 999, "a9b8c7d6")
        first["releaseCertification"].value["metadata"] = {
            "gitCommit": "a" * 40,
            "gitDirty": "false",
            "gitBranch": "release/283",
            "githubActions": "true",
            "githubWorkflow": "Stable 1.0 RC",
            "githubRunId": "1000",
            "githubRunAttempt": "1",
            "githubRef": "refs/heads/release/283",
            "githubSha": "a" * 40,
            "runnerOs": "Linux",
        }
        second["releaseCertification"].value["metadata"] = {
            "gitCommit": "a" * 40,
            "gitDirty": "false",
            "gitBranch": "detached-local-checkout",
        }

        first_identities = producer_identity_digests(first)
        second_identities = producer_identity_digests(second)
        self.assertEqual(first_identities, second_identities)

        second["productionBeta"].value["commands"][0]["args"].append(  # type: ignore[index]
            "--semantic-option-change"
        )
        self.assertNotEqual(
            first_identities["productionBeta"],
            producer_identity_digests(second)["productionBeta"],
        )
        second["productionBeta"].value["commands"][0]["args"].pop()  # type: ignore[index]

        external_keys = (
            "liveNetwork",
            "multiNodeSoak",
            "networkScaleSoak",
            "previousCandidate",
            "releaseHistory",
            "securityDrills",
            "thirdPartyIntake",
        )
        for collection in (first, second):
            collection.update(
                {
                    key: LoadedInput(key, Path(f"{key}.json"), {"status": "pass"}, digest_one)
                    for key in external_keys
                }
            )
        context = SimpleNamespace(
            manifest=SimpleNamespace(
                release=SimpleNamespace(release_id="stable-rc-283", version="283")
            )
        )
        source = SourceIdentity("a" * 40, "commit:" + "a" * 40, digest_one)

        def freeze(collection: dict[str, LoadedInput]) -> dict[str, object]:
            baseline = _freeze()
            return assemble_freeze(
                context=context,
                source=source,
                inputs=collection,
                catalog_operations=LoadedInput(
                    "stableCatalogOperations",
                    Path("catalog.json"),
                    {"status": "pass"},
                    digest_one,
                ),
                platform_api=copy.deepcopy(baseline["platformApi"]),
                stable_catalog=copy.deepcopy(baseline["stableCatalog"]),
                first_party_apps=copy.deepcopy(baseline["firstPartyApps"]),
                content_profiles=copy.deepcopy(baseline["contentFormatProfiles"]),
                limitations=copy.deepcopy(baseline["limitationsAndPolicy"]),
                accepted_exceptions=[],
                production_distribution_digest=digest_one,
            )

        first_freeze = freeze(first)
        second_freeze = freeze(second)
        self.assertEqual("no-drift", compare_freezes(first_freeze, second_freeze, [])["status"])

        second["releaseCertification"].value["metadata"]["gitCommit"] = "b" * 40
        commit_changed_identities = producer_identity_digests(second)
        self.assertNotEqual(
            first_identities["releaseCertification"],
            commit_changed_identities["releaseCertification"],
        )
        self.assertNotEqual(
            first_identities["stableReadiness"],
            commit_changed_identities["stableReadiness"],
        )
        second["releaseCertification"].value["metadata"]["gitCommit"] = "a" * 40
        second["ecosystemMatrix"].value["releaseBlockerCount"] = 1
        changed_identities = producer_identity_digests(second)
        self.assertNotEqual(
            first_identities["ecosystemMatrix"],
            changed_identities["ecosystemMatrix"],
        )
        self.assertNotEqual(
            first_identities["stableReadiness"],
            changed_identities["stableReadiness"],
        )

    def test_external_evidence_keeps_its_exact_file_digest(self) -> None:
        digest = "sha256:" + "3" * 64
        loaded = LoadedInput(
            "securityDrills",
            Path("security-drills.json"),
            {"status": "pass", "generatedAt": "2026-07-14T00:00:00Z"},
            digest,
        )

        self.assertEqual(digest, producer_identity_digest(loaded))

    def test_warning_prerequisites_remain_promotable_when_their_gate_fields_pass(self) -> None:
        self.assertTrue(
            release_certification_is_promotable(
                {"status": "warn", "releaseCandidatePassed": True}
            )
        )
        self.assertTrue(
            ecosystem_matrix_is_promotable(
                {"status": "warn", "releaseBlockerCount": 0}
            )
        )
        self.assertFalse(
            release_certification_is_promotable(
                {"status": "warn", "releaseCandidatePassed": False}
            )
        )
        self.assertFalse(
            ecosystem_matrix_is_promotable(
                {"status": "warn", "releaseBlockerCount": 1}
            )
        )

    def test_current_evidence_is_candidate_bound_without_expiring_historical_inputs(self) -> None:
        now = datetime.now(timezone.utc)
        fresh = (now - timedelta(hours=1)).isoformat()
        historical = (now - timedelta(days=365)).isoformat()
        digest = "sha256:" + "4" * 64

        def loaded(key: str, value: dict[str, object]) -> LoadedInput:
            return LoadedInput(key, Path(f"{key}.json"), value, digest)

        inputs = {
            "liveNetwork": loaded(
                "liveNetwork",
                {"status": "pass", "generatedAt": fresh, "mode": "live"},
            ),
            "multiNodeSoak": loaded(
                "multiNodeSoak",
                {"status": "pass", "generatedAt": fresh, "mode": "hybrid"},
            ),
            "networkScaleSoak": loaded(
                "networkScaleSoak",
                {"status": "pass", "generatedAt": fresh, "mode": "live-rc-soak"},
            ),
            "securityDrills": loaded(
                "securityDrills",
                {"status": "pass", "generatedAt": fresh},
            ),
            "thirdPartyIntake": loaded(
                "thirdPartyIntake",
                {
                    "status": "pass",
                    "releaseId": "stable-rc-283",
                    "buildVersion": "283",
                    "generatedAt": fresh,
                    "fixtureOnly": False,
                    "simulatedOnly": False,
                    "nonRelease": False,
                    "nonProduction": False,
                },
            ),
            "previousCandidate": loaded(
                "previousCandidate",
                {
                    "status": "pass",
                    "releaseId": "cryptad-beta-269",
                    "generatedAt": historical,
                },
            ),
            "releaseHistory": loaded(
                "releaseHistory",
                {
                    "status": "pass",
                    "releaseId": "cryptad-beta-269",
                    "generatedAt": historical,
                },
            ),
            "appPlatform": loaded(
                "appPlatform",
                {
                    "status": "pass",
                    "generatedAt": fresh,
                    "evidence": [{"id": "apphost.sandbox-provider", "status": "pass"}],
                },
            ),
        }
        state = ValidationState()

        validate_live_inputs(inputs, "stable-rc-283", "283", now, state)

        self.assertEqual([], state.blockers)
        inputs["multiNodeSoak"].value["generatedAt"] = historical
        stale_state = ValidationState()
        validate_live_inputs(inputs, "stable-rc-283", "283", now, stale_state)
        self.assertTrue(
            any(
                blocker["id"] == "stable-1.0-rc.evidence.multiNodeSoak"
                for blocker in stale_state.blockers
            )
        )
        inputs["multiNodeSoak"].value["generatedAt"] = fresh
        inputs["liveNetwork"].value["releaseId"] = "wrong-current-candidate"
        wrong_candidate_state = ValidationState()
        validate_live_inputs(
            inputs,
            "stable-rc-283",
            "283",
            now,
            wrong_candidate_state,
        )
        self.assertTrue(
            any(
                blocker["id"] == "stable-1.0-rc.evidence.liveNetwork"
                for blocker in wrong_candidate_state.blockers
            )
        )

        inputs["liveNetwork"].value["releaseId"] = "stable-rc-283"
        inputs["thirdPartyIntake"].value["buildVersion"] = "282"
        wrong_build_state = ValidationState()
        validate_live_inputs(
            inputs,
            "stable-rc-283",
            "283",
            now,
            wrong_build_state,
        )
        self.assertTrue(
            any(
                blocker["id"] == "stable-1.0-rc.evidence.thirdPartyIntake"
                and "buildVersion" in blocker["summary"]
                for blocker in wrong_build_state.blockers
            )
        )

        del inputs["thirdPartyIntake"].value["buildVersion"]
        missing_build_state = ValidationState()
        validate_live_inputs(
            inputs,
            "stable-rc-283",
            "283",
            now,
            missing_build_state,
        )
        self.assertTrue(
            any(
                blocker["id"] == "stable-1.0-rc.evidence.thirdPartyIntake"
                and "buildVersion" in blocker["summary"]
                for blocker in missing_build_state.blockers
            )
        )

    def test_third_party_release_proof_requires_explicit_false_classification_flags(self) -> None:
        from cryptad_certification.engines.production_beta_release_evidence import (
            third_party_intake_summary_is_non_release,
        )

        flags = {
            "fixtureOnly": False,
            "simulatedOnly": False,
            "nonRelease": False,
            "nonProduction": False,
        }
        self.assertEqual([], explicit_production_classification_errors(flags, "thirdPartyIntake"))
        self.assertFalse(
            third_party_intake_summary_is_non_release(flags, stable_rc=True)
        )
        for field in tuple(flags):
            with self.subTest(field=field):
                omitted = {key: value for key, value in flags.items() if key != field}
                self.assertTrue(
                    any(
                        field in error
                        for error in explicit_production_classification_errors(
                            omitted,
                            "thirdPartyIntake",
                        )
                    )
                )
                self.assertTrue(
                    third_party_intake_summary_is_non_release(
                        omitted,
                        stable_rc=True,
                    )
                )

    def test_policy_allowed_limitation_is_frozen_and_prominent_in_release_notes(self) -> None:
        digest = "sha256:" + "1" * 64
        limitation = safe_limitation({
            "id": "stable-1.0.local-rc-scope",
            "title": "Local RC scope",
            "summary": "Trust Graph remains explicitly local RC.",
            "classification": "allowed-for-stable-1.0",
            "status": "open",
            "category": "bounded-scope",
            "boundedBy": "Local node operation only.",
            "owner": "crypta-core",
            "evidenceIds": ["stable-1.0.known-limitations"],
        })
        state = ValidationState()
        frozen = build_limitations_freeze(
            {"allowedLimitations": [limitation], "disallowedLimitationCount": 0},
            LoadedInput("policy", Path("policy.json"), {"allowedLimitationCategories": ["bounded-scope"]}, digest),
            LoadedInput("known", Path("known.json"), {}, digest),
            LoadedInput("public", Path("public.json"), {}, digest),
            {"evidence": []},
            digest,
            state,
        )
        freeze = _freeze()
        freeze["limitationsAndPolicy"] = frozen
        notes = render_release_notes(freeze, {"releaseId": "stable-rc-282"}, [], [])

        self.assertEqual([], state.blockers)
        self.assertEqual([limitation], frozen["allowedLimitations"])
        self.assertIn("stable-1.0.local-rc-scope", notes)
        self.assertIn("Trust Graph remains explicitly local RC.", notes)

    def test_provenance_binds_the_exact_previous_freeze(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            component = root / "run/stable-rc"
            out = component / "artifacts/legacy"
            out.mkdir(parents=True)
            freeze = _freeze()
            (out / "stable-1.0-rc-freeze.json").write_text(
                json.dumps(freeze, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            production_archive = out / "crypta-production-beta-283.tar.gz"
            production_archive.write_bytes(b"production distribution")
            previous_path = root / "previous-freeze.json"
            previous_path.write_text(json.dumps(freeze, sort_keys=True) + "\n", encoding="utf-8")
            previous = LoadedInput(
                "previousStableRcFreeze",
                previous_path,
                freeze,
                stable_1_0_rc.file_digest(previous_path),
            )
            digest = "sha256:" + "1" * 64
            context = SimpleNamespace(
                component_dir=component,
                manifest=SimpleNamespace(
                    release=SimpleNamespace(release_id="stable-rc-283", version="283")
                ),
            )
            source = SourceIdentity("a" * 40, "commit:" + "a" * 40, digest)
            inputs = {
                "stableReadiness": LoadedInput(
                    "stableReadiness",
                    root / "stable-readiness.json",
                    {"status": "pass"},
                    digest,
                )
            }
            catalog = LoadedInput(
                "stableCatalogOperations",
                root / "catalog.json",
                {"status": "pass"},
                digest,
            )

            provenance = stable_1_0_rc._provenance(  # noqa: SLF001
                context,
                source,
                freeze,
                inputs,
                catalog,
                previous,
                production_archive,
                "refreeze",
            )

            expected = {
                "fileDigest": previous.digest,
                "contentDigest": freeze["contentDigest"],
            }
            self.assertEqual(expected, provenance["comparisonBaseline"])
            self.assertEqual("refreeze", provenance["freezeMode"])
            self.assertEqual(previous.digest, provenance["inputs"]["previousStableRcFreeze"])
            self.assertEqual(
                expected,
                stable_1_0_rc._comparison_baseline_binding(previous),  # noqa: SLF001
            )

    def test_release_notes_populate_every_checked_in_template_section(self) -> None:
        freeze = _freeze()

        notes = render_release_notes(
            freeze,
            {"releaseId": "stable-rc-282", "version": "282", "status": "pass"},
            [],
            [],
            public_known_issues={"knownIssues": []},
            stable_readiness={"decision": "ready", "stableReady": True},
            drift={"status": "no-drift", "regenerated": False},
        )

        self.assertTrue(notes.startswith("<!-- cryptad-stable-rc-release-notes-template:v1 -->\n"))
        self.assertEqual(12, notes.count("## "))
        self.assertNotIn("{{", notes)
        self.assertNotIn("missing", notes)
        self.assertIn(str(freeze["contentDigest"]), notes)
        self.assertIn(
            str(freeze["candidate"]["productionDistributionDigest"]),  # type: ignore[index]
            notes,
        )
        for app in freeze["firstPartyApps"]:  # type: ignore[union-attr]
            self.assertIn(str(app["appId"]), notes)
        for profile in freeze["contentFormatProfiles"]:  # type: ignore[union-attr]
            self.assertIn(str(profile["profileId"]), notes)

    def test_release_notes_reject_an_incomplete_template(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            template = Path(directory).resolve() / "stable-1.0-rc-release-notes.md"
            source = stable_1_0_rc_artifacts._RELEASE_NOTES_TEMPLATE.read_text(encoding="utf-8")  # noqa: SLF001
            template.write_text(source.replace("{{known_issues}}", "None."), encoding="utf-8")

            with (
                mock.patch.object(stable_1_0_rc_artifacts, "_RELEASE_NOTES_TEMPLATE", template),
                self.assertRaisesRegex(ValueError, "incomplete or out of order"),
            ):
                render_release_notes(_freeze(), {"releaseId": "stable-rc-282"}, [], [])

    def test_release_notes_require_the_complete_frozen_exception_history(self) -> None:
        freeze = _freeze()
        record = _exception("sha256:" + "1" * 64, "sha256:" + "2" * 64)
        freeze["acceptedFreezeExceptions"] = [record]
        freeze["contentDigest"] = freeze_content_digest(freeze)

        with self.assertRaisesRegex(ValueError, "exception history"):
            render_release_notes(freeze, {"releaseId": "stable-rc-282"}, [], [])

        notes = render_release_notes(
            freeze,
            {"releaseId": "stable-rc-282"},
            [],
            [record],
        )
        self.assertIn(str(record["exceptionId"]), notes)

    def test_only_valid_applied_waivers_are_reported_as_accepted(self) -> None:
        accepted = {
            "id": "waiver-accepted",
            "evidenceId": "app-store.submission-cli",
            "active": True,
            "appliesToMode": True,
            "externalRiskAccepted": False,
            "validationErrors": [],
            "usedBy": ["release-gate"],
        }
        inactive = {**accepted, "id": "waiver-inactive", "active": False}
        unused = {**accepted, "id": "waiver-unused", "usedBy": []}
        invalid_unknown = {
            **accepted,
            "id": "waiver-invalid-unknown",
            "evidenceId": "external.unknown-gate",
            "active": False,
            "validationErrors": [
                "evidenceId is unknown and externalRiskAccepted is not true"
            ],
        }

        result = stable_1_0_rc._accepted_waivers(  # noqa: SLF001
            {"waivers": [accepted, inactive, unused, invalid_unknown]}
        )

        self.assertEqual([accepted], result)

    def test_no_go_marks_final_decision_evidence_failed(self) -> None:
        digest = "sha256:" + "1" * 64

        def loaded(key: str, value: dict[str, object]) -> LoadedInput:
            return LoadedInput(key, Path(f"{key}.json"), value, digest)

        inputs = {
            "stableReadiness": loaded(
                "stableReadiness",
                {
                    "generatedAt": "2026-07-14T00:00:00Z",
                    "decision": "ready",
                    "stableReady": True,
                    "allowedLimitations": [],
                },
            ),
            "productionBeta": loaded(
                "productionBeta",
                {"generatedAt": "2026-07-14T00:00:00Z"},
            ),
            "goNoGo": loaded(
                "goNoGo",
                {"decision": "go", "waivers": []},
            ),
        }
        state = ValidationState()
        state.block(
            "stable-1.0-rc.catalog-invalid",
            "stable-1.0-rc.catalog-freeze",
            "Catalog validation failed.",
            "Regenerate the stable catalog.",
        )
        context = SimpleNamespace(
            manifest=SimpleNamespace(
                release=SimpleNamespace(release_id="stable-rc-283", version="283")
            )
        )

        summary = stable_1_0_rc._promotion_summary(  # noqa: SLF001
            context,
            _freeze(),
            {"status": "no-drift", "initialStatus": "no-drift", "regenerated": False},
            state,
            {"status": "pass"},
            inputs,
        )

        evidence = {row["id"]: row for row in summary["evidence"]}
        self.assertEqual("no-go", summary["decision"])
        self.assertFalse(summary["promotionReady"])
        self.assertEqual("fail", evidence["stable-1.0-rc.catalog-freeze"]["status"])
        self.assertEqual("fail", evidence["stable-1.0-rc.final-decision"]["status"])

    def test_passing_offline_candidate_executes_freeze_packaging_and_final_go_no_go(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            component = root / "run" / "stable-rc"
            out = component / "artifacts" / "legacy"
            out.mkdir(parents=True)
            context = SimpleNamespace(
                workspace_root=root,
                component_dir=component,
                manifest=SimpleNamespace(
                    release=SimpleNamespace(
                        release_id="stable-rc-283",
                        version="283",
                        profile="stable-review",
                    ),
                    policies={"stableRcFreezeMode": "first-freeze"},
                ),
            )
            digest = "sha256:" + "1" * 64

            def loaded(key: str, value: dict[str, object]) -> LoadedInput:
                return LoadedInput(key, root / f"{key}.json", value, digest)

            inputs = {
                key: loaded(key, {"status": "pass"})
                for key in (
                    "appPlatform",
                    "ecosystemMatrix",
                    "liveNetwork",
                    "multiNodeSoak",
                    "networkScaleSoak",
                    "releaseCertification",
                    "releaseHistory",
                    "securityDrills",
                    "thirdPartyIntake",
                )
            }
            inputs.update(
                {
                    "productionBeta": loaded(
                        "productionBeta",
                        {"generatedAt": "2026-07-14T00:00:00Z", "status": "pass"},
                    ),
                    "stableReadiness": loaded(
                        "stableReadiness",
                        {
                            "generatedAt": "2026-07-14T00:00:00Z",
                            "status": "pass",
                            "decision": "ready",
                            "stableReady": True,
                            "allowedLimitations": [],
                        },
                    ),
                    "goNoGo": loaded(
                        "goNoGo",
                        {"decision": "go", "promotionReady": True, "waivers": []},
                    ),
                    "previousCandidate": loaded(
                        "previousCandidate",
                        {"releaseId": "stable-rc-282", "status": "pass"},
                    ),
                }
            )
            catalog = loaded("stableCatalogOperations", {"sourceCommit": "a" * 40})
            raw_inputs = {
                "stableCatalogOperations": catalog,
                "stableReadinessPolicy": loaded("stableReadinessPolicy", {}),
                "stableKnownLimitations": loaded("stableKnownLimitations", {}),
                "publicBetaKnownIssues": loaded("publicBetaKnownIssues", {"knownIssues": []}),
            }
            valid_freeze = _freeze()
            platform = copy.deepcopy(valid_freeze["platformApi"])
            stable_catalog = copy.deepcopy(valid_freeze["stableCatalog"])
            apps = copy.deepcopy(valid_freeze["firstPartyApps"])
            profiles = copy.deepcopy(valid_freeze["contentFormatProfiles"])
            limitations = copy.deepcopy(valid_freeze["limitationsAndPolicy"])

            def write_supporting(*_args: object, **_kwargs: object) -> tuple[dict[str, object], Path, Path]:
                for name in SUPPORTING_VERIFIER_FILES:
                    (out / name).write_text("{}\n", encoding="utf-8")
                return platform, out / "platform-api-current-contract.json", out / "platform-api-stable-diff.json"

            def copy_distribution(*_args: object, **_kwargs: object) -> Path:
                path = out / "crypta-production-beta-283.tar.gz"
                path.write_bytes(b"offline deterministic production fixture")
                return path

            with (
                mock.patch.object(stable_1_0_rc, "load_existing_input", return_value=inputs["productionBeta"]),
                mock.patch.object(stable_1_0_rc, "production_native_root", return_value=root),
                mock.patch.object(stable_1_0_rc, "load_candidate_inputs", return_value=inputs),
                mock.patch.object(stable_1_0_rc, "_require_raw", side_effect=lambda _context, key: raw_inputs[key]),
                mock.patch.object(stable_1_0_rc, "load_raw_input", return_value=None),
                mock.patch.object(stable_1_0_rc, "validate_prerequisites"),
                mock.patch.object(
                    stable_1_0_rc,
                    "source_identity",
                    return_value=SourceIdentity("a" * 40, "commit:" + "a" * 40, digest),
                ),
                mock.patch.object(stable_1_0_rc, "build_platform_api_freeze", side_effect=write_supporting),
                mock.patch.object(stable_1_0_rc, "build_catalog_and_apps_freeze", return_value=(stable_catalog, apps)),
                mock.patch.object(
                    stable_1_0_rc,
                    "export_content_profiles",
                    return_value=(profiles, out / "content-format-profiles.json"),
                ),
                mock.patch.object(stable_1_0_rc, "build_limitations_freeze", return_value=limitations),
                mock.patch.object(stable_1_0_rc, "_copy_production_distribution", side_effect=copy_distribution),
                mock.patch.object(stable_1_0_rc, "_validate_production_distribution"),
            ):
                code = stable_1_0_rc._run(context, out, ValidationState())  # noqa: SLF001

            summary = json.loads((out / "stable-1.0-rc-promotion-summary.json").read_text(encoding="utf-8"))
            self.assertEqual(0, code)
            self.assertEqual("pass", summary["status"])
            self.assertEqual("go", summary["decision"])
            self.assertTrue(summary["promotionReady"])
            self.assertFalse(summary["nonRelease"])
            self.assertEqual([], verify_deterministic_archive(out / "cryptad-stable-1.0-rc-283.tar.gz"))

    def test_engine_structural_error_writes_sanitized_no_go_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            component = root / "stable-rc"
            (component / "artifacts").mkdir(parents=True)
            external = root / "external-sentinel.txt"
            external.write_text("must remain\n", encoding="utf-8")
            context = SimpleNamespace(
                component_dir=component,
                run_root=root,
                manifest=SimpleNamespace(
                    release=SimpleNamespace(
                        release_id="stable-rc-283",
                        version="283",
                    )
                ),
            )

            def fail_after_partial_output(
                _context: object,
                output: Path,
                _state: ValidationState,
            ) -> int:
                (output / "unsafe-partial.json").write_text(
                    '{"password":"must-not-survive"}\n',
                    encoding="utf-8",
                )
                nested = output / "nested"
                nested.mkdir()
                (nested / "local-path.txt").write_text("/home/release/private\n", encoding="utf-8")
                (nested / "external-link").symlink_to(external)
                raise TypeError("malformed nested protected evidence")

            with mock.patch.object(
                stable_1_0_rc,
                "_run",
                side_effect=fail_after_partial_output,
            ):
                code, summary_path, report_path = stable_1_0_rc.run(context)

            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            native_files = {path.name for path in summary_path.parent.iterdir()}
            self.assertEqual(1, code)
            self.assertEqual("no-go", summary["decision"])
            self.assertFalse(summary["promotionReady"])
            self.assertTrue(summary["nonRelease"])
            self.assertEqual("invalid-freeze", summary["freeze"]["driftStatus"])
            self.assertEqual("fail", summary["redactionStatus"])
            self.assertEqual(
                {
                    "redaction-report.json",
                    "stable-1.0-rc-go-no-go.md",
                    "stable-1.0-rc-promotion-summary.json",
                },
                native_files,
            )
            self.assertEqual("must remain\n", external.read_text(encoding="utf-8"))
            self.assertTrue(report_path.is_file())

    def test_freeze_content_digest_is_canonical_and_excludes_only_itself(self) -> None:
        value = _freeze()
        reordered = {key: value[key] for key in reversed(value)}

        self.assertEqual(value["contentDigest"], freeze_content_digest(reordered))
        reordered["stableMilestone"] = "changed"
        self.assertNotEqual(value["contentDigest"], freeze_content_digest(reordered))

    def test_valid_freeze_has_no_drift(self) -> None:
        value = _freeze()

        self.assertEqual([], validate_freeze_shape(value))
        self.assertEqual("no-drift", compare_freezes(value, copy.deepcopy(value), [])["status"])

    def test_invalid_nested_catalog_version_cannot_be_promotable(self) -> None:
        for catalog_version in (None, 0, -1, False, "5"):
            with self.subTest(catalog_version=catalog_version):
                value = _freeze()
                value["stableCatalog"]["catalogVersion"] = catalog_version  # type: ignore[index]
                value["contentDigest"] = freeze_content_digest(value)

                errors = validate_freeze_shape(value)
                drift = compare_freezes(None, value, [])

                self.assertTrue(any("catalogVersion" in error for error in errors))
                self.assertEqual("invalid-freeze", drift["status"])

    def test_changed_freeze_is_unapproved_drift(self) -> None:
        previous = _freeze()
        current = copy.deepcopy(previous)
        current["firstPartyApps"][0]["version"] = "284"  # type: ignore[index]
        current["contentDigest"] = freeze_content_digest(current)

        result = compare_freezes(previous, current, [])

        self.assertEqual("unapproved-drift", result["status"])
        self.assertEqual("firstPartyApps", result["changes"][0]["section"])

    def test_changed_production_distribution_is_candidate_drift(self) -> None:
        previous = _freeze()
        current = copy.deepcopy(previous)
        current["candidate"]["productionDistributionDigest"] = "sha256:" + "f" * 64  # type: ignore[index]
        current["contentDigest"] = freeze_content_digest(current)

        result = compare_freezes(previous, current, [])

        self.assertEqual("unapproved-drift", result["status"])
        self.assertTrue(
            any(
                change["section"] == "candidate"
                and change["item"] == "productionDistributionDigest"
                for change in result["changes"]
            )
        )

    def test_authorized_exception_classifies_initial_drift_but_requires_refreeze(self) -> None:
        previous = _freeze()
        current = copy.deepcopy(previous)
        current["firstPartyApps"][0]["version"] = "284"  # type: ignore[index]
        current["contentDigest"] = freeze_content_digest(current)
        before = semantic_digest(previous["firstPartyApps"][0])  # type: ignore[index]
        after = semantic_digest(current["firstPartyApps"][0])  # type: ignore[index]
        records, errors = validate_exception_collection(
            _collection(_exception(before, after)),
            "stable-rc-283",
            "283",
            datetime.now(timezone.utc),
        )

        self.assertEqual([], errors)
        current["acceptedFreezeExceptions"] = records
        current["contentDigest"] = freeze_content_digest(current)
        result = compare_freezes(previous, current, records)
        self.assertEqual("approved-freeze-exception", result["status"])
        self.assertTrue(
            any(
                change["section"] == "acceptedFreezeExceptions"
                for change in result["approvedChanges"]
            )
        )
        self.assertEqual("no-drift", compare_freezes(current, copy.deepcopy(current), [])["status"])

    def test_accepted_exception_audit_history_is_preserved_and_compared(self) -> None:
        previous = _freeze()
        record = _exception("sha256:" + "1" * 64, "sha256:" + "2" * 64)
        previous["acceptedFreezeExceptions"] = [record]
        previous["contentDigest"] = freeze_content_digest(previous)

        preserved = merge_accepted_exception_history(previous, [])
        self.assertEqual([record], preserved)

        for mutation in ("removed", "modified"):
            with self.subTest(mutation=mutation):
                current = copy.deepcopy(previous)
                if mutation == "removed":
                    current["acceptedFreezeExceptions"] = []
                else:
                    current["acceptedFreezeExceptions"][0]["reason"] = "Changed audit reason."  # type: ignore[index]
                current["contentDigest"] = freeze_content_digest(current)

                result = compare_freezes(previous, current, [])

                self.assertEqual("unapproved-drift", result["status"])
                self.assertTrue(
                    any(
                        change["section"] == "acceptedFreezeExceptions"
                        for change in result["unapprovedChanges"]
                    )
                )

    def test_exception_cannot_authorize_platform_api_baseline_drift(self) -> None:
        previous = _freeze()
        current = copy.deepcopy(previous)
        current["platformApi"]["baselineDigest"] = "sha256:" + "3" * 64  # type: ignore[index]
        current["contentDigest"] = freeze_content_digest(current)
        record = _exception(
            semantic_digest(previous["platformApi"]["baselineDigest"]),  # type: ignore[index]
            semantic_digest(current["platformApi"]["baselineDigest"]),  # type: ignore[index]
        )
        record["affectedSection"] = "platformApi"
        record["affectedItem"] = "baselineDigest"

        records, errors = validate_exception_collection(
            _collection(record),
            "stable-rc-283",
            "283",
            datetime.now(timezone.utc),
        )
        direct_result = compare_freezes(previous, current, [record])

        self.assertEqual([], records)
        self.assertTrue(any("non-waivable" in error for error in errors))
        self.assertEqual("invalid-freeze", direct_result["status"])
        self.assertTrue(any("non-waivable" in error for error in direct_result["errors"]))

    def test_exception_cannot_authorize_a_different_item_in_the_same_section(self) -> None:
        previous = _freeze()
        current = copy.deepcopy(previous)
        current["firstPartyApps"][1]["version"] = "284"  # type: ignore[index]
        current["contentDigest"] = freeze_content_digest(current)
        record = _exception(semantic_digest(None), semantic_digest(current["firstPartyApps"][1]))  # type: ignore[index]

        result = compare_freezes(previous, current, [record])

        self.assertEqual("invalid-freeze", result["status"])
        self.assertTrue(any("unmatched" in error for error in result["errors"]))

    def test_exception_without_change_is_invalid(self) -> None:
        value = _freeze()
        record = _exception("sha256:" + "1" * 64, "sha256:" + "2" * 64)

        result = compare_freezes(value, copy.deepcopy(value), [record])

        self.assertEqual("invalid-freeze", result["status"])

    def test_under_authorized_stale_and_non_waivable_exceptions_are_rejected(self) -> None:
        record = _exception("sha256:" + "1" * 64, "sha256:" + "2" * 64)
        record["affectedSection"] = "platformApi"
        record["affectedItem"] = "baselineDigest"
        record["expiresAt"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        value = _collection(record)
        value["authorizationRole"] = "developer"

        _, errors = validate_exception_collection(value, "stable-rc-283", "283", datetime.now(timezone.utc))

        self.assertTrue(any("under-authorized" in error for error in errors))
        self.assertTrue(any("expired" in error for error in errors))
        self.assertTrue(any("non-waivable" in error for error in errors))

    def test_freeze_exception_placeholder_audit_metadata_is_rejected(self) -> None:
        for field in ("issueReference", "owner", "approver"):
            with self.subTest(field=field):
                record = _exception("sha256:" + "1" * 64, "sha256:" + "2" * 64)
                record[field] = "REPLACE_ME"

                accepted, errors = validate_exception_collection(
                    _collection(record),
                    "stable-rc-283",
                    "283",
                    datetime.now(timezone.utc),
                )

                self.assertEqual([], accepted)
                self.assertTrue(any("placeholder" in error for error in errors), errors)

    def test_freeze_exception_collection_enforces_closed_schema(self) -> None:
        for target, field in (("collection", "unexpected"), ("redaction", "note")):
            with self.subTest(target=target):
                value = _collection(
                    _exception("sha256:" + "1" * 64, "sha256:" + "2" * 64)
                )
                if target == "collection":
                    value[field] = "not contracted"
                else:
                    value["redaction"][field] = "not contracted"  # type: ignore[index]

                accepted, errors = validate_exception_collection(
                    value,
                    "stable-rc-283",
                    "283",
                    datetime.now(timezone.utc),
                )

                self.assertEqual([], accepted)
                self.assertTrue(any("unknown field" in error for error in errors), errors)

    def test_stable_surface_addition_is_drift(self) -> None:
        baseline = {"name": "1.0", "capabilities": ["content.fetch"], "endpoints": ["POST /content/fetch"]}
        current = copy.deepcopy(baseline)
        current["capabilities"].append("new.stable")

        self.assertFalse(stable_surface_is_exact(baseline, current))

    def test_experimental_only_change_does_not_change_stable_surface(self) -> None:
        baseline = {"name": "1.0", "capabilities": ["content.fetch"], "endpoints": ["POST /content/fetch"]}
        current_contract = {"stableBaseline": copy.deepcopy(baseline), "capabilities": [{"id": "new.experimental", "stability": "experimental"}]}

        self.assertTrue(stable_surface_is_exact(baseline, current_contract["stableBaseline"]))

    def test_placeholder_production_metadata_is_rejected(self) -> None:
        findings = placeholder_findings({"supportUri": "https://example.invalid", "keyId": "REPLACE_ME"})

        self.assertGreaterEqual(len(findings), 2)


class StableRcArchiveTest(unittest.TestCase):
    def test_configured_input_rejects_a_symlinked_parent_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory).resolve()
            evidence = workspace / "evidence"
            evidence.mkdir()
            (evidence / "policy.json").write_text("{}\n", encoding="utf-8")
            linked = workspace / "linked"
            linked.symlink_to(evidence, target_is_directory=True)
            context = SimpleNamespace(
                workspace_root=workspace,
                manifest=SimpleNamespace(inputs={"stableReadinessPolicy": "linked/policy.json"}),
            )

            with self.assertRaisesRegex(ValueError, "symlink"):
                load_raw_input(context, "stableReadinessPolicy")

    def test_archive_is_reproducible_and_payload_checksums_bind_every_member(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            payload = root / "payload.bin"
            metadata = root / "freeze.json"
            payload.write_bytes(b"production distribution")
            metadata.write_text("{}\n", encoding="utf-8")
            checksums = root / "payload-checksums.txt"
            write_named_checksums(checksums, [("payload/payload.bin", payload), ("metadata/freeze.json", metadata)])
            members = [("payload/payload.bin", payload), ("metadata/freeze.json", metadata), ("payload-checksums.txt", checksums)]
            first = root / "first.tar.gz"
            second = root / "second.tar.gz"

            create_deterministic_archive(first, members)
            create_deterministic_archive(second, reversed(members))

            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual([], verify_deterministic_archive(first))

    def test_production_stable_rc_product_distribution_is_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            files = {
                "inputs/first-party-app-maintenance-policy.json": "{}\n",
                "inputs/first-party-app-beta-readiness.json": "{}\n",
                "build/staged-apps/queue-manager/cryptad-app.properties": (
                    "app.id=queue-manager\n"
                    "app.exec=bin/start-queue.sh\n"
                ),
                "build/staged-apps/queue-manager/bin/start-queue.sh": "#!/bin/sh\nexit 0\n",
                "build/staged-apps/feed-reader/cryptad-app.properties": (
                    "app.id=feed-reader\n"
                    "app.exec=bin/start-feed.sh\n"
                    "app.data.migration.ui-state-v1-v2.command=bin/migrate-feed-data.sh\n"
                ),
                "build/staged-apps/feed-reader/bin/start-feed.sh": "#!/bin/sh\nexit 0\n",
                "build/staged-apps/feed-reader/bin/migrate-feed-data.sh": "#!/bin/sh\nexit 0\n",
                "build/staged-apps/trust-graph/cryptad-app.properties": (
                    "app.id=trust-graph\n"
                    "app.exec=bin/start-trust.bat\n"
                    "app.data.migration.ui-state-v1-v2.command=bin/migrate-preview-data.sh\n"
                ),
                "build/staged-apps/trust-graph/bin/start-trust.bat": "@exit /b 0\n",
                "build/staged-apps/trust-graph/bin/migrate-preview-data.sh": "#!/bin/sh\nexit 0\n",
                "build/app-bundles/queue-manager-283.zip": "bundle bytes\n",
                "build/crypta-app-launcher/bin/crypta-app": "#!/bin/sh\nexit 0\n",
                "catalog/first-party-catalog.properties": "catalog.generatedAt=2026-07-14T00:00:00Z\n",
                "catalog/cryptad-app-catalog.signature": "signature\n",
                "reviews/review-receipts/queue-manager-review-receipt.properties": "reviewed\n",
                "reviews/review-transparency-log.json": "{}\n",
            }
            for relative, contents in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents, encoding="utf-8")
            launcher = root / "build/crypta-app-launcher/bin/crypta-app"
            launcher.chmod(0o755)
            migration_members = {
                "build/staged-apps/feed-reader/bin/migrate-feed-data.sh",
                "build/staged-apps/trust-graph/bin/migrate-preview-data.sh",
            }
            posix_app_launchers = {
                "build/staged-apps/queue-manager/bin/start-queue.sh",
                "build/staged-apps/feed-reader/bin/start-feed.sh",
            }
            staged_commands = {
                *migration_members,
                *posix_app_launchers,
                "build/staged-apps/trust-graph/bin/start-trust.bat",
            }
            for staged_command in staged_commands:
                (root / staged_command).chmod(0o644)
            settings = SimpleNamespace(
                out_dir=root,
                stable_rc_artifact_timestamp="2026-07-14T00:00:00Z",
            )

            first = production_beta_release.create_stable_rc_product_bundle(
                settings,
                "283",
            ).read_bytes()
            for relative, contents in reversed(tuple(files.items())):
                (root / relative).write_text(contents, encoding="utf-8")
            launcher.chmod(0o755)
            for staged_command in staged_commands:
                (root / staged_command).chmod(0o644)
            product_archive = production_beta_release.create_stable_rc_product_bundle(
                settings,
                "283",
            )
            broad_archive = production_beta_release.create_dist_bundle(settings, "283")

            self.assertEqual(first, product_archive.read_bytes())
            for archive in (product_archive, broad_archive):
                with self.subTest(archive=archive.name), tarfile.open(archive, "r:gz") as packaged:
                    members = packaged.getmembers()
                self.assertEqual(sorted(files), [member.name for member in members])
                self.assertTrue(all(member.isfile() for member in members))
                self.assertTrue(
                    all(
                        member.mtime == 0
                        and member.uid == 0
                        and member.gid == 0
                        and member.uname == "root"
                        and member.gname == "root"
                        for member in members
                    )
                )
                modes = {member.name: member.mode for member in members}
                expected_executables = {
                    "build/crypta-app-launcher/bin/crypta-app",
                    *migration_members,
                    *posix_app_launchers,
                }
                self.assertTrue(
                    all(modes[name] == 0o755 for name in expected_executables)
                )
                self.assertTrue(
                    all(
                        mode == 0o644
                        for name, mode in modes.items()
                        if name not in expected_executables
                    )
                )

    def test_production_checksum_must_name_and_bind_the_copied_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            native_root = root / "native"
            distribution = native_root / "dist"
            distribution.mkdir(parents=True)
            source_archive = distribution / "cryptad-production-beta-283.tar.gz"
            source_archive.write_bytes(b"production distribution")
            copied_archive = root / source_archive.name
            copied_archive.write_bytes(source_archive.read_bytes())
            checksums = distribution / "checksums.txt"
            context = SimpleNamespace(workspace_root=root)

            def validate() -> ValidationState:
                state = ValidationState()
                with mock.patch(
                    "cryptad_certification.engines.production_beta_release.scan_tarball",
                    return_value=[],
                ):
                    stable_1_0_rc._validate_production_distribution(  # noqa: SLF001
                        native_root,
                        copied_archive,
                        context,
                        state,
                    )
                return state

            checksums.write_text("", encoding="utf-8")
            self.assertTrue(any("omits required target" in row["summary"] for row in validate().blockers))

            unrelated = distribution / "unrelated.bin"
            unrelated.write_bytes(b"unrelated")
            write_named_checksums(checksums, [(unrelated.name, unrelated)])
            self.assertTrue(any("omits required target" in row["summary"] for row in validate().blockers))

            write_named_checksums(checksums, [(source_archive.name, source_archive)])
            copied_archive.write_bytes(b"modified after copy")
            self.assertTrue(
                any("copied target" in row["summary"] for row in validate().blockers)
            )

            copied_archive.write_bytes(source_archive.read_bytes())
            self.assertEqual([], validate().blockers)

    def test_stable_rc_freezes_the_deterministic_product_distribution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            native_root = root / "native"
            output = root / "stable-output"
            product = native_root / "dist/crypta-stable-1.0-rc-283-product.tar.gz"
            broad = native_root / "dist/crypta-production-beta-283.tar.gz"
            product.parent.mkdir(parents=True)
            output.mkdir()
            product.write_bytes(b"deterministic Stable RC product")
            broad.write_bytes(b"run-specific production evidence archive")

            copied = stable_1_0_rc._copy_production_distribution(  # noqa: SLF001
                native_root,
                {
                    "artifacts": {
                        "distArchive": "dist/crypta-production-beta-283.tar.gz",
                        "stableRcDistribution": (
                            "dist/crypta-stable-1.0-rc-283-product.tar.gz"
                        ),
                    }
                },
                output,
            )

            self.assertEqual(product.name, copied.name)
            self.assertEqual(product.read_bytes(), copied.read_bytes())
            self.assertNotEqual(broad.read_bytes(), copied.read_bytes())

    def test_archive_verifier_rejects_wrong_embedded_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            payload = root / "payload.bin"
            payload.write_bytes(b"candidate")
            checksums = root / "payload-checksums.txt"
            checksums.write_text(f"{'0' * 64}  payload/payload.bin\n", encoding="utf-8")
            archive = root / "candidate.tar.gz"
            create_deterministic_archive(archive, [("payload/payload.bin", payload), ("payload-checksums.txt", checksums)])

            self.assertTrue(any("mismatch" in error for error in verify_deterministic_archive(archive)))

    def test_symlink_sources_are_rejected_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "target.bin"
            target.write_bytes(b"candidate")
            link = root / "linked.bin"
            link.symlink_to(target)

            with self.assertRaisesRegex(ValueError, "unsafe"):
                write_named_checksums(root / "checksums.txt", [("payload/linked.bin", link)])
            with self.assertRaisesRegex(ValueError, "unsafe"):
                create_deterministic_archive(root / "candidate.tar.gz", [("payload/linked.bin", link)])

    def test_forbidden_appledouble_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory).resolve() / "source"
            source.write_text("unsafe", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "forbidden"):
                create_deterministic_archive(
                    Path(directory).resolve() / "candidate.tar.gz",
                    [("metadata/._freeze.json", source)],
                )


class StableRcFixtureInventoryTest(unittest.TestCase):
    def test_every_acceptance_fixture_executes_its_validator(self) -> None:
        root = Path(__file__).resolve().parents[4]
        value = json.loads((root / "tools/release-certification/fixtures/stable-1.0-rc-cases.json").read_text(encoding="utf-8"))

        self.assertEqual("stable-1.0-rc-self-test-cases", value["kind"])
        self.assertEqual(30, len(value["cases"]))
        self.assertEqual(30, len({row["id"] for row in value["cases"]}))
        for row in value["cases"]:
            with self.subTest(case=row["id"]):
                status, details = self._execute_fixture(row)
                self.assertEqual(row["expectedStatus"], status)
                blocker = row["expectedBlocker"]
                if blocker is not None:
                    self.assertIn(blocker, details)

    def _execute_fixture(self, row: dict[str, object]) -> tuple[str, str]:
        validator = row["validator"]
        mutation = str(row["mutation"])
        if validator == "freeze":
            previous = _freeze()
            if mutation in {"allowed-limitation", "limitation-removed"}:
                limitation = {
                    "id": "stable-1.0.local-rc",
                    "title": "Local RC scope",
                    "summary": "Trust and Social remain bounded to local RC operation.",
                    "category": "bounded-scope",
                    "classification": "allowed-for-stable-1.0",
                    "status": "open",
                    "owner": "crypta-core",
                    "boundedBy": "Local node operation only.",
                    "evidenceIds": ["stable-1.0.local-rc-scope"],
                }
                previous_limitations = previous["limitationsAndPolicy"]
                previous_limitations["allowedLimitations"] = [limitation]  # type: ignore[index]
                previous_limitations["allowedLimitationsDigest"] = semantic_digest([limitation])  # type: ignore[index]
                previous_limitations["allowedLimitationCount"] = 1  # type: ignore[index]
                previous["contentDigest"] = freeze_content_digest(previous)
            current = copy.deepcopy(previous)
            if mutation == "platform-baseline":
                current["platformApi"]["baselineDigest"] = "sha256:" + "3" * 64  # type: ignore[index]
            elif mutation == "catalog-digest":
                current["stableCatalog"]["catalogDigest"] = "sha256:" + "4" * 64  # type: ignore[index]
            elif mutation == "app-extra":
                current["firstPartyApps"].append({"appId": "unexpected", "version": "283"})  # type: ignore[union-attr]
            elif mutation == "app-version":
                current["firstPartyApps"][0]["version"] = "284"  # type: ignore[index]
            elif mutation == "app-schema":
                current["firstPartyApps"][0]["appDataSchemaVersion"] = 2  # type: ignore[index]
            elif mutation == "profile-version":
                current["contentFormatProfiles"][0]["version"] = 2  # type: ignore[index]
            elif mutation == "limitation-removed":
                current_limitations = current["limitationsAndPolicy"]
                current_limitations["allowedLimitations"] = []  # type: ignore[index]
                current_limitations["allowedLimitationsDigest"] = semantic_digest([])  # type: ignore[index]
                current_limitations["allowedLimitationCount"] = 0  # type: ignore[index]
            elif mutation == "disallowed-limitation":
                current["limitationsAndPolicy"]["disallowedLimitationCount"] = 1  # type: ignore[index]
            elif mutation == "source-provenance":
                current["candidate"]["sourceCommit"] = "b" * 40  # type: ignore[index]
            current["contentDigest"] = freeze_content_digest(current)
            result = compare_freezes(previous, current, [])
            return str(result["status"]), json.dumps(result, sort_keys=True)
        if validator == "production":
            summary = _production_summary()
            if mutation == "promotion":
                summary["promotionReady"] = False
            elif mutation == "signing":
                summary["signingProfile"] = {"kind": "test", "generatedTestKeys": True, "privateKeyMaterialIncluded": False}
            elif mutation == "stage":
                summary["pipelineStages"]["gradle-full-build"] = {"status": "skip"}  # type: ignore[index]
            elif mutation == "workspace":
                summary["dirtyWorkspace"] = True
            state = ValidationState()
            validate_production_beta(summary, "stable-rc-283", "283", state)
            return ("fail" if state.blockers else "pass"), json.dumps(state.blockers, sort_keys=True)
        if validator == "readiness":
            from cryptad_certification.engines import production_beta_go_no_go_dashboard as dashboard

            issues = dashboard.stable_readiness_issues(_readiness_summary(mutation), True, "stable-rc-283")
            blockers = [issue.id for issue in issues if issue.severity in {"blocker", "critical"}]
            return ("fail" if blockers else "pass"), " ".join(blockers)
        if validator == "api":
            baseline = {"name": "1.0", "capabilities": ["content.fetch"], "endpoints": ["POST /content/fetch"]}
            stable = copy.deepcopy(baseline)
            if mutation == "stable-addition":
                stable["capabilities"].append("new.stable")
            exact = stable_surface_is_exact(baseline, stable)
            return ("pass" if exact else "fail"), "" if exact else "stable-surface"
        if validator == "catalog":
            catalog = _catalog_operations()
            if mutation == "channel":
                catalog["channel"] = "nightly"
            elif mutation == "rotation":
                catalog["keyRotation"] = {"status": "complete", "compromised": True}
            state = ValidationState()
            validate_catalog_operations(catalog, "stable-rc-283", "283", datetime.now(timezone.utc), state)
            return ("fail" if state.blockers else "pass"), json.dumps(state.blockers, sort_keys=True)
        if validator == "exception":
            previous = _freeze()
            current = copy.deepcopy(previous)
            if mutation == "non-waivable":
                current["platformApi"]["baselineDigest"] = "sha256:" + "3" * 64  # type: ignore[index]
                record = _exception(
                    semantic_digest(previous["platformApi"]["baselineDigest"]),  # type: ignore[index]
                    semantic_digest(current["platformApi"]["baselineDigest"]),  # type: ignore[index]
                )
                record["affectedSection"] = "platformApi"
                record["affectedItem"] = "baselineDigest"
            else:
                current["firstPartyApps"][0]["version"] = "284"  # type: ignore[index]
                record = _exception(
                    semantic_digest(previous["firstPartyApps"][0]),  # type: ignore[index]
                    semantic_digest(current["firstPartyApps"][0]),  # type: ignore[index]
                )
            current["contentDigest"] = freeze_content_digest(current)
            if mutation == "stale":
                record["expiresAt"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
            records, errors = validate_exception_collection(
                _collection(record), "stable-rc-283", "283", datetime.now(timezone.utc)
            )
            if errors:
                return "invalid-freeze", " ".join(errors)
            result = compare_freezes(previous, current, records)
            return str(result["status"]), json.dumps(result, sort_keys=True)
        if validator == "redaction":
            candidate = (
                {"supportUri": "https://example.invalid"}
                if mutation == "placeholder"
                else {"privateKey": "not-a-real-private-key"}
            )
            findings = placeholder_findings(candidate) if mutation == "placeholder" else scan_value(candidate)
            return ("fail" if findings else "pass"), "placeholder" if mutation == "placeholder" else "redaction"
        if validator == "freshness":
            generated = (
                (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()
                if mutation == "stale"
                else None
            )
            error = freshness_error(generated, datetime.now(timezone.utc), 30, "release evidence")
            return ("fail" if error else "pass"), str(error or "")
        if validator == "archive":
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                payload = root / "payload.bin"
                payload.write_bytes(b"candidate")
                archive = root / "candidate.tar.gz"
                if mutation == "appledouble":
                    try:
                        create_deterministic_archive(archive, [("metadata/._freeze.json", payload)])
                    except ValueError as exc:
                        return "fail", str(exc)
                    return "pass", ""
                checksums = root / "payload-checksums.txt"
                checksums.write_text(f"{'0' * 64}  payload/payload.bin\n", encoding="utf-8")
                create_deterministic_archive(archive, [("payload/payload.bin", payload), ("payload-checksums.txt", checksums)])
                errors = verify_deterministic_archive(archive)
                return ("fail" if errors else "pass"), " ".join(errors)
        self.fail(f"unsupported Stable RC fixture validator: {validator}")


if __name__ == "__main__":
    unittest.main()
