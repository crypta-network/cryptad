"""Focused offline tests for Stable 1.0 lifecycle certification."""

from __future__ import annotations

import copy
import datetime as dt
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptad_certification.engines.stable_1_0_lifecycle import (
    _descriptor_freshness_errors,
    _history_governance_errors,
    _lifecycle_history_input_errors,
    _publication_plan,
    _validate_authorization,
    _verify_receipt,
)
from cryptad_certification.engines.stable_1_0_lifecycle_core import (
    NORMAL_ORDER,
    STATUSES,
    authenticate_inventory,
    build_descriptor,
    build_ledger,
    canonical_file_digest,
    entry_digest,
    ledger_digest,
    policy_errors,
    semantic_digest,
)
from cryptad_certification.io import read_json
from cryptad_certification.io import write_json
from cryptad_certification.manifest import load_manifest
from cryptad_certification.cli import main as certify_main
from cryptad_certification.redaction import scan_value
from cryptad_certification.schema_validation import validate_schema
from cryptad_certification.engines.stable_1_0_maintenance import (
    _apply_lifecycle_promotion_gate,
    _authenticated_lifecycle_errors,
    _hotfix_lifecycle_authority_errors,
    _lifecycle_input_presence_errors,
    _lifecycle_predecessor_errors,
    _lifecycle_successor_capacity_errors,
    _pending_lifecycle_transition,
    _provenance,
    _public_checksum_payload_paths,
    _validation,
)
from cryptad_certification.engines.stable_1_0_maintenance_core import (
    GaRoot,
    Predecessor,
    receipt_identity,
    successor_baseline_identity,
)
from cryptad_certification.engines.stable_1_0_rc_core import ValidationState
from cryptad_certification.tests.support import workspace_root
from cryptad_certification.tests.test_stable_maintenance import (
    _published_ga_maintenance_context,
)

ROOT = Path(__file__).resolve().parents[2]
POLICY = read_json(ROOT / "stable-1.0-support-lifecycle-policy.json")
DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
COMMIT = "a" * 40
PUBLIC_URI = "https://updates.crypta.network/stable-1.0/support-lifecycle/latest.json"
MAINTENANCE_POINTER_URI = "https://updates.crypta.network/stable-1.0/maintenance/latest.json"


def release(build: int, published: str) -> dict:
    return {
        "releaseId": f"stable-{build}",
        "buildVersion": str(build),
        "tag": f"v{build}",
        "sourceCommit": COMMIT,
        "releaseClass": "stable-ga" if build == 1 else "maintenance",
        "productDigest": DIGEST,
        "publicationReceiptDigest": DIGEST,
        "baselineDigest": DIGEST,
        "publishedAt": published,
        "chainDepth": build - 1,
        "unresolvedHotfixFollowUp": False,
    }


def inventory(rows: list[dict]) -> dict:
    return {
        "inventoryDigest": DIGEST,
        "entries": rows,
    }


class StableLifecyclePolicyTest(unittest.TestCase):
    def test_checked_in_manifest_example_is_unambiguous_and_schema_valid(self) -> None:
        path = ROOT / "manifests/stable-1.0-support-lifecycle.example.json"

        value = read_json(path)
        manifest = load_manifest(path, ROOT.parents[1])
        schema_errors = validate_schema(value, "release-run-v1.schema.json")

        self.assertEqual(schema_errors, [])
        self.assertEqual(manifest.release.profile, "stable-review")
        self.assertEqual(
            manifest.policies["latestMaintenancePointerPublicUri"],
            "https://REPLACE_ME.invalid/stable-1.0/maintenance/latest.json",
        )

    def test_policy_is_closed_and_uses_exact_vocabulary(self) -> None:
        self.assertEqual(
            validate_schema(POLICY, "stable-1.0-support-lifecycle-policy-v1.schema.json"), []
        )
        self.assertEqual(policy_errors(POLICY), [])
        self.assertEqual(POLICY["lifecycleVocabulary"], list(STATUSES))
        self.assertEqual(
            POLICY["descriptor"]["updateKeyIdentityDigest"],
            "sha256:b6386982e7eed893448339eed564fcdc140547266b0dc70978ddfa345f6136d7",
        )

    def test_policy_rejects_competing_transition_order(self) -> None:
        changed = copy.deepcopy(POLICY)
        changed["normalTransitions"][1]["to"] = "deprecated"
        self.assertTrue(policy_errors(changed))

    def test_policy_bounds_immediate_public_observation_age(self) -> None:
        self.assertEqual(
            30,
            POLICY["supportWindows"]["maximumPublicObservationAgeMinutes"],
        )
        for value in (0, 61):
            with self.subTest(value=value):
                changed = copy.deepcopy(POLICY)
                changed["supportWindows"]["maximumPublicObservationAgeMinutes"] = value
                self.assertTrue(policy_errors(changed))
                if value == 0:
                    self.assertTrue(
                        validate_schema(
                            changed,
                            "stable-1.0-support-lifecycle-policy-v1.schema.json",
                        )
                    )

    def test_policy_and_artifact_schemas_bind_runtime_descriptor_capacity(self) -> None:
        maximum_entries = POLICY["descriptor"]["maximumEntries"]
        self.assertEqual(maximum_entries, 256)
        for schema_name in (
            "stable-1.0-support-lifecycle-inventory-v1.schema.json",
            "stable-1.0-support-lifecycle-ledger-v1.schema.json",
            "stable-1.0-support-lifecycle-descriptor-v1.schema.json",
        ):
            with self.subTest(schema=schema_name):
                schema = read_json(ROOT / "schemas" / schema_name)
                self.assertEqual(
                    schema["properties"]["entries"]["maxItems"], maximum_entries
                )
        changed = copy.deepcopy(POLICY)
        changed["descriptor"]["maximumEntries"] = maximum_entries + 1
        self.assertTrue(
            validate_schema(
                changed,
                "stable-1.0-support-lifecycle-policy-v1.schema.json",
            )
        )


class StableLifecycleCommandIntegrationTest(unittest.TestCase):
    def _manifest(
        self,
        root: Path,
        ga_output: Path,
        history_path: Path,
        release_id: str,
    ) -> Path:
        workspace = workspace_root()
        ga_baseline = read_json(ga_output / "stable-1.0-maintenance-baseline.json")
        base_release = ga_baseline["release"]
        generated_at = (
            dt.datetime.now(dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )

        def relative(path: Path) -> str:
            return path.relative_to(workspace).as_posix()

        inputs = {
            name: relative(ga_output / file_name)
            for name, file_name in {
                "stableGaPromotionSummary": "stable-1.0-ga-promotion-summary.json",
                "stableGaValidation": "stable-1.0-ga-validation.json",
                "stableGaAuthorizationSummary": "stable-1.0-ga-authorization-summary.json",
                "stableGaPublicationPlan": "stable-1.0-ga-publication-plan.json",
                "stableGaPublicationReceipt": "stable-1.0-ga-publication-receipt.json",
                "stableGaChecksums": "stable-1.0-ga-checksums.txt",
                "stableGaProvenance": "stable-1.0-ga-provenance.json",
                "stableGaMaintenanceBaseline": "stable-1.0-maintenance-baseline.json",
            }.items()
        }
        inputs.update(
            {
                "predecessorPublicationReceipt": inputs["stableGaPublicationReceipt"],
                "predecessorBaseline": inputs["stableGaMaintenanceBaseline"],
                "stableMaintenanceHistory": relative(history_path),
                "stableLifecyclePolicy": relative(
                    workspace
                    / "tools/release-certification/stable-1.0-support-lifecycle-policy.json"
                ),
            }
        )
        manifest = {
            "schemaVersion": 1,
            "release": {
                "id": release_id,
                "version": base_release["buildVersion"],
                "profile": "stable-review",
            },
            "output": {"root": relative(root / "lifecycle-output"), "reset": True},
            "requirements": {},
            "inputs": inputs,
            "policies": {
                "expectedPredecessorBuild": base_release["buildVersion"],
                "expectedPredecessorProductDigest": base_release["rcProductDigest"],
                "expectedPredecessorReleaseId": base_release["releaseId"],
                "lifecycleDescriptorPublicUri": "https://93.184.216.34/stable-1.0/support-lifecycle/latest.json",
                "latestMaintenancePointerPublicUri": "https://93.184.216.34/stable-1.0/maintenance/latest.json",
                "metadata": {"lifecycleEvaluationAt": generated_at},
                "publicationIntent": "prepare-explicit-protected-publication",
                "releaseClass": "maintenance",
            },
            "execution": {},
            "commands": {"stable-lifecycle": {"mode": "evaluate"}},
        }
        path = root / f"{release_id}.json"
        write_json(path, manifest)
        return path

    def test_ga_only_unified_command_writes_release_scoped_side_effect_free_artifacts(self) -> None:
        workspace = workspace_root()
        with tempfile.TemporaryDirectory(dir=workspace) as directory:
            root = Path(directory)
            _, ga_output = _published_ga_maintenance_context(root)
            history_path = root / "history.json"
            write_json(
                history_path,
                {
                    "schemaVersion": 1,
                    "kind": "stable-1.0-maintenance-authenticated-history",
                    "stableMilestone": "1.0",
                    "links": [],
                    "redaction": {"status": "pass", "findingCount": 0, "findings": []},
                },
            )
            manifest_path = self._manifest(
                root, ga_output, history_path, "stable-lifecycle-ga-only-test"
            )
            preliminary_code = certify_main(
                [
                    "stable-lifecycle",
                    "--workspace-root",
                    str(workspace),
                    "--manifest",
                    str(manifest_path),
                ]
            )
            self.assertEqual(preliminary_code, 1)
            component = (
                root
                / "lifecycle-output/stable-lifecycle-ga-only-test/stable-lifecycle"
            )
            native = component / "artifacts/legacy"
            inventory = read_json(
                native / "stable-1.0-support-lifecycle-inventory.json"
            )
            tip = inventory["entries"][-1]
            manifest = read_json(manifest_path)
            generated_at = manifest["policies"]["metadata"]["lifecycleEvaluationAt"]
            key_digest = POLICY["descriptor"]["updateKeyIdentityDigest"]
            proof = {
                "schemaVersion": 1,
                "kind": "stable-1.0-support-lifecycle-genesis-proof",
                "generatedAt": generated_at,
                "observedAt": generated_at,
                "stableMilestone": "1.0",
                "observationStatus": "absent",
                "transportStatus": 404,
                "publicRequestUri": manifest["policies"]["lifecycleDescriptorPublicUri"],
                "updateKeyIdentityDigest": key_digest,
                "updateKeyScope": f"{key_digest}/support-lifecycle/0",
                "updateKeyDocName": "support-lifecycle",
                "inventoryDigest": inventory["inventoryDigest"],
                "gaRootDigest": inventory["gaRootDigest"],
                "latestPointerDigest": inventory["latestPointerDigest"],
                "chainDepth": inventory["chainDepth"],
                "releaseId": tip["releaseId"],
                "buildVersion": tip["buildVersion"],
                "baselineDigest": tip["baselineDigest"],
                "publicationReceiptDigest": tip["publicationReceiptDigest"],
                "provider": {
                    "sourceCommit": "c" * 40,
                    "artifactDigest": DIGEST,
                    "signerWorkflow": "crypta-network/cryptad/.github/workflows/stable-1.0-support-lifecycle-publication-backend-producer.yml",
                },
                "redaction": {"status": "pass", "findingCount": 0, "findings": []},
            }
            proof["proofDigest"] = semantic_digest(proof)
            proof_path = root / "genesis-proof.json"
            write_json(proof_path, proof)
            manifest["inputs"]["stableLifecycleGenesisProof"] = (
                proof_path.relative_to(workspace).as_posix()
            )
            write_json(manifest_path, manifest)
            code = certify_main(
                [
                    "stable-lifecycle",
                    "--workspace-root",
                    str(workspace),
                    "--manifest",
                    str(manifest_path),
                ]
            )
            self.assertEqual(
                code,
                0,
                read_json(native / "stable-1.0-support-lifecycle-summary.json"),
            )
            envelope = read_json(component / "summary.json")
            self.assertEqual(envelope["schemaVersion"], 2)
            self.assertEqual(envelope["result"]["status"], "pass")
            expected = {
                "stable-1.0-support-lifecycle-inventory.json",
                "stable-1.0-support-lifecycle-ledger.json",
                "stable-1.0-support-lifecycle-transition-set.json",
                "stable-1.0-support-lifecycle-descriptor.json",
                "stable-1.0-support-lifecycle-summary.json",
                "stable-1.0-support-lifecycle-report.md",
                "stable-1.0-support-lifecycle-provenance.json",
                "stable-1.0-support-lifecycle-genesis-proof.json",
                "stable-1.0-support-lifecycle-checksums.txt",
                "redaction-report.json",
            }
            self.assertTrue(expected.issubset({path.name for path in native.iterdir()}))
            provenance = read_json(
                native / "stable-1.0-support-lifecycle-provenance.json"
            )
            self.assertFalse(provenance["sideEffectsPerformed"])
            summary = read_json(native / "stable-1.0-support-lifecycle-summary.json")
            self.assertEqual(
                validate_schema(
                    summary, "stable-1.0-support-lifecycle-summary-v1.schema.json"
                ),
                [],
            )
            self.assertFalse(summary["promotionReady"])
            self.assertEqual(summary["publicationState"], "not-published")

            manifest = read_json(manifest_path)
            manifest["commands"]["stable-lifecycle"]["mode"] = "prepare-transition"
            write_json(manifest_path, manifest)
            self.assertEqual(
                certify_main(
                    [
                        "stable-lifecycle",
                        "--workspace-root",
                        str(workspace),
                        "--manifest",
                        str(manifest_path),
                    ]
                ),
                0,
            )
            authorization = read_json(
                native / "stable-1.0-support-lifecycle-authorization-summary.json"
            )
            generated = dt.datetime.fromisoformat(
                authorization["generatedAt"].replace("Z", "+00:00")
            )
            authorization.update(
                {
                    "authorizationId": "stable-lifecycle-test-approval",
                    "expiresAt": (generated + dt.timedelta(minutes=1))
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "decision": "approved",
                }
            )
            authorization_path = root / "authorization.json"
            write_json(authorization_path, authorization)
            relative_path = authorization_path.relative_to(workspace).as_posix()
            manifest["inputs"]["stableLifecycleAuthorization"] = relative_path
            self.assertEqual(relative_path, manifest["inputs"]["stableLifecycleAuthorization"])
            manifest["commands"]["stable-lifecycle"]["mode"] = "validate-authorization"
            write_json(manifest_path, manifest)
            self.assertEqual(
                certify_main(
                    [
                        "stable-lifecycle",
                        "--workspace-root",
                        str(workspace),
                        "--manifest",
                        str(manifest_path),
                    ]
                ),
                0,
            )
            validated = read_json(native / "stable-1.0-support-lifecycle-summary.json")
            self.assertTrue(validated["authorizationReady"])
            self.assertFalse(validated["promotionReady"])
            descriptor = read_json(
                native / "stable-1.0-support-lifecycle-descriptor.json"
            )
            plan = read_json(native / "stable-1.0-support-lifecycle-publication-plan.json")
            receipt = {
                "schemaVersion": 1,
                "kind": "stable-1.0-support-lifecycle-publication-receipt",
                "generatedAt": descriptor["generatedAt"],
                "stableMilestone": "1.0",
                "descriptorEdition": descriptor["descriptorEdition"],
                "descriptorDigest": descriptor["descriptorDigest"],
                "descriptorBytesDigest": canonical_file_digest(descriptor),
                "ledgerDigest": descriptor["ledgerDigest"],
                "updateKeyIdentityDigest": descriptor["updateKeyIdentityDigest"],
                "updateKeyScope": descriptor["updateKeyScope"],
                "updateKeyDocName": descriptor["updateKeyDocName"],
                "publicRequestUri": plan["publicRequestUri"],
                "previousDescriptorEdition": descriptor["previousDescriptorEdition"],
                "previousDescriptorDigest": descriptor["previousDescriptorDigest"],
                "publicationPlanDigest": plan["publicationPlanDigest"],
                "authorizationDigest": canonical_file_digest(authorization),
                "operation": "verified-existing",
                "publicationState": "publication-complete",
                "verificationStatus": "verified",
                "conflict": False,
                "redaction": {"status": "pass", "findingCount": 0, "findings": []},
            }
            receipt_path = root / "receipt.json"
            write_json(receipt_path, receipt)
            manifest["inputs"]["stableLifecyclePublicationReceipt"] = (
                receipt_path.relative_to(workspace).as_posix()
            )
            manifest["commands"]["stable-lifecycle"]["mode"] = "verify-publication"
            write_json(manifest_path, manifest)
            verification_time = generated + dt.timedelta(minutes=2)

            class VerificationDateTime(dt.datetime):
                @classmethod
                def now(cls, timezone: dt.tzinfo | None = None) -> dt.datetime:
                    return (
                        verification_time.astimezone(timezone)
                        if timezone is not None
                        else verification_time.replace(tzinfo=None)
                    )

            with patch(
                "cryptad_certification.engines.stable_1_0_lifecycle.dt.datetime",
                VerificationDateTime,
            ):
                self.assertEqual(
                    certify_main(
                        [
                            "stable-lifecycle",
                            "--workspace-root",
                            str(workspace),
                            "--manifest",
                            str(manifest_path),
                        ]
                    ),
                    0,
                    read_json(
                        native / "stable-1.0-support-lifecycle-summary.json"
                    ),
                )
            verified = read_json(native / "stable-1.0-support-lifecycle-summary.json")
            self.assertTrue(verified["promotionReady"])
            self.assertEqual(verified["publicationState"], "publication-verified")

            write_json(
                history_path,
                {
                    "schemaVersion": 1,
                    "kind": "stable-1.0-maintenance-authenticated-history",
                    "stableMilestone": "1.0",
                    "links": [{"tampered": True}],
                    "redaction": {"status": "pass", "findingCount": 0, "findings": []},
                },
            )
            bad_manifest = self._manifest(
                root, ga_output, history_path, "stable-lifecycle-tampered-chain-test"
            )
            code = certify_main(
                [
                    "stable-lifecycle",
                    "--workspace-root",
                    str(workspace),
                    "--manifest",
                    str(bad_manifest),
                ]
            )
            self.assertEqual(code, 1)
            failed = read_json(
                root
                / "lifecycle-output/stable-lifecycle-tampered-chain-test/stable-lifecycle/artifacts/legacy/stable-1.0-support-lifecycle-summary.json"
            )
            self.assertEqual(failed["status"], "fail")
            self.assertFalse(failed["promotionReady"])
            self.assertEqual(
                validate_schema(
                    failed, "stable-1.0-support-lifecycle-summary-v1.schema.json"
                ),
                [],
            )

    def test_manifest_build_must_equal_authenticated_inventory_tip(self) -> None:
        workspace = workspace_root()
        with tempfile.TemporaryDirectory(dir=workspace) as directory:
            root = Path(directory)
            _, ga_output = _published_ga_maintenance_context(root)
            history_path = root / "history.json"
            write_json(
                history_path,
                {
                    "schemaVersion": 1,
                    "kind": "stable-1.0-maintenance-authenticated-history",
                    "stableMilestone": "1.0",
                    "links": [],
                    "redaction": {
                        "status": "pass",
                        "findingCount": 0,
                        "findings": [],
                    },
                },
            )
            release_id = "stable-lifecycle-mislabeled-build-test"
            manifest_path = self._manifest(
                root, ga_output, history_path, release_id
            )
            manifest = read_json(manifest_path)
            authenticated_build = int(manifest["release"]["version"])
            manifest["release"]["version"] = str(authenticated_build + 1)
            manifest["policies"]["expectedPredecessorBuild"] = str(
                authenticated_build + 1
            )
            write_json(manifest_path, manifest)

            code = certify_main(
                [
                    "stable-lifecycle",
                    "--workspace-root",
                    str(workspace),
                    "--manifest",
                    str(manifest_path),
                ]
            )

            self.assertEqual(code, 1)
            summary = read_json(
                root
                / f"lifecycle-output/{release_id}/stable-lifecycle/artifacts/legacy/"
                "stable-1.0-support-lifecycle-summary.json"
            )
            self.assertTrue(
                any(
                    blocker["summary"]
                    == (
                        "manifest build version does not equal the authenticated "
                        "release inventory tip."
                    )
                    for blocker in summary["blockers"]
                ),
                summary,
            )


class StableLifecycleLedgerTest(unittest.TestCase):
    def test_genesis_requires_proof_and_successor_requires_exact_pair(self) -> None:
        genesis_proof = {"proofDigest": DIGEST}
        previous_ledger = {"ledgerDigest": DIGEST}
        previous_descriptor = {"descriptorDigest": OTHER_DIGEST}

        self.assertTrue(
            any(
                "absence proof" in error
                for error in _lifecycle_history_input_errors(None, None, None)
            )
        )
        self.assertEqual(
            _lifecycle_history_input_errors(None, None, genesis_proof), []
        )
        self.assertTrue(
            any(
                "supplied together" in error
                for error in _lifecycle_history_input_errors(
                    previous_ledger, None, None
                )
            )
        )
        self.assertEqual(
            _lifecycle_history_input_errors(
                previous_ledger, previous_descriptor, None
            ),
            [],
        )
        self.assertTrue(
            _lifecycle_history_input_errors(
                previous_ledger, previous_descriptor, genesis_proof
            )
        )

    @staticmethod
    def _revocation_request(effective_at: str, replacement_build: str) -> dict:
        return {
            "transitions": [
                {
                    "targetBuild": "1",
                    "toStatus": "revoked",
                    "effectiveAt": effective_at,
                    "reasonCode": "unsafe-build",
                    "advisoryId": "CRYPTA-ADV-2026-001",
                    "severity": "critical",
                    "affectedBuilds": ["1"],
                    "securityEvidenceIds": ["security-drill-2026-001"],
                    "publicationTargetDigest": OTHER_DIGEST,
                    "replacementBuild": replacement_build,
                    "recoveryGuidance": None,
                }
            ]
        }

    def test_ga_only_has_exactly_one_current_stable(self) -> None:
        ledger, proposed, errors = build_ledger(
            inventory([release(1, "2026-01-01T00:00:00Z")]),
            POLICY,
            DIGEST,
            "2026-01-02T00:00:00Z",
            None,
            None,
        )
        self.assertEqual(errors, [])
        self.assertEqual(proposed, [])
        self.assertEqual(ledger["entries"][0]["lifecycleStatus"], "current-stable")
        self.assertEqual(ledger["ledgerDigest"], ledger_digest(ledger))

    def test_inventory_and_descriptor_reject_more_than_policy_entry_bound(self) -> None:
        maximum_entries = POLICY["descriptor"]["maximumEntries"]
        published = inventory(
            [
                release(build, "2026-01-01T00:00:00Z")
                for build in range(1, maximum_entries + 2)
            ]
        )

        ledger, _, ledger_errors = build_ledger(
            published,
            POLICY,
            DIGEST,
            "2026-01-02T00:00:00Z",
            None,
            None,
        )
        _, descriptor_errors = build_descriptor(
            ledger,
            POLICY,
            "2026-01-02T00:00:00Z",
            None,
            POLICY["descriptor"]["updateKeyIdentityDigest"],
        )

        self.assertIn(
            "published inventory exceeds the lifecycle descriptor entry bound",
            ledger_errors,
        )
        self.assertIn(
            "lifecycle descriptor exceeds its policy entry bound",
            descriptor_errors,
        )

    def test_current_tip_can_be_revoked_with_recovery_only_guidance(self) -> None:
        published = inventory([release(1, "2026-01-01T00:00:00Z")])
        prior, _, errors = build_ledger(
            published,
            POLICY,
            DIGEST,
            "2026-01-02T00:00:00Z",
            None,
            None,
        )
        self.assertEqual(errors, [])
        request = {
            "transitions": [
                {
                    "targetBuild": "1",
                    "toStatus": "revoked",
                    "effectiveAt": "2026-01-03T00:00:00Z",
                    "reasonCode": "unsafe-current-build",
                    "advisoryId": "CRYPTA-ADV-2026-001",
                    "severity": "critical",
                    "affectedBuilds": ["1"],
                    "securityEvidenceIds": ["security-drill-2026-001"],
                    "publicationTargetDigest": OTHER_DIGEST,
                    "replacementBuild": None,
                    "recoveryGuidance": "Restore the prior verified package from offline media.",
                }
            ]
        }

        ledger, proposed, errors = build_ledger(
            published,
            POLICY,
            DIGEST,
            "2026-01-03T00:00:00Z",
            prior,
            request,
        )
        descriptor, descriptor_errors = build_descriptor(
            ledger,
            POLICY,
            "2026-01-03T00:00:00Z",
            None,
            POLICY["descriptor"]["updateKeyIdentityDigest"],
        )

        self.assertEqual(errors, [])
        self.assertEqual(descriptor_errors, [])
        self.assertEqual(len(proposed), 1)
        self.assertEqual(proposed[0]["fromStatus"], "current-stable")
        self.assertEqual(proposed[0]["toStatus"], "revoked")
        self.assertIsNone(proposed[0]["replacementBuild"])
        self.assertEqual(
            proposed[0]["recoveryGuidance"],
            "Restore the prior verified package from offline media.",
        )
        self.assertEqual(ledger["entries"][0]["lifecycleStatus"], "revoked")
        self.assertIsNone(ledger["entries"][0]["replacementBuild"])
        self.assertEqual(
            ledger["entries"][0]["recoveryGuidance"],
            "Restore the prior verified package from offline media.",
        )
        self.assertIsNone(descriptor["currentStableBuild"])
        self.assertIsNone(descriptor["recommendedBuild"])
        self.assertEqual(
            descriptor["entries"][0]["recoveryGuidance"],
            "Restore the prior verified package from offline media.",
        )
        self.assertEqual(
            validate_schema(
                ledger, "stable-1.0-support-lifecycle-ledger-v1.schema.json"
            ),
            [],
        )
        self.assertEqual(
            validate_schema(
                descriptor,
                "stable-1.0-support-lifecycle-descriptor-v1.schema.json",
            ),
            [],
        )

        refreshed, refreshed_transitions, refreshed_errors = build_ledger(
            published,
            POLICY,
            DIGEST,
            "2026-01-04T00:00:00Z",
            ledger,
            None,
        )
        refreshed_descriptor, refreshed_descriptor_errors = build_descriptor(
            refreshed,
            POLICY,
            "2026-01-04T00:00:00Z",
            descriptor,
            POLICY["descriptor"]["updateKeyIdentityDigest"],
        )
        self.assertEqual(refreshed_errors, [])
        self.assertEqual(refreshed_descriptor_errors, [])
        self.assertEqual(refreshed_transitions, [])
        self.assertEqual(refreshed["entries"][0]["lifecycleStatus"], "revoked")
        self.assertIsNone(refreshed_descriptor["currentStableBuild"])
        self.assertEqual(
            refreshed_descriptor["entries"][0]["recoveryGuidance"],
            "Restore the prior verified package from offline media.",
        )

    def test_first_edition_recovery_only_tip_revocation_clears_older_replacements(
        self,
    ) -> None:
        published = inventory(
            [
                release(1, "2024-01-01T00:00:00Z"),
                release(2, "2025-01-01T00:00:00Z"),
                release(3, "2026-01-01T00:00:00Z"),
            ]
        )
        guidance = "Restore a verified package from offline recovery media."
        request = {
            "transitions": [
                {
                    "targetBuild": "3",
                    "toStatus": "revoked",
                    "effectiveAt": "2026-01-03T00:00:00Z",
                    "reasonCode": "unsafe-current-build",
                    "advisoryId": "CRYPTA-ADV-2026-001",
                    "severity": "critical",
                    "affectedBuilds": ["3"],
                    "securityEvidenceIds": ["security-drill-2026-001"],
                    "publicationTargetDigest": OTHER_DIGEST,
                    "replacementBuild": None,
                    "recoveryGuidance": guidance,
                }
            ]
        }

        ledger, _, errors = build_ledger(
            published,
            POLICY,
            DIGEST,
            "2026-01-03T00:00:00Z",
            None,
            request,
        )
        descriptor, descriptor_errors = build_descriptor(
            ledger,
            POLICY,
            "2026-01-03T00:00:00Z",
            None,
            POLICY["descriptor"]["updateKeyIdentityDigest"],
        )

        self.assertEqual(errors, [])
        self.assertEqual(descriptor_errors, [])
        self.assertTrue(
            all(row["replacementBuild"] is None for row in ledger["entries"])
        )
        self.assertTrue(
            all(row["recoveryGuidance"] == guidance for row in ledger["entries"])
        )
        self.assertTrue(
            all(row["replacementBuild"] != "3" for row in descriptor["entries"])
        )

    def test_successor_recovery_only_tip_revocation_replaces_stale_guidance_pointer(
        self,
    ) -> None:
        published = inventory(
            [
                release(1, "2025-01-01T00:00:00Z"),
                release(2, "2026-01-01T00:00:00Z"),
            ]
        )
        prior, _, errors = build_ledger(
            published,
            POLICY,
            DIGEST,
            "2026-01-02T00:00:00Z",
            None,
            None,
        )
        self.assertEqual(errors, [])
        self.assertEqual(prior["entries"][0]["replacementBuild"], "2")
        previous_entry_digest = prior["entries"][0]["entryDigest"]
        guidance = "Restore a verified package from offline recovery media."
        request = {
            "transitions": [
                {
                    "targetBuild": "2",
                    "toStatus": "revoked",
                    "effectiveAt": "2026-01-03T00:00:00Z",
                    "reasonCode": "unsafe-current-build",
                    "advisoryId": "CRYPTA-ADV-2026-001",
                    "severity": "critical",
                    "affectedBuilds": ["2"],
                    "securityEvidenceIds": ["security-drill-2026-001"],
                    "publicationTargetDigest": OTHER_DIGEST,
                    "replacementBuild": None,
                    "recoveryGuidance": guidance,
                }
            ]
        }

        ledger, _, errors = build_ledger(
            published,
            POLICY,
            DIGEST,
            "2026-01-03T00:00:00Z",
            prior,
            request,
        )
        descriptor, descriptor_errors = build_descriptor(
            ledger,
            POLICY,
            "2026-01-03T00:00:00Z",
            None,
            POLICY["descriptor"]["updateKeyIdentityDigest"],
        )

        older = ledger["entries"][0]
        self.assertEqual(errors, [])
        self.assertEqual(descriptor_errors, [])
        self.assertEqual(older["previousEntryDigest"], previous_entry_digest)
        self.assertIsNone(older["replacementBuild"])
        self.assertEqual(older["recoveryGuidance"], guidance)
        self.assertTrue(
            all(row["replacementBuild"] != "2" for row in descriptor["entries"])
        )

        unsafe = copy.deepcopy(ledger)
        unsafe["entries"][0]["replacementBuild"] = "2"
        unsafe["entries"][0]["entryDigest"] = entry_digest(unsafe["entries"][0])
        unsafe["ledgerDigest"] = ledger_digest(unsafe)
        _, unsafe_descriptor_errors = build_descriptor(
            unsafe,
            POLICY,
            "2026-01-03T00:00:00Z",
            None,
            POLICY["descriptor"]["updateKeyIdentityDigest"],
        )
        self.assertIn(
            "lifecycle descriptor would recommend a revoked replacement build",
            unsafe_descriptor_errors,
        )

    def test_first_safe_successor_replaces_recovery_only_projection(self) -> None:
        initial_inventory = inventory(
            [
                release(1, "2025-01-01T00:00:00Z"),
                release(2, "2026-01-01T00:00:00Z"),
            ]
        )
        prior, _, prior_errors = build_ledger(
            initial_inventory,
            POLICY,
            DIGEST,
            "2026-01-02T00:00:00Z",
            None,
            None,
        )
        guidance = "Restore a verified package from offline recovery media."
        request = {
            "transitions": [
                {
                    "targetBuild": "2",
                    "toStatus": "revoked",
                    "effectiveAt": "2026-01-03T00:00:00Z",
                    "reasonCode": "unsafe-current-build",
                    "advisoryId": "CRYPTA-ADV-2026-001",
                    "severity": "critical",
                    "affectedBuilds": ["2"],
                    "securityEvidenceIds": ["security-drill-2026-001"],
                    "publicationTargetDigest": OTHER_DIGEST,
                    "replacementBuild": None,
                    "recoveryGuidance": guidance,
                }
            ]
        }
        revoked, revocation_transitions, revocation_errors = build_ledger(
            initial_inventory,
            POLICY,
            DIGEST,
            "2026-01-03T00:00:00Z",
            prior,
            request,
        )
        revoked_entry_digest = revoked["entries"][1]["entryDigest"]
        original_revocation = copy.deepcopy(revocation_transitions[-1])

        successor_inventory = inventory(
            [
                release(1, "2025-01-01T00:00:00Z"),
                release(2, "2026-01-01T00:00:00Z"),
                release(3, "2026-01-04T00:00:00Z"),
            ]
        )
        successor, proposed, successor_errors = build_ledger(
            successor_inventory,
            POLICY,
            DIGEST,
            "2026-01-05T00:00:00Z",
            revoked,
            None,
        )
        descriptor, descriptor_errors = build_descriptor(
            successor,
            POLICY,
            "2026-01-05T00:00:00Z",
            None,
            POLICY["descriptor"]["updateKeyIdentityDigest"],
        )

        self.assertEqual(prior_errors, [])
        self.assertEqual(revocation_errors, [])
        self.assertEqual(successor_errors, [])
        self.assertEqual(descriptor_errors, [])
        self.assertEqual(proposed, [])
        self.assertEqual(descriptor["currentStableBuild"], "3")
        self.assertEqual(descriptor["recommendedBuild"], "3")
        self.assertTrue(
            all(row["recoveryGuidance"] is None for row in successor["entries"])
        )
        self.assertEqual(successor["entries"][0]["replacementBuild"], "3")
        self.assertEqual(successor["entries"][1]["replacementBuild"], "3")
        self.assertIsNone(successor["entries"][2]["replacementBuild"])
        self.assertEqual(
            successor["entries"][1]["previousEntryDigest"], revoked_entry_digest
        )
        self.assertEqual(successor["transitions"][-1], original_revocation)
        self.assertIsNone(successor["transitions"][-1]["replacementBuild"])
        self.assertEqual(
            successor["transitions"][-1]["recoveryGuidance"], guidance
        )
        self.assertTrue(
            all(
                row["replacementBuild"] != "2"
                for row in descriptor["entries"]
            )
        )

    def test_successor_repoints_revocation_replacement_after_security_support_ends(
        self,
    ) -> None:
        initial_inventory = inventory(
            [
                release(1, "2025-01-01T00:00:00Z"),
                release(2, "2026-01-01T00:00:00Z"),
            ]
        )
        prior, _, prior_errors = build_ledger(
            initial_inventory,
            POLICY,
            DIGEST,
            "2026-01-02T00:00:00Z",
            None,
            None,
        )
        prior_descriptor, prior_descriptor_errors = build_descriptor(
            prior,
            POLICY,
            "2026-01-02T00:00:00Z",
            None,
            POLICY["descriptor"]["updateKeyIdentityDigest"],
        )
        request = {
            "transitions": [
                {
                    "targetBuild": "1",
                    "toStatus": "revoked",
                    "effectiveAt": "2026-01-03T00:00:00Z",
                    "reasonCode": "unsafe-build",
                    "advisoryId": "CRYPTA-ADV-2026-001",
                    "severity": "critical",
                    "affectedBuilds": ["1"],
                    "securityEvidenceIds": ["security-drill-2026-001"],
                    "publicationTargetDigest": OTHER_DIGEST,
                    "replacementBuild": "2",
                    "recoveryGuidance": None,
                }
            ]
        }
        revoked, revocation_transitions, revocation_errors = build_ledger(
            initial_inventory,
            POLICY,
            DIGEST,
            "2026-01-03T00:00:00Z",
            prior,
            request,
        )
        revoked_descriptor, revoked_descriptor_errors = build_descriptor(
            revoked,
            POLICY,
            "2026-01-03T00:00:00Z",
            prior_descriptor,
            POLICY["descriptor"]["updateKeyIdentityDigest"],
        )

        successor_inventory = inventory(
            [
                release(1, "2025-01-01T00:00:00Z"),
                release(2, "2026-01-01T00:00:00Z"),
                release(3, "2027-01-01T00:00:00Z"),
            ]
        )
        refreshed, proposed, refreshed_errors = build_ledger(
            successor_inventory,
            POLICY,
            DIGEST,
            "2027-01-02T00:00:00Z",
            revoked,
            None,
        )
        refreshed_descriptor, refreshed_descriptor_errors = build_descriptor(
            refreshed,
            POLICY,
            "2027-01-02T00:00:00Z",
            revoked_descriptor,
            POLICY["descriptor"]["updateKeyIdentityDigest"],
        )

        self.assertEqual(prior_errors, [])
        self.assertEqual(prior_descriptor_errors, [])
        self.assertEqual(revocation_errors, [])
        self.assertEqual(revoked_descriptor_errors, [])
        self.assertEqual(refreshed_errors, [])
        self.assertEqual(refreshed_descriptor_errors, [])
        self.assertEqual(
            [row["toStatus"] for row in proposed],
            ["supported-maintenance", "security-fixes-only", "deprecated"],
        )
        self.assertEqual(refreshed["entries"][0]["lifecycleStatus"], "revoked")
        self.assertEqual(refreshed["entries"][0]["replacementBuild"], "3")
        self.assertEqual(refreshed["entries"][1]["lifecycleStatus"], "deprecated")
        self.assertEqual(refreshed["entries"][2]["lifecycleStatus"], "current-stable")
        self.assertEqual(refreshed_descriptor["entries"][0]["replacementBuild"], "3")
        self.assertEqual(revocation_transitions[-1]["replacementBuild"], "2")
        self.assertEqual(
            refreshed["transitions"][: len(revocation_transitions)],
            revocation_transitions,
        )

    def test_no_current_stable_is_rejected_without_tip_revocation(self) -> None:
        ledger, _, errors = build_ledger(
            inventory([release(1, "2025-01-01T00:00:00Z")]),
            POLICY,
            DIGEST,
            "2025-01-02T00:00:00Z",
            None,
            None,
        )
        self.assertEqual(errors, [])
        ledger["entries"][0]["lifecycleStatus"] = "end-of-support"
        ledger["entries"][0]["entryDigest"] = entry_digest(ledger["entries"][0])
        ledger["ledgerDigest"] = ledger_digest(ledger)

        descriptor, descriptor_errors = build_descriptor(
            ledger,
            POLICY,
            "2025-01-02T00:00:00Z",
            None,
            POLICY["descriptor"]["updateKeyIdentityDigest"],
        )

        self.assertTrue(
            any("lacks current-stable" in error for error in descriptor_errors)
        )
        self.assertIsNone(descriptor["currentStableBuild"])

    def test_tip_revocation_rejects_an_end_of_support_replacement(self) -> None:
        published = inventory(
            [
                release(1, "2024-01-01T00:00:00Z"),
                release(2, "2026-01-01T00:00:00Z"),
            ]
        )
        prior, _, errors = build_ledger(
            published,
            POLICY,
            DIGEST,
            "2026-01-02T00:00:00Z",
            None,
            None,
        )
        self.assertEqual(errors, [])
        request = {
            "transitions": [
                {
                    "targetBuild": "2",
                    "toStatus": "revoked",
                    "effectiveAt": "2026-01-03T00:00:00Z",
                    "reasonCode": "unsafe-current-build",
                    "advisoryId": "CRYPTA-ADV-2026-001",
                    "severity": "critical",
                    "affectedBuilds": ["2"],
                    "securityEvidenceIds": ["security-drill-2026-001"],
                    "publicationTargetDigest": OTHER_DIGEST,
                    "replacementBuild": "1",
                    "recoveryGuidance": None,
                }
            ]
        }

        _, _, errors = build_ledger(
            published,
            POLICY,
            DIGEST,
            "2026-01-03T00:00:00Z",
            prior,
            request,
        )

        self.assertTrue(any("safe recovery fields" in error for error in errors))

    def test_tip_revocation_can_recommend_a_security_supported_replacement(self) -> None:
        published = inventory(
            [
                release(1, "2025-12-01T00:00:00Z"),
                release(2, "2026-01-01T00:00:00Z"),
            ]
        )
        prior, _, errors = build_ledger(
            published,
            POLICY,
            DIGEST,
            "2026-01-02T00:00:00Z",
            None,
            None,
        )
        self.assertEqual(errors, [])
        request = {
            "transitions": [
                {
                    "targetBuild": "2",
                    "toStatus": "revoked",
                    "effectiveAt": "2026-01-03T00:00:00Z",
                    "reasonCode": "unsafe-current-build",
                    "advisoryId": "CRYPTA-ADV-2026-001",
                    "severity": "critical",
                    "affectedBuilds": ["2"],
                    "securityEvidenceIds": ["security-drill-2026-001"],
                    "publicationTargetDigest": OTHER_DIGEST,
                    "replacementBuild": "1",
                    "recoveryGuidance": None,
                }
            ]
        }

        ledger, _, errors = build_ledger(
            published,
            POLICY,
            DIGEST,
            "2026-01-03T00:00:00Z",
            prior,
            request,
        )
        descriptor, descriptor_errors = build_descriptor(
            ledger,
            POLICY,
            "2026-01-03T00:00:00Z",
            None,
            POLICY["descriptor"]["updateKeyIdentityDigest"],
        )

        self.assertEqual(errors, [])
        self.assertEqual(descriptor_errors, [])
        self.assertIsNone(descriptor["currentStableBuild"])
        self.assertEqual(descriptor["recommendedBuild"], "1")
        self.assertIsNone(ledger["entries"][0]["replacementBuild"])
        self.assertTrue(
            all(row["replacementBuild"] != "2" for row in ledger["entries"])
        )

        ambiguous = copy.deepcopy(request)
        ambiguous["transitions"][0]["recoveryGuidance"] = (
            "Restore a verified package from offline recovery media."
        )
        _, _, ambiguous_errors = build_ledger(
            published,
            POLICY,
            DIGEST,
            "2026-01-03T00:00:00Z",
            prior,
            ambiguous,
        )
        self.assertTrue(
            any("safe recovery fields" in error for error in ambiguous_errors)
        )
        self.assertIn(
            "lifecycle ledger mixes replacement and recovery-only guidance",
            ambiguous_errors,
        )

    def test_recovery_guidance_schema_matches_runtime_safe_text_boundaries(self) -> None:
        request = {
            "schemaVersion": 1,
            "kind": "stable-1.0-support-lifecycle-transition-request",
            "generatedAt": "2026-01-03T00:00:00Z",
            "stableMilestone": "1.0",
            "transitions": [
                {
                    "targetBuild": "1",
                    "toStatus": "revoked",
                    "effectiveAt": "2026-01-03T00:00:00Z",
                    "reasonCode": "unsafe-current-build",
                    "advisoryId": "CRYPTA-ADV-2026-001",
                    "severity": "critical",
                    "affectedBuilds": ["1"],
                    "securityEvidenceIds": ["security-drill-2026-001"],
                    "publicationTargetDigest": OTHER_DIGEST,
                    "replacementBuild": None,
                    "recoveryGuidance": "x" * 256,
                }
            ],
            "redaction": {"status": "pass", "findingCount": 0, "findings": []},
        }

        self.assertEqual(
            validate_schema(
                request,
                "stable-1.0-support-lifecycle-transition-request-v1.schema.json",
            ),
            [],
        )
        invalid_guidance = {
            "supplementary-emoji": "Recover safely \U0001f6e1",
            "isolated-surrogate": "Recover safely \ud800",
            "unicode-format": "Recover\u200e safely",
            "c0-control": "unsafe\ntext",
            "c1-control": "unsafe\u0085text",
            "java-utf16-overflow": "x" * 257,
        }
        for name, value in invalid_guidance.items():
            with self.subTest(name=name):
                request["transitions"][0]["recoveryGuidance"] = value
                self.assertTrue(
                    validate_schema(
                        request,
                        "stable-1.0-support-lifecycle-transition-request-v1.schema.json",
                    )
                )

    def test_recovery_guidance_producer_and_redaction_reject_runtime_unsafe_text(self) -> None:
        request = {
            "transitions": [
                {
                    "targetBuild": "1",
                    "toStatus": "revoked",
                    "effectiveAt": "2026-01-03T00:00:00Z",
                    "reasonCode": "unsafe-current-build",
                    "advisoryId": "CRYPTA-ADV-2026-001",
                    "severity": "critical",
                    "affectedBuilds": ["1"],
                    "securityEvidenceIds": ["security-drill-2026-001"],
                    "publicationTargetDigest": OTHER_DIGEST,
                    "replacementBuild": None,
                    "recoveryGuidance": "Recover\u200e safely",
                }
            ]
        }

        ledger, proposed, errors = build_ledger(
            inventory([release(1, "2026-01-01T00:00:00Z")]),
            POLICY,
            DIGEST,
            "2026-01-03T00:00:00Z",
            None,
            request,
        )
        finding_categories = {
            finding["category"]
            for finding in scan_value({"recoveryGuidance": "Recover\u200e safely"})
        }

        self.assertTrue(any("safe-text contract" in error for error in errors))
        self.assertEqual(proposed, [])
        self.assertIsNone(ledger["entries"][0]["recoveryGuidance"])
        self.assertIn("unsafe-recovery-guidance", finding_categories)
        self.assertNotIn(
            "unsafe-recovery-guidance",
            {
                finding["category"]
                for finding in scan_value({"recoveryGuidance": "x" * 256})
            },
        )

    def test_genesis_bootstrap_uses_successor_and_policy_status_clocks(self) -> None:
        scenarios = (
            (
                "supported-maintenance",
                "2026-01-01T00:00:00Z",
                "2026-01-10T00:00:00Z",
                "2026-01-11T00:00:00Z",
                "successor",
            ),
            (
                "security-fixes-only",
                "2025-01-01T00:00:00Z",
                "2025-02-01T00:00:00Z",
                "2025-07-01T00:00:00Z",
                "fullSupportUntil",
            ),
            (
                "deprecated",
                "2024-10-01T00:00:00Z",
                "2024-11-01T00:00:00Z",
                "2025-11-01T00:00:00Z",
                "deprecationEffectiveAt",
            ),
            (
                "end-of-support",
                "2024-01-01T00:00:00Z",
                "2025-06-01T00:00:00Z",
                "2025-07-01T00:00:00Z",
                "successor",
            ),
        )
        for status, published_at, successor_at, evaluated_at, expected_field in scenarios:
            with self.subTest(status=status):
                ledger, proposed, errors = build_ledger(
                    inventory(
                        [release(1, published_at), release(2, successor_at)]
                    ),
                    POLICY,
                    DIGEST,
                    evaluated_at,
                    None,
                    None,
                )

                entry = ledger["entries"][0]
                expected = (
                    successor_at
                    if expected_field == "successor"
                    else entry[expected_field]
                )
                self.assertEqual(errors, [])
                self.assertEqual(proposed, [])
                self.assertEqual(entry["lifecycleStatus"], status)
                self.assertEqual(entry["statusEffectiveAt"], expected)
                self.assertNotEqual(entry["statusEffectiveAt"], published_at)

    def test_supported_successor_is_recommended_without_required_replacement(self) -> None:
        genesis, _, genesis_errors = build_ledger(
            inventory([release(1, "2026-01-01T00:00:00Z")]),
            POLICY,
            DIGEST,
            "2026-01-02T00:00:00Z",
            None,
            None,
        )
        published = inventory(
            [
                release(1, "2026-01-01T00:00:00Z"),
                release(2, "2026-01-10T00:00:00Z"),
            ]
        )

        ledger, proposed, ledger_errors = build_ledger(
            published,
            POLICY,
            DIGEST,
            "2026-01-11T00:00:00Z",
            genesis,
            None,
        )
        descriptor, descriptor_errors = build_descriptor(
            ledger,
            POLICY,
            "2026-01-11T00:00:00Z",
            None,
            POLICY["descriptor"]["updateKeyIdentityDigest"],
        )

        self.assertEqual(genesis_errors, [])
        self.assertEqual(ledger_errors, [])
        self.assertEqual(descriptor_errors, [])
        self.assertEqual(ledger["entries"][0]["lifecycleStatus"], "supported-maintenance")
        self.assertIsNone(ledger["entries"][0]["replacementBuild"])
        self.assertEqual(
            [(row["toStatus"], row["replacementBuild"]) for row in proposed],
            [("supported-maintenance", None)],
        )
        self.assertEqual(descriptor["recommendedBuild"], "2")
        self.assertIsNone(descriptor["entries"][0]["replacementBuild"])

    def test_successor_and_overdue_windows_append_every_adjacent_transition(self) -> None:
        first_inventory = inventory([release(1, "2024-01-01T00:00:00Z")])
        previous, _, errors = build_ledger(
            first_inventory, POLICY, DIGEST, "2024-01-02T00:00:00Z", None, None
        )
        self.assertEqual(errors, [])
        next_inventory = inventory(
            [release(1, "2024-01-01T00:00:00Z"), release(2, "2026-01-01T00:00:00Z")]
        )
        ledger, proposed, errors = build_ledger(
            next_inventory, POLICY, DIGEST, "2026-01-02T00:00:00Z", previous, None
        )
        self.assertEqual(errors, [])
        self.assertEqual(
            [(row["fromStatus"], row["toStatus"]) for row in proposed],
            list(zip(NORMAL_ORDER, NORMAL_ORDER[1:])),
        )
        effective = [row["effectiveAt"] for row in proposed]
        self.assertEqual(effective, sorted(effective))
        self.assertEqual(ledger["entries"][0]["lifecycleStatus"], "end-of-support")
        self.assertEqual(ledger["entries"][1]["lifecycleStatus"], "current-stable")

    def test_explicit_normal_jump_and_backward_transition_fail(self) -> None:
        prior, _, _ = build_ledger(
            inventory([release(1, "2025-01-01T00:00:00Z")]),
            POLICY,
            DIGEST,
            "2025-01-02T00:00:00Z",
            None,
            None,
        )
        # Simulate a superseded, supported build without changing immutable identity.
        prior["entries"][0]["lifecycleStatus"] = "supported-maintenance"
        prior["entries"][0]["entryDigest"] = entry_digest(prior["entries"][0])
        prior["ledgerDigest"] = ledger_digest(prior)
        request = {
            "transitions": [
                {
                    "targetBuild": "1",
                    "toStatus": "end-of-support",
                    "effectiveAt": "2025-01-03T00:00:00Z",
                    "reasonCode": "test",
                    "advisoryId": None,
                    "replacementBuild": None,
                    "recoveryGuidance": None,
                }
            ]
        }
        _, _, errors = build_ledger(
            inventory([release(1, "2025-01-01T00:00:00Z")]),
            POLICY,
            DIGEST,
            "2025-01-03T00:00:00Z",
            prior,
            request,
        )
        self.assertTrue(any("not adjacent" in error for error in errors))

    def test_revocation_requires_advisory_and_is_terminal(self) -> None:
        prior, _, _ = build_ledger(
            inventory([release(1, "2026-01-01T00:00:00Z")]),
            POLICY,
            DIGEST,
            "2026-01-02T00:00:00Z",
            None,
            None,
        )
        bad_request = {
            "transitions": [
                {
                    "targetBuild": "1",
                    "toStatus": "revoked",
                    "effectiveAt": "2026-01-03T00:00:00Z",
                    "reasonCode": "unsafe-build",
                    "advisoryId": None,
                    "replacementBuild": None,
                    "recoveryGuidance": None,
                }
            ]
        }
        _, _, errors = build_ledger(
            inventory([release(1, "2026-01-01T00:00:00Z")]),
            POLICY,
            DIGEST,
            "2026-01-03T00:00:00Z",
            prior,
            bad_request,
        )
        self.assertTrue(any("lacks advisory" in error for error in errors))

    def test_newly_inventoried_revocation_emits_security_transition_and_role(self) -> None:
        published = inventory(
            [
                release(1, "2026-01-01T00:00:00Z"),
                release(2, "2026-01-03T00:00:00Z"),
            ]
        )

        ledger, proposed, errors = build_ledger(
            published,
            POLICY,
            DIGEST,
            "2026-01-04T00:00:00Z",
            None,
            self._revocation_request("2026-01-04T00:00:00Z", "2"),
        )
        descriptor, descriptor_errors = build_descriptor(
            ledger,
            POLICY,
            "2026-01-04T00:00:00Z",
            None,
            POLICY["descriptor"]["updateKeyIdentityDigest"],
        )
        transition_set = {
            "transitionRequestDigest": semantic_digest(
                [row["authorizationRequestDigest"] for row in proposed]
            ),
            "transitions": proposed,
        }
        authorization, valid, authorization_errors = _validate_authorization(
            None,
            POLICY,
            descriptor,
            ledger,
            transition_set,
            "https://93.184.216.34/support-lifecycle/1",
            "https://93.184.216.34/stable-1.0/maintenance/latest.json",
            None,
            dt.datetime(2026, 1, 4, tzinfo=dt.timezone.utc),
        )

        self.assertEqual(errors, [])
        self.assertEqual(descriptor_errors, [])
        self.assertEqual(
            [(row["fromStatus"], row["toStatus"]) for row in proposed],
            [("supported-maintenance", "revoked")],
        )
        self.assertEqual(ledger["entries"][0]["lifecycleStatus"], "revoked")
        self.assertEqual(ledger["entries"][0]["transitionSequence"], 1)
        self.assertFalse(valid)
        self.assertEqual(authorization_errors, [])
        self.assertEqual(
            authorization["role"], "stable-lifecycle-security-manager"
        )

    def test_revoked_build_is_carried_forward_after_successor_publication(self) -> None:
        genesis, _, errors = build_ledger(
            inventory([release(1, "2026-01-01T00:00:00Z")]),
            POLICY,
            DIGEST,
            "2026-01-02T00:00:00Z",
            None,
            None,
        )
        self.assertEqual(errors, [])
        predecessor_inventory = inventory(
            [
                release(1, "2026-01-01T00:00:00Z"),
                release(2, "2026-01-03T00:00:00Z"),
            ]
        )
        predecessor, _, errors = build_ledger(
            predecessor_inventory,
            POLICY,
            DIGEST,
            "2026-01-03T00:00:00Z",
            genesis,
            None,
        )
        self.assertEqual(errors, [])
        revoked, _, errors = build_ledger(
            predecessor_inventory,
            POLICY,
            DIGEST,
            "2026-01-04T00:00:00Z",
            predecessor,
            self._revocation_request("2026-01-04T00:00:00Z", "2"),
        )
        self.assertEqual(errors, [])
        revoked_descriptor, errors = build_descriptor(
            revoked,
            POLICY,
            "2026-01-04T00:00:00Z",
            None,
            POLICY["descriptor"]["updateKeyIdentityDigest"],
        )
        self.assertEqual(errors, [])

        refreshed, proposed, errors = build_ledger(
            inventory(
                [
                    release(1, "2026-01-01T00:00:00Z"),
                    release(2, "2026-01-03T00:00:00Z"),
                    release(3, "2026-01-05T00:00:00Z"),
                ]
            ),
            POLICY,
            DIGEST,
            "2026-01-06T00:00:00Z",
            revoked,
            None,
        )
        refreshed_descriptor, descriptor_errors = build_descriptor(
            refreshed,
            POLICY,
            "2026-01-06T00:00:00Z",
            revoked_descriptor,
            POLICY["descriptor"]["updateKeyIdentityDigest"],
        )

        self.assertEqual(errors, [])
        self.assertEqual(descriptor_errors, [])
        self.assertEqual(
            validate_schema(
                refreshed_descriptor,
                "stable-1.0-support-lifecycle-descriptor-v1.schema.json",
            ),
            [],
        )
        self.assertEqual(
            [(row["targetBuild"], row["toStatus"]) for row in proposed],
            [("2", "supported-maintenance")],
        )
        prior_revocation = revoked["entries"][0]
        carried_revocation = refreshed["entries"][0]
        for field in (
            "lifecycleStatus",
            "statusEffectiveAt",
            "securityRevocationEffectiveAt",
            "replacementBuild",
            "recoveryGuidance",
            "advisoryIds",
            "reasonCodes",
            "transitionSequence",
        ):
            self.assertEqual(carried_revocation[field], prior_revocation[field], field)
        self.assertEqual(
            refreshed_descriptor["entries"][0], revoked_descriptor["entries"][0]
        )

    def test_explicit_normal_transition_cannot_precede_its_policy_deadline(self) -> None:
        genesis, _, errors = build_ledger(
            inventory([release(1, "2026-01-01T00:00:00Z")]),
            POLICY,
            DIGEST,
            "2026-01-02T00:00:00Z",
            None,
            None,
        )
        self.assertEqual(errors, [])
        published = inventory(
            [
                release(1, "2026-01-01T00:00:00Z"),
                release(2, "2026-01-10T00:00:00Z"),
            ]
        )
        prior, _, errors = build_ledger(
            published,
            POLICY,
            DIGEST,
            "2026-01-10T00:00:00Z",
            genesis,
            None,
        )
        self.assertEqual(errors, [])
        request = {
            "transitions": [
                {
                    "targetBuild": "1",
                    "toStatus": "security-fixes-only",
                    "effectiveAt": "2026-01-11T00:00:00Z",
                    "reasonCode": "policy-window-transition",
                    "advisoryId": None,
                    "severity": None,
                    "affectedBuilds": [],
                    "securityEvidenceIds": [],
                    "publicationTargetDigest": None,
                    "replacementBuild": "2",
                    "recoveryGuidance": None,
                }
            ]
        }

        ledger, proposed, errors = build_ledger(
            published,
            POLICY,
            DIGEST,
            "2026-01-12T00:00:00Z",
            prior,
            request,
        )

        self.assertTrue(any("precedes its policy deadline" in error for error in errors))
        self.assertEqual(proposed, [])
        self.assertEqual(ledger["entries"][0]["lifecycleStatus"], "supported-maintenance")

        at_deadline = copy.deepcopy(request)
        at_deadline["transitions"][0]["effectiveAt"] = "2026-06-30T00:00:00Z"
        ledger, proposed, errors = build_ledger(
            published,
            POLICY,
            DIGEST,
            "2026-06-30T00:00:00Z",
            prior,
            at_deadline,
        )
        self.assertEqual(errors, [])
        self.assertEqual(
            [(row["targetBuild"], row["toStatus"]) for row in proposed],
            [("1", "security-fixes-only")],
        )
        self.assertEqual(ledger["entries"][0]["lifecycleStatus"], "security-fixes-only")

    def test_explicit_transition_cannot_predate_prior_status_effective_time(self) -> None:
        genesis, _, errors = build_ledger(
            inventory([release(1, "2026-01-01T00:00:00Z")]),
            POLICY,
            DIGEST,
            "2026-01-02T00:00:00Z",
            None,
            None,
        )
        self.assertEqual(errors, [])
        published = inventory(
            [
                release(1, "2026-01-01T00:00:00Z"),
                release(2, "2026-01-10T00:00:00Z"),
            ]
        )
        prior, _, errors = build_ledger(
            published,
            POLICY,
            DIGEST,
            "2026-01-10T00:00:00Z",
            genesis,
            None,
        )
        self.assertEqual(errors, [])

        ledger, proposed, errors = build_ledger(
            published,
            POLICY,
            DIGEST,
            "2026-01-12T00:00:00Z",
            prior,
            self._revocation_request("2026-01-05T00:00:00Z", "2"),
        )

        self.assertTrue(any("predates its prior status" in error for error in errors))
        self.assertEqual(proposed, [])
        self.assertEqual(ledger["entries"][0]["lifecycleStatus"], "supported-maintenance")

    def test_previous_ledger_omission_and_digest_tamper_fail(self) -> None:
        prior, _, _ = build_ledger(
            inventory([release(1, "2026-01-01T00:00:00Z")]),
            POLICY,
            DIGEST,
            "2026-01-02T00:00:00Z",
            None,
            None,
        )
        prior["entries"][0]["productDigest"] = OTHER_DIGEST
        _, _, errors = build_ledger(
            inventory([release(1, "2026-01-01T00:00:00Z")]),
            POLICY,
            DIGEST,
            "2026-01-03T00:00:00Z",
            prior,
            None,
        )
        self.assertTrue(any("digest" in error or "rewritten" in error for error in errors))

    def test_previous_ledger_rejects_duplicate_build_and_invalid_transition_targets(self) -> None:
        genesis, _, _ = build_ledger(
            inventory([release(1, "2025-01-01T00:00:00Z")]),
            POLICY,
            DIGEST,
            "2025-01-02T00:00:00Z",
            None,
            None,
        )
        prior, _, _ = build_ledger(
            inventory(
                [
                    release(1, "2025-01-01T00:00:00Z"),
                    release(2, "2026-01-01T00:00:00Z"),
                ]
            ),
            POLICY,
            DIGEST,
            "2026-01-02T00:00:00Z",
            genesis,
            None,
        )
        duplicate = copy.deepcopy(prior["entries"][0])
        prior["entries"].append(duplicate)
        prior["transitions"][0]["targetBuild"] = "999"
        prior["transitions"][0]["transitionSequence"] = 2
        prior["transitions"][0]["transitionDigest"] = semantic_digest(
            {
                key: value
                for key, value in prior["transitions"][0].items()
                if key not in {"transitionDigest", "resultingLedgerDigest"}
            }
        )
        prior["ledgerDigest"] = ledger_digest(prior)
        _, _, errors = build_ledger(
            inventory(
                [
                    release(1, "2025-01-01T00:00:00Z"),
                    release(2, "2026-01-01T00:00:00Z"),
                ]
            ),
            POLICY,
            DIGEST,
            "2026-01-03T00:00:00Z",
            prior,
            None,
        )
        self.assertTrue(any("more than once" in error for error in errors))
        self.assertTrue(any("outside the prior inventory" in error for error in errors))
        self.assertTrue(any("sequence" in error for error in errors))

    def test_revocation_requires_every_protected_security_field(self) -> None:
        prior, _, errors = build_ledger(
            inventory(
                [
                    release(1, "2026-01-01T00:00:00Z"),
                    release(2, "2026-01-02T00:00:00Z"),
                ]
            ),
            POLICY,
            DIGEST,
            "2026-01-03T00:00:00Z",
            None,
            None,
        )
        self.assertEqual(errors, [])
        request = {
            "transitions": [
                {
                    "targetBuild": "1",
                    "toStatus": "revoked",
                    "effectiveAt": "2026-01-04T00:00:00Z",
                    "reasonCode": "unsafe-build",
                    "advisoryId": "CRYPTA-ADV-2026-001",
                    "severity": "critical",
                    "affectedBuilds": ["1"],
                    "securityEvidenceIds": ["security-drill-2026-001"],
                    "publicationTargetDigest": OTHER_DIGEST,
                    "replacementBuild": "2",
                    "recoveryGuidance": None,
                }
            ]
        }
        ledger, proposed, errors = build_ledger(
            inventory(
                [
                    release(1, "2026-01-01T00:00:00Z"),
                    release(2, "2026-01-02T00:00:00Z"),
                ]
            ),
            POLICY,
            DIGEST,
            "2026-01-04T00:00:00Z",
            prior,
            request,
        )
        self.assertEqual(errors, [])
        self.assertEqual(ledger["entries"][0]["lifecycleStatus"], "revoked")
        self.assertEqual(proposed[0]["severity"], "critical")
        self.assertEqual(proposed[0]["affectedBuilds"], ["1"])
        missing = copy.deepcopy(request)
        missing["transitions"][0]["securityEvidenceIds"] = []
        _, _, errors = build_ledger(
            inventory(
                [
                    release(1, "2026-01-01T00:00:00Z"),
                    release(2, "2026-01-02T00:00:00Z"),
                ]
            ),
            POLICY,
            DIGEST,
            "2026-01-04T00:00:00Z",
            prior,
            missing,
        )
        self.assertTrue(any("security-evidence" in error for error in errors))


class StableLifecycleAuthenticatedInventoryTest(unittest.TestCase):
    def _chain(self) -> tuple[GaRoot, Predecessor, dict, dict, dict, dict]:
        ga_baseline_digest = "sha256:" + "1" * 64
        ga_receipt_digest = "sha256:" + "2" * 64
        ga = GaRoot(
            baseline={"securityBaseline": {"digest": "sha256:" + "3" * 64}},
            baseline_digest=ga_baseline_digest,
            receipt={"generatedAt": "2026-01-01T00:00:00Z"},
            receipt_digest=ga_receipt_digest,
            release_id="stable-1",
            build_version="1",
            source_commit="1" * 40,
            product_digest="sha256:" + "4" * 64,
            tag="v1",
            root_identity_digest="sha256:" + "5" * 64,
        )
        receipt = {
            "schemaVersion": 1,
            "kind": "stable-1.0-maintenance-publication-receipt",
            "releaseId": "stable-2",
            "buildVersion": "2",
            "releaseClass": "maintenance",
            "sourceCommit": "2" * 40,
            "productDigest": "sha256:" + "6" * 64,
            "publicationState": "publication-complete",
            "finalVerificationStatus": "pass",
            "generatedAt": "2026-02-01T00:00:00Z",
            "tag": {"name": "v2"},
        }
        baseline = {
            "schemaVersion": 2,
            "kind": "stable-1.0-maintenance-successor-baseline",
            "generatedAt": "2026-02-01T00:00:00Z",
            "stableMilestone": "1.0",
            "status": "active",
            "previousBaselineDigest": ga_baseline_digest,
            "lineage": {"chainDepth": 1, "history": []},
            "publication": {"receiptIdentityDigest": receipt_identity(receipt)},
            "releaseTrain": {
                "validationDigest": "sha256:" + "9" * 64,
                "requiredEvidenceId": "stable-maintenance.backport-release-train",
                "candidateCommit": "2" * 40,
                "predecessorCommit": "1" * 40,
                "unresolvedObligationsCarried": False,
            },
            "release": {
                "releaseId": "stable-2",
                "buildVersion": "2",
                "releaseClass": "maintenance",
                "sourceCommit": "2" * 40,
                "productDigest": "sha256:" + "6" * 64,
                "tag": "v2",
            },
        }
        identity = successor_baseline_identity(baseline)
        baseline["lineage"]["history"] = [
            {"baselineIdentityDigest": ga.root_identity_digest},
            {"baselineIdentityDigest": identity},
        ]
        baseline_digest = canonical_file_digest(baseline)
        receipt["successorBaselineDigest"] = baseline_digest
        receipt_digest = canonical_file_digest(receipt)
        lineage_digest = "sha256:" + "7" * 64
        pointer_digest = "sha256:" + "8" * 64
        predecessor = Predecessor(
            baseline=baseline,
            baseline_digest=baseline_digest,
            receipt=receipt,
            receipt_digest=receipt_digest,
            release_id="stable-2",
            build_version="2",
            source_commit="2" * 40,
            product_digest="sha256:" + "6" * 64,
            tag="v2",
            chain_depth=1,
            previous_lineage_digest=lineage_digest,
            lineage_history=baseline["lineage"]["history"],
            outstanding_follow_up=None,
            latest_pointer_digest=pointer_digest,
        )
        history = {
            "kind": "stable-1.0-maintenance-authenticated-history",
            "stableMilestone": "1.0",
            "links": [
                {
                    "successorBaseline": baseline,
                    "publicationReceipt": receipt,
                    "baselineDigest": baseline_digest,
                    "publicationReceiptDigest": receipt_digest,
                }
            ],
        }
        latest = {
            "releaseId": "stable-2",
            "buildVersion": "2",
            "baselineDigest": baseline_digest,
            "publicationReceiptDigest": receipt_digest,
            "lineageDigest": lineage_digest,
            "backportReleaseTrainDigest": baseline["releaseTrain"][
                "validationDigest"
            ],
            "status": "active",
        }
        return ga, predecessor, history, latest, baseline, receipt

    def test_exact_authenticated_chain_derives_ordered_inventory_and_rejects_fork(self) -> None:
        ga, predecessor, history, latest, baseline, receipt = self._chain()
        result = authenticate_inventory(
            ga,
            predecessor,
            ga.receipt,
            history,
            baseline,
            receipt,
            latest,
            "2026-02-02T00:00:00Z",
            POLICY["descriptor"]["maximumEntries"],
        )
        self.assertEqual(result.errors, [])
        self.assertEqual(
            [row["buildVersion"] for row in result.value["entries"]], ["1", "2"]
        )
        over_capacity = authenticate_inventory(
            ga,
            predecessor,
            ga.receipt,
            history,
            baseline,
            receipt,
            latest,
            "2026-02-02T00:00:00Z",
            1,
        )
        self.assertIn(
            "published inventory exceeds the lifecycle descriptor entry bound",
            over_capacity.errors,
        )
        fork = copy.deepcopy(history)
        fork["links"][0]["successorBaseline"]["previousBaselineDigest"] = OTHER_DIGEST
        rejected = authenticate_inventory(
            ga,
            predecessor,
            ga.receipt,
            fork,
            baseline,
            receipt,
            latest,
            "2026-02-02T00:00:00Z",
            POLICY["descriptor"]["maximumEntries"],
        )
        self.assertTrue(rejected.errors)

        substituted_train = copy.deepcopy(latest)
        substituted_train["backportReleaseTrainDigest"] = OTHER_DIGEST
        rejected_train = authenticate_inventory(
            ga,
            predecessor,
            ga.receipt,
            history,
            baseline,
            receipt,
            substituted_train,
            "2026-02-02T00:00:00Z",
            POLICY["descriptor"]["maximumEntries"],
        )
        self.assertIn(
            "latest published pointer is stale or does not select the history tip",
            rejected_train.errors,
        )


class StableLifecycleDescriptorAndPublicationTest(unittest.TestCase):
    def _descriptor(self) -> tuple[dict, dict]:
        ledger, _, errors = build_ledger(
            inventory([release(1, "2026-07-20T00:00:00Z")]),
            POLICY,
            DIGEST,
            "2026-07-21T00:00:00Z",
            None,
            None,
        )
        self.assertEqual(errors, [])
        descriptor, errors = build_descriptor(
            ledger,
            POLICY,
            "2026-07-21T00:00:00Z",
            None,
            POLICY["descriptor"]["updateKeyIdentityDigest"],
        )
        self.assertEqual(errors, [])
        return ledger, descriptor

    def test_descriptor_scope_staleness_and_schema(self) -> None:
        _, descriptor = self._descriptor()
        self.assertEqual(descriptor["descriptorEdition"], 1)
        self.assertEqual(descriptor["updateKeyDocName"], "support-lifecycle")
        self.assertEqual(descriptor["staleAt"], "2026-07-28T00:00:00Z")
        self.assertEqual(
            validate_schema(
                descriptor, "stable-1.0-support-lifecycle-descriptor-v1.schema.json"
            ),
            [],
        )

    def test_descriptor_rejects_future_effective_entry_status(self) -> None:
        ledger, descriptor = self._descriptor()
        ledger["entries"][0]["statusEffectiveAt"] = "2026-07-22T00:00:00Z"

        _, errors = build_descriptor(
            ledger,
            POLICY,
            descriptor["effectiveAt"],
            None,
            POLICY["descriptor"]["updateKeyIdentityDigest"],
        )

        self.assertIn(
            "lifecycle descriptor entry status is future-effective at descriptor activation",
            errors,
        )

    def test_descriptor_rejects_runtime_unsafe_guidance_projections(self) -> None:
        published = inventory(
            [
                release(1, "2024-01-01T00:00:00Z"),
                release(2, "2026-07-20T00:00:00Z"),
            ]
        )
        ledger, _, ledger_errors = build_ledger(
            published,
            POLICY,
            DIGEST,
            "2026-07-21T00:00:00Z",
            None,
            None,
        )
        self.assertEqual(ledger_errors, [])
        self.assertEqual(ledger["entries"][0]["lifecycleStatus"], "end-of-support")

        unsafe_replacements = {
            "missing": (0, "999"),
            "self": (0, "1"),
            "not-security-supported": (1, "1"),
        }
        for name, (entry_index, replacement) in unsafe_replacements.items():
            with self.subTest(name=name):
                unsafe = copy.deepcopy(ledger)
                unsafe["entries"][entry_index]["replacementBuild"] = replacement
                _, errors = build_descriptor(
                    unsafe,
                    POLICY,
                    "2026-07-21T00:00:00Z",
                    None,
                    POLICY["descriptor"]["updateKeyIdentityDigest"],
                )
                self.assertIn(
                    "lifecycle descriptor recommends a missing, self-referential, "
                    "or non-security-supported replacement build",
                    errors,
                )

        recovery_only = copy.deepcopy(ledger)
        recovery_only["entries"][0]["replacementBuild"] = None
        recovery_only["entries"][0]["recoveryGuidance"] = (
            "Restore a verified package from offline recovery media."
        )
        _, recovery_errors = build_descriptor(
            recovery_only,
            POLICY,
            "2026-07-21T00:00:00Z",
            None,
            POLICY["descriptor"]["updateKeyIdentityDigest"],
        )
        self.assertIn(
            "lifecycle descriptor carries recovery-only guidance while current-stable exists",
            recovery_errors,
        )

    def test_descriptor_edition_and_previous_digest_advance(self) -> None:
        ledger, first = self._descriptor()
        second, errors = build_descriptor(
            ledger,
            POLICY,
            "2026-07-22T00:00:00Z",
            first,
            POLICY["descriptor"]["updateKeyIdentityDigest"],
        )
        self.assertEqual(errors, [])
        self.assertEqual(second["descriptorEdition"], 2)
        self.assertEqual(second["previousDescriptorDigest"], first["descriptorDigest"])

    def test_successor_generation_time_must_advance_and_descriptor_must_be_fresh(self) -> None:
        ledger, first = self._descriptor()

        successor, errors = build_descriptor(
            ledger,
            POLICY,
            first["generatedAt"],
            first,
            POLICY["descriptor"]["updateKeyIdentityDigest"],
        )

        self.assertEqual(successor["descriptorEdition"], 2)
        self.assertTrue(any("did not advance" in error for error in errors))
        self.assertEqual(
            _descriptor_freshness_errors(
                first, dt.datetime(2026, 7, 27, tzinfo=dt.timezone.utc)
            ),
            [],
        )
        self.assertTrue(
            any(
                "already stale" in error
                for error in _descriptor_freshness_errors(
                    first, dt.datetime(2026, 7, 28, tzinfo=dt.timezone.utc)
                )
            )
        )

    def test_shared_runtime_fixture_is_exact_build_descriptor_output(self) -> None:
        expected = read_json(
            ROOT / "fixtures/stable-lifecycle/runtime-descriptor-v1.json"
        )
        ledger = {
            "ledgerDigest": expected["ledgerDigest"],
            "inventoryDigest": expected["inventoryDigest"],
            "entries": expected["entries"],
        }
        actual, errors = build_descriptor(
            ledger,
            POLICY,
            expected["generatedAt"],
            None,
            POLICY["descriptor"]["updateKeyIdentityDigest"],
        )
        self.assertEqual(errors, [])
        self.assertEqual(actual, expected)
        self.assertEqual(
            validate_schema(
                expected, "stable-1.0-support-lifecycle-descriptor-v1.schema.json"
            ),
            [],
        )

    def test_authorization_expiry_uses_actual_time(self) -> None:
        ledger, descriptor = self._descriptor()
        transition_set = {
            "transitionRequestDigest": DIGEST,
            "transitionSetDigest": OTHER_DIGEST,
            "transitions": [],
        }
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        prepared, _, _ = _validate_authorization(
            None,
            POLICY,
            descriptor,
            ledger,
            transition_set,
            PUBLIC_URI,
            MAINTENANCE_POINTER_URI,
            None,
            now,
        )
        expired = dict(prepared)
        expired.update(
            {
                "authorizationId": "AUTH-1",
                "generatedAt": (now - dt.timedelta(hours=2)).isoformat().replace("+00:00", "Z"),
                "expiresAt": (now - dt.timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
                "decision": "approved",
            }
        )
        _, valid, errors = _validate_authorization(
            expired,
            POLICY,
            descriptor,
            ledger,
            transition_set,
            PUBLIC_URI,
            MAINTENANCE_POINTER_URI,
            None,
            now,
        )
        self.assertFalse(valid)
        self.assertTrue(any("expired" in error for error in errors))

    def test_publication_receipt_binds_exact_descriptor_bytes(self) -> None:
        ledger, descriptor = self._descriptor()
        transition_set = {
            "transitionRequestDigest": DIGEST,
            "transitionSetDigest": OTHER_DIGEST,
            "transitions": [],
        }
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        authorization, _, _ = _validate_authorization(
            None,
            POLICY,
            descriptor,
            ledger,
            transition_set,
            PUBLIC_URI,
            MAINTENANCE_POINTER_URI,
            None,
            now,
        )
        authorization.update(
            {
                "authorizationId": "AUTH-1",
                "generatedAt": now.isoformat().replace("+00:00", "Z"),
                "expiresAt": (now + dt.timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
                "decision": "approved",
            }
        )
        # Rebuild to make the prepared request fields match the updated timestamps.
        prepared, _, _ = _validate_authorization(
            None,
            POLICY,
            descriptor,
            ledger,
            transition_set,
            PUBLIC_URI,
            MAINTENANCE_POINTER_URI,
            None,
            now,
        )
        for key in prepared:
            if key not in {"authorizationId", "generatedAt", "expiresAt", "decision"}:
                authorization[key] = prepared[key]
        _, authorization_valid, authorization_errors = _validate_authorization(
            authorization,
            POLICY,
            descriptor,
            ledger,
            transition_set,
            PUBLIC_URI,
            MAINTENANCE_POINTER_URI,
            None,
            now,
        )
        self.assertTrue(authorization_valid, authorization_errors)
        plan = _publication_plan(
            descriptor,
            ledger,
            authorization,
            True,
            PUBLIC_URI,
            MAINTENANCE_POINTER_URI,
            None,
            transition_set["transitionSetDigest"],
        )
        receipt = {
            "schemaVersion": 1,
            "kind": "stable-1.0-support-lifecycle-publication-receipt",
            "generatedAt": now.isoformat().replace("+00:00", "Z"),
            "stableMilestone": "1.0",
            "descriptorEdition": descriptor["descriptorEdition"],
            "descriptorDigest": descriptor["descriptorDigest"],
            "descriptorBytesDigest": canonical_file_digest(descriptor),
            "ledgerDigest": ledger["ledgerDigest"],
            "updateKeyIdentityDigest": descriptor["updateKeyIdentityDigest"],
            "updateKeyScope": descriptor["updateKeyScope"],
            "updateKeyDocName": descriptor["updateKeyDocName"],
            "publicRequestUri": plan["publicRequestUri"],
            "previousDescriptorEdition": None,
            "previousDescriptorDigest": None,
            "publicationPlanDigest": plan["publicationPlanDigest"],
            "authorizationDigest": canonical_file_digest(authorization),
            "operation": "verified-existing",
            "publicationState": "publication-complete",
            "verificationStatus": "verified",
            "conflict": False,
            "redaction": {"status": "pass", "findingCount": 0, "findings": []},
        }
        valid, errors = _verify_receipt(receipt, descriptor, plan, authorization, now)
        self.assertTrue(valid, errors)

        verification_after_expiry = now + dt.timedelta(hours=2)
        _, historical_authorization_valid, historical_authorization_errors = (
            _validate_authorization(
                authorization,
                POLICY,
                descriptor,
                ledger,
                transition_set,
                PUBLIC_URI,
                MAINTENANCE_POINTER_URI,
                None,
                verification_after_expiry,
                valid_at=now,
            )
        )
        self.assertTrue(
            historical_authorization_valid, historical_authorization_errors
        )
        historical_receipt_valid, historical_receipt_errors = _verify_receipt(
            receipt,
            descriptor,
            plan,
            authorization,
            verification_after_expiry,
        )
        self.assertTrue(historical_receipt_valid, historical_receipt_errors)

        receipt["generatedAt"] = authorization["expiresAt"]
        valid, errors = _verify_receipt(
            receipt, descriptor, plan, authorization, verification_after_expiry
        )
        self.assertFalse(valid)
        self.assertTrue(any("authorization interval" in error for error in errors))

        receipt["generatedAt"] = now.isoformat().replace("+00:00", "Z")
        receipt["descriptorBytesDigest"] = OTHER_DIGEST
        valid, _ = _verify_receipt(receipt, descriptor, plan, authorization, now)
        self.assertFalse(valid)


class StableLifecycleGovernanceTest(unittest.TestCase):
    def test_deprecation_clock_reset_app_omission_and_profile_change_fail(self) -> None:
        base = {
            "platformApi": {
                "baselineName": "1.0",
                "baselineDigest": DIGEST,
                "baselineContractVersion": 19,
                "stableSurfaceDigest": DIGEST,
                "compatibilityWindowPolicyDigest": DIGEST,
                "deprecationHistory": [
                    {
                        "kind": "endpoint",
                        "identity": "GET /api/v1/test",
                        "deprecatedSinceContractVersion": 20,
                        "removalContractVersion": 24,
                    }
                ],
            },
            "firstPartyApps": [
                {"appId": "publisher", "supportLevel": "core", "channel": "stable"}
            ],
            "contentFormatProfiles": [
                {
                    "profileId": "crypta.profile.v1",
                    "version": 1,
                    "canonicalizationRulesDigest": DIGEST,
                    "maximumSizePolicyDigest": DIGEST,
                    "signaturePayloadRulesDigest": DIGEST,
                }
            ],
            "stableCatalog": {"catalogId": "first-party", "channel": "stable"},
        }
        successor = copy.deepcopy(base)
        successor["platformApi"]["deprecationHistory"][0][
            "deprecatedSinceContractVersion"
        ] = 21
        successor["firstPartyApps"] = []
        successor["contentFormatProfiles"][0]["canonicalizationRulesDigest"] = OTHER_DIGEST
        errors = _history_governance_errors(
            {"links": [{"successorBaseline": successor}]}, base
        )
        self.assertTrue(any("deprecation clock" in error for error in errors))
        self.assertTrue(any("app identity" in error for error in errors))
        self.assertTrue(any("canonicalization" in error for error in errors))

    def test_reviewed_app_and_versioned_profile_additions_are_not_removals(self) -> None:
        ga_security = {"advisoryCount": 1, "denylistCount": 1}
        base = {
            "platformApi": {
                "baselineName": "1.0",
                "baselineDigest": DIGEST,
                "baselineContractVersion": 19,
                "stableSurfaceDigest": DIGEST,
                "compatibilityWindowPolicyDigest": DIGEST,
                "deprecationHistory": [],
            },
            "firstPartyApps": [
                {"appId": "publisher", "supportLevel": "core", "channel": "stable"}
            ],
            "contentFormatProfiles": [
                {
                    "profileId": "crypta.profile.v1",
                    "version": 1,
                    "canonicalizationRulesDigest": DIGEST,
                    "maximumSizePolicyDigest": DIGEST,
                    "signaturePayloadRulesDigest": DIGEST,
                }
            ],
            "stableCatalog": {"catalogId": "first-party", "channel": "stable"},
            "securityBaseline": ga_security,
        }
        successor = copy.deepcopy(base)
        successor["firstPartyApps"].append(
            {"appId": "new-reviewed-app", "supportLevel": "maintained", "channel": "stable"}
        )
        successor["contentFormatProfiles"].append(
            {
                "profileId": "crypta.profile.v2",
                "version": 2,
                "canonicalizationRulesDigest": OTHER_DIGEST,
                "maximumSizePolicyDigest": OTHER_DIGEST,
                "signaturePayloadRulesDigest": OTHER_DIGEST,
            }
        )
        successor["security"] = {
            "currentDigest": OTHER_DIGEST,
            "gaBaselineDigest": semantic_digest(ga_security),
            "predecessorDigest": semantic_digest(ga_security),
        }
        errors = _history_governance_errors(
            {"links": [{"successorBaseline": successor}]}, base
        )
        self.assertFalse(any("removed or renamed" in error for error in errors), errors)

    def test_security_digest_and_ga_hotfix_obligation_cannot_silently_clear(self) -> None:
        ga_security = {"advisoryCount": 2, "denylistCount": 1}
        base = {
            "platformApi": {"deprecationHistory": []},
            "firstPartyApps": [],
            "contentFormatProfiles": [],
            "stableCatalog": {"catalogId": "first-party", "channel": "stable"},
            "securityBaseline": ga_security,
            "hotfixFollowUp": {
                "status": "open",
                "obligationDigest": DIGEST,
            },
        }
        successor = copy.deepcopy(base)
        successor["security"] = {
            "currentDigest": OTHER_DIGEST,
            "gaBaselineDigest": OTHER_DIGEST,
            "predecessorDigest": semantic_digest(ga_security),
        }
        successor["hotfixFollowUp"] = {
            "status": "closed",
            "obligationDigest": DIGEST,
            "closureEvidenceDigest": None,
        }
        errors = _history_governance_errors(
            {"links": [{"successorBaseline": successor}]}, base
        )
        self.assertTrue(any("security-state digest continuity" in error for error in errors))
        self.assertTrue(any("without closure evidence" in error for error in errors))


class StableMaintenanceLifecycleIntegrationTest(unittest.TestCase):
    def _state(self) -> tuple[dict, SimpleNamespace]:
        ledger, _, errors = build_ledger(
            inventory([release(1, "2026-07-20T00:00:00Z")]),
            POLICY,
            DIGEST,
            "2026-07-21T00:00:00Z",
            None,
            None,
        )
        self.assertEqual(errors, [])
        predecessor = SimpleNamespace(
            release_id="stable-1",
            build_version="1",
            tag="v1",
            source_commit=COMMIT,
            product_digest=DIGEST,
            receipt_digest=DIGEST,
            baseline_digest=DIGEST,
            chain_depth=0,
        )
        return ledger, predecessor

    def test_routine_maintenance_rejects_eol_and_revoked_predecessor(self) -> None:
        ledger, predecessor = self._state()
        for status in ("end-of-support", "revoked", "security-fixes-only"):
            changed = copy.deepcopy(ledger)
            changed["entries"][0]["lifecycleStatus"] = status
            changed["entries"][0]["entryDigest"] = entry_digest(changed["entries"][0])
            changed["ledgerDigest"] = ledger_digest(changed)
            errors = _lifecycle_predecessor_errors(changed, predecessor, "maintenance")
            self.assertTrue(errors, status)

    def test_security_hotfix_accepts_supported_predecessor(self) -> None:
        ledger, predecessor = self._state()
        ledger["entries"][0]["lifecycleStatus"] = "supported-maintenance"
        ledger["entries"][0]["entryDigest"] = entry_digest(ledger["entries"][0])
        ledger["ledgerDigest"] = ledger_digest(ledger)
        self.assertEqual(
            _lifecycle_predecessor_errors(ledger, predecessor, "security-hotfix"), []
        )

    def test_security_hotfix_accepts_exactly_authorized_security_only_predecessor(
        self,
    ) -> None:
        ledger, predecessor = self._state()
        ledger["entries"][0]["lifecycleStatus"] = "security-fixes-only"
        current = {
            **ledger["entries"][0],
            **release(2, "2026-07-21T00:00:00Z"),
            "lifecycleStatus": "current-stable",
        }
        ledger["entries"].append(current)
        descriptor = {"currentStableBuild": "2"}
        scope = {
            "incidentId": "CRYPTA-SEC-2026-001",
            "hotfixPolicyAuthorizationDigest": DIGEST,
        }

        errors = _hotfix_lifecycle_authority_errors(
            ledger,
            descriptor,
            predecessor,
            "security-hotfix",
            scope,
        )

        self.assertEqual(errors, [])

    def test_security_hotfix_rejects_non_current_predecessor_without_exact_scope(
        self,
    ) -> None:
        ledger, predecessor = self._state()
        ledger["entries"][0]["lifecycleStatus"] = "deprecated"
        current = {
            **ledger["entries"][0],
            **release(2, "2026-07-21T00:00:00Z"),
            "lifecycleStatus": "current-stable",
        }
        ledger["entries"].append(current)

        errors = _hotfix_lifecycle_authority_errors(
            ledger,
            {"currentStableBuild": "2"},
            predecessor,
            "security-hotfix",
            {},
        )

        self.assertTrue(any("exact incident" in error for error in errors), errors)

    def test_security_hotfix_accepts_advisory_bound_revoked_tip_without_current(
        self,
    ) -> None:
        ledger, predecessor = self._state()
        incident_id = "CRYPTA-SEC-2026-001"
        entry = ledger["entries"][0]
        entry["lifecycleStatus"] = "revoked"
        entry["advisoryIds"] = [incident_id]
        entry["reasonCodes"] = ["unsafe-runtime"]
        ledger["transitions"] = [
            {
                "targetBuild": predecessor.build_version,
                "toStatus": "revoked",
                "advisoryId": incident_id,
                "affectedBuilds": [predecessor.build_version],
                "securityEvidenceIds": ["SEC-DRILL-001"],
                "publicationTargetDigest": DIGEST,
                "authorizationRequestDigest": DIGEST,
            }
        ]

        errors = _hotfix_lifecycle_authority_errors(
            ledger,
            {"currentStableBuild": None},
            predecessor,
            "security-hotfix",
            {
                "incidentId": incident_id,
                "hotfixPolicyAuthorizationDigest": DIGEST,
            },
        )

        self.assertEqual(errors, [])

    def test_security_hotfix_rejects_revoked_tip_with_different_advisory(self) -> None:
        ledger, predecessor = self._state()
        entry = ledger["entries"][0]
        entry["lifecycleStatus"] = "revoked"
        entry["advisoryIds"] = ["CRYPTA-SEC-2026-001"]
        entry["reasonCodes"] = ["unsafe-runtime"]
        ledger["transitions"] = []

        errors = _hotfix_lifecycle_authority_errors(
            ledger,
            {"currentStableBuild": None},
            predecessor,
            "security-hotfix",
            {
                "incidentId": "CRYPTA-SEC-2026-002",
                "hotfixPolicyAuthorizationDigest": DIGEST,
            },
        )

        self.assertTrue(any("exact advisory" in error for error in errors), errors)

    def test_candidate_transition_remains_pending_and_non_activating(self) -> None:
        _, predecessor = self._state()
        context = SimpleNamespace(
            manifest=SimpleNamespace(
                release=SimpleNamespace(release_id="stable-2", version="2"),
                policies={"releaseClass": "maintenance"},
            )
        )
        candidate = SimpleNamespace(
            input_value={"generatedAt": "2026-07-21T00:00:00Z"},
            source={"commit": COMMIT},
            product_digest=OTHER_DIGEST,
            identity_digest=DIGEST,
            input_digest=DIGEST,
            freeze_digest=DIGEST,
            checksums_digest=DIGEST,
            provenance_digest=DIGEST,
            assets=[],
            asset_paths={},
        )
        proposal = _pending_lifecycle_transition(
            context, predecessor, candidate, "current-stable", DIGEST
        )
        self.assertFalse(proposal["activeLedgerChanged"])
        self.assertEqual(
            proposal["proposalDigest"],
            semantic_digest(
                {key: value for key, value in proposal.items() if key != "proposalDigest"}
            ),
        )
        self.assertEqual(proposal["candidate"]["proposedStatus"], "current-stable")
        self.assertEqual(
            validate_schema(
                proposal,
                "stable-1.0-support-lifecycle-pending-maintenance-transition-v1.schema.json",
            ),
            [],
        )
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            write_json(
                out / "stable-1.0-support-lifecycle-pending-maintenance-transition.json",
                proposal,
            )
            self.assertIn(
                "stable-1.0-support-lifecycle-pending-maintenance-transition.json",
                _public_checksum_payload_paths(candidate, out),
            )
        ga = SimpleNamespace(
            root_identity_digest=DIGEST,
            baseline_digest=DIGEST,
            receipt_digest=DIGEST,
        )
        provenance = _provenance(
            context,
            DIGEST,
            ga,
            predecessor,
            candidate,
            DIGEST,
            DIGEST,
            DIGEST,
            DIGEST,
            proposal["proposalDigest"],
            DIGEST,
        )
        self.assertEqual(
            provenance["pendingLifecycleTransitionDigest"], proposal["proposalDigest"]
        )
        state = ValidationState()
        validation = _validation(
            context,
            state,
            "validate-only",
            candidate,
            DIGEST,
            DIGEST,
            {
                "evidenceRows": [
                    {
                        "evidenceId": "stable-maintenance.security",
                        "status": "pass",
                        "evidenceDigest": DIGEST,
                        "fresh": True,
                        "production": True,
                    }
                ]
            },
            DIGEST,
            DIGEST,
            DIGEST,
            DIGEST,
            proposal["proposalDigest"],
            DIGEST,
            True,
            DIGEST,
            False,
            "validated",
        )
        self.assertEqual(state.blockers, [])
        self.assertEqual(
            validation["pendingLifecycleTransitionDigest"], proposal["proposalDigest"]
        )

    def test_security_hotfix_pending_transition_never_moves_predecessor_backward(
        self,
    ) -> None:
        _, predecessor = self._state()
        context = SimpleNamespace(
            manifest=SimpleNamespace(
                release=SimpleNamespace(release_id="stable-2", version="2"),
                policies={"releaseClass": "security-hotfix"},
            )
        )
        candidate = SimpleNamespace(
            input_value={"generatedAt": "2026-07-21T00:00:00Z"},
            source={"commit": COMMIT},
            product_digest=OTHER_DIGEST,
            identity_digest=DIGEST,
        )
        expected = {
            "current-stable": "supported-maintenance",
            "supported-maintenance": "supported-maintenance",
            "security-fixes-only": "security-fixes-only",
            "deprecated": "deprecated",
            "revoked": "revoked",
        }

        for authenticated_status, proposed_status in expected.items():
            with self.subTest(authenticated_status=authenticated_status):
                proposal = _pending_lifecycle_transition(
                    context,
                    predecessor,
                    candidate,
                    authenticated_status,
                    DIGEST,
                )

                self.assertEqual(
                    proposal["predecessor"]["proposedStatus"], proposed_status
                )
                self.assertEqual(
                    validate_schema(
                        proposal,
                        "stable-1.0-support-lifecycle-pending-maintenance-transition-v1.schema.json",
                    ),
                    [],
                )

    def test_lifecycle_authority_chain_is_optional_only_for_ga_genesis(self) -> None:
        absent = (None, None, None, None, None)
        self.assertEqual(_lifecycle_input_presence_errors(absent, 0), [])
        self.assertTrue(_lifecycle_input_presence_errors(absent, 1))
        self.assertTrue(
            _lifecycle_input_presence_errors((object(), None, None, None, None), 0)
        )
        summary = {"promotionReady": True, "decision": "go"}
        _apply_lifecycle_promotion_gate(summary, False)
        self.assertFalse(summary["promotionReady"])
        self.assertEqual(summary["decision"], "no-go")

    def test_maintenance_blocks_candidate_before_inventory_would_exceed_runtime_bound(
        self,
    ) -> None:
        _, predecessor = self._state()
        maximum_entries = POLICY["descriptor"]["maximumEntries"]
        predecessor_at_capacity_minus_one = SimpleNamespace(
            **{
                **predecessor.__dict__,
                "chain_depth": maximum_entries - 2,
            }
        )
        predecessor_at_capacity = SimpleNamespace(
            **{
                **predecessor.__dict__,
                "chain_depth": maximum_entries - 1,
            }
        )

        allowed = _lifecycle_successor_capacity_errors(
            predecessor_at_capacity_minus_one, POLICY
        )
        blocked = _lifecycle_successor_capacity_errors(
            predecessor_at_capacity, POLICY
        )

        self.assertEqual(allowed, [])
        self.assertEqual(
            blocked,
            [
                "candidate publication would exceed the authenticated lifecycle descriptor "
                f"entry bound of {maximum_entries}"
            ],
        )

    def test_maintenance_accepts_only_exact_authenticated_lifecycle_authority_chain(
        self,
    ) -> None:
        ledger, predecessor = self._state()
        descriptor, errors = build_descriptor(
            ledger,
            POLICY,
            "2026-07-21T00:00:00Z",
            None,
            POLICY["descriptor"]["updateKeyIdentityDigest"],
        )
        self.assertEqual(errors, [])
        transition_set = {
            "transitions": [],
            "transitionRequestDigest": DIGEST,
        }
        authorization, _, errors = _validate_authorization(
            None,
            POLICY,
            descriptor,
            ledger,
            transition_set,
            PUBLIC_URI,
            MAINTENANCE_POINTER_URI,
            None,
            dt.datetime(2026, 7, 21, 0, 30, tzinfo=dt.timezone.utc),
        )
        self.assertEqual(errors, [])
        authorization.update(
            {
                "authorizationId": "stable-lifecycle-maintenance-test",
                "expiresAt": "2026-07-21T01:00:00Z",
                "decision": "approved",
            }
        )
        authorization, authorization_valid, errors = _validate_authorization(
            authorization,
            POLICY,
            descriptor,
            ledger,
            transition_set,
            PUBLIC_URI,
            MAINTENANCE_POINTER_URI,
            None,
            dt.datetime(2026, 7, 21, 0, 30, tzinfo=dt.timezone.utc),
        )
        self.assertTrue(authorization_valid)
        self.assertEqual(errors, [])
        plan = _publication_plan(
            descriptor,
            ledger,
            authorization,
            True,
            PUBLIC_URI,
            MAINTENANCE_POINTER_URI,
            None,
            DIGEST,
        )
        receipt = {
            "schemaVersion": 1,
            "kind": "stable-1.0-support-lifecycle-publication-receipt",
            "generatedAt": "2026-07-21T00:30:00Z",
            "stableMilestone": "1.0",
            "descriptorEdition": 1,
            "descriptorDigest": descriptor["descriptorDigest"],
            "descriptorBytesDigest": canonical_file_digest(descriptor),
            "ledgerDigest": ledger["ledgerDigest"],
            "updateKeyIdentityDigest": descriptor["updateKeyIdentityDigest"],
            "updateKeyScope": descriptor["updateKeyScope"],
            "updateKeyDocName": "support-lifecycle",
            "publicRequestUri": PUBLIC_URI,
            "previousDescriptorEdition": None,
            "previousDescriptorDigest": None,
            "publicationPlanDigest": plan["publicationPlanDigest"],
            "authorizationDigest": canonical_file_digest(authorization),
            "operation": "verified-existing",
            "publicationState": "publication-complete",
            "verificationStatus": "verified",
            "conflict": False,
            "redaction": {"status": "pass", "findingCount": 0, "findings": []},
        }
        errors = _authenticated_lifecycle_errors(
            ledger,
            descriptor,
            authorization,
            plan,
            receipt,
            canonical_file_digest(authorization),
            canonical_file_digest(descriptor),
            DIGEST,
            predecessor,
            "maintenance",
            dt.datetime(2026, 7, 22, tzinfo=dt.timezone.utc),
        )
        self.assertEqual(errors, [])
        errors = _authenticated_lifecycle_errors(
            ledger,
            descriptor,
            authorization,
            plan,
            receipt,
            canonical_file_digest(authorization),
            canonical_file_digest(descriptor),
            OTHER_DIGEST,
            predecessor,
            "maintenance",
            dt.datetime(2026, 7, 22, tzinfo=dt.timezone.utc),
        )
        self.assertEqual(
            errors,
            [
                "lifecycle ledger policy digest does not match the exact checked-in support "
                "lifecycle policy"
            ],
        )
        fabricated_receipt = copy.deepcopy(receipt)
        fabricated_receipt["publicationPlanDigest"] = OTHER_DIGEST
        self.assertEqual(
            validate_schema(
                fabricated_receipt,
                "stable-1.0-support-lifecycle-publication-receipt-v1.schema.json",
            ),
            [],
        )
        errors = _authenticated_lifecycle_errors(
            ledger,
            descriptor,
            authorization,
            plan,
            fabricated_receipt,
            canonical_file_digest(authorization),
            canonical_file_digest(descriptor),
            DIGEST,
            predecessor,
            "maintenance",
            dt.datetime(2026, 7, 22, tzinfo=dt.timezone.utc),
        )
        self.assertTrue(any("authorized publication plan" in error for error in errors))
        rewritten = copy.deepcopy(descriptor)
        rewritten["entries"][0]["productDigest"] = OTHER_DIGEST
        rewritten["descriptorDigest"] = semantic_digest(
            {key: value for key, value in rewritten.items() if key != "descriptorDigest"}
        )
        rewritten_receipt = copy.deepcopy(receipt)
        rewritten_receipt["descriptorDigest"] = rewritten["descriptorDigest"]
        rewritten_receipt["descriptorBytesDigest"] = canonical_file_digest(rewritten)
        errors = _authenticated_lifecycle_errors(
            ledger,
            rewritten,
            authorization,
            plan,
            rewritten_receipt,
            canonical_file_digest(authorization),
            canonical_file_digest(rewritten),
            DIGEST,
            predecessor,
            "maintenance",
            dt.datetime(2026, 7, 22, tzinfo=dt.timezone.utc),
        )
        self.assertTrue(any("rewrites ledger" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
