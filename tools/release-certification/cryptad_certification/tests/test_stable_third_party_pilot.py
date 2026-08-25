"""Tests for the closed external third-party app pilot verifier."""

from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import zipfile

from cryptad_certification.cli import build_parser
from cryptad_certification.engines import stable_1_0_third_party_pilot as pilot
from cryptad_certification.redaction import scan_value
from cryptad_certification.schema_validation import validate_schema
from cryptad_certification.tests.third_party_pilot_fixtures import (
    PilotFixture,
    digest,
    key,
    provenance,
    rechain_transparency,
    seal_receipt,
    signature,
    zip_bytes,
)


class StableThirdPartyPilotTest(unittest.TestCase):
    """Exercises identity, signature, review, catalog, runtime, and closeout boundaries."""

    def setUp(self) -> None:
        self.workspace = Path(__file__).resolve().parents[4]
        (self.workspace / "build").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            dir=self.workspace / "build",
            prefix="third-party-pilot-test-",
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fixture = PilotFixture(self.root)
        self.policy, _digest = pilot._policy(self.workspace)
        self.run_number = 0

    def run_mode(self, mode: str) -> tuple[int, dict[str, object]]:
        self.run_number += 1
        output = self.root / f"output-{self.run_number}"
        result = pilot.run(
            self.workspace,
            self.fixture.contract_path,
            mode,
            output,
            self.fixture.evidence,
        )
        summary = json.loads((output / pilot.SUMMARY_FILE).read_text(encoding="utf-8"))
        return result, summary

    def authority(self, role: str) -> dict[str, object]:
        return next(
            key
            for key in self.fixture.contract["authorities"]["keys"]
            if key["role"] == role
        )

    def add_nonselected_keyset_key(
        self, role: str, key_id: str, lifecycle: str
    ) -> tuple[dict[str, object], bytes, bytes]:
        retained, private_seed, public = key(role, key_id)
        subject_key = {
            "keyId": retained["keyId"],
            "role": retained["role"],
            "algorithm": "Ed25519",
            "publicKeySpkiBase64": retained["publicKeySpkiBase64"],
            "publicKeyFingerprintSha256": retained["fingerprint"],
            "lifecycle": lifecycle,
            "validFrom": retained["validFrom"],
            "validUntil": retained["validUntil"],
            "predecessorKeyId": None,
            "successorKeyId": None,
            "compromiseState": (
                "compromised" if lifecycle == "revoked" else "uncompromised"
            ),
            "publicTransparencyEligible": True,
        }
        keyset = self.fixture.contract["authorities"]["keysetSubject"]["keys"]
        keyset.append(subject_key)
        keyset.sort(key=lambda item: item["keyId"])
        self.fixture.contract["authorities"]["keysetDigest"] = digest(
            pilot._canonical_bytes(
                self.fixture.contract["authorities"]["keysetSubject"]
            )
        )
        return retained, private_seed, public

    def replace_collector_and_rebind_runtime(
        self,
        collector: dict[str, object],
        runtime_updates: dict[str, object] | None = None,
    ) -> None:
        self.fixture.replace_evidence("collectorSummary", collector)
        runtime = self.fixture.load_evidence("runtimeDrill")
        runtime.update(runtime_updates or {})
        binding = self.fixture.contract["evidence"]["collectorSummary"]
        runtime["collector"]["summaryDigest"] = binding["digest"]
        runtime["collector"]["summarySize"] = binding["size"]
        seal_receipt(runtime, *self.fixture.material["node"])
        self.fixture.replace_evidence("runtimeDrill", runtime)

    @staticmethod
    def collector_lifecycle_details(
        collector: dict[str, object],
    ) -> dict[str, object]:
        lifecycle = next(
            row
            for row in collector["evidence"]
            if row["id"] == "live-network-beta.app-install-update-rollback"
        )
        return lifecycle["details"]

    def replace_review_and_reseal(self, review: dict[str, object]) -> None:
        rechain_transparency(review)
        seal_receipt(review, *self.fixture.material["app-reviewer"])
        self.fixture.replace_evidence("reviewCohort", review)

    def rebuild_signed_bundle(
        self,
        entries: dict[str, bytes],
        *,
        executable_paths: frozenset[str] = frozenset(),
        modes: dict[str, int] | None = None,
    ) -> tuple[bytes, bytes]:
        payload = {
            name: value
            for name, value in entries.items()
            if name not in {"cryptad-app.digests", "cryptad-app.signature"}
        }
        digest_lines = ["digest.version=1", "digest.algorithm=SHA-256"]
        for index, name in enumerate(sorted(payload)):
            digest_lines.extend(
                (
                    f"file.{index}.path={name}",
                    f"file.{index}.sha256={hashlib.sha256(payload[name]).hexdigest()}",
                )
            )
            if name in executable_paths:
                digest_lines.append(f"file.{index}.executable=true")
        digest_bytes = ("\n".join(digest_lines) + "\n").encode()
        publisher_seed, publisher_public = self.fixture.material["publisher"]
        signature_bytes = (
            "signature.version=1\n"
            "signature.algorithm=Ed25519\n"
            f"signature.key.id={self.fixture.contract['externalApp']['publisherKeyId']}\n"
            "signature.payload=cryptad-app.digests\n"
            f"signature.value.base64={signature(publisher_seed, publisher_public, digest_bytes)}\n"
        ).encode()
        rebuilt = {
            **payload,
            "cryptad-app.digests": digest_bytes,
            "cryptad-app.signature": signature_bytes,
        }
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            for name in sorted(rebuilt):
                info = zipfile.ZipInfo(name)
                info.date_time = (1980, 1, 1, 0, 0, 0)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | (modes or {}).get(name, 0o644)) << 16
                info.compress_type = zipfile.ZIP_STORED
                archive.writestr(info, rebuilt[name])
        return output.getvalue(), signature_bytes

    @staticmethod
    def pkcs8_ed25519_private_key() -> bytes:
        """Return a minimal well-formed binary PKCS#8 Ed25519 private key."""

        return bytes.fromhex("302e020100300506032b657004220420") + bytes(range(32))

    def test_parser_when_command_selected_expect_all_closed_modes(self) -> None:
        parser = build_parser()

        for mode in pilot.MODES:
            with self.subTest(mode=mode):
                arguments = parser.parse_args(
                    [
                        "stable-third-party-pilot",
                        "--mode",
                        mode,
                        "--execution-contract",
                        "execution.json",
                    ]
                )
                self.assertEqual(mode, arguments.mode)

    def test_manifest_parser_when_key_and_value_use_unicode_escapes_expect_apphost_projection(
        self,
    ) -> None:
        manifest = pilot._manifest_properties(
            b"app.permissi\\u006fns=content.\\u0066etch\n",
            "bundle manifest",
        )

        permissions = pilot._manifest_permissions(manifest)

        self.assertEqual({"app.permissions": "content.fetch"}, manifest)
        self.assertEqual(["content.fetch"], permissions)

    def test_manifest_parser_when_decoded_keys_collide_expect_failure(self) -> None:
        raw = (
            b"app.permissions=queue.read\n"
            b"app.permissi\\u006fns=content.fetch\n"
        )

        with self.assertRaisesRegex(ValueError, "duplicate decoded property"):
            pilot._manifest_properties(raw, "bundle manifest")

    def test_manifest_parser_when_unicode_escape_is_malformed_expect_failure(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid unicode escape"):
            pilot._manifest_properties(
                b"app.permissions=content.\\u00zz\n",
                "bundle manifest",
            )

    def test_manifest_parser_when_properties_use_supported_syntax_expect_apphost_projection(
        self,
    ) -> None:
        manifest = pilot._manifest_properties(
            b"\xef\xbb\xbf  # generated properties\n"
            b"manifest.version: 1\n"
            b"app.exec=bin\\run.cmd\n",
            "bundle manifest",
        )

        self.assertEqual("1", manifest["manifest.version"])
        self.assertEqual(r"bin\run.cmd", manifest["app.exec"])

    def test_fixture_when_runtime_cohort_is_authentic_expect_fixture_only_completion(self) -> None:
        result, summary = self.run_mode("verify-runtime-drill")
        review = self.fixture.load_evidence("reviewCohort")
        receipts = {
            row["cohortId"]: row["standardReviewReceipt"]
            for row in review["rows"]
        }

        self.assertEqual(0, result)
        self.assertEqual("pass", summary["status"])
        self.assertEqual("fixture-verification-complete", summary["state"])
        self.assertTrue(summary["fixtureVerificationComplete"])
        self.assertFalse(summary["externalHandoffAuthenticated"])
        self.assertFalse(summary["operationalPilotComplete"])
        self.assertFalse(summary["operational"])
        self.assertEqual([], validate_schema(summary, pilot.SUMMARY_SCHEMA))
        self.assertIsNone(receipts["version-2-rejected"])
        self.assertIsNone(receipts["version-2-corrected"]["expiresAt"])
        self.assertIsNone(receipts["version-3-caution"]["expiresAt"])

    def test_preflight_when_evidence_is_absent_expect_side_effect_free_pass(self) -> None:
        self.fixture.contract["evidence"] = {
            name: None for name in self.fixture.contract["evidence"]
        }
        self.fixture.reload_contract()

        result, summary = self.run_mode("preflight")

        self.assertEqual(0, result)
        self.assertEqual("preflight-passed", summary["state"])
        self.assertFalse(summary["fixtureVerificationComplete"])

    def test_verification_time_when_operational_contract_is_retained_expect_current_time(
        self,
    ) -> None:
        contract = copy.deepcopy(self.fixture.contract)
        contract["fixtureOnly"] = False
        contract["selfTest"] = False
        contract["evaluationTime"] = "2026-08-23T12:00:00Z"
        observed = pilot._timestamp(
            "2026-08-24T12:00:00Z", "test operational verification time"
        )

        evaluation = pilot._verification_time(contract, self.policy, observed)

        self.assertEqual(observed, evaluation)

    def test_verification_time_when_operational_contract_is_future_dated_expect_failure(
        self,
    ) -> None:
        contract = copy.deepcopy(self.fixture.contract)
        contract["fixtureOnly"] = False
        contract["selfTest"] = False
        contract["evaluationTime"] = "2026-08-24T12:05:01Z"
        observed = pilot._timestamp(
            "2026-08-24T12:00:00Z", "test operational verification time"
        )

        with self.assertRaisesRegex(ValueError, "evaluation time is in the future"):
            pilot._verification_time(contract, self.policy, observed)

    def test_verification_time_when_key_expired_after_contract_creation_expect_failure(
        self,
    ) -> None:
        contract = copy.deepcopy(self.fixture.contract)
        contract["fixtureOnly"] = False
        contract["selfTest"] = False
        selected = next(
            key
            for key in contract["authorities"]["keys"]
            if key["role"] == "catalog-signing"
        )
        selected["validUntil"] = "2026-08-24T00:00:00Z"
        subject_key = next(
            key
            for key in contract["authorities"]["keysetSubject"]["keys"]
            if key["keyId"] == selected["keyId"]
        )
        subject_key["validUntil"] = selected["validUntil"]
        contract["authorities"]["keysetDigest"] = digest(
            pilot._canonical_bytes(contract["authorities"]["keysetSubject"])
        )
        observed = pilot._timestamp(
            "2026-08-24T12:00:00Z", "test operational verification time"
        )
        evaluation = pilot._verification_time(contract, self.policy, observed)

        errors, _by_role = pilot._key_errors(contract, evaluation)

        self.assertIn("catalog-signing key is outside its validity interval", errors)

    def test_fixture_when_catalog_stage_passes_expect_not_complete_before_runtime(self) -> None:
        result, summary = self.run_mode("verify-catalog-publication")

        self.assertEqual(0, result)
        self.assertEqual("preflight-passed", summary["state"])
        self.assertFalse(summary["fixtureVerificationComplete"])

    def test_contract_when_unknown_field_is_added_expect_closed_schema_rejection(self) -> None:
        self.fixture.contract["external"] = True
        self.fixture.reload_contract()

        with self.assertRaisesRegex(ValueError, "closed schema"):
            self.run_mode("preflight")

    def test_externality_when_checked_in_sample_is_substituted_expect_fail_closed(self) -> None:
        self.fixture.contract["externalApp"]["appId"] = "org.example.hello"
        self.fixture.reload_contract()

        result, summary = self.run_mode("preflight")

        self.assertEqual(1, result)
        self.assertIn(
            "checked-in-sample-app-cannot-satisfy-operational-externality",
            summary["blockers"],
        )

    def test_externality_when_first_party_repository_is_substituted_expect_fail_closed(self) -> None:
        source = self.fixture.contract["externalApp"]["source"]
        source.update(
            {
                "repositoryIdentity": "github.com/crypta-network/cryptad",
                "host": "github.com",
                "owner": "crypta-network",
                "name": "cryptad",
            }
        )
        self.fixture.reload_contract()

        result, summary = self.run_mode("preflight")

        self.assertEqual(1, result)
        self.assertIn(
            "external-source-repository-is-controlled-by-crypta",
            summary["blockers"],
        )
        self.assertIn(
            "external-source-owner-is-controlled-by-crypta",
            summary["blockers"],
        )

    def test_externality_when_mutable_branch_is_used_expect_schema_rejection(self) -> None:
        self.fixture.contract["externalApp"]["source"]["revision"] = "main"
        self.fixture.reload_contract()

        with self.assertRaisesRegex(ValueError, "closed schema"):
            self.run_mode("preflight")

    def test_externality_when_publisher_reuses_catalog_key_expect_fail_closed(self) -> None:
        catalog = self.authority("catalog-signing")
        app = self.fixture.contract["externalApp"]
        app["publisherKeyId"] = catalog["keyId"]
        app["publisherPublicKeySpkiBase64"] = catalog["publicKeySpkiBase64"]
        app["publisherFingerprint"] = catalog["fingerprint"]
        self.fixture.reload_contract()

        result, summary = self.run_mode("preflight")

        self.assertEqual(1, result)
        self.assertIn(
            "external-publisher-key-is-reused-for-a-pr-293-authority-role",
            summary["blockers"],
        )

    def test_externality_when_publisher_reuses_retired_key_id_expect_fail_closed(
        self,
    ) -> None:
        retained, _private_seed, _public = self.add_nonselected_keyset_key(
            "catalog-signing", "retired-catalog-key-fixture-294", "retired"
        )
        self.fixture.contract["externalApp"]["publisherKeyId"] = retained["keyId"]
        self.fixture.reload_contract()

        result, summary = self.run_mode("preflight")

        self.assertEqual(1, result)
        self.assertIn(
            "external-publisher-key-is-reused-for-a-pr-293-authority-role",
            summary["blockers"],
        )

    def test_externality_when_publisher_reuses_nonselected_key_material_expect_fail_closed(
        self,
    ) -> None:
        retained, _private_seed, _public = self.add_nonselected_keyset_key(
            "first-party-app-signing", "staged-app-key-fixture-294", "staged"
        )
        app = self.fixture.contract["externalApp"]
        app["publisherPublicKeySpkiBase64"] = retained["publicKeySpkiBase64"]
        app["publisherFingerprint"] = retained["fingerprint"]
        self.fixture.reload_contract()

        result, summary = self.run_mode("preflight")

        self.assertEqual(1, result)
        self.assertIn(
            "external-publisher-key-is-reused-for-a-pr-293-authority-role",
            summary["blockers"],
        )

    def test_externality_when_workload_reuses_nonselected_key_material_expect_fail_closed(
        self,
    ) -> None:
        retained, _private_seed, _public = self.add_nonselected_keyset_key(
            "offline-recovery", "revoked-recovery-key-fixture-294", "revoked"
        )
        profile = self.fixture.contract["externalApp"]["workloadProfile"]
        profile["workloadPublicKeySpkiBase64"] = retained["publicKeySpkiBase64"]
        profile["workloadFingerprint"] = retained["fingerprint"]
        reviewer_seed, reviewer_public = self.fixture.material["app-reviewer"]
        profile["approvalSignatureBase64"] = signature(
            reviewer_seed,
            reviewer_public,
            pilot._profile_subject(self.fixture.contract),
        )
        self.fixture.reload_contract()

        result, summary = self.run_mode("preflight")

        self.assertEqual(1, result)
        self.assertIn("workload-key-is-not-role-distinct", summary["blockers"])

    def test_externality_when_retiring_key_is_distinct_expect_preflight_pass(self) -> None:
        self.add_nonselected_keyset_key(
            "app-reviewer", "retiring-reviewer-key-fixture-294", "retiring"
        )
        self.fixture.reload_contract()

        result, summary = self.run_mode("preflight")

        self.assertEqual(0, result)
        self.assertEqual("pass", summary["status"])

    def test_authority_when_selected_reviewer_key_is_substituted_expect_fail_closed(self) -> None:
        substituted, _private_seed, _public = key(
            "app-reviewer", "substituted-reviewer-fixture-294"
        )
        reviewer = self.authority("app-reviewer")
        reviewer["publicKeySpkiBase64"] = substituted["publicKeySpkiBase64"]
        reviewer["fingerprint"] = substituted["fingerprint"]
        self.fixture.reload_contract()

        result, summary = self.run_mode("verify-external-handoff")

        self.assertEqual(1, result)
        self.assertFalse(summary["externalHandoffAuthenticated"])
        self.assertIn(
            "selected-app-reviewer-key-differs-from-the-pr-293-keyset-subject",
            summary["blockers"],
        )
        self.assertIn(
            "external-handoff-validation-blocked-by-invalid-preflight",
            summary["blockers"],
        )

    def test_authority_when_keyset_subject_changes_without_digest_expect_fail_closed(self) -> None:
        self.fixture.contract["authorities"]["keysetSubject"]["keys"][0][
            "publicTransparencyEligible"
        ] = False
        self.fixture.reload_contract()

        result, summary = self.run_mode("preflight")

        self.assertEqual(1, result)
        self.assertIn(
            "pr-293-keyset-digest-does-not-match-the-canonical-keyset-subject",
            summary["blockers"],
        )

    def test_externality_when_same_ci_provider_has_distinct_authority_expect_allowed(self) -> None:
        contract = copy.deepcopy(self.fixture.contract)
        contract["fixtureOnly"] = False
        contract["selfTest"] = False
        contract["pilotId"] = "external-pilot-294"
        contract["externalApp"]["appId"] = "org.external.pilot"
        contract["externalApp"]["publisherKeyId"] = "external-publisher-294"
        profile = contract["externalApp"]["workloadProfile"]
        profile.update(
            {
                "profileId": "external-provider-profile-294",
                "profileType": "operational",
                "accountId": "external-account-294",
                "subject": "repo:outside/pilot-app:ref:commit",
                "operationalAllowed": True,
            }
        )
        reviewer_seed, reviewer_public = self.fixture.material["app-reviewer"]
        profile["approvalSignatureBase64"] = signature(
            reviewer_seed,
            reviewer_public,
            pilot._profile_subject(contract),
        )
        key_errors, by_role = pilot._key_errors(
            contract,
            pilot._timestamp(contract["evaluationTime"], "evaluation"),
        )

        errors = pilot._externality_errors(
            contract,
            self.policy,
            by_role,
            pilot._timestamp(contract["evaluationTime"], "evaluation"),
        )

        self.assertEqual([], key_errors)
        self.assertEqual([], errors)

    def test_handoff_when_developer_signature_is_substituted_expect_fail_closed(self) -> None:
        handoff = self.fixture.load_evidence("externalHandoff")
        handoff["cohort"][0]["attestationSignatureBase64"] = base64.b64encode(
            b"x" * 64
        ).decode()
        handoff["handoffDigest"] = pilot._semantic_digest(handoff, "handoffDigest")
        self.fixture.replace_evidence("externalHandoff", handoff)

        result, summary = self.run_mode("verify-external-handoff")

        self.assertEqual(1, result)
        self.assertTrue(
            any("developer-attestation-version-1-reviewed-signature" in item for item in summary["blockers"])
        )

    def test_receipt_when_workflow_coordinates_are_substituted_expect_fail_closed(self) -> None:
        cases = (
            ("externalHandoff", "verify-external-handoff"),
            ("reviewCohort", "verify-review-cohort"),
            ("catalogPublication", "verify-catalog-publication"),
            ("runtimeDrill", "verify-runtime-drill"),
        )
        for field, mode in cases:
            with self.subTest(field=field):
                fixture = PilotFixture(self.root / field)
                fixture.contract["evidence"][field]["provenance"]["runAttempt"] = 2
                fixture.reload_contract()
                output = self.root / f"coordinate-output-{field}"

                result = pilot.run(
                    self.workspace,
                    fixture.contract_path,
                    mode,
                    output,
                    fixture.evidence,
                )
                summary = json.loads(
                    (output / pilot.SUMMARY_FILE).read_text(encoding="utf-8")
                )

                self.assertEqual(1, result)
                self.assertTrue(
                    any("protected-artifact-provenance-differs" in item for item in summary["blockers"])
                )

    def test_handoff_when_workflow_commit_differs_from_approved_pipeline_expect_fail_closed(
        self,
    ) -> None:
        handoff = self.fixture.load_evidence("externalHandoff")
        handoff["provenance"]["workflowCommit"] = "c" * 40
        self.fixture.contract["evidence"]["externalHandoff"]["provenance"][
            "workflowCommit"
        ] = "c" * 40
        workload_subject = pilot._workload_subject(self.fixture.contract, handoff)
        handoff["workload"]["attestationDigest"] = digest(workload_subject)
        handoff["workload"]["signatureBase64"] = signature(
            *self.fixture.material["workload"], workload_subject
        )
        handoff["handoffDigest"] = pilot._semantic_digest(handoff, "handoffDigest")
        self.fixture.replace_evidence("externalHandoff", handoff)

        result, summary = self.run_mode("verify-external-handoff")

        self.assertEqual(1, result)
        self.assertIn(
            "external-handoff-workflow-commit-differs-from-the-approved-pipeline-revision",
            summary["blockers"],
        )
        self.assertFalse(summary["externalHandoffAuthenticated"])

    def test_handoff_when_attestation_domain_is_substituted_expect_schema_rejection(self) -> None:
        handoff = self.fixture.load_evidence("externalHandoff")
        handoff["cohort"][0]["attestation"]["domain"] = "wrong.domain"
        handoff["handoffDigest"] = pilot._semantic_digest(handoff, "handoffDigest")
        self.fixture.replace_evidence("externalHandoff", handoff)

        result, summary = self.run_mode("verify-external-handoff")

        self.assertEqual(1, result)
        self.assertTrue(any("required-schema-constant" in item for item in summary["blockers"]))

    def test_bundle_when_signature_only_names_key_expect_cryptographic_failure(self) -> None:
        handoff = self.fixture.load_evidence("externalHandoff")
        artifact = handoff["cohort"][0]
        raw = (self.fixture.evidence / artifact["bundleFile"]).read_bytes()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        sidecar = entries["cryptad-app.signature"].decode()
        sidecar = sidecar.replace(
            next(line for line in sidecar.splitlines() if line.startswith("signature.value.base64=")),
            "signature.value.base64=" + base64.b64encode(b"x" * 64).decode(),
        )
        entries["cryptad-app.signature"] = sidecar.encode()
        tampered = zip_bytes(entries, stored=False)
        row = self.fixture.contract["cohort"][0]

        errors, _manifest = pilot._bundle_errors(
            tampered,
            row,
            self.fixture.contract,
            self.policy,
        )

        self.assertIn("external app bundle signature does not verify", errors)

    def test_bundle_when_canonical_zero_based_digest_is_used_expect_pass(self) -> None:
        handoff = self.fixture.load_evidence("externalHandoff")
        artifact = handoff["cohort"][0]
        raw = (self.fixture.evidence / artifact["bundleFile"]).read_bytes()

        errors, manifest_digest = pilot._bundle_errors(
            raw,
            self.fixture.contract["cohort"][0],
            self.fixture.contract,
            self.policy,
        )

        self.assertEqual([], errors)
        self.assertEqual(
            artifact["attestation"]["manifestDigest"],
            manifest_digest,
        )

    def test_submission_when_permission_key_is_escaped_expect_review_projection_rejected(
        self,
    ) -> None:
        handoff = self.fixture.load_evidence("externalHandoff")
        artifact = handoff["cohort"][0]
        bundle_raw = (self.fixture.evidence / artifact["bundleFile"]).read_bytes()
        with zipfile.ZipFile(io.BytesIO(bundle_raw)) as archive:
            bundle_entries = {name: archive.read(name) for name in archive.namelist()}
        bundle_entries["cryptad-app.properties"] += (
            b"app.permissi\\u006fns=content.fetch\n"
        )
        rebuilt_bundle, signature_bytes = self.rebuild_signed_bundle(bundle_entries)
        with zipfile.ZipFile(io.BytesIO(rebuilt_bundle)) as archive:
            rebuilt_entries = {name: archive.read(name) for name in archive.namelist()}

        submission_raw = (
            self.fixture.evidence / artifact["submissionFile"]
        ).read_bytes()
        with zipfile.ZipFile(io.BytesIO(submission_raw)) as archive:
            submission_entries = {
                name: archive.read(name) for name in archive.namelist()
            }
        submission_entries["artifacts/app-bundle.zip"] = rebuilt_bundle
        for name, value in rebuilt_entries.items():
            submission_entries[f"bundle/{name}"] = value
        metadata = json.loads(submission_entries["crypta-app-submission.json"])
        metadata["bundleDigest"] = hashlib.sha256(rebuilt_bundle).hexdigest()
        submission_entries["crypta-app-submission.json"] = (
            json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        row = copy.deepcopy(self.fixture.contract["cohort"][0])
        row.update(
            {
                "appId": self.fixture.contract["externalApp"]["appId"],
                "publisherKeyId": self.fixture.contract["externalApp"]["publisherKeyId"],
                "bundleDigest": digest(rebuilt_bundle),
                "bundleSignatureDigest": digest(signature_bytes),
            }
        )

        bundle_errors, _manifest_digest = pilot._bundle_errors(
            rebuilt_bundle,
            row,
            self.fixture.contract,
            self.policy,
        )
        submission_errors = pilot._submission_errors(
            zip_bytes(submission_entries),
            row,
            rebuilt_bundle,
            self.policy,
            allow_non_production=True,
        )

        self.assertEqual([], bundle_errors)
        self.assertIn(
            "submission package omits required review evidence: review/permission-rationale.md",
            submission_errors,
        )
        self.assertIn(
            "submission metadata requestedPermissions differs from the reviewed bundle",
            submission_errors,
        )

    def test_bundle_when_signed_manifest_is_not_apphost_launchable_expect_failure(self) -> None:
        handoff = self.fixture.load_evidence("externalHandoff")
        artifact = handoff["cohort"][0]
        raw = (self.fixture.evidence / artifact["bundleFile"]).read_bytes()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        manifest = entries["cryptad-app.properties"].decode()
        entries["cryptad-app.properties"] = "\n".join(
            line for line in manifest.splitlines() if not line.startswith("app.exec=")
        ).encode() + b"\n"
        payload_names = sorted(
            set(entries).difference({"cryptad-app.digests", "cryptad-app.signature"})
        )
        digest_lines = ["digest.version=1", "digest.algorithm=SHA-256"]
        for index, name in enumerate(payload_names):
            digest_lines.extend(
                (
                    f"file.{index}.path={name}",
                    f"file.{index}.sha256={hashlib.sha256(entries[name]).hexdigest()}",
                )
            )
        digest_bytes = ("\n".join(digest_lines) + "\n").encode()
        publisher_seed, publisher_public = self.fixture.material["publisher"]
        signature_bytes = (
            "signature.version=1\n"
            "signature.algorithm=Ed25519\n"
            f"signature.key.id={self.fixture.contract['externalApp']['publisherKeyId']}\n"
            "signature.payload=cryptad-app.digests\n"
            f"signature.value.base64={signature(publisher_seed, publisher_public, digest_bytes)}\n"
        ).encode()
        entries["cryptad-app.digests"] = digest_bytes
        entries["cryptad-app.signature"] = signature_bytes
        row = copy.deepcopy(self.fixture.contract["cohort"][0])
        row["bundleSignatureDigest"] = digest(signature_bytes)

        errors, _manifest = pilot._bundle_errors(
            zip_bytes(entries),
            row,
            self.fixture.contract,
            self.policy,
        )

        self.assertIn("bundle manifest omits a required AppHost field", errors)

    def test_bundle_when_signed_text_payload_contains_secret_expect_redaction_failure(
        self,
    ) -> None:
        handoff = self.fixture.load_evidence("externalHandoff")
        artifact = handoff["cohort"][0]
        raw = (self.fixture.evidence / artifact["bundleFile"]).read_bytes()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        entries["web/index.html"] = (
            b"<pre>-----BEGIN PRIVATE KEY-----\nnot-public-material\n</pre>"
        )
        tampered, signature_bytes = self.rebuild_signed_bundle(entries)
        row = copy.deepcopy(self.fixture.contract["cohort"][0])
        row["bundleSignatureDigest"] = digest(signature_bytes)

        errors, _manifest = pilot._bundle_errors(
            tampered,
            row,
            self.fixture.contract,
            self.policy,
        )

        self.assertIn(
            "bundle member contains prohibited material: web/index.html",
            errors,
        )

    def test_bundle_when_nested_archive_has_neutral_name_expect_failure(self) -> None:
        handoff = self.fixture.load_evidence("externalHandoff")
        artifact = handoff["cohort"][0]
        raw = (self.fixture.evidence / artifact["bundleFile"]).read_bytes()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        entries["web/credentials.dat"] = zip_bytes(
            {"publisher.bin": self.pkcs8_ed25519_private_key()}
        )
        rebuilt, signature_bytes = self.rebuild_signed_bundle(entries)
        row = copy.deepcopy(self.fixture.contract["cohort"][0])
        row["bundleSignatureDigest"] = digest(signature_bytes)

        errors, _manifest = pilot._bundle_errors(
            rebuilt,
            row,
            self.fixture.contract,
            self.policy,
        )

        self.assertIn(
            "bundle member is an unexpected nested archive: web/credentials.dat",
            errors,
        )

    def test_archive_container_when_compressed_secret_has_neutral_name_expect_detected(
        self,
    ) -> None:
        compressed = gzip.compress(self.pkcs8_ed25519_private_key(), mtime=0)

        kind = pilot._archive_container_kind(compressed)

        self.assertEqual("gzip", kind)

    def test_archive_container_when_zip_marker_is_incidental_expect_not_detected(
        self,
    ) -> None:
        value = b"ordinary payload with PK\x03\x04 bytes but no archive structure"

        kind = pilot._archive_container_kind(value)

        self.assertIsNone(kind)

    def test_bundle_when_signed_binary_payload_contains_private_key_expect_failure(
        self,
    ) -> None:
        handoff = self.fixture.load_evidence("externalHandoff")
        artifact = handoff["cohort"][0]
        raw = (self.fixture.evidence / artifact["bundleFile"]).read_bytes()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        entries["web/publisher.bin"] = self.pkcs8_ed25519_private_key()
        tampered, signature_bytes = self.rebuild_signed_bundle(entries)
        row = copy.deepcopy(self.fixture.contract["cohort"][0])
        row["bundleSignatureDigest"] = digest(signature_bytes)

        errors, _manifest = pilot._bundle_errors(
            tampered,
            row,
            self.fixture.contract,
            self.policy,
        )

        self.assertIn(
            "bundle member contains prohibited binary material: web/publisher.bin",
            errors,
        )

    def test_bundle_when_interpreted_launcher_claims_executable_metadata_expect_failure(
        self,
    ) -> None:
        handoff = self.fixture.load_evidence("externalHandoff")
        artifact = handoff["cohort"][0]
        raw = (self.fixture.evidence / artifact["bundleFile"]).read_bytes()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        tampered, signature_bytes = self.rebuild_signed_bundle(
            entries,
            executable_paths=frozenset({"bin/run.sh"}),
        )
        row = copy.deepcopy(self.fixture.contract["cohort"][0])
        row["bundleSignatureDigest"] = digest(signature_bytes)

        errors, _manifest = pilot._bundle_errors(
            tampered,
            row,
            self.fixture.contract,
            self.policy,
        )

        self.assertIn("bundle executable metadata mismatch for bin/run.sh", errors)

    def test_bundle_when_posix_launcher_omits_executable_metadata_expect_failure(self) -> None:
        handoff = self.fixture.load_evidence("externalHandoff")
        artifact = handoff["cohort"][0]
        raw = (self.fixture.evidence / artifact["bundleFile"]).read_bytes()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        entries["cryptad-app.properties"] = entries[
            "cryptad-app.properties"
        ].replace(b"app.exec=bin/run.sh", b"app.exec=bin/run")
        entries.pop("bin/run.sh")
        entries["bin/run"] = b"native-launcher\n"
        tampered, signature_bytes = self.rebuild_signed_bundle(
            entries,
            modes={"bin/run": 0o755},
        )
        row = copy.deepcopy(self.fixture.contract["cohort"][0])
        row["bundleSignatureDigest"] = digest(signature_bytes)

        errors, _manifest = pilot._bundle_errors(
            tampered,
            row,
            self.fixture.contract,
            self.policy,
        )

        self.assertIn("bundle executable metadata mismatch for bin/run", errors)

    def test_bundle_when_posix_launcher_authenticates_executable_metadata_expect_pass(
        self,
    ) -> None:
        handoff = self.fixture.load_evidence("externalHandoff")
        artifact = handoff["cohort"][0]
        raw = (self.fixture.evidence / artifact["bundleFile"]).read_bytes()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        entries["cryptad-app.properties"] = entries[
            "cryptad-app.properties"
        ].replace(b"app.exec=bin/run.sh", b"app.exec=bin/run")
        entries.pop("bin/run.sh")
        entries["bin/run"] = b"native-launcher\n"
        rebuilt, signature_bytes = self.rebuild_signed_bundle(
            entries,
            executable_paths=frozenset({"bin/run"}),
            modes={"bin/run": 0o755},
        )
        row = copy.deepcopy(self.fixture.contract["cohort"][0])
        row["bundleSignatureDigest"] = digest(signature_bytes)

        errors, _manifest = pilot._bundle_errors(
            rebuilt,
            row,
            self.fixture.contract,
            self.policy,
        )

        self.assertEqual([], errors)

    def test_submission_when_private_key_is_embedded_expect_redaction_failure(self) -> None:
        handoff = self.fixture.load_evidence("externalHandoff")
        artifact = handoff["cohort"][0]
        raw = (self.fixture.evidence / artifact["submissionFile"]).read_bytes()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        entries["review/private.md"] = b"-----BEGIN PRIVATE KEY-----\nredacted-no\n"
        tampered = zip_bytes(entries)
        bundle_raw = (self.fixture.evidence / artifact["bundleFile"]).read_bytes()
        row = copy.deepcopy(self.fixture.contract["cohort"][0])
        row["appId"] = self.fixture.contract["externalApp"]["appId"]
        row["publisherKeyId"] = self.fixture.contract["externalApp"]["publisherKeyId"]

        errors = pilot._submission_errors(
            tampered,
            row,
            bundle_raw,
            self.policy,
        )

        self.assertIn(
            "submission member contains prohibited material: review/private.md",
            errors,
        )

    def test_submission_when_fixture_uses_canonical_package_expect_structural_pass(self) -> None:
        handoff = self.fixture.load_evidence("externalHandoff")
        artifact = handoff["cohort"][0]
        submission_raw = (self.fixture.evidence / artifact["submissionFile"]).read_bytes()
        bundle_raw = (self.fixture.evidence / artifact["bundleFile"]).read_bytes()
        row = copy.deepcopy(self.fixture.contract["cohort"][0])
        row.update(
            {
                "appId": self.fixture.contract["externalApp"]["appId"],
                "publisherKeyId": self.fixture.contract["externalApp"]["publisherKeyId"],
                "sourceRepositoryIdentity": self.fixture.contract["externalApp"]["source"][
                    "repositoryIdentity"
                ],
                "sourceRevision": self.fixture.contract["externalApp"]["source"][
                    "revision"
                ],
            }
        )

        errors = pilot._submission_errors(
            submission_raw,
            row,
            bundle_raw,
            self.policy,
            allow_non_production=True,
        )

        self.assertEqual([], errors)

    def test_submission_when_reviewed_bundle_tree_is_missing_expect_failure(self) -> None:
        handoff = self.fixture.load_evidence("externalHandoff")
        artifact = handoff["cohort"][0]
        submission_raw = (self.fixture.evidence / artifact["submissionFile"]).read_bytes()
        with zipfile.ZipFile(io.BytesIO(submission_raw)) as archive:
            entries = {
                name: archive.read(name)
                for name in archive.namelist()
                if name != "bundle/cryptad-app.properties"
            }
        bundle_raw = (self.fixture.evidence / artifact["bundleFile"]).read_bytes()
        row = copy.deepcopy(self.fixture.contract["cohort"][0])
        row.update(
            {
                "appId": self.fixture.contract["externalApp"]["appId"],
                "publisherKeyId": self.fixture.contract["externalApp"]["publisherKeyId"],
            }
        )

        errors = pilot._submission_errors(
            zip_bytes(entries),
            row,
            bundle_raw,
            self.policy,
            allow_non_production=True,
        )

        self.assertIn(
            "submission reviewed bundle tree differs from the packaged app bundle",
            errors,
        )
        self.assertIn("submission reviewed bundle omits required sidecars", errors)

    def test_submission_when_reviewed_bundle_bytes_differ_expect_failure(self) -> None:
        handoff = self.fixture.load_evidence("externalHandoff")
        artifact = handoff["cohort"][0]
        submission_raw = (self.fixture.evidence / artifact["submissionFile"]).read_bytes()
        with zipfile.ZipFile(io.BytesIO(submission_raw)) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        entries["bundle/web/index.html"] = b"different-reviewed-content"
        bundle_raw = (self.fixture.evidence / artifact["bundleFile"]).read_bytes()
        row = copy.deepcopy(self.fixture.contract["cohort"][0])
        row.update(
            {
                "appId": self.fixture.contract["externalApp"]["appId"],
                "publisherKeyId": self.fixture.contract["externalApp"]["publisherKeyId"],
            }
        )

        errors = pilot._submission_errors(
            zip_bytes(entries),
            row,
            bundle_raw,
            self.policy,
            allow_non_production=True,
        )

        self.assertIn(
            "submission reviewed bundle bytes differ for web/index.html",
            errors,
        )

    def test_submission_when_source_revision_differs_expect_failure(self) -> None:
        handoff = self.fixture.load_evidence("externalHandoff")
        artifact = handoff["cohort"][0]
        submission_raw = (self.fixture.evidence / artifact["submissionFile"]).read_bytes()
        with zipfile.ZipFile(io.BytesIO(submission_raw)) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        metadata = json.loads(entries["crypta-app-submission.json"])
        metadata["sourceReference"]["revision"] = "c" * 40
        entries["crypta-app-submission.json"] = (
            json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        bundle_raw = (self.fixture.evidence / artifact["bundleFile"]).read_bytes()
        row = copy.deepcopy(self.fixture.contract["cohort"][0])
        row.update(
            {
                "appId": self.fixture.contract["externalApp"]["appId"],
                "publisherKeyId": self.fixture.contract["externalApp"]["publisherKeyId"],
                "sourceRepositoryIdentity": self.fixture.contract["externalApp"]["source"][
                    "repositoryIdentity"
                ],
                "sourceRevision": self.fixture.contract["externalApp"]["source"][
                    "revision"
                ],
            }
        )

        errors = pilot._submission_errors(
            zip_bytes(entries),
            row,
            bundle_raw,
            self.policy,
            allow_non_production=True,
        )

        self.assertIn(
            "submission source revision differs from the authenticated source",
            errors,
        )

    def test_submission_when_redaction_digest_differs_expect_failure(self) -> None:
        handoff = self.fixture.load_evidence("externalHandoff")
        artifact = handoff["cohort"][0]
        submission_raw = (self.fixture.evidence / artifact["submissionFile"]).read_bytes()
        with zipfile.ZipFile(io.BytesIO(submission_raw)) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        metadata = json.loads(entries["crypta-app-submission.json"])
        metadata["redactionScanDigest"] = "0" * 64
        entries["crypta-app-submission.json"] = (
            json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        bundle_raw = (self.fixture.evidence / artifact["bundleFile"]).read_bytes()
        row = copy.deepcopy(self.fixture.contract["cohort"][0])
        row.update(
            {
                "appId": self.fixture.contract["externalApp"]["appId"],
                "publisherKeyId": self.fixture.contract["externalApp"]["publisherKeyId"],
            }
        )

        errors = pilot._submission_errors(
            zip_bytes(entries),
            row,
            bundle_raw,
            self.policy,
            allow_non_production=True,
        )

        self.assertIn("submission redaction scan digest differs", errors)

    def test_submission_when_manifest_projection_differs_expect_failure(self) -> None:
        handoff = self.fixture.load_evidence("externalHandoff")
        artifact = handoff["cohort"][0]
        submission_raw = (self.fixture.evidence / artifact["submissionFile"]).read_bytes()
        with zipfile.ZipFile(io.BytesIO(submission_raw)) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        metadata = json.loads(entries["crypta-app-submission.json"])
        metadata["apiTargetStability"] = "experimental"
        entries["crypta-app-submission.json"] = (
            json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        bundle_raw = (self.fixture.evidence / artifact["bundleFile"]).read_bytes()
        row = copy.deepcopy(self.fixture.contract["cohort"][0])
        row.update(
            {
                "appId": self.fixture.contract["externalApp"]["appId"],
                "publisherKeyId": self.fixture.contract["externalApp"]["publisherKeyId"],
            }
        )

        errors = pilot._submission_errors(
            zip_bytes(entries),
            row,
            bundle_raw,
            self.policy,
            allow_non_production=True,
        )

        self.assertIn(
            "submission metadata apiTargetStability differs from the reviewed bundle",
            errors,
        )

    def test_submission_when_secret_uses_non_text_suffix_expect_redaction_failure(self) -> None:
        handoff = self.fixture.load_evidence("externalHandoff")
        artifact = handoff["cohort"][0]
        raw = (self.fixture.evidence / artifact["submissionFile"]).read_bytes()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        entries["metadata/publisher.pem"] = (
            b"-----BEGIN PRIVATE KEY-----\nnot-public-material\n"
        )
        bundle_raw = (self.fixture.evidence / artifact["bundleFile"]).read_bytes()
        row = copy.deepcopy(self.fixture.contract["cohort"][0])
        row["appId"] = self.fixture.contract["externalApp"]["appId"]
        row["publisherKeyId"] = self.fixture.contract["externalApp"]["publisherKeyId"]

        errors = pilot._submission_errors(
            zip_bytes(entries),
            row,
            bundle_raw,
            self.policy,
        )

        self.assertIn(
            "submission member contains prohibited material: metadata/publisher.pem",
            errors,
        )

    def test_submission_when_binary_private_key_has_opaque_name_expect_failure(self) -> None:
        handoff = self.fixture.load_evidence("externalHandoff")
        artifact = handoff["cohort"][0]
        raw = (self.fixture.evidence / artifact["submissionFile"]).read_bytes()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        entries["metadata/publisher.bin"] = self.pkcs8_ed25519_private_key()
        bundle_raw = (self.fixture.evidence / artifact["bundleFile"]).read_bytes()
        row = copy.deepcopy(self.fixture.contract["cohort"][0])
        row["appId"] = self.fixture.contract["externalApp"]["appId"]
        row["publisherKeyId"] = self.fixture.contract["externalApp"]["publisherKeyId"]

        errors = pilot._submission_errors(
            zip_bytes(entries),
            row,
            bundle_raw,
            self.policy,
        )

        self.assertIn(
            "submission member contains prohibited binary material: metadata/publisher.bin",
            errors,
        )

    def test_submission_when_nested_archive_has_neutral_name_expect_failure(self) -> None:
        handoff = self.fixture.load_evidence("externalHandoff")
        artifact = handoff["cohort"][0]
        raw = (self.fixture.evidence / artifact["submissionFile"]).read_bytes()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        entries["metadata/credentials.dat"] = zip_bytes(
            {"publisher.bin": self.pkcs8_ed25519_private_key()}
        )
        metadata = json.loads(entries["crypta-app-submission.json"])
        metadata["redactionScanDigest"] = pilot._submission_redaction_digest(
            set(entries)
        )
        entries["crypta-app-submission.json"] = (
            json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        bundle_raw = (self.fixture.evidence / artifact["bundleFile"]).read_bytes()
        row = copy.deepcopy(self.fixture.contract["cohort"][0])
        row["appId"] = self.fixture.contract["externalApp"]["appId"]
        row["publisherKeyId"] = self.fixture.contract["externalApp"]["publisherKeyId"]

        errors = pilot._submission_errors(
            zip_bytes(entries),
            row,
            bundle_raw,
            self.policy,
        )

        self.assertIn(
            "submission package contains an unexpected nested archive: metadata/credentials.dat",
            errors,
        )

    def test_archive_when_member_traverses_expect_rejected_before_read(self) -> None:
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            info = zipfile.ZipInfo("../escape")
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, b"escape")

        with zipfile.ZipFile(io.BytesIO(output.getvalue())) as archive:
            with self.assertRaisesRegex(ValueError, "unsafe archive member"):
                pilot._members(archive, "submission", self.policy, stored=True)

    def test_review_when_rejected_candidate_is_marked_eligible_expect_fail_closed(self) -> None:
        review = self.fixture.load_evidence("reviewCohort")
        rejected = next(row for row in review["rows"] if row["cohortId"] == "version-2-rejected")
        rejected["candidateEligible"] = True
        seal_receipt(review, *self.fixture.material["app-reviewer"])
        self.fixture.replace_evidence("reviewCohort", review)

        result, summary = self.run_mode("verify-review-cohort")

        self.assertEqual(1, result)
        self.assertIn(
            "candidate-eligibility-is-invalid-for-version-2-rejected",
            summary["blockers"],
        )

    def test_review_when_assignment_record_is_missing_expect_fail_closed(self) -> None:
        review = self.fixture.load_evidence("reviewCohort")
        review["transparencyRecords"] = [
            record
            for record in review["transparencyRecords"]
            if record["recordId"]
            != "submission-v1-fixture:reviewer_assigned"
        ]
        self.replace_review_and_reseal(review)

        result, summary = self.run_mode("verify-review-cohort")

        self.assertEqual(1, result)
        self.assertIn(
            "review-transparency-requires-one-reviewer-assignment-for-version-1-reviewed",
            summary["blockers"],
        )

    def test_review_when_assignment_digest_is_substituted_expect_fail_closed(self) -> None:
        review = self.fixture.load_evidence("reviewCohort")
        review["assignmentDigest"] = digest("substituted-assignment")
        seal_receipt(review, *self.fixture.material["app-reviewer"])
        self.fixture.replace_evidence("reviewCohort", review)

        result, summary = self.run_mode("verify-review-cohort")

        self.assertEqual(1, result)
        self.assertIn(
            "review-transparency-assignment-binding-differs-for-version-1-reviewed",
            summary["blockers"],
        )

    def test_review_when_pre_review_record_is_missing_expect_fail_closed(self) -> None:
        review = self.fixture.load_evidence("reviewCohort")
        review["transparencyRecords"] = [
            record
            for record in review["transparencyRecords"]
            if record["recordId"]
            != "submission-v1-fixture:pre_review_completed"
        ]
        self.replace_review_and_reseal(review)

        result, summary = self.run_mode("verify-review-cohort")

        self.assertEqual(1, result)
        self.assertIn(
            "review-transparency-requires-one-completed-pre-review-for-version-1-reviewed",
            summary["blockers"],
        )

    def test_review_when_pre_review_digest_is_substituted_expect_fail_closed(self) -> None:
        review = self.fixture.load_evidence("reviewCohort")
        pre_review = next(
            record
            for record in review["transparencyRecords"]
            if record["recordId"]
            == "submission-v1-fixture:pre_review_completed"
        )
        pre_review["evidenceSha256"] = digest("substituted-pre-review").removeprefix(
            "sha256:"
        )
        self.replace_review_and_reseal(review)

        result, summary = self.run_mode("verify-review-cohort")

        self.assertEqual(1, result)
        self.assertIn(
            "review-transparency-pre-review-binding-differs-for-version-1-reviewed",
            summary["blockers"],
        )

    def test_review_when_decision_record_is_missing_expect_fail_closed(self) -> None:
        review = self.fixture.load_evidence("reviewCohort")
        review["transparencyRecords"] = [
            record
            for record in review["transparencyRecords"]
            if record["recordId"]
            != "submission-v1-fixture:review_decision_recorded"
        ]
        self.replace_review_and_reseal(review)

        result, summary = self.run_mode("verify-review-cohort")

        self.assertEqual(1, result)
        self.assertIn(
            "review-transparency-requires-one-recorded-decision-for-version-1-reviewed",
            summary["blockers"],
        )

    def test_review_when_prerequisites_are_reordered_expect_fail_closed(self) -> None:
        review = self.fixture.load_evidence("reviewCohort")
        records = review["transparencyRecords"]
        assignment_index = next(
            index
            for index, record in enumerate(records)
            if record["recordId"]
            == "submission-v1-fixture:reviewer_assigned"
        )
        pre_review_index = next(
            index
            for index, record in enumerate(records)
            if record["recordId"]
            == "submission-v1-fixture:pre_review_completed"
        )
        records[assignment_index], records[pre_review_index] = (
            records[pre_review_index],
            records[assignment_index],
        )
        self.replace_review_and_reseal(review)

        result, summary = self.run_mode("verify-review-cohort")

        self.assertEqual(1, result)
        self.assertIn(
            "review-transparency-prerequisites-are-out-of-order-for-version-1-reviewed",
            summary["blockers"],
        )

    def test_review_when_completion_predates_authenticated_handoff_expect_fail_closed(self) -> None:
        review = self.fixture.load_evidence("reviewCohort")
        reviewed_at = "2026-08-23T11:59:59Z"
        reviewer_seed, reviewer_public = self.fixture.material["app-reviewer"]
        for row in review["rows"]:
            receipt = row["standardReviewReceipt"]
            if receipt is None:
                continue
            receipt["reviewedAt"] = reviewed_at
            receipt["signatureBase64"] = signature(
                reviewer_seed,
                reviewer_public,
                pilot._standard_review_receipt_payload(receipt),
            )
            row["standardReviewReceiptDigest"] = digest(
                pilot._standard_review_receipt_bytes(receipt)
            )
        review["reviewedAt"] = reviewed_at
        seal_receipt(review, reviewer_seed, reviewer_public)
        self.fixture.replace_evidence("reviewCohort", review)

        result, summary = self.run_mode("verify-review-cohort")

        self.assertEqual(1, result)
        self.assertIn(
            "review-cohort-predates-authenticated-workload-handoff",
            summary["blockers"],
        )
        self.assertIn(
            "review-cohort-predates-developer-attestation-for-version-1-reviewed",
            summary["blockers"],
        )

    def test_review_when_caution_allowance_is_missing_expect_fail_closed(self) -> None:
        review = self.fixture.load_evidence("reviewCohort")
        caution = next(row for row in review["rows"] if row["cohortId"] == "version-3-caution")
        caution["cautionAllowance"] = False
        seal_receipt(review, *self.fixture.material["app-reviewer"])
        self.fixture.replace_evidence("reviewCohort", review)

        result, summary = self.run_mode("verify-review-cohort")

        self.assertEqual(1, result)
        self.assertIn(
            "caution-decision-omits-warnings-or-explicit-candidate-allowance",
            summary["blockers"],
        )

    def test_publication_when_review_cohort_membership_is_invalid_expect_bounded_failure(
        self,
    ) -> None:
        review = self.fixture.load_evidence("reviewCohort")
        for index, row in enumerate(review["rows"]):
            row["cohortId"] = f"unexpected-cohort-{index}"
        seal_receipt(review, *self.fixture.material["app-reviewer"])
        self.fixture.replace_evidence("reviewCohort", review)

        result, summary = self.run_mode("verify-catalog-publication")

        self.assertEqual(1, result)
        self.assertIn(
            "review-cohort-is-incomplete-or-reordered", summary["blockers"]
        )
        self.assertIn(
            "catalog-publication-validation-blocked-by-invalid-review-cohort",
            summary["blockers"],
        )
        self.assertFalse(summary["betaCatalogPublished"])

    def test_publication_when_nested_review_receipt_is_malformed_expect_bounded_failure(
        self,
    ) -> None:
        review = self.fixture.load_evidence("reviewCohort")
        reviewed = next(
            row for row in review["rows"] if row["cohortId"] == "version-1-reviewed"
        )
        del reviewed["standardReviewReceipt"]["reviewerKeyId"]
        seal_receipt(review, *self.fixture.material["app-reviewer"])
        self.fixture.replace_evidence("reviewCohort", review)

        result, summary = self.run_mode("verify-catalog-publication")

        self.assertEqual(1, result)
        self.assertIn(
            "rows-0-standardreviewreceipt-does-not-match-exactly-one-allowed-schema-shape",
            summary["blockers"],
        )
        self.assertIn(
            "catalog-publication-validation-blocked-by-invalid-review-cohort",
            summary["blockers"],
        )
        self.assertFalse(summary["betaCatalogPublished"])

    def test_review_when_resubmission_reuses_stale_digest_expect_preflight_failure(self) -> None:
        rows = {row["cohortId"]: row for row in self.fixture.contract["cohort"]}
        rows["version-2-corrected"]["preReviewDigest"] = rows["version-2-rejected"]["preReviewDigest"]
        self.fixture.reload_contract()

        result, summary = self.run_mode("preflight")

        self.assertEqual(1, result)
        self.assertIn(
            "corrected-resubmission-reuses-stale-prereviewdigest",
            summary["blockers"],
        )

    def test_preflight_when_version_2_identity_changes_expect_fail_closed(self) -> None:
        rows = {row["cohortId"]: row for row in self.fixture.contract["cohort"]}
        rows["version-2-rejected"]["appVersion"] = "2.0.1"
        self.fixture.reload_contract()

        result, summary = self.run_mode("preflight")

        self.assertEqual(1, result)
        self.assertIn(
            "initial-and-corrected-version-2-app-versions-differ",
            summary["blockers"],
        )

    def test_preflight_when_corrected_version_descends_expect_fail_closed(self) -> None:
        rows = {row["cohortId"]: row for row in self.fixture.contract["cohort"]}
        rows["version-1-reviewed"]["appVersion"] = "4.0.0"
        self.fixture.reload_contract()

        result, summary = self.run_mode("preflight")

        self.assertEqual(1, result)
        self.assertIn(
            "corrected-version-2-does-not-strictly-advance-the-app-version",
            summary["blockers"],
        )

    def test_preflight_when_normal_and_pilot_registry_roots_match_expect_fail_closed(
        self,
    ) -> None:
        node = self.fixture.contract["protectedPilotNode"]
        node["pilotRegistryDigest"] = node["normalStableRegistryDigest"]
        self.fixture.reload_contract()

        result, summary = self.run_mode("preflight")

        self.assertEqual(1, result)
        self.assertIn(
            "normal-stable-catalog-and-pilot-registry-digests-are-not-distinct",
            summary["blockers"],
        )

    def test_preflight_when_catalog_registry_is_not_pr293_projection_expect_fail_closed(
        self,
    ) -> None:
        self.fixture.contract["protectedPilotNode"]["catalogRegistryDigest"] = digest(
            "substituted-catalog-registry"
        )
        self.fixture.reload_contract()

        result, summary = self.run_mode("preflight")

        self.assertEqual(1, result)
        self.assertIn(
            "pilot-catalog-registry-digest-is-not-the-canonical-authenticated-pr-293-projection",
            summary["blockers"],
        )

    def test_preflight_when_caution_version_is_numerically_equal_expect_fail_closed(
        self,
    ) -> None:
        rows = {row["cohortId"]: row for row in self.fixture.contract["cohort"]}
        rows["version-3-caution"]["appVersion"] = "2.0.0.0"
        self.fixture.reload_contract()

        result, summary = self.run_mode("preflight")

        self.assertEqual(1, result)
        self.assertIn(
            "caution-version-3-does-not-strictly-advance-the-app-version",
            summary["blockers"],
        )

    def test_preflight_when_version_component_exceeds_java_integer_expect_fail_closed(
        self,
    ) -> None:
        rows = {row["cohortId"]: row for row in self.fixture.contract["cohort"]}
        rows["version-3-caution"]["appVersion"] = "2147483648.0"
        self.fixture.reload_contract()

        result, summary = self.run_mode("preflight")

        self.assertEqual(1, result)
        self.assertIn(
            "pilot-cohort-app-versions-are-not-appupdateservice-compatible",
            summary["blockers"],
        )

    def test_preflight_when_version_uses_prerelease_segment_expect_schema_rejection(
        self,
    ) -> None:
        rows = {row["cohortId"]: row for row in self.fixture.contract["cohort"]}
        rows["version-3-caution"]["appVersion"] = "3.0.0-rc1"
        self.fixture.reload_contract()

        with self.assertRaisesRegex(ValueError, "closed schema"):
            self.run_mode("preflight")

    def test_review_when_negative_row_carries_standard_receipt_expect_fail_closed(
        self,
    ) -> None:
        review = self.fixture.load_evidence("reviewCohort")
        rejected = next(
            row for row in review["rows"] if row["cohortId"] == "version-2-rejected"
        )
        reviewed = next(
            row for row in review["rows"] if row["cohortId"] == "version-1-reviewed"
        )
        rejected["standardReviewReceipt"] = copy.deepcopy(
            reviewed["standardReviewReceipt"]
        )
        rejected["standardReviewReceiptDigest"] = reviewed[
            "standardReviewReceiptDigest"
        ]
        seal_receipt(review, *self.fixture.material["app-reviewer"])
        self.fixture.replace_evidence("reviewCohort", review)

        result, summary = self.run_mode("verify-review-cohort")

        self.assertEqual(1, result)
        self.assertIn(
            "negative-review-row-must-not-carry-a-standard-receipt-for-version-2-rejected",
            summary["blockers"],
        )

    def test_review_when_receipts_precede_cohort_completion_expect_allowed(self) -> None:
        review = self.fixture.load_evidence("reviewCohort")
        review["reviewedAt"] = "2026-08-23T12:01:00Z"
        self.fixture.contract["evaluationTime"] = "2026-08-23T12:02:00Z"
        seal_receipt(review, *self.fixture.material["app-reviewer"])
        self.fixture.replace_evidence("reviewCohort", review)

        result, summary = self.run_mode("verify-review-cohort")

        self.assertEqual(0, result)
        self.assertEqual("pass", summary["status"])

    def test_review_when_receipt_follows_cohort_completion_expect_fail_closed(self) -> None:
        review = self.fixture.load_evidence("reviewCohort")
        reviewed = next(
            row for row in review["rows"] if row["cohortId"] == "version-1-reviewed"
        )
        receipt = reviewed["standardReviewReceipt"]
        receipt["reviewedAt"] = "2026-08-23T12:00:01Z"
        reviewer_seed, reviewer_public = self.fixture.material["app-reviewer"]
        receipt["signatureBase64"] = signature(
            reviewer_seed,
            reviewer_public,
            pilot._standard_review_receipt_payload(receipt),
        )
        reviewed["standardReviewReceiptDigest"] = digest(
            pilot._standard_review_receipt_bytes(receipt)
        )
        self.fixture.contract["evaluationTime"] = "2026-08-23T12:00:02Z"
        seal_receipt(review, reviewer_seed, reviewer_public)
        self.fixture.replace_evidence("reviewCohort", review)

        result, summary = self.run_mode("verify-review-cohort")

        self.assertEqual(1, result)
        self.assertIn(
            "standard-review-receipt-follows-cohort-completion-for-version-1-reviewed",
            summary["blockers"],
        )

    def test_review_when_optional_receipt_expiry_has_elapsed_expect_fail_closed(
        self,
    ) -> None:
        review = self.fixture.load_evidence("reviewCohort")
        reviewed = next(
            row for row in review["rows"] if row["cohortId"] == "version-1-reviewed"
        )
        receipt = reviewed["standardReviewReceipt"]
        receipt["expiresAt"] = "2026-08-23T12:00:00Z"
        reviewer_seed, reviewer_public = self.fixture.material["app-reviewer"]
        receipt["signatureBase64"] = signature(
            reviewer_seed,
            reviewer_public,
            pilot._standard_review_receipt_payload(receipt),
        )
        reviewed["standardReviewReceiptDigest"] = digest(
            pilot._standard_review_receipt_bytes(receipt)
        )
        seal_receipt(review, reviewer_seed, reviewer_public)
        self.fixture.replace_evidence("reviewCohort", review)

        result, summary = self.run_mode("verify-review-cohort")

        self.assertEqual(1, result)
        self.assertIn(
            "standard-review-receipt-is-expired-for-version-1-reviewed",
            summary["blockers"],
        )

    def test_review_when_transparency_head_is_zero_expect_fail_closed(self) -> None:
        review = self.fixture.load_evidence("reviewCohort")
        review["transparencyHead"] = pilot.ZERO_DIGEST
        seal_receipt(review, *self.fixture.material["app-reviewer"])
        self.fixture.replace_evidence("reviewCohort", review)

        result, summary = self.run_mode("verify-review-cohort")

        self.assertEqual(1, result)
        self.assertIn(
            "review-transparency-lineage-is-incomplete",
            summary["blockers"],
        )

    def test_review_when_standard_receipt_signature_is_substituted_expect_fail_closed(self) -> None:
        review = self.fixture.load_evidence("reviewCohort")
        reviewed = next(
            row
            for row in review["rows"]
            if row["cohortId"] == "version-1-reviewed"
        )
        reviewed["standardReviewReceipt"]["signatureBase64"] = base64.b64encode(
            b"x" * 64
        ).decode()
        reviewed["standardReviewReceiptDigest"] = digest(
            pilot._standard_review_receipt_bytes(
                reviewed["standardReviewReceipt"]
            )
        )
        seal_receipt(review, *self.fixture.material["app-reviewer"])
        self.fixture.replace_evidence("reviewCohort", review)

        result, summary = self.run_mode("verify-review-cohort")

        self.assertEqual(1, result)
        self.assertIn(
            "standard-review-receipt-version-1-reviewed-signature-does-not-verify",
            summary["blockers"],
        )

    def test_review_when_transparency_predecessor_forks_expect_fail_closed(self) -> None:
        review = self.fixture.load_evidence("reviewCohort")
        review["transparencyRecords"][4]["previousRecordHash"] = "f" * 64
        review["transparencyLogDigest"] = digest(
            pilot._transparency_jsonl(review["transparencyRecords"])
        )
        seal_receipt(review, *self.fixture.material["app-reviewer"])
        self.fixture.replace_evidence("reviewCohort", review)

        result, summary = self.run_mode("verify-review-cohort")

        self.assertEqual(1, result)
        self.assertIn(
            "review-transparency-predecessor-differs-at-5",
            summary["blockers"],
        )

    def test_approval_when_wrong_app_is_authorized_expect_fail_closed(self) -> None:
        approval = self.fixture.load_evidence("publisherApproval")
        approval["appId"] = "org.external.unrelated"
        seal_receipt(approval, *self.fixture.material["app-reviewer"])
        self.fixture.replace_evidence("publisherApproval", approval)

        result, summary = self.run_mode("verify-review-cohort")

        self.assertEqual(1, result)
        self.assertIn("pilot-publisher-approval-appid-differs", summary["blockers"])

    def test_approval_when_catalog_registry_differs_expect_fail_closed(self) -> None:
        approval = self.fixture.load_evidence("publisherApproval")
        approval["catalogRegistryDigest"] = digest("substituted-catalog-registry")
        seal_receipt(approval, *self.fixture.material["app-reviewer"])
        self.fixture.replace_evidence("publisherApproval", approval)

        result, summary = self.run_mode("verify-review-cohort")

        self.assertEqual(1, result)
        self.assertIn(
            "pilot-publisher-approval-catalogregistrydigest-differs",
            summary["blockers"],
        )

    def test_approval_when_node_reuses_publisher_key_expect_fail_closed(self) -> None:
        approval = self.fixture.load_evidence("publisherApproval")
        approval["nodeAttestationFingerprint"] = self.fixture.contract["externalApp"][
            "publisherFingerprint"
        ]
        seal_receipt(approval, *self.fixture.material["app-reviewer"])
        self.fixture.replace_evidence("publisherApproval", approval)

        result, summary = self.run_mode("verify-review-cohort")

        self.assertEqual(1, result)
        self.assertIn(
            "pilot-node-attestation-key-is-not-role-distinct",
            summary["blockers"],
        )

    def test_node_attestation_when_any_existing_role_is_reused_expect_failure(
        self,
    ) -> None:
        fingerprints = {
            self.fixture.contract["externalApp"]["publisherFingerprint"],
            self.fixture.contract["externalApp"]["workloadProfile"][
                "workloadFingerprint"
            ],
            *(
                key["publicKeyFingerprintSha256"]
                for key in self.fixture.contract["authorities"]["keysetSubject"][
                    "keys"
                ]
            ),
        }

        for fingerprint in fingerprints:
            with self.subTest(fingerprint=fingerprint):
                self.assertEqual(
                    ["pilot node attestation key is not role-distinct"],
                    pilot._node_attestation_role_errors(
                        self.fixture.contract, fingerprint
                    ),
                )

    def test_approval_when_subject_bundle_drifts_expect_fail_closed(self) -> None:
        approval = self.fixture.load_evidence("publisherApproval")
        approval["permittedSubjects"][0]["bundleDigest"] = digest("wrong-bundle")
        seal_receipt(approval, *self.fixture.material["app-reviewer"])
        self.fixture.replace_evidence("publisherApproval", approval)

        result, summary = self.run_mode("verify-review-cohort")

        self.assertEqual(1, result)
        self.assertIn(
            "pilot-publisher-approval-does-not-bind-the-exact-eligible-subjects",
            summary["blockers"],
        )

    def test_approval_when_valid_but_older_than_freshness_window_expect_fail_closed(
        self,
    ) -> None:
        approval = self.fixture.load_evidence("publisherApproval")
        approval["validFrom"] = "2026-08-01T00:00:00Z"
        seal_receipt(approval, *self.fixture.material["app-reviewer"])
        self.fixture.replace_evidence("publisherApproval", approval)

        result, summary = self.run_mode("verify-review-cohort")

        self.assertEqual(1, result)
        self.assertIn("pilot-publisher-approval-is-stale", summary["blockers"])

    def test_publication_when_partial_is_resealed_expect_never_complete(self) -> None:
        publication = self.fixture.load_evidence("catalogPublication")
        publication["status"] = "partial"
        publication["partial"] = True
        seal_receipt(publication, *self.fixture.material["catalog-signing"])
        self.fixture.replace_evidence("catalogPublication", publication)

        result, summary = self.run_mode("verify-catalog-publication")

        self.assertEqual(1, result)
        self.assertEqual("partial", summary["status"])
        self.assertFalse(summary["betaCatalogPublished"])
        self.assertIn(
            "partial-or-failed-catalog-publication-cannot-advance-the-pilot",
            summary["blockers"],
        )

    def test_publication_when_mirror_subject_drifts_expect_fail_closed(self) -> None:
        publication = self.fixture.load_evidence("catalogPublication")
        publication["observations"][1]["subjectDigest"] = digest("stale-mirror")
        seal_receipt(publication, *self.fixture.material["catalog-signing"])
        self.fixture.replace_evidence("catalogPublication", publication)

        result, summary = self.run_mode("verify-catalog-publication")

        self.assertEqual(1, result)
        self.assertIn(
            "primary-and-mirrors-do-not-observe-the-exact-signed-catalog-subject",
            summary["blockers"],
        )

    def test_publication_when_all_observations_use_unrelated_subject_expect_fail_closed(self) -> None:
        publication = self.fixture.load_evidence("catalogPublication")
        for observation in publication["observations"]:
            observation["subjectDigest"] = digest("unrelated-catalog-subject")
            observation["signatureSiblingDigest"] = digest("unrelated-signature")
        seal_receipt(publication, *self.fixture.material["catalog-signing"])
        self.fixture.replace_evidence("catalogPublication", publication)

        result, summary = self.run_mode("verify-catalog-publication")

        self.assertEqual(1, result)
        self.assertIn(
            "primary-and-mirrors-do-not-observe-the-exact-signed-catalog-subject",
            summary["blockers"],
        )

    def test_publication_when_final_subject_differs_from_final_edition_expect_fail_closed(
        self,
    ) -> None:
        publication = self.fixture.load_evidence("catalogPublication")
        first_edition = publication["editions"][0]
        publication["publishedSubject"]["subjectDigest"] = first_edition[
            "subjectDigest"
        ]
        publication["publishedSubject"]["signatureSiblingDigest"] = first_edition[
            "signatureSiblingDigest"
        ]
        for observation in publication["observations"]:
            observation["subjectDigest"] = first_edition["subjectDigest"]
            observation["signatureSiblingDigest"] = first_edition[
                "signatureSiblingDigest"
            ]
        seal_receipt(publication, *self.fixture.material["catalog-signing"])
        self.fixture.replace_evidence("catalogPublication", publication)

        result, summary = self.run_mode("verify-catalog-publication")

        self.assertEqual(1, result)
        self.assertIn(
            "published-catalog-subject-does-not-bind-the-reviewed-edition-sequence",
            summary["blockers"],
        )

    def test_publication_when_editions_reuse_signed_subject_expect_fail_closed(
        self,
    ) -> None:
        publication = self.fixture.load_evidence("catalogPublication")
        publication["editions"][0]["subjectDigest"] = publication["editions"][1][
            "subjectDigest"
        ]
        publication["editions"][0]["signatureSiblingDigest"] = publication[
            "editions"
        ][1]["signatureSiblingDigest"]
        seal_receipt(publication, *self.fixture.material["catalog-signing"])
        self.fixture.replace_evidence("catalogPublication", publication)

        result, summary = self.run_mode("verify-catalog-publication")

        self.assertEqual(1, result)
        self.assertIn(
            "catalog-editions-do-not-bind-distinct-signed-subjects",
            summary["blockers"],
        )

    def test_publication_when_observation_is_stale_expect_fail_closed(self) -> None:
        publication = self.fixture.load_evidence("catalogPublication")
        publication["observations"][0]["observedAt"] = "2025-01-01T00:00:00Z"
        seal_receipt(publication, *self.fixture.material["catalog-signing"])
        self.fixture.replace_evidence("catalogPublication", publication)

        result, summary = self.run_mode("verify-catalog-publication")

        self.assertEqual(1, result)
        self.assertIn("catalog-observation-primary-is-stale", summary["blockers"])

    def test_publication_when_observation_is_in_future_expect_fail_closed(self) -> None:
        publication = self.fixture.load_evidence("catalogPublication")
        publication["observations"][0]["observedAt"] = "2026-08-24T12:00:00Z"
        seal_receipt(publication, *self.fixture.material["catalog-signing"])
        self.fixture.replace_evidence("catalogPublication", publication)

        result, summary = self.run_mode("verify-catalog-publication")

        self.assertEqual(1, result)
        self.assertIn("catalog-observation-primary-is-in-the-future", summary["blockers"])

    def test_publication_when_timestamp_predates_review_expect_fail_closed(self) -> None:
        publication = self.fixture.load_evidence("catalogPublication")
        publication["publishedAt"] = "2026-08-23T11:59:59Z"
        seal_receipt(publication, *self.fixture.material["catalog-signing"])
        self.fixture.replace_evidence("catalogPublication", publication)

        result, summary = self.run_mode("verify-catalog-publication")

        self.assertEqual(1, result)
        self.assertIn(
            "catalog-publication-predates-review-cohort-completion",
            summary["blockers"],
        )

    def test_publication_when_catalog_key_activates_after_publication_expect_fail_closed(
        self,
    ) -> None:
        self.fixture.contract["evaluationTime"] = "2026-08-23T12:02:00Z"
        catalog_key = self.authority("catalog-signing")
        catalog_key["validFrom"] = "2026-08-23T12:01:00Z"
        keyset_key = next(
            key
            for key in self.fixture.contract["authorities"]["keysetSubject"]["keys"]
            if key["keyId"] == catalog_key["keyId"]
        )
        keyset_key["validFrom"] = catalog_key["validFrom"]
        self.fixture.contract["authorities"]["keysetDigest"] = digest(
            pilot._canonical_bytes(
                self.fixture.contract["authorities"]["keysetSubject"]
            )
        )
        catalog_registry_digest = pilot._catalog_registry_digest(
            self.fixture.contract["authorities"]["keysetSubject"]
        )
        self.fixture.contract["protectedPilotNode"][
            "catalogRegistryDigest"
        ] = catalog_registry_digest
        approval = self.fixture.load_evidence("publisherApproval")
        approval["catalogRegistryDigest"] = catalog_registry_digest
        seal_receipt(approval, *self.fixture.material["app-reviewer"])
        self.fixture.replace_evidence("publisherApproval", approval)
        publication = self.fixture.load_evidence("catalogPublication")
        publication["keysetDigest"] = self.fixture.contract["authorities"][
            "keysetDigest"
        ]
        seal_receipt(publication, *self.fixture.material["catalog-signing"])
        self.fixture.replace_evidence("catalogPublication", publication)

        result, summary = self.run_mode("verify-catalog-publication")

        self.assertEqual(1, result)
        self.assertIn(
            "catalog-signing-key-was-not-valid-at-publication-time",
            summary["blockers"],
        )
        self.assertFalse(summary["betaCatalogPublished"])

    def test_runtime_when_caution_consent_is_missing_expect_fail_closed(self) -> None:
        runtime = self.fixture.load_evidence("runtimeDrill")
        consent = next(event for event in runtime["events"] if event["event"] == "caution-v3-consent-recorded")
        consent["consentSnapshotDigest"] = None
        seal_receipt(runtime, *self.fixture.material["node"])
        self.fixture.replace_evidence("runtimeDrill", runtime)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertFalse(summary["runtimeDrillComplete"])
        self.assertIn(
            "caution-consent-event-does-not-bind-the-exact-caution-subject",
            summary["blockers"],
        )

    def test_runtime_when_catalog_registry_differs_expect_fail_closed(self) -> None:
        runtime = self.fixture.load_evidence("runtimeDrill")
        runtime["catalogRegistryDigest"] = digest("substituted-catalog-registry")
        seal_receipt(runtime, *self.fixture.material["node"])
        self.fixture.replace_evidence("runtimeDrill", runtime)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertFalse(summary["runtimeDrillComplete"])
        self.assertIn(
            "runtime-receipt-uses-a-different-catalog-key-registry",
            summary["blockers"],
        )

    def test_runtime_when_normal_registry_differs_expect_fail_closed(self) -> None:
        runtime = self.fixture.load_evidence("runtimeDrill")
        runtime["normalStableRegistryDigest"] = digest(
            "substituted-normal-stable-registry"
        )
        seal_receipt(runtime, *self.fixture.material["node"])
        self.fixture.replace_evidence("runtimeDrill", runtime)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertFalse(summary["runtimeDrillComplete"])
        self.assertIn(
            "runtime-receipt-uses-a-different-normal-stable-key-registry",
            summary["blockers"],
        )

    def test_runtime_when_normal_registry_observation_is_missing_expect_schema_failure(
        self,
    ) -> None:
        runtime = self.fixture.load_evidence("runtimeDrill")
        del runtime["normalStableRegistryDigest"]
        seal_receipt(runtime, *self.fixture.material["node"])
        self.fixture.replace_evidence("runtimeDrill", runtime)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertFalse(summary["runtimeDrillComplete"])
        self.assertTrue(
            any("normalstableregistrydigest" in blocker for blocker in summary["blockers"]),
            summary["blockers"],
        )

    def test_runtime_when_observed_registry_roots_overlap_expect_fail_closed(self) -> None:
        runtime = self.fixture.load_evidence("runtimeDrill")
        runtime["normalStableRegistryDigest"] = runtime["catalogRegistryDigest"]
        seal_receipt(runtime, *self.fixture.material["node"])
        self.fixture.replace_evidence("runtimeDrill", runtime)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertFalse(summary["runtimeDrillComplete"])
        self.assertIn(
            "runtime-receipt-does-not-isolate-all-three-registry-trust-roots",
            summary["blockers"],
        )

    def test_runtime_when_managed_daemon_identity_is_substituted_expect_fail_closed(
        self,
    ) -> None:
        original = self.fixture.load_evidence("runtimeDrill")
        substitutions = (
            ("releaseId", "unrelated-release"),
            ("buildVersion", 295),
            ("sourceCommit", "b" * 40),
            ("protectedReleaseRootDigest", digest("unrelated-protected-root")),
            ("productDistributionDigest", digest("unrelated-product")),
        )

        for field, value in substitutions:
            with self.subTest(field=field):
                runtime = copy.deepcopy(original)
                runtime["daemonIdentity"][field] = value
                seal_receipt(runtime, *self.fixture.material["node"])
                self.fixture.replace_evidence("runtimeDrill", runtime)

                result, summary = self.run_mode("verify-runtime-drill")

                self.assertEqual(1, result)
                self.assertFalse(summary["runtimeDrillComplete"])
                self.assertIn(
                    "managed-daemon-identity-does-not-match-the-certified-product-and-apphost-policy",
                    summary["blockers"],
                )

    def test_runtime_when_managed_daemon_observation_follows_collector_expect_fail_closed(
        self,
    ) -> None:
        runtime = self.fixture.load_evidence("runtimeDrill")
        runtime["daemonIdentity"]["observedAt"] = "2026-08-23T12:00:01Z"
        runtime["completedAt"] = "2026-08-23T12:00:01Z"
        seal_receipt(runtime, *self.fixture.material["node"])
        self.fixture.replace_evidence("runtimeDrill", runtime)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertFalse(summary["runtimeDrillComplete"])
        self.assertIn(
            "managed-daemon-identity-was-not-observed-before-collector-execution",
            summary["blockers"],
        )

    def test_runtime_when_caution_blocked_subject_is_omitted_expect_fail_closed(self) -> None:
        runtime = self.fixture.load_evidence("runtimeDrill")
        blocked = next(
            event
            for event in runtime["events"]
            if event["event"] == "caution-v3-blocked-without-acknowledgement"
        )
        for field in (
            "version",
            "bundleDigest",
            "publisherKeyId",
            "reviewStatus",
            "permissionsDigest",
        ):
            blocked[field] = None
        seal_receipt(runtime, *self.fixture.material["node"])
        self.fixture.replace_evidence("runtimeDrill", runtime)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertIn(
            "caution-blocked-event-does-not-bind-the-exact-caution-subject",
            summary["blockers"],
        )

    def test_runtime_when_caution_consent_subject_is_substituted_expect_fail_closed(self) -> None:
        runtime = self.fixture.load_evidence("runtimeDrill")
        consent = next(
            event
            for event in runtime["events"]
            if event["event"] == "caution-v3-consent-recorded"
        )
        corrected = next(
            row
            for row in self.fixture.contract["cohort"]
            if row["cohortId"] == "version-2-corrected"
        )
        consent["version"] = corrected["appVersion"]
        consent["bundleDigest"] = corrected["bundleDigest"]
        consent["reviewStatus"] = "reviewed"
        seal_receipt(runtime, *self.fixture.material["node"])
        self.fixture.replace_evidence("runtimeDrill", runtime)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertIn(
            "caution-consent-event-does-not-bind-the-exact-caution-subject",
            summary["blockers"],
        )

    def test_runtime_when_caution_permission_subject_drifts_expect_fail_closed(self) -> None:
        runtime = self.fixture.load_evidence("runtimeDrill")
        consent = next(
            event
            for event in runtime["events"]
            if event["event"] == "caution-v3-consent-recorded"
        )
        consent["permissionsDigest"] = digest("substituted-caution-permissions")
        seal_receipt(runtime, *self.fixture.material["node"])
        self.fixture.replace_evidence("runtimeDrill", runtime)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertIn(
            "caution-consent-permission-metadata-differs-from-the-blocked-or-applied-update",
            summary["blockers"],
        )

    def test_runtime_when_rollback_digest_drifts_expect_fail_closed(self) -> None:
        runtime = self.fixture.load_evidence("runtimeDrill")
        runtime["finalBundleDigest"] = digest("wrong-rollback")
        seal_receipt(runtime, *self.fixture.material["node"])
        self.fixture.replace_evidence("runtimeDrill", runtime)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertIn(
            "runtime-rollback-is-not-the-exact-corrected-version-2-subject",
            summary["blockers"],
        )

    def test_runtime_when_rollback_permissions_drift_expect_fail_closed(self) -> None:
        runtime = self.fixture.load_evidence("runtimeDrill")
        rollback = next(
            event
            for event in runtime["events"]
            if event["event"] == "corrected-v2-rollback"
        )
        rollback["permissionsDigest"] = digest("different-rollback-permissions")
        seal_receipt(runtime, *self.fixture.material["node"])
        self.fixture.replace_evidence("runtimeDrill", runtime)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertIn(
            "runtime-rollback-permission-metadata-differs-from-corrected-version-2-update",
            summary["blockers"],
        )

    def test_runtime_when_collector_digest_is_self_declared_expect_fail_closed(self) -> None:
        runtime = self.fixture.load_evidence("runtimeDrill")
        runtime["collector"]["summaryDigest"] = digest("invented-collector-summary")
        seal_receipt(runtime, *self.fixture.material["node"])
        self.fixture.replace_evidence("runtimeDrill", runtime)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertIn(
            "runtime-receipt-does-not-bind-the-exact-live-network-collector-summary-bytes",
            summary["blockers"],
        )

    def test_runtime_when_bound_collector_gate_fails_expect_fail_closed(self) -> None:
        collector = self.fixture.load_evidence("collectorSummary")
        lifecycle = next(
            row
            for row in collector["evidence"]
            if row["id"] == "live-network-beta.app-install-update-rollback"
        )
        lifecycle["status"] = "fail"
        self.replace_collector_and_rebind_runtime(collector)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertTrue(
            any("live-network-collector" in blocker for blocker in summary["blockers"])
        )

    def test_runtime_when_collector_endpoint_shape_is_remote_expect_fail_closed(
        self,
    ) -> None:
        collector = self.fixture.load_evidence("collectorSummary")
        collector["node"]["baseUrlShape"] = "https://public.example/pilot"
        self.replace_collector_and_rebind_runtime(collector)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertIn(
            "live-network-collector-endpoint-shape-is-not-canonical-loopback",
            summary["blockers"],
        )

    def test_runtime_when_collector_endpoint_shape_is_canonical_loopback_expect_pass(
        self,
    ) -> None:
        for shape in (
            "http://127.0.0.1:<port>",
            "http://localhost:<port>",
            "http://[::1]:<port>",
        ):
            with self.subTest(shape=shape):
                collector = self.fixture.load_evidence("collectorSummary")
                collector["node"]["baseUrlShape"] = shape
                self.replace_collector_and_rebind_runtime(collector)

                result, summary = self.run_mode("verify-runtime-drill")

                self.assertEqual(0, result)
                self.assertTrue(summary["fixtureVerificationComplete"])

    def test_runtime_when_catalog_refresh_coordinates_are_omitted_expect_fail_closed(
        self,
    ) -> None:
        original = self.fixture.load_evidence("runtimeDrill")
        for event_name in (
            "beta-catalog-refreshed",
            "corrected-v2-catalog-refreshed",
            "caution-v3-catalog-refreshed",
        ):
            with self.subTest(event=event_name):
                runtime = copy.deepcopy(original)
                refresh = next(
                    event
                    for event in runtime["events"]
                    if event["event"] == event_name
                )
                for field in (
                    "catalogRevision",
                    "catalogEdition",
                    "catalogEntryDigest",
                    "catalogSubjectDigest",
                    "catalogSignatureSiblingDigest",
                ):
                    refresh[field] = None
                seal_receipt(runtime, *self.fixture.material["node"])
                self.fixture.replace_evidence("runtimeDrill", runtime)

                result, summary = self.run_mode("verify-runtime-drill")

                self.assertEqual(1, result)
                self.assertIn(
                    f"runtime-event-{event_name}-does-not-bind-the-exact-beta-catalog-edition-subject",
                    summary["blockers"],
                )

    def test_runtime_when_catalog_refresh_subject_drifts_expect_fail_closed(
        self,
    ) -> None:
        original = self.fixture.load_evidence("runtimeDrill")
        mutations = {
            "version": "9.9.9",
            "bundleDigest": digest("wrong-refresh-bundle"),
            "publisherKeyId": "wrong-publisher",
            "reviewStatus": "caution",
            "warningCodes": ["wrong-warning"],
            "catalogRevision": 99,
            "catalogEdition": 99,
            "catalogEntryDigest": digest("wrong-entry"),
            "catalogSubjectDigest": digest("wrong-catalog-subject"),
            "catalogSignatureSiblingDigest": digest("wrong-catalog-signature"),
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                runtime = copy.deepcopy(original)
                refresh = next(
                    event
                    for event in runtime["events"]
                    if event["event"] == "beta-catalog-refreshed"
                )
                refresh[field] = value
                seal_receipt(runtime, *self.fixture.material["node"])
                self.fixture.replace_evidence("runtimeDrill", runtime)

                result, summary = self.run_mode("verify-runtime-drill")

                self.assertEqual(1, result)
                self.assertIn(
                    "runtime-event-beta-catalog-refreshed-does-not-bind-the-exact-beta-catalog-edition-subject",
                    summary["blockers"],
                )

    def test_runtime_when_collector_completion_predates_start_expect_fail_closed(
        self,
    ) -> None:
        collector = self.fixture.load_evidence("collectorSummary")
        collector["startedAt"] = "2026-08-23T12:00:00Z"
        collector["finishedAt"] = "2026-08-23T11:59:59Z"
        self.replace_collector_and_rebind_runtime(collector)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertIn(
            "live-network-collector-completion-predates-its-start",
            summary["blockers"],
        )

    def test_runtime_when_collector_predates_publication_expect_fail_closed(self) -> None:
        collector = self.fixture.load_evidence("collectorSummary")
        collector["startedAt"] = "2026-08-23T11:59:59Z"
        collector["finishedAt"] = "2026-08-23T11:59:59Z"
        self.replace_collector_and_rebind_runtime(collector)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertIn(
            "live-network-collector-execution-predates-review-or-catalog-publication",
            summary["blockers"],
        )

    def test_runtime_when_collector_is_stale_expect_fail_closed(self) -> None:
        collector = self.fixture.load_evidence("collectorSummary")
        collector["startedAt"] = "2025-01-01T00:00:00Z"
        collector["finishedAt"] = "2025-01-01T00:00:01Z"
        self.replace_collector_and_rebind_runtime(collector)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertIn(
            "live-network-collector-completion-is-stale", summary["blockers"]
        )

    def test_runtime_when_rejected_event_uses_corrected_digest_expect_fail_closed(self) -> None:
        runtime = self.fixture.load_evidence("runtimeDrill")
        rejected = next(
            event
            for event in runtime["events"]
            if event["event"] == "rejected-v2-absent"
        )
        corrected = next(
            row
            for row in self.fixture.contract["cohort"]
            if row["cohortId"] == "version-2-corrected"
        )
        rejected["bundleDigest"] = corrected["bundleDigest"]
        seal_receipt(runtime, *self.fixture.material["node"])
        self.fixture.replace_evidence("runtimeDrill", runtime)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertIn(
            "runtime-did-not-prove-the-rejected-version-absent-and-blocked",
            summary["blockers"],
        )

    def test_runtime_when_completion_predates_publication_expect_fail_closed(self) -> None:
        runtime = self.fixture.load_evidence("runtimeDrill")
        runtime["completedAt"] = "2026-08-23T11:59:00Z"
        seal_receipt(runtime, *self.fixture.material["node"])
        self.fixture.replace_evidence("runtimeDrill", runtime)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertIn(
            "runtime-drill-completion-predates-review-publication-or-collector-completion",
            summary["blockers"],
        )

    def test_runtime_when_no_preexisting_app_expect_restore_results_not_required(
        self,
    ) -> None:
        collector = self.fixture.load_evidence("collectorSummary")
        details = self.collector_lifecycle_details(collector)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertNotIn("restoreSucceeded", details)
        self.assertNotIn("preExistingStoppedRestoreSucceeded", details)
        self.assertEqual(0, result)
        self.assertTrue(summary["fixtureVerificationComplete"])

    def test_runtime_when_running_app_restore_result_is_missing_expect_fail_closed(
        self,
    ) -> None:
        collector = self.fixture.load_evidence("collectorSummary")
        details = self.collector_lifecycle_details(collector)
        details.update(
            {
                "preExistingInstall": True,
                "preExistingRunning": True,
                "preExistingStoppedStartedBySmoke": False,
                "installedByThisRun": False,
                "preExistingRunningStoppedForSmoke": True,
            }
        )
        details.pop("restoreSucceeded", None)
        self.replace_collector_and_rebind_runtime(
            collector,
            {
                "preexistingApp": True,
                "appCleanupStatus": "not-required",
            },
        )

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertIn(
            "live-network-collector-did-not-prove-restoration-of-the-pre-existing-running-app",
            summary["blockers"],
        )

    def test_runtime_when_stopped_app_restore_result_is_missing_expect_fail_closed(
        self,
    ) -> None:
        collector = self.fixture.load_evidence("collectorSummary")
        details = self.collector_lifecycle_details(collector)
        details.update(
            {
                "preExistingInstall": True,
                "preExistingRunning": False,
                "preExistingStoppedStartedBySmoke": True,
                "installedByThisRun": False,
            }
        )
        details.pop("preExistingStoppedRestoredByLifecycle", None)
        details.pop("preExistingStoppedRestoreSucceeded", None)
        self.replace_collector_and_rebind_runtime(
            collector,
            {
                "preexistingApp": True,
                "appCleanupStatus": "not-required",
            },
        )

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertIn(
            "live-network-collector-did-not-prove-restoration-of-the-pre-existing-stopped-app",
            summary["blockers"],
        )

    def test_runtime_when_stopped_app_is_restored_by_lifecycle_expect_pass(
        self,
    ) -> None:
        collector = self.fixture.load_evidence("collectorSummary")
        details = self.collector_lifecycle_details(collector)
        details.update(
            {
                "preExistingInstall": True,
                "preExistingRunning": False,
                "preExistingStoppedStartedBySmoke": True,
                "installedByThisRun": False,
                "preExistingStoppedRestoredByLifecycle": True,
            }
        )
        self.replace_collector_and_rebind_runtime(
            collector,
            {
                "preexistingApp": True,
                "appCleanupStatus": "not-required",
            },
        )

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(0, result)
        self.assertTrue(summary["fixtureVerificationComplete"])

    def test_runtime_when_collector_initial_state_differs_expect_fail_closed(self) -> None:
        collector = self.fixture.load_evidence("collectorSummary")
        details = self.collector_lifecycle_details(collector)
        details.update(
            {
                "preExistingInstall": True,
                "preExistingRunning": True,
                "preExistingStoppedStartedBySmoke": False,
                "installedByThisRun": False,
                "preExistingRunningStoppedForSmoke": True,
                "restoreSucceeded": True,
            }
        )
        self.replace_collector_and_rebind_runtime(collector)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertIn(
            "live-network-collector-initial-app-state-differs-from-runtime-receipt",
            summary["blockers"],
        )

    def test_runtime_when_collector_state_flag_is_missing_expect_fail_closed(self) -> None:
        collector = self.fixture.load_evidence("collectorSummary")
        details = self.collector_lifecycle_details(collector)
        del details["preExistingRunning"]
        self.replace_collector_and_rebind_runtime(collector)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertIn(
            "live-network-collector-lifecycle-state-is-incomplete-or-malformed",
            summary["blockers"],
        )

    def test_runtime_when_cleanup_is_partial_expect_never_complete(self) -> None:
        runtime = self.fixture.load_evidence("runtimeDrill")
        runtime.update(
            {
                "registryCleanupStatus": "failed",
                "cleanStateRestored": False,
                "status": "partial",
                "partial": True,
            }
        )
        seal_receipt(runtime, *self.fixture.material["node"])
        self.fixture.replace_evidence("runtimeDrill", runtime)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertEqual("partial", summary["status"])
        self.assertIn(
            "runtime-cleanup-is-partial-failed-or-hidden-as-success",
            summary["blockers"],
        )

    def test_runtime_when_preexisting_state_is_restored_expect_not_required_cleanup_allowed(
        self,
    ) -> None:
        collector = self.fixture.load_evidence("collectorSummary")
        details = self.collector_lifecycle_details(collector)
        details.update(
            {
                "preExistingInstall": True,
                "preExistingRunning": True,
                "preExistingStoppedStartedBySmoke": False,
                "installedByThisRun": False,
                "preExistingRunningStoppedForSmoke": True,
                "restoreSucceeded": True,
            }
        )
        self.replace_collector_and_rebind_runtime(
            collector,
            {
                "preexistingApp": True,
                "preexistingCatalog": True,
                "appCleanupStatus": "not-required",
                "catalogCleanupStatus": "not-required",
            },
        )

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(0, result)
        self.assertEqual("pass", summary["status"])
        self.assertEqual("fixture-verification-complete", summary["state"])

    def test_runtime_when_new_state_uses_not_required_cleanup_expect_fail_closed(self) -> None:
        runtime = self.fixture.load_evidence("runtimeDrill")
        runtime["appCleanupStatus"] = "not-required"
        seal_receipt(runtime, *self.fixture.material["node"])
        self.fixture.replace_evidence("runtimeDrill", runtime)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertIn(
            "app-cleanup-status-does-not-match-the-pre-existing-state",
            summary["blockers"],
        )
        self.assertIn(
            "runtime-cleanup-is-partial-failed-or-hidden-as-success",
            summary["blockers"],
        )

    def test_runtime_when_required_setup_event_fails_expect_never_complete(self) -> None:
        runtime = self.fixture.load_evidence("runtimeDrill")
        registry = next(
            event
            for event in runtime["events"]
            if event["event"] == "pilot-registry-installed"
        )
        registry["status"] = "fail"
        seal_receipt(runtime, *self.fixture.material["node"])
        self.fixture.replace_evidence("runtimeDrill", runtime)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertIn(
            "runtime-event-pilot-registry-installed-does-not-have-required-status-pass",
            summary["blockers"],
        )

    def test_runtime_when_required_cleanup_event_fails_expect_never_complete(self) -> None:
        runtime = self.fixture.load_evidence("runtimeDrill")
        cleanup = next(
            event
            for event in runtime["events"]
            if event["event"] == "app-removed-or-restored"
        )
        cleanup["status"] = "fail"
        seal_receipt(runtime, *self.fixture.material["node"])
        self.fixture.replace_evidence("runtimeDrill", runtime)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertIn(
            "runtime-event-app-removed-or-restored-does-not-have-required-status-pass",
            summary["blockers"],
        )

    def test_runtime_when_node_key_is_substituted_expect_authenticated_binding_failure(self) -> None:
        runtime = self.fixture.load_evidence("runtimeDrill")
        runtime["nodeAttestationFingerprint"] = digest("substituted-node")
        seal_receipt(runtime, *self.fixture.material["node"])
        self.fixture.replace_evidence("runtimeDrill", runtime)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertTrue(any("node-attestation-fingerprint" in item for item in summary["blockers"]))

    def test_runtime_when_workflow_commit_differs_from_certified_source_expect_fail_closed(
        self,
    ) -> None:
        runtime = self.fixture.load_evidence("runtimeDrill")
        runtime["provenance"]["workflowCommit"] = "c" * 40
        self.fixture.contract["evidence"]["runtimeDrill"]["provenance"][
            "workflowCommit"
        ] = "c" * 40
        seal_receipt(runtime, *self.fixture.material["node"])
        self.fixture.replace_evidence("runtimeDrill", runtime)

        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(1, result)
        self.assertIn(
            "runtime-provenance-is-not-the-protected-node-side-producer-at-the-certified-source-commit",
            summary["blockers"],
        )
        self.assertFalse(summary["runtimeDrillComplete"])

    def test_run_when_contract_is_symlink_expect_rejected_before_resolution(self) -> None:
        contract_link = self.root / "execution-link.json"
        contract_link.symlink_to(self.fixture.contract_path)

        with self.assertRaisesRegex(ValueError, "symbolic-link component"):
            pilot.run(
                self.workspace,
                contract_link,
                "preflight",
                self.root / "symlink-contract-output",
                self.fixture.evidence,
            )

    def test_run_when_evidence_parent_is_symlink_expect_rejected_before_resolution(
        self,
    ) -> None:
        evidence_parent = self.root / "evidence-parent-link"
        evidence_parent.symlink_to(self.root, target_is_directory=True)

        with self.assertRaisesRegex(ValueError, "symbolic-link component"):
            pilot.run(
                self.workspace,
                self.fixture.contract_path,
                "preflight",
                self.root / "symlink-evidence-output",
                evidence_parent / "evidence",
            )

    def test_closeout_when_protected_roots_are_absent_expect_no_operational_claim(self) -> None:
        result, summary = self.run_mode("closeout")

        self.assertEqual(1, result)
        self.assertFalse(summary["operationalPilotComplete"])
        self.assertFalse(summary["operational"])
        self.assertTrue(
            {
                "protectedrelease-evidence-is-not-bound",
                "independentreproducibility-evidence-is-not-bound",
                "selectedrcfreeze-evidence-is-not-bound",
                "catalogauthority-evidence-is-not-bound",
            }.issubset(summary["blockers"])
        )

    def test_closeout_when_deriving_catalog_expectations_expect_pr291_and_pr292_roots(
        self,
    ) -> None:
        from cryptad_certification.engines.stable_1_0_supply_chain_core import (
            semantic_digest,
        )
        from cryptad_certification.tests.test_stable_protected_release import (
            COMMIT,
            RELEASE_ID,
            _rc_freeze_record,
            _selected_rc,
        )

        selected = _selected_rc()
        freeze = _rc_freeze_record(selected)
        frozen_catalog = freeze["stableCatalog"]
        inventory = {
            "releaseId": RELEASE_ID,
            "buildVersion": 3,
            "sourceCommit": COMMIT,
            "subjects": [
                {
                    "subjectKey": "stable-catalog",
                    "subjectClass": "catalog",
                    "reproducibilityClass": "byte-identical",
                    "digest": frozen_catalog["catalogDigest"],
                    "size": 4096,
                },
                {
                    "subjectKey": "stable-catalog-signature",
                    "subjectClass": "catalog",
                    "reproducibilityClass": "byte-identical",
                    "digest": frozen_catalog["signatureDigest"],
                    "size": 256,
                },
            ],
            "subjectInventoryDigest": pilot.ZERO_DIGEST,
        }
        inventory["subjectInventoryDigest"] = semantic_digest(
            inventory, "subjectInventoryDigest"
        )
        protected = {
            "dispatchPackage": {
                "gaValidation": {"selectedRc": copy.deepcopy(selected)},
                "gaPublication": {"selectedRc": copy.deepcopy(selected)},
            }
        }
        independent_selected = {
            "workflowPath": pilot.SELECTED_RC_WORKFLOW,
            "workflowCommit": COMMIT,
            "runId": selected["runId"],
            "runAttempt": int(selected["runAttempt"]),
            "artifactName": selected["artifactName"],
            "artifactDigest": selected["artifactDigest"],
            "freezeDigest": selected["freezeDigest"],
            "freezeFileDigest": digest("selected-freeze-file"),
            "productDigest": selected["productDigest"],
            "subjectInventoryDigest": inventory["subjectInventoryDigest"],
        }
        independent = {
            "selectedRc": independent_selected,
            "subjectInventoryDigest": inventory["subjectInventoryDigest"],
        }
        contract = {
            "repository": {
                "identity": "github.com/crypta-network/cryptad",
                "sourceCommit": COMMIT,
            },
            "release": {
                "releaseId": RELEASE_ID,
                "buildVersion": 3,
                "productDistributionDigest": selected["productDigest"],
            },
        }
        selected_provenance = provenance(
            contract["repository"]["identity"],
            pilot.SELECTED_RC_WORKFLOW,
            int(selected["runId"]),
            selected["artifactName"],
            workflow_commit=COMMIT,
            environment=pilot.SELECTED_RC_ENVIRONMENT,
        )
        selected_provenance["artifactDigest"] = selected["artifactDigest"]
        binding = {
            "digest": independent_selected["freezeFileDigest"],
            "provenance": selected_provenance,
        }

        with mock.patch.object(
            pilot, "_github_actions_coordinate_errors", return_value=[]
        ):
            actual_selected, actual_catalog, errors = (
                pilot._selected_rc_freeze_expectations(
                    contract,
                    protected,
                    independent,
                    freeze,
                    inventory,
                    binding,
                )
            )

        self.assertEqual([], errors)
        self.assertEqual(selected, actual_selected)
        self.assertEqual(frozen_catalog, actual_catalog)
        self.assertEqual("catalog-production-2026", actual_catalog["catalogSigningKeyId"])

    def test_closeout_when_pr292_signature_subject_is_substituted_expect_fail_closed(
        self,
    ) -> None:
        from cryptad_certification.engines.stable_1_0_supply_chain_core import (
            semantic_digest,
        )
        from cryptad_certification.tests.test_stable_protected_release import (
            COMMIT,
            RELEASE_ID,
            _rc_freeze_record,
            _selected_rc,
        )

        selected = _selected_rc()
        freeze = _rc_freeze_record(selected)
        inventory = {
            "releaseId": RELEASE_ID,
            "buildVersion": 3,
            "sourceCommit": COMMIT,
            "subjects": [
                {
                    "subjectKey": "stable-catalog",
                    "subjectClass": "catalog",
                    "reproducibilityClass": "byte-identical",
                    "digest": freeze["stableCatalog"]["catalogDigest"],
                    "size": 4096,
                },
                {
                    "subjectKey": "stable-catalog-signature",
                    "subjectClass": "catalog",
                    "reproducibilityClass": "byte-identical",
                    "digest": digest("substituted-signature"),
                    "size": 256,
                },
            ],
            "subjectInventoryDigest": pilot.ZERO_DIGEST,
        }
        inventory["subjectInventoryDigest"] = semantic_digest(
            inventory, "subjectInventoryDigest"
        )
        independent_selected = {
            "workflowPath": pilot.SELECTED_RC_WORKFLOW,
            "workflowCommit": COMMIT,
            "runId": selected["runId"],
            "runAttempt": int(selected["runAttempt"]),
            "artifactName": selected["artifactName"],
            "artifactDigest": selected["artifactDigest"],
            "freezeDigest": selected["freezeDigest"],
            "freezeFileDigest": digest("selected-freeze-file"),
            "productDigest": selected["productDigest"],
            "subjectInventoryDigest": inventory["subjectInventoryDigest"],
        }
        contract = {
            "repository": {
                "identity": "github.com/crypta-network/cryptad",
                "sourceCommit": COMMIT,
            },
            "release": {
                "releaseId": RELEASE_ID,
                "buildVersion": 3,
                "productDistributionDigest": selected["productDigest"],
            },
        }
        selected_provenance = provenance(
            contract["repository"]["identity"],
            pilot.SELECTED_RC_WORKFLOW,
            int(selected["runId"]),
            selected["artifactName"],
            workflow_commit=COMMIT,
            environment=pilot.SELECTED_RC_ENVIRONMENT,
        )
        selected_provenance["artifactDigest"] = selected["artifactDigest"]

        with mock.patch.object(
            pilot, "_github_actions_coordinate_errors", return_value=[]
        ):
            _selected, _catalog, errors = pilot._selected_rc_freeze_expectations(
                contract,
                {
                    "dispatchPackage": {
                        "gaValidation": {"selectedRc": copy.deepcopy(selected)},
                        "gaPublication": {"selectedRc": copy.deepcopy(selected)},
                    }
                },
                {
                    "selectedRc": independent_selected,
                    "subjectInventoryDigest": inventory["subjectInventoryDigest"],
                },
                freeze,
                inventory,
                {
                    "digest": independent_selected["freezeFileDigest"],
                    "provenance": selected_provenance,
                },
            )

        self.assertIn(
            "PR-292 catalog or signature subject differs from the selected RC freeze",
            errors,
        )

    def test_catalog_authority_when_summary_expansion_exceeds_bound_expect_rejected_before_read(
        self,
    ) -> None:
        archive_path = self.root / "oversized-catalog-authority.zip"
        with zipfile.ZipFile(
            archive_path, "w", compression=zipfile.ZIP_DEFLATED
        ) as archive:
            archive.writestr(
                pilot.catalog_authority_closeout.SUMMARY_MEMBER,
                b" " * 5_000_001,
            )
            archive.writestr(
                pilot.catalog_authority_closeout.REPORT_MEMBER,
                b"report",
            )
            archive.writestr(
                pilot.catalog_authority_closeout.REDACTION_MEMBER,
                b"{}",
            )

        with self.assertRaisesRegex(ValueError, "archive expansion exceeds"):
            pilot._catalog_authority_summary(archive_path)

    def test_root_when_retained_artifact_digest_is_substituted_expect_fail_closed(self) -> None:
        collector = self.fixture.load_evidence("collectorSummary")
        archive_bytes = zip_bytes({"summary.json": json.dumps(collector).encode()})
        archive_path = self.fixture.evidence / "protected-root.zip"
        archive_path.write_bytes(archive_bytes)
        artifact_digest = digest(archive_bytes)
        root_provenance = provenance(
            "github.com/crypta-network/cryptad",
            ".github/workflows/stable-1.0-protected-release-closeout.yml",
            291,
            "protected-root-fixture",
        )
        root_provenance["artifactDigest"] = digest("different-actions-artifact")
        self.fixture.contract["evidence"]["protectedRelease"] = {
            "fileName": archive_path.name,
            "digest": artifact_digest,
            "size": len(archive_bytes),
            "schema": None,
            "provenance": root_provenance,
        }

        _value, errors = pilot._bound_artifact_json(
            self.fixture.contract,
            self.fixture.evidence,
            "protectedRelease",
            "summary.json",
            pilot.COLLECTOR_SCHEMA,
        )

        self.assertIn(
            "protectedRelease retained artifact digest differs from protected provenance",
            errors,
        )

    def test_outputs_when_fixture_passes_expect_no_sensitive_material(self) -> None:
        result, summary = self.run_mode("verify-runtime-drill")

        self.assertEqual(0, result)
        self.assertEqual([], scan_value(summary))
        serialized = json.dumps(summary)
        self.assertNotIn("PRIVATE KEY", serialized)
        self.assertNotIn(str(self.root), serialized)


if __name__ == "__main__":
    unittest.main()
