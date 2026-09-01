"""Focused tests for federated catalog discovery and local-trust certification."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from cryptad_certification.cli import build_parser
from cryptad_certification.engines import stable_1_0_federated_catalog as federation
from cryptad_certification.io import write_json
from cryptad_certification.tests.third_party_pilot_fixtures import (
    digest,
    keypair,
    signature,
    spki,
)


NOW = "2026-08-25T12:00:00Z"
EXPIRES = "2026-08-26T12:00:00Z"


def _provenance(workflow: str, artifact_digest: str, source_commit: str) -> dict[str, object]:
    return {
        "repositoryIdentity": "github.com/crypta-network/cryptad",
        "workflowPath": workflow,
        "workflowCommit": source_commit,
        "runId": 100,
        "runAttempt": 1,
        "artifactName": "stable-federation-fixture-100-1",
        "artifactDigest": artifact_digest,
        "environment": "stable-1-0-fixture",
        "conclusion": "success",
    }


def _seal(
    value: dict[str, object],
    digest_field: str,
    private_seed: bytes,
    public: bytes,
) -> None:
    value[digest_field] = federation._semantic_digest(value, digest_field)
    value["signatureBase64"] = signature(
        private_seed,
        public,
        federation._signature_subject(value),
    )


def _runtime_hash(value: bytes | str) -> str:
    encoded = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(encoded).hexdigest()


def _seal_runtime_document(
    value: dict[str, object],
    private_seed: bytes,
    public: bytes,
    *,
    descriptor: bool,
) -> None:
    content = (
        federation._runtime_descriptor_content(value)
        if descriptor
        else federation._runtime_endorsement_content(value)
    )
    value["selfDigestSha256"] = _runtime_hash(
        federation._runtime_document_bytes(content)
    )
    signed = dict(content)
    signed["selfDigestSha256"] = value["selfDigestSha256"]
    value["signature"] = {
        "algorithm": "Ed25519",
        "valueBase64": signature(
            private_seed,
            public,
            federation._runtime_document_bytes(signed),
        ),
    }


class FederationFixture:
    """Build one deterministic non-production federation evidence set."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.evidence = root / "evidence"
        self.evidence.mkdir()
        self.source_commit = "a" * 40
        self.issuer = keypair("pr-295-descriptor-issuer")
        self.observer = keypair("pr-295-runtime-observer")
        self.descriptor = self._descriptor()
        self.endorsement = self._endorsement()
        self.runtime = self._runtime()
        self.contract = self._contract()
        self.contract_path = root / "execution.json"
        self.write_all()

    def _descriptor(self) -> dict[str, object]:
        private_seed, public = self.issuer
        descriptor: dict[str, object] = {
            "schemaVersion": 1,
            "descriptorId": "fixture-independent-catalog-descriptor",
            "subject": {
                "catalogId": "fixture-independent-catalog",
                "signerKeyId": "fixture-independent-catalog-key",
                "signerFingerprintSha256": _runtime_hash("independent-catalog-key"),
                "sourceHints": ["https://catalogs.example/independent/catalog.json"],
                "channels": ["beta"],
            },
            "display": {
                "name": "Independent fixture catalog",
                "summary": "Bounded non-production discovery metadata.",
                "providerId": "fixture-independent-provider",
            },
            "transparency": {
                "reviewerSetDigestSha256": _runtime_hash("reviewer-policy"),
                "publisherPolicyDigestSha256": _runtime_hash("publisher-policy"),
            },
            "validity": {"issuedAt": NOW, "expiresAt": EXPIRES},
            "issuer": {
                "issuerId": "fixture-independent-provider",
                "keyId": "fixture-descriptor-issuer",
                "keyFingerprintSha256": _runtime_hash(
                    base64.b64decode(spki(public))
                ),
            },
            "selfDigestSha256": "0" * 64,
            "signature": {"algorithm": "Ed25519", "valueBase64": "A" * 86 + "=="},
        }
        _seal_runtime_document(
            descriptor, private_seed, public, descriptor=True
        )
        return descriptor

    def _endorsement(self) -> dict[str, object]:
        private_seed, public = self.issuer
        endorsement: dict[str, object] = {
            "schemaVersion": 1,
            "endorsementId": "fixture-endorsement",
            "subject": {
                "catalogId": self.descriptor["subject"]["catalogId"],
                "signerFingerprintSha256": self.descriptor["subject"][
                    "signerFingerprintSha256"
                ],
                "descriptorDigestSha256": self.descriptor["selfDigestSha256"],
            },
            "evidence": {
                "reviewerSetDigestSha256": self.descriptor["transparency"][
                    "reviewerSetDigestSha256"
                ],
                "publisherPolicyDigestSha256": self.descriptor["transparency"][
                    "publisherPolicyDigestSha256"
                ],
                "labels": ["independent"],
                "reason": "Fixture recommendation only.",
            },
            "validity": {"issuedAt": NOW, "expiresAt": EXPIRES},
            "issuer": {
                "issuerId": "fixture-stable-operator",
                "keyId": "fixture-endorsement-key",
                "keyFingerprintSha256": _runtime_hash(
                    base64.b64decode(spki(public))
                ),
            },
            "selfDigestSha256": "0" * 64,
            "signature": {"algorithm": "Ed25519", "valueBase64": "A" * 86 + "=="},
        }
        _seal_runtime_document(
            endorsement, private_seed, public, descriptor=False
        )
        return endorsement

    def _runtime(self) -> dict[str, object]:
        private_seed, public = self.observer
        authority_digests = {
            "protectedRelease": digest("pr-291-summary"),
            "independentReproducibility": digest("pr-292-summary"),
            "catalogAuthority": digest("pr-293-summary"),
            "thirdPartyPilot": digest("pr-294-summary"),
        }
        catalogs = []
        for catalog_id, status in (
            ("stable", "active"),
            ("external-pilot", "active"),
            ("fixture-independent-catalog", "suspended"),
        ):
            catalogs.append(
                {
                    "catalogId": catalog_id,
                    "signerKeyId": f"{catalog_id}-signer",
                    "signerFingerprint": digest(f"{catalog_id}-signer"),
                    "trustBindingId": f"binding-{catalog_id}",
                    "trustBindingDigest": digest(f"binding-{catalog_id}"),
                    "publisherPolicyDigest": digest(f"publisher-{catalog_id}"),
                    "reviewerPolicyDigest": digest(f"reviewer-{catalog_id}"),
                    "status": status,
                }
            )
        scenarios = {
            "multipleCatalogsCoexisted": True,
            "scopedCatalogSignersEnforced": True,
            "roleSeparationEnforced": True,
            "publisherScopeEnforced": True,
            "reviewerScopeEnforced": True,
            "endorsementsNonTransitive": True,
            "unresolvedHardConflictBlocked": True,
            "lexicalTieBreakDisabled": True,
            "securityBlockStrongest": True,
            "pinnedOriginRetained": True,
            "unavailableOriginRequiresOperator": True,
            "sourceSwitchRequiredConsent": True,
            "publisherSwitchRequiredConsent": True,
            "rollbackRestoredBytesAndOrigin": True,
            "catalogRevocationIsolated": True,
            "catalogRemovalLeftAppInstalled": True,
            "supportSummaryRedacted": True,
            "cleanupComplete": True,
        }
        observation: dict[str, object] = {
            "schemaVersion": 1,
            "kind": "stable-1.0-federated-catalog-runtime-observation",
            "executionId": "fixture-federation",
            "provenance": {
                **_provenance(
                    ".github/workflows/stable-1.0-federated-catalog-runtime.yml",
                    digest("runtime-artifact"),
                    self.source_commit,
                ),
                "environment": "stable-1-0-federated-catalog-runtime-observation",
            },
            "observedAt": NOW,
            "expiresAt": EXPIRES,
            "authorityDigests": authority_digests,
            "discovery": {
                "descriptorDigest": "sha256:" + self.descriptor["selfDigestSha256"],
                "endorsementDigests": [
                    "sha256:" + self.endorsement["selfDigestSha256"]
                ],
                "pendingOnly": True,
                "trustCreated": False,
                "localStateSent": False,
                "stableRemoteIdentifierCreated": False,
            },
            "catalogs": catalogs,
            "publisherPolicyDigest": digest("all-publisher-policies"),
            "reviewerPolicyDigest": digest("all-reviewer-policies"),
            "conflictSetDigest": digest("conflict-set"),
            "conflictResolutionDigest": digest("conflict-resolution"),
            "installedOriginDigest": digest("installed-origin"),
            "catalogCount": 3,
            "activeCatalogCount": 2,
            "conflictCounts": {
                "exactDuplicate": 1,
                "metadataDisagreement": 1,
                "sameVersionPayload": 1,
                "publisher": 1,
                "competingVersions": 1,
                "securityPolicy": 1,
                "reviewerPolicy": 1,
                "unresolvedHard": 2,
            },
            "scenarios": scenarios,
            "status": "pass",
            "partial": False,
            "observerKeyId": "fixture-runtime-observer",
            "observerPublicKeySpkiBase64": spki(public),
            "observerFingerprint": digest(base64.b64decode(spki(public))),
            "receiptDigest": federation.ZERO_DIGEST,
            "signatureBase64": "A" * 86 + "==",
        }
        _seal(observation, "receiptDigest", private_seed, public)
        return observation

    def _contract(self) -> dict[str, object]:
        policy, policy_digest = federation._policy(Path(__file__).resolve().parents[4])
        authorities = {}
        for name, workflow in policy["requiredAuthorityWorkflows"].items():
            artifact_digest = digest(f"{name}-artifact")
            authorities[name] = {
                "summaryDigest": self.runtime["authorityDigests"][name],
                "artifactDigest": artifact_digest,
                "operational": False,
                "provenance": _provenance(workflow, artifact_digest, self.source_commit),
                "summary": None,
            }
        return {
            "schemaVersion": 1,
            "kind": "stable-1.0-federated-catalog-execution",
            "executionId": "fixture-federation",
            "repository": {
                "identity": "github.com/crypta-network/cryptad",
                "sourceCommit": self.source_commit,
            },
            "release": {"releaseId": "stable-fixture", "buildVersion": "1"},
            "evaluationTime": NOW,
            "requestedState": "fixture-verification-complete",
            "fixtureOnly": True,
            "selfTest": True,
            "policyDigest": policy_digest,
            "authorities": authorities,
            "evidence": {
                "descriptor": None,
                "endorsements": [],
                "runtimeObservation": None,
            },
        }

    def write_all(self) -> None:
        descriptor_path = self.evidence / "descriptor.json"
        endorsement_path = self.evidence / "endorsement.json"
        runtime_path = self.evidence / "runtime.json"
        write_json(descriptor_path, self.descriptor)
        write_json(endorsement_path, self.endorsement)
        write_json(runtime_path, self.runtime)
        self.contract["evidence"] = {
            "descriptor": {
                "fileName": descriptor_path.name,
                "digest": digest(descriptor_path.read_bytes()),
                "size": descriptor_path.stat().st_size,
                "issuerPublicKeySpkiBase64": spki(self.issuer[1]),
            },
            "endorsements": [
                {
                    "fileName": endorsement_path.name,
                    "digest": digest(endorsement_path.read_bytes()),
                    "size": endorsement_path.stat().st_size,
                    "issuerPublicKeySpkiBase64": spki(self.issuer[1]),
                }
            ],
            "runtimeObservation": {
                "fileName": runtime_path.name,
                "digest": digest(runtime_path.read_bytes()),
                "size": runtime_path.stat().st_size,
                "observerKeyId": self.runtime["observerKeyId"],
                "observerFingerprint": self.runtime["observerFingerprint"],
                "observerPublicKeySpkiBase64": self.runtime[
                    "observerPublicKeySpkiBase64"
                ],
                "receiptProvenance": {
                    **self.runtime["provenance"],
                    "artifactName": "stable-federation-fixture-runtime-receipt",
                    "artifactDigest": digest("runtime-receipt-artifact"),
                },
            },
        }
        write_json(self.contract_path, self.contract)


class StableFederatedCatalogTest(unittest.TestCase):
    """Exercises closed discovery, trust, conflict, runtime, and state boundaries."""

    def setUp(self) -> None:
        self.workspace = Path(__file__).resolve().parents[4]
        (self.workspace / "build").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            dir=self.workspace / "build", prefix="federated-catalog-test-"
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fixture = FederationFixture(self.root)
        self.run_number = 0

    def run_mode(self, mode: str) -> tuple[int, dict[str, object]]:
        self.run_number += 1
        output = self.root / f"output-{self.run_number}"
        code = federation.run(
            self.workspace,
            self.fixture.contract_path,
            mode,
            output,
            self.fixture.evidence,
        )
        summary = json.loads((output / federation.SUMMARY_FILE).read_text())
        return code, summary

    def rewrite(self) -> None:
        write_json(self.fixture.contract_path, self.fixture.contract)

    def test_cli_when_parsed_expect_one_closed_special_command(self) -> None:
        parser = build_parser()
        for mode in federation.MODES:
            args = parser.parse_args(
                [
                    "stable-federated-catalog",
                    "--mode",
                    mode,
                    "--execution-contract",
                    "execution.json",
                ]
            )
            self.assertEqual(mode, args.mode)
        self.assertEqual(
            "stable-federated-catalog",
            parser.parse_args(["stable-federated-catalog", "--self-test"]).command,
        )

    def test_public_host_when_literal_is_not_global_unicast_expect_rejected(self) -> None:
        rejected = (
            "::ffff:127.0.0.1",
            "ff02::1",
            "fec0::1",
            "2001:db8::1",
            "100.64.0.1",
            "192.0.2.1",
            "127.1",
            "2130706433",
            "node.local.",
        )
        accepted = (
            "8.8.8.8",
            "192.0.1.1",
            "::ffff:8.8.8.8",
            "2606:4700:4700::1111",
            "catalogs.example",
        )

        for hostname in rejected:
            with self.subTest(hostname=hostname):
                self.assertFalse(federation._public_host(hostname))
        for hostname in accepted:
            with self.subTest(hostname=hostname):
                self.assertTrue(federation._public_host(hostname))

    def test_https_hint_when_java_uri_would_reject_expect_rejected(self) -> None:
        rejected = (
            "https://exa_mple.com/catalog",
            "https://example.com/%zz",
            "https://example.com:invalid/catalog",
            "https://bad..example/catalog",
            "https://example.com/catalog path",
            "https://example.com/catalog?",
            "https://example.com/catalog#",
        )
        accepted = (
            "https://catalogs.example/catalog",
            "https://catalogs.example.:99999/catalog",
            "https://[2606:4700:4700::1111]/catalog",
        )

        for hint in rejected:
            with self.subTest(hint=hint):
                self.assertTrue(federation._source_hint_errors([hint]))
                self.assertTrue(
                    federation._public_reference_errors(hint, "transparency URI")
                )
        for hint in accepted:
            with self.subTest(hint=hint):
                self.assertFalse(federation._source_hint_errors([hint]))
                self.assertFalse(
                    federation._public_reference_errors(hint, "transparency URI")
                )

    def test_discovery_when_timestamp_uses_utc_offset_expect_runtime_signature_valid(self) -> None:
        self.fixture.descriptor["validity"]["issuedAt"] = NOW.replace("Z", "+00:00")
        self.fixture.endorsement["validity"]["expiresAt"] = EXPIRES.replace(
            "Z", "+00:00"
        )
        self.fixture.write_all()

        code, summary = self.run_mode("verify-discovery")

        self.assertEqual(0, code)
        self.assertTrue(summary["fixtureVerificationComplete"])
        self.assertFalse(summary["blockers"])

    def test_descriptor_when_signed_over_noncanonical_timestamp_expect_fail_closed(self) -> None:
        noncanonical = NOW.replace("Z", "+00:00")
        self.fixture.descriptor["validity"]["issuedAt"] = noncanonical
        content = federation._runtime_descriptor_content(self.fixture.descriptor)
        content["validity"]["issuedAt"] = noncanonical
        self.fixture.descriptor["selfDigestSha256"] = _runtime_hash(
            federation._runtime_document_bytes(content)
        )
        signed = dict(content)
        signed["selfDigestSha256"] = self.fixture.descriptor["selfDigestSha256"]
        self.fixture.descriptor["signature"] = {
            "algorithm": "Ed25519",
            "valueBase64": signature(
                self.fixture.issuer[0],
                self.fixture.issuer[1],
                federation._runtime_document_bytes(signed),
            ),
        }
        self.fixture.write_all()

        code, summary = self.run_mode("verify-discovery")

        self.assertEqual(1, code)
        self.assertTrue(any("self-digest" in item for item in summary["blockers"]))

    def test_descriptor_when_https_uri_is_not_java_compatible_expect_fail_closed(self) -> None:
        self.fixture.descriptor["subject"]["sourceHints"] = [
            "https://example.com/%zz"
        ]
        _seal_runtime_document(
            self.fixture.descriptor, *self.fixture.issuer, descriptor=True
        )
        self.fixture.endorsement["subject"]["descriptorDigestSha256"] = (
            self.fixture.descriptor["selfDigestSha256"]
        )
        _seal_runtime_document(
            self.fixture.endorsement, *self.fixture.issuer, descriptor=False
        )
        self.fixture.write_all()

        code, summary = self.run_mode("verify-discovery")

        self.assertEqual(1, code)
        self.assertTrue(any("source-hint" in item for item in summary["blockers"]))

    def test_contract_when_nine_endorsements_expect_closed_schema_rejection(self) -> None:
        binding = self.fixture.contract["evidence"]["endorsements"][0]
        self.fixture.contract["evidence"]["endorsements"] = [
            {
                **binding,
                "fileName": f"endorsement-{index}.json",
                "digest": digest(f"endorsement-{index}"),
            }
            for index in range(9)
        ]
        self.rewrite()

        with self.assertRaisesRegex(ValueError, "closed schema"):
            self.run_mode("preflight")

    def test_all_modes_when_fixture_is_valid_expect_only_fixture_completion(self) -> None:
        for mode in federation.MODES:
            with self.subTest(mode=mode):
                code, summary = self.run_mode(mode)
                self.assertEqual(0, code)
                self.assertFalse(summary["operational"])
                self.assertFalse(summary["operationalFederationComplete"])
                expected = (
                    "implementation-complete"
                    if mode == "preflight"
                    else "fixture-verification-complete"
                )
                self.assertEqual(expected, summary["state"])

    def test_fixture_when_requesting_operational_state_expect_blocked(self) -> None:
        self.fixture.contract["requestedState"] = "operational-federation-complete"
        self.rewrite()

        code, summary = self.run_mode("closeout")

        self.assertEqual(1, code)
        self.assertEqual("blocked", summary["state"])
        self.assertFalse(summary["operational"])

    def test_false_fixture_flags_when_identities_are_fixture_shaped_expect_blocked(self) -> None:
        self.fixture.contract["fixtureOnly"] = False
        self.fixture.contract["selfTest"] = False
        self.fixture.contract["requestedState"] = "operational-federation-complete"
        for authority in self.fixture.contract["authorities"].values():
            authority["operational"] = True
        self.rewrite()

        code, summary = self.run_mode("closeout")

        self.assertEqual(1, code)
        self.assertFalse(summary["operational"])
        self.assertTrue(any("test-identity" in item for item in summary["blockers"]))

    def test_descriptor_when_signature_is_substituted_expect_fail_closed(self) -> None:
        self.fixture.descriptor["signature"]["valueBase64"] = "A" * 86 + "=="
        self.fixture.write_all()

        code, summary = self.run_mode("verify-discovery")

        self.assertEqual(1, code)
        self.assertEqual("partial", summary["state"])
        self.assertTrue(any("signature" in item for item in summary["blockers"]))

    def test_endorsement_when_creating_trust_expect_closed_schema_rejection(self) -> None:
        self.fixture.endorsement["createsTrust"] = True
        self.fixture.write_all()

        code, summary = self.run_mode("verify-discovery")

        self.assertEqual(1, code)
        self.assertFalse(summary["operational"])
        self.assertTrue(any("endorsement" in item for item in summary["blockers"]))

    def test_runtime_when_local_state_is_sent_expect_fail_closed(self) -> None:
        self.fixture.runtime["discovery"]["localStateSent"] = True
        self.fixture.write_all()

        code, summary = self.run_mode("verify-runtime")

        self.assertEqual(1, code)
        self.assertFalse(summary["runtimeFederationVerified"])
        self.assertFalse(summary["operational"])

    def test_runtime_when_lexical_tie_break_returns_expect_fail_closed(self) -> None:
        self.fixture.runtime["scenarios"]["lexicalTieBreakDisabled"] = False
        self.fixture.write_all()

        code, summary = self.run_mode("verify-conflicts")

        self.assertEqual(1, code)
        self.assertFalse(summary["conflictPolicyVerified"])

    def test_runtime_when_catalog_binding_is_aliased_expect_fail_closed(self) -> None:
        self.fixture.runtime["catalogs"][2]["trustBindingId"] = self.fixture.runtime[
            "catalogs"
        ][0]["trustBindingId"]
        _seal(self.fixture.runtime, "receiptDigest", *self.fixture.observer)
        self.fixture.write_all()

        code, summary = self.run_mode("verify-local-trust")

        self.assertEqual(1, code)
        self.assertTrue(any("aliases" in item for item in summary["blockers"]))

    def test_runtime_when_observerBindingIsSubstituted_expectFailClosed(self) -> None:
        self.fixture.contract["evidence"]["runtimeObservation"][
            "observerFingerprint"
        ] = digest("substituted-observer")
        self.rewrite()

        code, summary = self.run_mode("verify-runtime")

        self.assertEqual(1, code)
        self.assertTrue(any("observer-identity" in item for item in summary["blockers"]))

    def test_runtime_whenProtectedReceiptProvenanceDiffers_expectFailClosed(self) -> None:
        self.fixture.contract["evidence"]["runtimeObservation"]["receiptProvenance"][
            "runAttempt"
        ] = 2
        self.rewrite()

        code, summary = self.run_mode("verify-runtime")

        self.assertEqual(1, code)
        self.assertTrue(any("producer-coordinates" in item for item in summary["blockers"]))

    def test_binding_when_digest_changes_expect_fail_closed(self) -> None:
        self.fixture.contract["evidence"]["descriptor"]["digest"] = digest("wrong")
        self.rewrite()

        code, summary = self.run_mode("verify-discovery")

        self.assertEqual(1, code)
        self.assertTrue(any("digest" in item for item in summary["blockers"]))

    def test_preflight_when_archiveContainsUnboundMember_expectFailClosed(self) -> None:
        write_json(
            self.fixture.evidence / "unbound-runtime-dump.json",
            {"rawAppData": "private application state"},
        )

        code, summary = self.run_mode("preflight")

        self.assertEqual(1, code)
        self.assertFalse(summary["implementationComplete"])
        self.assertTrue(any("unbound-member" in item for item in summary["blockers"]))

    def test_closeout_whenPredecessorSummariesAreUnbound_expectAuthorityErrors(self) -> None:
        policy, _ = federation._policy(self.workspace)

        errors = federation._authority_errors(
            self.fixture.contract, policy, self.fixture.evidence
        )

        for name in federation.AUTHORITY_WORKFLOW_KEYS:
            with self.subTest(authority=name):
                self.assertTrue(
                    any(
                        f"{name} predecessor summary is not bound" in error
                        for error in errors
                    )
                )

    def test_contract_when_private_insert_uri_present_expect_rejected_before_output(self) -> None:
        self.fixture.contract["executionId"] = "USK@abc,def,AQECAAE/private"
        self.rewrite()

        with self.assertRaisesRegex(ValueError, "closed schema|prohibited"):
            federation.run(
                self.workspace,
                self.fixture.contract_path,
                "preflight",
                self.root / "unsafe-output",
                self.fixture.evidence,
            )
        self.assertFalse((self.root / "unsafe-output").exists())

    @unittest.skipIf(os.name == "nt", "symlink creation is not consistently available")
    def test_evidence_when_directory_is_symlink_expect_rejected_before_output(self) -> None:
        linked = self.root / "linked-evidence"
        linked.symlink_to(self.fixture.evidence, target_is_directory=True)

        with self.assertRaisesRegex(ValueError, "symlink"):
            federation.run(
                self.workspace,
                self.fixture.contract_path,
                "verify-discovery",
                self.root / "linked-evidence-output",
                linked,
            )
        self.assertFalse((self.root / "linked-evidence-output").exists())

    @unittest.skipIf(os.name == "nt", "symlink creation is not consistently available")
    def test_output_when_path_is_symlink_expect_no_evidence_written(self) -> None:
        linked = self.root / "linked-output"
        linked.symlink_to(self.fixture.evidence, target_is_directory=True)

        with self.assertRaisesRegex(ValueError, "output"):
            federation.run(
                self.workspace,
                self.fixture.contract_path,
                "preflight",
                linked,
                self.fixture.evidence,
            )
        self.assertEqual(
            ["descriptor.json", "endorsement.json", "runtime.json"],
            sorted(path.name for path in self.fixture.evidence.iterdir()),
        )

    def test_schemas_when_loaded_expect_closed_supported_contracts(self) -> None:
        schemas = self.workspace / "tools/release-certification/schemas"
        for name in (
            federation.EXECUTION_SCHEMA,
            federation.DESCRIPTOR_SCHEMA,
            federation.ENDORSEMENT_SCHEMA,
            federation.RUNTIME_SCHEMA,
            federation.SUMMARY_SCHEMA,
        ):
            with self.subTest(schema=name):
                value = json.loads((schemas / name).read_text())
                self.assertFalse(value["additionalProperties"])
                self.assertEqual(
                    "https://json-schema.org/draft/2020-12/schema", value["$schema"]
                )

    def test_certification_contracts_when_loaded_expect_runtime_endorsement_limit(self) -> None:
        schemas = self.workspace / "tools/release-certification/schemas"
        execution = json.loads((schemas / federation.EXECUTION_SCHEMA).read_text())
        runtime = json.loads((schemas / federation.RUNTIME_SCHEMA).read_text())
        summary = json.loads((schemas / federation.SUMMARY_SCHEMA).read_text())
        policy, _ = federation._policy(self.workspace)

        self.assertEqual(
            8,
            execution["properties"]["evidence"]["properties"]["endorsements"][
                "maxItems"
            ],
        )
        self.assertEqual(
            8,
            runtime["properties"]["discovery"]["properties"][
                "endorsementDigests"
            ]["maxItems"],
        )
        self.assertEqual(8, summary["properties"]["endorsementDigests"]["maxItems"])
        self.assertEqual(8, policy["limits"]["maximumEndorsements"])

    def test_summary_when_emitted_expect_self_digest_and_clean_redaction(self) -> None:
        code, summary = self.run_mode("verify-runtime")

        self.assertEqual(0, code)
        self.assertEqual(
            summary["summaryDigest"],
            federation._semantic_digest(summary, "summaryDigest"),
        )
        redaction = json.loads(
            (
                self.root
                / f"output-{self.run_number}"
                / federation.REDACTION_FILE
            ).read_text()
        )
        self.assertEqual("pass", redaction["status"])
        self.assertEqual(0, redaction["findingCount"])


if __name__ == "__main__":
    unittest.main()
