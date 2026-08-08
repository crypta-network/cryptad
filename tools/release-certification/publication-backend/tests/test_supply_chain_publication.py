"""Offline characterization of the Stable supply-chain publication backend."""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit


BACKEND_ROOT = Path(__file__).resolve().parents[1]
RELEASE_CERTIFICATION_ROOT = BACKEND_ROOT.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))
sys.path.insert(0, str(RELEASE_CERTIFICATION_ROOT))

from cryptad_certification.io import write_json as engine_write_json  # noqa: E402
from cryptad_certification.engines.stable_1_0_supply_chain import (  # noqa: E402
    _evidence_for_mode as engine_evidence_for_mode,
)
from cryptad_certification.engines.stable_1_0_supply_chain_core import (  # noqa: E402
    PUBLICATION_ROLE_FILES as ENGINE_PUBLICATION_ROLE_FILES,
    semantic_digest as engine_semantic_digest,
)
from cryptad_certification.engines.stable_1_0_supply_chain_reproducibility import (  # noqa: E402
    publication_errors as engine_publication_errors,
)
from cryptad_stable_maintenance_backend.provider import ProviderError  # noqa: E402
from cryptad_stable_maintenance_backend.supply_chain import (  # noqa: E402
    AuthenticatedObserver,
    AuthenticatedProducer,
    SUPPLY_CHAIN_ASSET_FILES,
    SUPPLY_CHAIN_ROLES,
    SupplyChainPublicationBackend,
)


COMMIT = "1" * 40
ATTESTATION = "sha256:" + "2" * 64
GENERATED_AT = "2026-08-04T00:00:00Z"


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode() + b"\n"


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def semantic_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def semantic_digest(value: dict[str, object], field: str) -> str:
    payload = {key: child for key, child in value.items() if key != field}
    return digest(semantic_bytes(payload))


def promotion_summary(release: dict[str, object]) -> dict[str, object]:
    value: dict[str, object] = {
        "schemaVersion": 1,
        "kind": "stable-1.0-supply-chain-promotion-summary",
        **{
            key: release[key]
            for key in (
                "releaseId",
                "buildVersion",
                "tag",
                "sourceCommit",
                "sourceRef",
                "policyDigest",
            )
        },
        "mode": "evaluate-promotion",
        "status": "pass",
        "promotionReady": True,
        "candidateIdentityDigest": None,
        "candidateFreezeDigest": None,
        "productDigest": None,
        "predecessorReleaseId": None,
        "predecessorBuildVersion": None,
        "predecessorProductDigest": None,
        "packageMatrixDigest": None,
        "packageAuthenticationDigest": None,
        "selectedSubjectInventoryDigest": None,
        "vulnerabilitySummaryDigest": None,
        "vulnerabilityReverseIndexDigest": None,
        "resolvedDependencySnapshotDigest": None,
        "componentInventoryDigest": None,
        "subjectInventoryDigest": None,
        "sbomDigest": None,
        "licenseInventoryDigest": None,
        "buildMaterialsDigest": None,
        "primaryBuilderReceiptDigest": None,
        "verifierBuilderReceiptDigest": None,
        "comparisonPlanDigest": None,
        "reproducibilityResultDigest": None,
        "evidence": [
            {
                "evidenceId": evidence_id,
                "status": "pass",
                "nonWaivable": True,
            }
            for evidence_id in engine_evidence_for_mode("evaluate-promotion")
        ],
        "blockers": [],
        "waivers": [],
        "artifacts": [],
        "redaction": {
            "status": "pass",
            "privatePathsExcluded": True,
            "credentialsExcluded": True,
            "privateUrisExcluded": True,
            "embargoedVulnerabilityDataExcluded": True,
            "sideEffectsPerformed": False,
        },
        "summaryDigest": "sha256:" + "0" * 64,
    }
    value["summaryDigest"] = semantic_digest(value, "summaryDigest")
    return value


class FakeGitHubTransport:
    """In-memory GitHub API used to prove the self-test performs no remote mutation."""

    def __init__(self, plan: dict[str, object]) -> None:
        self.plan = plan
        self.tag_sha = "a" * 40
        self.assets: list[dict[str, object]] = []
        self.contents: dict[int, bytes] = {}
        self.post_count = 0

    def request(
        self,
        method: str,
        uri: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        del headers
        if method == "GET" and "/git/ref/tags/" in uri:
            return 200, {}, json.dumps(
                {"object": {"type": "tag", "sha": self.tag_sha}}
            ).encode()
        if method == "GET" and f"/git/tags/{self.tag_sha}" in uri:
            return 200, {}, json.dumps(
                {
                    "tag": self.plan["tag"],
                    "object": {
                        "type": "commit",
                        "sha": self.plan["sourceCommit"],
                    },
                }
            ).encode()
        if method == "GET" and "/releases/tags/" in uri:
            release = {
                "id": 17,
                "tag_name": self.plan["tag"],
                "target_commitish": self.plan["sourceCommit"],
                "html_url": (
                    "https://github.com/crypta-network/cryptad/releases/tag/"
                    + str(self.plan["tag"])
                ),
                "draft": False,
                "prerelease": False,
                "assets": copy.deepcopy(self.assets),
            }
            return 200, {}, json.dumps(release).encode()
        if method == "POST" and "/releases/17/assets?" in uri:
            self.post_count += 1
            name = parse_qs(urlsplit(uri).query)["name"][0]
            content = bytes(body or b"")
            asset_id = 100 + len(self.assets)
            self.contents[asset_id] = content
            self.assets.append(
                {
                    "id": asset_id,
                    "name": name,
                    "size": len(content),
                    "browser_download_url": (
                        "https://github.com/crypta-network/cryptad/releases/download/"
                        f"{self.plan['tag']}/{name}"
                    ),
                }
            )
            return 201, {}, b"{}"
        raise AssertionError(f"unexpected fake request: {method} {uri}")

    def digest(
        self,
        uri: str,
        expected_size: int,
        *,
        headers: dict[str, str] | None = None,
        redirect_budget: int = 1,
    ) -> tuple[int, int, str | None]:
        del headers, redirect_budget
        asset_id = int(uri.rsplit("/", 1)[1])
        content = self.contents.get(asset_id)
        if content is None:
            return 404, 0, None
        return 200, len(content), digest(content)

    def seed(self, row: dict[str, object], content: bytes) -> None:
        asset_id = 100 + len(self.assets)
        self.contents[asset_id] = content
        self.assets.append(
            {
                "id": asset_id,
                "name": row["fileName"],
                "size": len(content),
                "browser_download_url": row["uri"],
            }
        )


class SupplyChainPublicationBackendTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.contents: dict[str, bytes] = {}
        assets: list[dict[str, object]] = []
        for role in SUPPLY_CHAIN_ROLES:
            file_name = SUPPLY_CHAIN_ASSET_FILES[role]
            content = canonical_bytes({"role": role})
            (self.root / file_name).write_bytes(content)
            self.contents[role] = content
            assets.append(
                {
                    "role": role,
                    "fileName": file_name,
                    "digest": digest(content),
                    "size": len(content),
                    "uri": (
                        "https://github.com/crypta-network/cryptad/releases/download/"
                        f"v123/{file_name}"
                    ),
                }
            )
        self.plan: dict[str, object] = {
            "schemaVersion": 1,
            "kind": "stable-1.0-supply-chain-publication-plan",
            "releaseId": "stable-1.0-build-123",
            "buildVersion": 123,
            "tag": "v123",
            "sourceCommit": COMMIT,
            "sourceRef": "refs/heads/release/123",
            "policyDigest": "sha256:" + "3" * 64,
            "summaryDigest": "sha256:" + "4" * 64,
            "assets": assets,
            "overwriteAllowed": False,
            "allowedOperations": ["created", "verified-existing"],
            "sideEffectsPerformed": False,
            "planDigest": "sha256:" + "0" * 64,
        }
        self.summary = promotion_summary(self.plan)
        self.plan["summaryDigest"] = self.summary["summaryDigest"]
        self.plan["planDigest"] = semantic_digest(self.plan, "planDigest")
        self.producer = AuthenticatedProducer(
            "cryptad_stable_maintenance_backend:supply_chain_factory@sha256:"
            + "5" * 64,
            (
                "github.com/crypta-network/cryptad/.github/workflows/"
                "stable-1.0-supply-chain.yml@"
                + COMMIT
            ),
            ATTESTATION,
            True,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _backend(self) -> tuple[SupplyChainPublicationBackend, FakeGitHubTransport]:
        transport = FakeGitHubTransport(self.plan)
        return SupplyChainPublicationBackend("offline-test-token", transport), transport

    def _publish(
        self, backend: SupplyChainPublicationBackend
    ) -> dict[str, object]:
        return backend.publish(
            self.plan,
            canonical_bytes(self.plan),
            self.root,
            self.producer,
            GENERATED_AT,
        )

    def test_publish_when_all_roles_are_absent_creates_exact_deterministic_receipt(self) -> None:
        backend, transport = self._backend()

        first = self._publish(backend)
        other_backend, other_transport = self._backend()
        second = self._publish(other_backend)

        self.assertEqual(first, second)
        self.assertEqual(len(SUPPLY_CHAIN_ASSET_FILES), transport.post_count)
        self.assertEqual(len(SUPPLY_CHAIN_ASSET_FILES), other_transport.post_count)
        self.assertEqual(
            {"created"}, {row["operation"] for row in first["operations"]}
        )
        self.assertEqual(
            semantic_digest(first, "receiptDigest"), first["receiptDigest"]
        )
        self.assertEqual(
            list(SUPPLY_CHAIN_ROLES),
            [row["role"] for row in first["operations"]],
        )

    def test_publish_when_engine_plan_is_used_emits_engine_compatible_evidence(self) -> None:
        self.assertEqual(
            engine_semantic_digest(self.plan, "planDigest"),
            self.plan["planDigest"],
        )
        self.assertEqual(tuple(ENGINE_PUBLICATION_ROLE_FILES), SUPPLY_CHAIN_ROLES)
        policy = json.loads(
            (
                RELEASE_CERTIFICATION_ROOT
                / "stable-1.0-supply-chain-policy.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            tuple(policy["publicationPolicy"]["requiredRoles"]),
            SUPPLY_CHAIN_ROLES,
        )
        engine_plan_path = self.root / "engine-publication-plan.json"
        engine_write_json(engine_plan_path, self.plan)
        engine_plan_bytes = engine_plan_path.read_bytes()
        backend, _transport = self._backend()

        receipt = backend.publish(
            self.plan,
            engine_plan_bytes,
            self.root,
            self.producer,
            GENERATED_AT,
        )
        observation = backend.observe(
            self.plan,
            engine_plan_bytes,
            str(receipt["receiptDigest"]),
            AuthenticatedObserver(
                "github.com/crypta-network/cryptad/.github/workflows/"
                "stable-1.0-supply-chain.yml@" + COMMIT,
                "sha256:" + "6" * 64,
                True,
            ),
            "2026-08-04T00:01:00Z",
        )
        release = {
            key: self.plan[key]
            for key in (
                "releaseId",
                "buildVersion",
                "tag",
                "sourceCommit",
                "sourceRef",
                "policyDigest",
            )
        }
        self.assertEqual(
            engine_semantic_digest(receipt, "receiptDigest"),
            receipt["receiptDigest"],
        )
        self.assertEqual(
            engine_semantic_digest(observation, "observationDigest"),
            observation["observationDigest"],
        )
        self.assertEqual(
            list(SUPPLY_CHAIN_ROLES),
            [row["role"] for row in receipt["operations"]],
        )
        self.assertEqual(
            list(SUPPLY_CHAIN_ROLES),
            [row["role"] for row in observation["assets"]],
        )
        self.assertEqual(
            [],
            engine_publication_errors(
                self.plan,
                receipt,
                observation,
                self.summary,
                release,
                policy,
                "2026-08-04T00:02:00Z",
            ),
        )

    def test_publish_when_plan_bytes_are_compact_instead_of_exact_fails_closed(self) -> None:
        backend, transport = self._backend()

        with self.assertRaisesRegex(ProviderError, "plan-not-canonical"):
            backend.publish(
                self.plan,
                semantic_bytes(self.plan),
                self.root,
                self.producer,
                GENERATED_AT,
            )

        self.assertEqual(0, transport.post_count)

    def test_publish_when_exact_bytes_exist_is_idempotent(self) -> None:
        backend, transport = self._backend()
        self._publish(backend)
        posts_after_first = transport.post_count

        receipt = self._publish(backend)

        self.assertEqual(posts_after_first, transport.post_count)
        self.assertEqual(
            {"verified-existing"},
            {row["operation"] for row in receipt["operations"]},
        )

    def test_publish_when_existing_bytes_conflict_fails_before_upload(self) -> None:
        backend, transport = self._backend()
        row = self.plan["assets"][0]
        transport.seed(row, b"conflicting bytes")

        with self.assertRaisesRegex(ProviderError, "conflicting-existing-bytes"):
            self._publish(backend)

        self.assertEqual(0, transport.post_count)

    def test_publish_when_release_subject_inventory_role_is_missing_fails_closed(self) -> None:
        self.plan["assets"] = [
            row
            for row in self.plan["assets"]
            if row["role"] != "release-subject-inventory"
        ]
        self.plan["planDigest"] = semantic_digest(self.plan, "planDigest")
        backend, transport = self._backend()

        with self.assertRaisesRegex(ProviderError, "role-set-invalid"):
            self._publish(backend)

        self.assertEqual(0, transport.post_count)

    def test_publish_when_engine_sealed_plan_reorders_roles_fails_closed(self) -> None:
        self.plan["assets"][4], self.plan["assets"][5] = (
            self.plan["assets"][5],
            self.plan["assets"][4],
        )
        self.plan["planDigest"] = engine_semantic_digest(self.plan, "planDigest")
        backend, transport = self._backend()

        with self.assertRaisesRegex(ProviderError, "role-set-invalid"):
            self._publish(backend)

        self.assertEqual(0, transport.post_count)

    def test_publish_when_immutable_uri_is_for_another_tag_fails_closed(self) -> None:
        self.plan["assets"][0]["uri"] = str(self.plan["assets"][0]["uri"]).replace(
            "/v123/", "/v124/"
        )
        self.plan["planDigest"] = semantic_digest(self.plan, "planDigest")
        backend, transport = self._backend()

        with self.assertRaisesRegex(ProviderError, "asset-binding-invalid"):
            self._publish(backend)

        self.assertEqual(0, transport.post_count)

    def test_publish_when_local_bytes_drift_fails_before_upload(self) -> None:
        changed = SUPPLY_CHAIN_ASSET_FILES["sbom"]
        (self.root / changed).write_bytes(b"changed")
        backend, transport = self._backend()

        with self.assertRaisesRegex(ProviderError, "local-asset-binding-changed"):
            self._publish(backend)

        self.assertEqual(0, transport.post_count)

    def test_publish_when_producer_is_unauthenticated_fails_before_upload(self) -> None:
        self.producer = dataclasses.replace(self.producer, authenticated=False)
        backend, transport = self._backend()

        with self.assertRaisesRegex(ProviderError, "producer-not-authenticated"):
            self._publish(backend)

        self.assertEqual(0, transport.post_count)

    def test_observe_when_public_bytes_match_emits_exact_observation(self) -> None:
        backend, _transport = self._backend()
        receipt = self._publish(backend)
        observer = AuthenticatedObserver(
            "github.com/crypta-network/cryptad/.github/workflows/"
            "stable-1.0-supply-chain.yml@" + COMMIT,
            "sha256:" + "6" * 64,
            True,
        )

        observation = backend.observe(
            self.plan,
            canonical_bytes(self.plan),
            str(receipt["receiptDigest"]),
            observer,
            "2026-08-04T00:01:00Z",
        )

        self.assertEqual(len(SUPPLY_CHAIN_ASSET_FILES), len(observation["assets"]))
        self.assertTrue(observation["observerAuthenticated"])
        self.assertEqual(
            list(SUPPLY_CHAIN_ROLES),
            [row["role"] for row in observation["assets"]],
        )
        self.assertEqual(
            semantic_digest(observation, "observationDigest"),
            observation["observationDigest"],
        )

    def test_observe_when_public_bytes_drift_fails_closed(self) -> None:
        backend, transport = self._backend()
        receipt = self._publish(backend)
        first_asset_id = int(transport.assets[0]["id"])
        transport.contents[first_asset_id] = b"drift"
        observer = AuthenticatedObserver(
            "github.com/crypta-network/cryptad/.github/workflows/"
            "stable-1.0-supply-chain.yml@" + COMMIT,
            "sha256:" + "6" * 64,
            True,
        )

        with self.assertRaisesRegex(ProviderError, "observation-not-exact"):
            backend.observe(
                self.plan,
                canonical_bytes(self.plan),
                str(receipt["receiptDigest"]),
                observer,
                "2026-08-04T00:01:00Z",
            )


if __name__ == "__main__":
    unittest.main()
