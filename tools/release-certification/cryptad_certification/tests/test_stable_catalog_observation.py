"""Tests for protected Stable catalog mirror receipt construction."""

from __future__ import annotations

import copy
import hashlib
import tempfile
import unittest
from pathlib import Path

from cryptad_certification.engines import stable_1_0_catalog_authority as authority
from cryptad_certification.engines import stable_1_0_catalog_observation as observation
from cryptad_certification.tests.test_stable_catalog_authority import _manifest


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


class StableCatalogObservationTest(unittest.TestCase):
    """Keeps raw fetches outside the canonical redacted observation receipt."""

    def setUp(self) -> None:
        self.catalog = b"catalog.id=crypta-stable-apps\ncatalog.channel=stable\n"
        self.signature = b"schemaVersion=1\nkeyId=stable-catalog-fixture-1\nsignature=fixture\n"
        self.observed_at = "2026-08-22T02:00:00Z"
        self.collection_started_at = "2026-08-22T02:01:00Z"
        self.collection_completed_at = "2026-08-22T02:02:00Z"
        self.manifest = _manifest()
        self.manifest["fixtureOnly"] = False
        subject = self.manifest["catalog"]
        subject["catalogDigest"] = _digest(self.catalog)
        subject["catalogSize"] = len(self.catalog)
        subject["signatureDigest"] = _digest(self.signature)
        subject["signatureSize"] = len(self.signature)
        self.revision_digest = observation._revision_digest(self.catalog, self.signature)
        catalog_subject = authority._catalog_subject(subject)
        locations = [
            self.manifest["publication"]["networkPrimary"],
            *self.manifest["publication"]["mirrors"],
        ]
        self.manifest["publication"]["observations"] = [
            {
                "locationId": location["locationId"],
                "observedAt": self.observed_at,
                "status": "exact-match",
                **catalog_subject,
            }
            for location in locations
        ]
        self.manifest["publication"]["requestedState"] = "observed"
        self.plan = authority._publication_plan(self.manifest, "sha256:" + "a" * 64)
        self.live = {
            "mode": "live",
            "catalogId": subject["catalogId"],
            "publicCatalogSource": self.manifest["publication"]["networkPrimary"][
                "publicUri"
            ],
            "catalogSha256": subject["catalogDigest"].removeprefix("sha256:"),
            "signatureSha256": subject["signatureDigest"].removeprefix("sha256:"),
            "catalogSigningKeyId": subject["signingKeyId"],
            "postPublishVerificationStatus": "verified",
        }
        self.health = {
            "health": {
                "catalogId": subject["catalogId"],
                "catalogDigest": self.revision_digest,
                "signatureKeyId": subject["signingKeyId"],
                "status": "success",
                "sourceHealth": [
                    {
                        "role": role,
                        "lastFetchStatus": "success",
                        "lastAttemptAt": "2026-08-22T02:01:30Z",
                        "lastSuccessfulRefreshAt": "2026-08-22T02:01:30Z",
                        "lastCatalogDigest": self.revision_digest,
                        "lastSignatureKeyId": subject["signingKeyId"],
                    }
                    for role in ("primary", "mirror")
                ],
            }
        }

    def test_construct_receipt_when_primary_and_mirror_are_exact_expect_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, fetched = self._write_sidecars(root)

            receipt = observation.construct_receipt(
                self.manifest,
                self.plan,
                self.live,
                evidence,
                fetched,
                self.health,
                self.observed_at,
                self.collection_started_at,
                self.collection_completed_at,
            )

        self.assertEqual("pass", receipt["status"])
        self.assertEqual("pass", receipt["schedulerRefreshVerificationStatus"])
        self.assertNotIn("publicKeySpkiBase64", str(receipt))
        self.assertNotIn("contentText", str(receipt))

    def test_revision_digest_when_sidecars_are_exact_expect_java_runtime_contract(self) -> None:
        revision_digest = observation._revision_digest(self.catalog, self.signature)

        self.assertEqual(
            "sha256:34dd007a638a11fc22055d9465d0b90bc631fc33060c309b66aded49f92f4b4c",
            revision_digest,
        )
        self.assertNotEqual(_digest(self.catalog), revision_digest)

    def test_construct_receipt_when_scheduler_uses_content_digest_expect_rejection(self) -> None:
        health = copy.deepcopy(self.health)
        health["health"]["catalogDigest"] = self.manifest["catalog"]["catalogDigest"]
        for row in health["health"]["sourceHealth"]:
            row["lastCatalogDigest"] = self.manifest["catalog"]["catalogDigest"]
        with tempfile.TemporaryDirectory() as directory:
            evidence, fetched = self._write_sidecars(Path(directory))

            with self.assertRaisesRegex(ValueError, "exact current catalog"):
                observation.construct_receipt(
                    self.manifest,
                    self.plan,
                    self.live,
                    evidence,
                    fetched,
                    health,
                    self.observed_at,
                    self.collection_started_at,
                    self.collection_completed_at,
                )

    def test_construct_receipt_when_mirror_signature_drifts_expect_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, fetched = self._write_sidecars(root)
            (fetched / "independent-web-mirror.signature").write_bytes(b"different")

            with self.assertRaisesRegex(ValueError, "exact catalog and signature"):
                observation.construct_receipt(
                    self.manifest,
                    self.plan,
                    self.live,
                    evidence,
                    fetched,
                    self.health,
                    self.observed_at,
                    self.collection_started_at,
                    self.collection_completed_at,
                )

    def test_construct_receipt_when_scheduler_has_no_exact_mirror_expect_rejection(
        self,
    ) -> None:
        health = copy.deepcopy(self.health)
        health["health"]["sourceHealth"] = health["health"]["sourceHealth"][:1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, fetched = self._write_sidecars(root)

            with self.assertRaisesRegex(ValueError, "primary and mirror"):
                observation.construct_receipt(
                    self.manifest,
                    self.plan,
                    self.live,
                    evidence,
                    fetched,
                    health,
                    self.observed_at,
                    self.collection_started_at,
                    self.collection_completed_at,
                )

    def test_construct_receipt_when_scheduler_success_is_stale_expect_rejection(self) -> None:
        health = copy.deepcopy(self.health)
        health["health"]["sourceHealth"][1]["lastAttemptAt"] = "2026-08-22T01:59:59Z"
        health["health"]["sourceHealth"][1]["lastSuccessfulRefreshAt"] = (
            "2026-08-22T01:59:59Z"
        )
        with tempfile.TemporaryDirectory() as directory:
            evidence, fetched = self._write_sidecars(Path(directory))

            with self.assertRaisesRegex(ValueError, "fresh exact successful primary and mirror"):
                observation.construct_receipt(
                    self.manifest,
                    self.plan,
                    self.live,
                    evidence,
                    fetched,
                    health,
                    self.observed_at,
                    self.collection_started_at,
                    self.collection_completed_at,
                )

    def test_construct_receipt_when_scheduler_timestamp_is_not_current_expect_rejection(
        self,
    ) -> None:
        cases = (
            ("lastSuccessfulRefreshAt", None),
            ("lastSuccessfulRefreshAt", "not-a-timestamp"),
            ("lastSuccessfulRefreshAt", "2026-08-22T02:02:01Z"),
            ("lastAttemptAt", "2026-08-22T02:01:31Z"),
        )
        with tempfile.TemporaryDirectory() as directory:
            evidence, fetched = self._write_sidecars(Path(directory))
            for field, value in cases:
                with self.subTest(field=field, value=value):
                    health = copy.deepcopy(self.health)
                    health["health"]["sourceHealth"][0][field] = value

                    with self.assertRaisesRegex(
                        ValueError, "fresh exact successful primary and mirror"
                    ):
                        observation.construct_receipt(
                            self.manifest,
                            self.plan,
                            self.live,
                            evidence,
                            fetched,
                            health,
                            self.observed_at,
                            self.collection_started_at,
                            self.collection_completed_at,
                        )

    def test_construct_receipt_when_health_envelope_is_substituted_expect_rejection(self) -> None:
        health = self.health["health"]
        with tempfile.TemporaryDirectory() as directory:
            evidence, fetched = self._write_sidecars(Path(directory))

            with self.assertRaisesRegex(ValueError, "closed health envelope"):
                observation.construct_receipt(
                    self.manifest,
                    self.plan,
                    self.live,
                    evidence,
                    fetched,
                    health,
                    self.observed_at,
                    self.collection_started_at,
                    self.collection_completed_at,
                )

    def test_construct_receipt_when_collection_is_delayed_expect_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence, fetched = self._write_sidecars(Path(directory))

            with self.assertRaisesRegex(ValueError, "did not complete inside"):
                observation.construct_receipt(
                    self.manifest,
                    self.plan,
                    self.live,
                    evidence,
                    fetched,
                    self.health,
                    self.observed_at,
                    self.collection_started_at,
                    "2026-08-22T02:15:01Z",
                )

    def test_construct_receipt_when_signer_expires_during_collection_expect_rejection(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["keyset"]["keys"][0]["validUntil"] = "2026-08-22T02:02:00Z"
        plan = authority._publication_plan(manifest, "sha256:" + "a" * 64)
        with tempfile.TemporaryDirectory() as directory:
            evidence, fetched = self._write_sidecars(Path(directory))

            with self.assertRaisesRegex(ValueError, "through collection completion"):
                observation.construct_receipt(
                    manifest,
                    plan,
                    self.live,
                    evidence,
                    fetched,
                    self.health,
                    self.observed_at,
                    self.collection_started_at,
                    self.collection_completed_at,
                )

    def test_safe_bytes_when_file_is_at_bound_expect_bounded_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "signature"
            path.write_bytes(b"s" * 65536)

            value = observation._safe_bytes(path, "signature", 65536)

        self.assertEqual(65536, len(value))

    def test_safe_bytes_when_file_exceeds_bound_expect_rejection_before_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog"
            path.touch()
            path.write_bytes(b"c" * (1048576 + 1))

            with self.assertRaisesRegex(ValueError, "byte bound"):
                observation._safe_bytes(path, "catalog", 1048576)

    def _write_sidecars(self, root: Path) -> tuple[Path, Path]:
        evidence = root / "evidence"
        fetched = root / "fetched"
        evidence.mkdir()
        fetched.mkdir()
        (evidence / authority.FROZEN_CATALOG_FILE).write_bytes(self.catalog)
        (evidence / authority.FROZEN_SIGNATURE_FILE).write_bytes(self.signature)
        for location in [
            self.manifest["publication"]["networkPrimary"],
            *self.manifest["publication"]["mirrors"],
        ]:
            location_id = location["locationId"]
            (fetched / f"{location_id}.catalog").write_bytes(self.catalog)
            (fetched / f"{location_id}.signature").write_bytes(self.signature)
        return evidence, fetched


if __name__ == "__main__":
    unittest.main()
