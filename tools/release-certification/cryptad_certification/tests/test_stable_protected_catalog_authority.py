"""Focused PR-293 integration tests for Stable protected-release closeout."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from cryptad_certification.engines import stable_1_0_protected_release as protected
from cryptad_certification.tests import test_stable_protected_release as base
from cryptad_certification.tests.support import workspace_root


def _summary(
    contract: dict[str, object],
    freeze_record: dict[str, object],
    independent_digests: dict[str, str],
) -> dict[str, object]:
    catalog = freeze_record["stableCatalog"]
    assert isinstance(catalog, dict)
    value: dict[str, object] = {
        "schemaVersion": 1,
        "kind": "stable-1.0-catalog-authority-summary",
        "mode": "closeout",
        "releaseId": contract["release"]["id"],  # type: ignore[index]
        "buildVersion": int(contract["release"]["integerBuild"]),  # type: ignore[index]
        "sourceCommit": contract["repository"]["candidateCommit"],  # type: ignore[index]
        "policyDigest": "sha256:" + "5" * 64,
        "protectedReleaseSummaryDigest": "sha256:" + "6" * 64,
        "protectedReleaseContractDigest": protected._plan_digest(contract),  # noqa: SLF001
        "independentReproducibilitySummaryDigest": independent_digests[
            "summaryDigest"
        ],
        "independentReproducibilityResultDigest": independent_digests[
            "resultDigest"
        ],
        "independentSubjectInventoryDigest": independent_digests[
            "subjectInventoryDigest"
        ],
        "keysetDigest": "sha256:" + "7" * 64,
        "catalogSubject": {
            "catalogId": catalog["catalogId"],
            "channel": catalog["channel"],
            "revision": catalog["revision"],
            "uskEdition": catalog["edition"],
            "catalogDigest": catalog["catalogDigest"],
            "catalogSize": 1024,
            "signatureDigest": catalog["signatureDigest"],
            "signatureSize": 64,
            "signingKeyId": catalog["catalogSigningKeyId"],
            "signingKeyFingerprintSha256": "sha256:" + "8" * 64,
        },
        "checks": {
            "ceremony": "pass",
            "publication": "pass",
            "rotationAndRollbackDrills": "pass",
            "roleSpecificRegistries": "pass",
            "redaction": "pass",
        },
        "fixtureOnly": False,
        "operational": False,
        "state": "partial",
        "status": "pass",
        "blockers": [],
        "generatedAt": "2026-08-16T02:00:00Z",
        "summaryDigest": base.DIGEST_ZERO,
    }
    value["summaryDigest"] = protected._semantic_digest(value)  # noqa: SLF001
    return value


def _archive(root: Path, relative: Path, summary: dict[str, object]) -> dict[str, object]:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    redaction = {
        "schemaVersion": 1,
        "kind": "stable-1.0-catalog-authority-redaction",
        "status": "pass",
        "findingCount": 0,
        "findings": [],
        "publicKeyMaterialLimitedTo": [
            "stable-1.0-public-key-transparency.json",
            "stable-1.0-catalog-trusted-keys.properties",
            "stable-1.0-app-trusted-keys.properties",
            "stable-1.0-reviewer-trusted-keys.properties",
        ],
    }

    def regular_member(name: str) -> zipfile.ZipInfo:
        member = zipfile.ZipInfo(name)
        member.create_system = 3
        member.external_attr = 0o100644 << 16
        return member

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(
            regular_member(protected.CATALOG_AUTHORITY_SUMMARY_MEMBER),
            json.dumps(summary, sort_keys=True, separators=(",", ":")),
        )
        archive.writestr(
            regular_member(protected.CATALOG_AUTHORITY_REPORT_MEMBER),
            "# Stable 1.0 catalog authority report\n\nAuthenticated partial state.\n",
        )
        archive.writestr(
            regular_member(protected.CATALOG_AUTHORITY_REDACTION_MEMBER),
            json.dumps(redaction, sort_keys=True, separators=(",", ":")),
        )
    return base._binding(root, relative)  # noqa: SLF001


class StableProtectedCatalogAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.contract = base._contract(self.root)  # noqa: SLF001
        self.policy = json.loads(
            (
                workspace_root()
                / "tools/release-certification/stable-1.0-protected-release-policy.json"
            ).read_text(encoding="utf-8")
        )
        source_patcher = mock.patch.object(protected, "_source_errors", return_value=[])
        source_patcher.start()
        self.addCleanup(source_patcher.stop)

    def test_closeout_requires_coordinate_and_artifact(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["workflowCoordinates"]["catalogAuthority"] = base._coordinate(  # type: ignore[index]  # noqa: SLF001
            protected.CATALOG_AUTHORITY_WORKFLOW,
            protected.CATALOG_AUTHORITY_ENVIRONMENT,
        )

        with mock.patch.object(protected, "_policy_errors", return_value=[]):
            findings, statuses = protected._closeout(  # noqa: SLF001
                self.root, contract, self.policy
            )

        self.assertEqual("blocked", statuses["catalogAuthority"])
        self.assertTrue(
            any("requires both exact workflow coordinates" in item for item in findings),
            findings,
        )

    def test_closeout_authenticates_exact_artifact(self) -> None:
        contract = copy.deepcopy(self.contract)
        selected = base._selected_rc()  # noqa: SLF001
        freeze_record = base._rc_freeze_record(selected)  # noqa: SLF001
        contract["ga"]["selectedRc"] = selected  # type: ignore[index]
        independent = {
            "summaryDigest": "sha256:" + "9" * 64,
            "resultDigest": "sha256:" + "a" * 64,
            "subjectInventoryDigest": "sha256:" + "c" * 64,
        }
        summary = _summary(contract, freeze_record, independent)
        binding = _archive(self.root, Path("catalog-authority/exact.zip"), summary)
        coordinate = base._coordinate(  # noqa: SLF001
            protected.CATALOG_AUTHORITY_WORKFLOW,
            protected.CATALOG_AUTHORITY_ENVIRONMENT,
            run_id="70",
            artifact_name=(
                f"stable-1-0-catalog-authority-closeout-{base.RELEASE_ID}-3-70-1"
            ),
            artifact_digest=binding["sha256"],
        )
        contract["workflowCoordinates"]["catalogAuthority"] = coordinate  # type: ignore[index]
        contract["operationEvidence"]["catalogAuthority"] = binding  # type: ignore[index]

        with mock.patch.object(
            protected, "_github_actions_coordinate_errors", return_value=[]
        ), mock.patch.object(
            protected,
            "_independent_summary_digests",
            return_value=(independent, []),
        ):
            state, findings = protected._catalog_authority_closeout(  # noqa: SLF001
                self.root, contract, freeze_record, "independently-reproduced"
            )

        self.assertEqual("mirrors-observed", state)
        self.assertEqual([], findings)

    def test_closeout_rejects_resealed_subject(self) -> None:
        contract = copy.deepcopy(self.contract)
        selected = base._selected_rc()  # noqa: SLF001
        freeze_record = base._rc_freeze_record(selected)  # noqa: SLF001
        contract["ga"]["selectedRc"] = selected  # type: ignore[index]
        independent = {
            "summaryDigest": "sha256:" + "9" * 64,
            "resultDigest": "sha256:" + "a" * 64,
            "subjectInventoryDigest": "sha256:" + "c" * 64,
        }
        summary = _summary(contract, freeze_record, independent)
        summary["sourceCommit"] = "b" * 40
        summary["independentReproducibilityResultDigest"] = "sha256:" + "e" * 64
        summary["summaryDigest"] = base.DIGEST_ZERO
        summary["summaryDigest"] = protected._semantic_digest(summary)  # noqa: SLF001
        binding = _archive(self.root, Path("catalog-authority/resealed.zip"), summary)
        coordinate = base._coordinate(  # noqa: SLF001
            protected.CATALOG_AUTHORITY_WORKFLOW,
            protected.CATALOG_AUTHORITY_ENVIRONMENT,
            run_id="71",
            artifact_name=(
                f"stable-1-0-catalog-authority-closeout-{base.RELEASE_ID}-3-71-1"
            ),
            artifact_digest=binding["sha256"],
        )
        contract["workflowCoordinates"]["catalogAuthority"] = coordinate  # type: ignore[index]
        contract["operationEvidence"]["catalogAuthority"] = binding  # type: ignore[index]

        with mock.patch.object(
            protected, "_github_actions_coordinate_errors", return_value=[]
        ), mock.patch.object(
            protected,
            "_independent_summary_digests",
            return_value=(independent, []),
        ):
            state, findings = protected._catalog_authority_closeout(  # noqa: SLF001
                self.root, contract, freeze_record, "independently-reproduced"
            )

        self.assertEqual("blocked", state)
        self.assertTrue(any("exact PR-291 release root" in item for item in findings))
        self.assertTrue(any("exact PR-292 result" in item for item in findings))
