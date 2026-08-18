"""Credential-free Stable RC dispatch receipt tests."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from cryptad_certification.engines import stable_1_0_protected_release as protected
from cryptad_certification.tests.support import workspace_root
from cryptad_certification.tests.test_stable_protected_release import (
    _contract,
    _preflight_summary,
)


def _bound_dispatch(root: Path) -> tuple[dict[str, object], dict[str, object], str]:
    contract = _contract(root)
    receipt = _preflight_summary(contract)
    receipt_text = json.dumps(receipt, separators=(",", ":"), sort_keys=True)
    contract["operationEvidence"]["preflight"] = {  # type: ignore[index]
        "path": "reviewed-preflight.json",
        "sha256": "sha256:" + hashlib.sha256(receipt_text.encode("utf-8")).hexdigest(),
        "schema": protected.SUMMARY_SCHEMA,
    }
    return contract, receipt, receipt_text


class StableProtectedRcPreflightTests(unittest.TestCase):
    """Exercise the receipt gate that runs before the protected environment."""

    def test_credential_free_gate_accepts_exact_reviewed_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            contract, receipt, receipt_text = _bound_dispatch(Path(temporary).resolve())
            digest = "sha256:" + hashlib.sha256(receipt_text.encode("utf-8")).hexdigest()

            errors = protected.credential_free_preflight_receipt_errors(
                contract,
                receipt,
                digest,
            )

        self.assertEqual([], errors)

    def test_credential_free_gate_rejects_stale_or_substituted_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            contract, receipt, receipt_text = _bound_dispatch(Path(temporary).resolve())
            digest = "sha256:" + hashlib.sha256(receipt_text.encode("utf-8")).hexdigest()
            cases: dict[str, tuple[dict[str, object], dict[str, object], str]] = {}
            wrong_digest = "sha256:" + "9" * 64
            cases["different receipt bytes"] = (contract, receipt, wrong_digest)
            stale_receipt = copy.deepcopy(receipt)
            stale_receipt["mode"] = "closeout"
            cases["stale receipt"] = (contract, stale_receipt, digest)
            changed_contract = copy.deepcopy(contract)
            changed_contract["publicTargets"]["artifactBaseUri"] = (  # type: ignore[index]
                "https://8.8.4.4/stable/"
            )
            cases["changed reviewed targets"] = (changed_contract, receipt, digest)

            for label, (candidate_contract, candidate_receipt, candidate_digest) in cases.items():
                with self.subTest(label=label):
                    self.assertTrue(
                        protected.credential_free_preflight_receipt_errors(
                            candidate_contract,
                            candidate_receipt,
                            candidate_digest,
                        )
                    )

    def test_rc_workflow_authenticates_receipt_before_protected_job(self) -> None:
        workflow = (
            workspace_root() / ".github/workflows/stable-1.0-rc-release.yml"
        ).read_text(encoding="utf-8")
        preflight = workflow[
            workflow.index("\n  preflight:") : workflow.index("\n  stable-rc:")
        ]

        self.assertIn(
            "PROTECTED_PREFLIGHT_RECEIPT_JSON: ${{ inputs.protected_preflight_receipt }}",
            preflight,
        )
        self.assertIn("credential_free_preflight_receipt_errors", preflight)
        self.assertIn("receipt_digest", preflight)
        self.assertNotIn("environment: stable-1-0-rc", preflight)
        self.assertNotIn("secrets.", preflight)


if __name__ == "__main__":
    unittest.main()
