"""Compatibility tests for Stable maintenance authorization v1."""

from __future__ import annotations

import copy
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from cryptad_certification.io import write_json
from cryptad_certification.schema_validation import validate_schema
from cryptad_certification.tests import test_stable_maintenance as fixtures

from ..engines import stable_1_0_maintenance
from ..engines.stable_1_0_maintenance import (
    _authorization,
    _authorization_expected,
    _close_authorization_errors,
)
from ..engines.stable_1_0_maintenance_core import (
    AUTHORIZATION_SCHEMA,
    LoadedJson,
    ValidationState,
    file_digest,
)


def _authorization_fixture(
    root: Path,
    *,
    release_class: str,
) -> tuple[object, object, dict[str, object], dict[str, object]]:
    context = fixtures._context(  # noqa: SLF001
        root,
        release_class=release_class,
        inputs={"stableMaintenanceAuthorization": "legacy-authorization.json"},
    )
    ga, predecessor = fixtures._ga_and_predecessor()  # noqa: SLF001
    candidate = fixtures._candidate(root, release_class)  # noqa: SLF001
    expected = _authorization_expected(
        context,
        ga,
        predecessor,
        candidate,
        fixtures._digest("2"),  # noqa: SLF001
        fixtures._digest("3"),  # noqa: SLF001
        fixtures._digest("4"),  # noqa: SLF001
        fixtures._digest("5"),  # noqa: SLF001
        fixtures._digest("6"),  # noqa: SLF001
        fixtures._digest("7"),  # noqa: SLF001
        fixtures._digest("8"),  # noqa: SLF001
        fixtures._digest("9") if release_class == "security-hotfix" else None,  # noqa: SLF001
        fixtures._digest("a"),  # noqa: SLF001
    )
    authorization = {
        "schemaVersion": 1,
        "kind": "stable-1.0-maintenance-authorization",
        "authorizationId": f"{release_class}-301-authorization",
        **expected,
        "approverIdentity": "stable-maintenance-approver",
        "authorizedAt": fixtures._timestamp(  # noqa: SLF001
            fixtures.NOW - timedelta(minutes=5)
        ),
        "expiresAt": fixtures._timestamp(  # noqa: SLF001
            fixtures.NOW + timedelta(hours=1)
        ),
        "decision": "go",
        "status": "approved",
        "redaction": fixtures._redaction(),  # noqa: SLF001
    }
    return context, candidate, expected, authorization


class StableMaintenanceAuthorizationCompatibilityTest(unittest.TestCase):
    """Keep legacy closure readable without weakening current authorization."""

    def test_new_authorization_requires_train_digest_semantically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context, _candidate, expected, authorization = _authorization_fixture(
                root,
                release_class="maintenance",
            )
            authorization.pop("backportReleaseTrainDigest")
            write_json(root / "legacy-authorization.json", authorization)
            state = ValidationState()

            with mock.patch.object(
                stable_1_0_maintenance,
                "_now",
                return_value=fixtures.NOW,
            ):
                _value, _digest_value, authorized = _authorization(
                    context,
                    expected,
                    fixtures._policy(),  # noqa: SLF001
                    state,
                    prepare=False,
                )

            self.assertFalse(authorized)
            self.assertTrue(state.blockers)

    def test_new_authorization_requires_explicit_governance_state_semantically(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context, _candidate, expected, authorization = _authorization_fixture(
                root,
                release_class="maintenance",
            )
            authorization.pop("dependencyVulnerabilityGovernanceActive")
            write_json(root / "legacy-authorization.json", authorization)
            state = ValidationState()

            with mock.patch.object(
                stable_1_0_maintenance,
                "_now",
                return_value=fixtures.NOW,
            ):
                _value, _digest_value, authorized = _authorization(
                    context,
                    expected,
                    fixtures._policy(),  # noqa: SLF001
                    state,
                    prepare=False,
                )

            self.assertFalse(authorized)
            self.assertTrue(state.blockers)

    def test_legacy_authorization_can_close_exact_published_follow_up(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _context, candidate, _expected, authorization = _authorization_fixture(
                root,
                release_class="security-hotfix",
            )
            legacy = copy.deepcopy(authorization)
            legacy.pop("backportReleaseTrainDigest")
            legacy.pop("dependencyVulnerabilityGovernanceActive")
            legacy_path = root / "legacy-authorization.json"
            write_json(legacy_path, legacy)
            loaded = LoadedJson(
                "stableMaintenanceAuthorization",
                legacy_path,
                legacy,
                file_digest(legacy_path),
            )
            obligation = SimpleNamespace(
                value={
                    "releaseId": fixtures.RELEASE_ID,
                    "buildVersion": fixtures.BUILD,
                    "productDigest": candidate.product_digest,
                    "candidateIdentityDigest": candidate.identity_digest,
                    "candidateFreezeDigest": candidate.freeze_digest,
                }
            )

            errors = _close_authorization_errors(
                loaded,
                obligation,
                {"authorizationDigest": loaded.digest},
            )

            self.assertEqual(validate_schema(legacy, AUTHORIZATION_SCHEMA), [])
            self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
