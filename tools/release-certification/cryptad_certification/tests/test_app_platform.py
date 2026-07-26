"""Characterization suite for app-platform certification evidence."""

from __future__ import annotations

import unittest

from cryptad_certification.engines import app_platform_smoke
from cryptad_certification.tests.support import workspace_root


class AppPlatformCharacterizationTest(unittest.TestCase):
    def test_checked_in_hello_stable_sample_tracks_current_contract_version(self) -> None:
        manifest = app_platform_smoke.parse_properties(
            workspace_root()
            / "samples/third-party/hello-stable-app/cryptad-app.properties"
        )

        self.assertEqual(
            str(app_platform_smoke.CURRENT_PLATFORM_API_CONTRACT_VERSION),
            manifest["api.maximumTestedVersion"],
        )

    def test_existing_app_platform_scenarios(self) -> None:
        app_platform_smoke.run_self_test(workspace_root())
