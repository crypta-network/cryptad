"""Characterization suite for app-platform certification evidence."""

from __future__ import annotations

import unittest

from cryptad_certification.engines import app_platform_smoke
from cryptad_certification.tests.support import workspace_root


class AppPlatformCharacterizationTest(unittest.TestCase):
    def test_existing_app_platform_scenarios(self) -> None:
        app_platform_smoke.run_self_test(workspace_root())
