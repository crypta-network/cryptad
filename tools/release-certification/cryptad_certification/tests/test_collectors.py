"""Characterization suite for the smaller certification collectors."""

from __future__ import annotations

import unittest

from cryptad_certification.engines import app_platform_docs_check, live_network_beta_smoke, network_scale_soak
from cryptad_certification.tests.support import workspace_root


class CollectorCharacterizationTest(unittest.TestCase):
    def test_app_platform_docs(self) -> None:
        app_platform_docs_check.run_self_test(workspace_root())

    def test_live_network_beta(self) -> None:
        live_network_beta_smoke.run_self_test()

    def test_network_scale(self) -> None:
        network_scale_soak.run_self_test()
