"""Characterization suite for the production beta go/no-go dashboard."""

from __future__ import annotations

import unittest

from cryptad_certification.engines import production_beta_go_no_go_dashboard


class DashboardCharacterizationTest(unittest.TestCase):
    def test_existing_go_no_go_scenarios(self) -> None:
        production_beta_go_no_go_dashboard.run_self_test()
