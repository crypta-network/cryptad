"""Prospective activation rule for Stable 1.0 supply-chain governance."""

from __future__ import annotations

from typing import Any

from .stable_1_0_rc_core import parse_timestamp


def supply_chain_governance_active(
    frozen_at: Any, supply_policy: dict[str, Any] | None
) -> bool:
    """Return whether the authenticated candidate freeze requires the PR-289 handoff.

    Missing or malformed policy data activates the newer requirement.  Only an
    unambiguously valid freeze before the reviewed activation threshold may use
    the historical handoff contract.
    """

    if not isinstance(supply_policy, dict):
        return True
    activation = supply_policy.get("governanceActivation")
    activation = activation if isinstance(activation, dict) else {}
    threshold = parse_timestamp(activation.get("candidateFrozenAtNotBefore"))
    frozen = parse_timestamp(frozen_at)
    if threshold is None or frozen is None:
        return True
    return frozen >= threshold
