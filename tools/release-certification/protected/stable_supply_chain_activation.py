#!/usr/bin/env python3
"""Determine whether one authenticated freeze requires the PR-289 handoff."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptad_certification.engines.stable_1_0_supply_chain_activation import (  # noqa: E402
    supply_chain_governance_active,
)
from cryptad_certification.io import read_json  # noqa: E402


def _read_object(path: Path) -> dict[str, Any] | None:
    try:
        value = read_json(path)
    except (OSError, UnicodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def main(argv: list[str] | None = None) -> int:
    """Print the fail-closed activation decision for a policy and exact freeze."""

    parser = argparse.ArgumentParser()
    parser.add_argument("policy", type=Path)
    parser.add_argument("freeze", type=Path)
    args = parser.parse_args(argv)

    policy = _read_object(args.policy)
    freeze = _read_object(args.freeze)
    frozen_at = freeze.get("frozenAt") if freeze is not None else None
    print("true" if supply_chain_governance_active(frozen_at, policy) else "false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
