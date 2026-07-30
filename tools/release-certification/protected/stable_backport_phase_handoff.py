#!/usr/bin/env python3
"""Verify one authenticated evaluate-to-prepare release-train phase handoff."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import stat
import sys
from typing import Any


_RELEASE_CERTIFICATION_ROOT = Path(__file__).resolve().parents[1]
if str(_RELEASE_CERTIFICATION_ROOT) not in sys.path:
    sys.path.insert(0, str(_RELEASE_CERTIFICATION_ROOT))

from cryptad_certification.engines.stable_1_0_backport_core import (  # noqa: E402
    public_phase_evolution_errors,
)


MAX_QUEUE_BYTES = 16 * 1024 * 1024


class HandoffError(RuntimeError):
    """Bounded failure while authenticating a local protected phase handoff."""


def _load_queue(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise HandoffError("release-train-phase-queue-unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size <= 0
        or metadata.st_size > MAX_QUEUE_BYTES
    ):
        raise HandoffError("release-train-phase-queue-unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HandoffError("release-train-phase-queue-invalid") from exc
    if not isinstance(value, dict):
        raise HandoffError("release-train-phase-queue-invalid")
    return value


def main(argv: list[str] | None = None) -> int:
    """Run the side-effect-free phase-evolution verifier."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--evaluated-queue", type=Path, required=True)
    parser.add_argument("--prepared-queue", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        previous = _load_queue(arguments.evaluated_queue)
        current = _load_queue(arguments.prepared_queue)
        errors = public_phase_evolution_errors(previous, current)
        if errors:
            raise HandoffError("; ".join(errors))
    except HandoffError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
