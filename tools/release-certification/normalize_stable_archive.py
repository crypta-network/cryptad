#!/usr/bin/env python3
"""Normalize a Gradle portable archive at the Stable release packaging boundary."""

from __future__ import annotations

import sys
from pathlib import Path

from cryptad_certification.engines.stable_1_0_maintenance_core import (
    archive_hygiene_errors,
)
from cryptad_certification.engines.stable_1_0_rc_artifacts import (
    normalize_portable_distribution_archive,
)


def main(arguments: list[str]) -> int:
    """Normalize each named archive and fail unless the strict maintenance gate accepts it."""

    if not arguments:
        raise SystemExit("usage: normalize_stable_archive.py ARCHIVE [ARCHIVE ...]")
    for argument in arguments:
        archive = Path(argument)
        normalize_portable_distribution_archive(archive)
        errors = archive_hygiene_errors(archive)
        if errors:
            raise SystemExit(
                f"normalized archive {archive.name} failed hygiene: " + "; ".join(errors)
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
