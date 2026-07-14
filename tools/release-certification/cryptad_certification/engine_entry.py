#!/usr/bin/env python3
"""Internal subprocess bridge for composed certification engines.

The public command is ``certify.py``. This bridge exists only for pipeline stages that isolate a
collector in a child Python process and still pass its established internal argument contract.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.dont_write_bytecode = True

PACKAGE_PARENT = Path(__file__).resolve().parents[1]
if str(PACKAGE_PARENT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_PARENT))

from cryptad_certification.engines import (  # noqa: E402
    app_platform_smoke,
    live_network_beta_smoke,
    multi_node_beta_soak,
    production_beta_go_no_go_dashboard,
    release_certification,
    security_response_runbook,
    stable_1_0_readiness,
)

ENGINES = {
    "app-platform": app_platform_smoke,
    "live-network-beta": live_network_beta_smoke,
    "multi-node-beta": multi_node_beta_soak,
    "go-no-go": production_beta_go_no_go_dashboard,
    "release-certification": release_certification,
    "security-response": security_response_runbook,
    "stable-readiness": stable_1_0_readiness,
}


def main(argv: list[str] | None = None) -> int:
    """Dispatch an established internal argument list to one composed engine."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] not in ENGINES:
        print("engine_entry.py requires an internal engine name", file=sys.stderr)
        return 2
    engine = ENGINES[arguments.pop(0)]
    return int(engine.main(arguments))


if __name__ == "__main__":
    raise SystemExit(main())
