#!/usr/bin/env python3
"""Emit deterministic PR-256 network-scale soak evidence.

The helper is intentionally offline and standard-library only.  It models the
release-candidate soak summary shape without sleeping for wall-clock hours or
performing live network I/O.  A real RC can attach a live summary with the same
safe fields.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


SUMMARY: dict[str, Any] = {
    "mode": "simulated-rc-soak",
    "status": "success",
    "durationHoursSimulated": 24,
    "apps": {
        "social-inbox": {
            "subscriptions": 12,
            "pollAttempts": 288,
            "budgetSkips": 3,
            "queuePressureSkips": 2,
            "updatesObserved": 5,
            "rawContentPersisted": False,
        },
        "feed-reader": {
            "subscriptions": 8,
            "pollAttempts": 192,
            "budgetSkips": 1,
            "queuePressureSkips": 1,
            "updatesObserved": 4,
            "rawContentPersisted": False,
        },
    },
    "trustGraph": {
        "importsAttempted": 120,
        "budgetSkips": 2,
        "rawStatementsInEvidence": False,
    },
    "budgets": {
        "globalFetchBudgetEnforced": True,
        "perAppFetchBudgetEnforced": True,
        "concurrencyLeasesReleased": True,
    },
    "redaction": {
        "rawFetchedContentExcluded": True,
        "privateInsertUrisExcluded": True,
        "tokensExcluded": True,
        "absolutePathsExcluded": True,
        "queueHtmlExcluded": True,
    },
}


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def validate(summary: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if summary.get("mode") not in {"simulated-rc-soak", "live-rc-soak"}:
        errors.append("mode must be simulated-rc-soak or live-rc-soak")
    if summary.get("status") != "success":
        errors.append("status must be success")
    if int(summary.get("durationHoursSimulated", 0)) < 24:
        errors.append("durationHoursSimulated must cover at least 24 hours")
    apps = summary.get("apps", {})
    if not isinstance(apps, dict) or {"social-inbox", "feed-reader"} - set(apps):
        errors.append("apps must include social-inbox and feed-reader")
    for app_id in ("social-inbox", "feed-reader"):
        app = apps.get(app_id, {}) if isinstance(apps, dict) else {}
        if not isinstance(app, dict) or app.get("rawContentPersisted") is not False:
            errors.append(f"{app_id} must report rawContentPersisted=false")
    trust_graph = summary.get("trustGraph", {})
    if not isinstance(trust_graph, dict) or trust_graph.get("rawStatementsInEvidence") is not False:
        errors.append("trustGraph must exclude raw statements")
    for section, required in (
        (
            "budgets",
            ("globalFetchBudgetEnforced", "perAppFetchBudgetEnforced", "concurrencyLeasesReleased"),
        ),
        (
            "redaction",
            (
                "rawFetchedContentExcluded",
                "privateInsertUrisExcluded",
                "tokensExcluded",
                "absolutePathsExcluded",
                "queueHtmlExcluded",
            ),
        ),
    ):
        value = summary.get(section, {})
        if not isinstance(value, dict):
            errors.append(f"{section} must be an object")
            continue
        for key in required:
            if value.get(key) is not True:
                errors.append(f"{section}.{key} must be true")
    return errors


def run_self_test() -> None:
    errors = validate(SUMMARY)
    if errors:
        raise SystemExit("network-scale soak self-test failed: " + "; ".join(errors))
    encoded = json.dumps(SUMMARY, sort_keys=True)
    for forbidden in (
        "USK@",
        "SSK@",
        "CHK@",
        "browserSessionToken",
        "CRYPTAD_APP_TOKEN",
        "<html",
        "/home/",
        "C:\\",
        "privateKey",
    ):
        if forbidden in encoded:
            raise SystemExit(f"network-scale soak self-test leaked {forbidden}")
    print("network-scale soak self-test passed")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run offline validation checks.")
    parser.add_argument("--output", type=Path, default=None, help="Write summary JSON to this path.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.self_test:
        run_self_test()
        return 0
    if args.output:
        write_json(args.output, SUMMARY)
    else:
        print(json.dumps(SUMMARY, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
