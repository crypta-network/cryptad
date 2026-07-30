"""Shared test paths and manifest fixtures."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from cryptad_certification.io import write_json


def workspace_root() -> Path:
    """Return the repository root from the installed-in-tree test package."""

    return Path(__file__).resolve().parents[4]


def release_train_evidence_result(
    fix_id: str,
    evidence_id: str,
    evidence_digest: str,
    now: datetime,
) -> dict[str, object]:
    """Return one current, candidate-bound release-train evidence result."""

    deadline = now + timedelta(hours=1)

    def timestamp(value: datetime) -> str:
        return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")

    return {
        "fixId": fix_id,
        "evidenceId": evidence_id,
        "status": "pass",
        "evidenceDigest": evidence_digest,
        "generatedAt": timestamp(now),
        "expiresAt": timestamp(deadline),
        "freshnessDeadlineAt": timestamp(deadline),
        "candidateBound": True,
        "predecessorBound": True,
        "fresh": True,
    }


def write_manifest(root: Path, **overrides: Any) -> Path:
    """Write a minimal valid manifest below a temporary workspace."""

    value: dict[str, Any] = {
        "schemaVersion": 1,
        "release": {"id": "self-test-release", "version": "self-test", "profile": "pr"},
        "output": {"root": "build/release-certification", "reset": False},
        "requirements": {},
        "inputs": {},
        "policies": {},
        "execution": {},
        "commands": {},
    }
    value.update(overrides)
    path = root / "manifest.json"
    write_json(path, value)
    return path
