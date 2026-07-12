"""Shared test paths and manifest fixtures."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cryptad_certification.io import write_json


def workspace_root() -> Path:
    """Return the repository root from the installed-in-tree test package."""

    return Path(__file__).resolve().parents[4]


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
