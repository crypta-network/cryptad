"""Typed public models for release-certification runs and evidence."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 2
MANIFEST_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ReleaseSpec:
    """Identity and operating profile for one certification run."""

    release_id: str
    version: str | None
    profile: str


@dataclass(frozen=True)
class OutputSpec:
    """Output policy for one certification run."""

    root: Path
    reset: bool = False


@dataclass(frozen=True)
class RunManifest:
    """Validated, non-secret configuration shared by certification commands."""

    path: Path
    release: ReleaseSpec
    output: OutputSpec
    requirements: dict[str, Any]
    inputs: dict[str, Any]
    policies: dict[str, Any]
    execution: dict[str, Any]
    commands: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class RunContext:
    """Resolved filesystem context for a certification command."""

    workspace_root: Path
    run_root: Path
    component: str
    manifest: RunManifest

    @property
    def component_dir(self) -> Path:
        return self.run_root / Path(self.component)


@dataclass
class EvidenceEnvelope:
    """Versioned summary shared by all release-certification components."""

    kind: str
    generated_at: str
    subject: dict[str, Any]
    result: dict[str, Any]
    counts: dict[str, int]
    evidence: list[dict[str, Any]] = field(default_factory=list)
    issues: dict[str, list[dict[str, Any]]] = field(
        default_factory=lambda: {"blockers": [], "warnings": []}
    )
    waivers: list[dict[str, Any]] = field(default_factory=list)
    redaction: dict[str, Any] = field(default_factory=dict)
    inputs: dict[str, Any] = field(default_factory=dict)
    artifacts: dict[str, str] = field(default_factory=dict)
    payload: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        """Return the stable JSON representation of this envelope."""

        return {
            "schemaVersion": SCHEMA_VERSION,
            "kind": self.kind,
            "generatedAt": self.generated_at,
            "subject": self.subject,
            "result": self.result,
            "counts": self.counts,
            "evidence": self.evidence,
            "issues": self.issues,
            "waivers": self.waivers,
            "redaction": self.redaction,
            "inputs": self.inputs,
            "artifacts": self.artifacts,
            "payload": self.payload,
        }
