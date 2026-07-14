"""Safe release-workspace creation and artifact path handling."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from .io import read_json, write_json
from .models import RunContext, RunManifest

MARKER_NAME = ".cryptad-certification-run.json"


class WorkspaceError(ValueError):
    """Raised when an output directory cannot be used safely."""


def prepare_run_root(manifest: RunManifest) -> Path:
    """Create or reset a marked release workspace exactly once per CLI invocation."""

    run_root = manifest.output.root / manifest.release.release_id
    marker = run_root / MARKER_NAME
    expected: dict[str, Any] = {
        "schemaVersion": 1,
        "releaseId": manifest.release.release_id,
        "version": manifest.release.version,
        "profile": manifest.release.profile,
    }
    if run_root.exists():
        if run_root.is_symlink() or not run_root.is_dir():
            raise WorkspaceError(f"release workspace is not a real directory: {run_root}")
        if marker.is_symlink() or not marker.is_file():
            raise WorkspaceError(f"refusing to use unmarked run directory: {run_root}")
        if read_json(marker) != expected:
            raise WorkspaceError(f"release workspace marker does not match manifest: {run_root}")
        if manifest.output.reset:
            shutil.rmtree(run_root)
    run_root.mkdir(parents=True, exist_ok=True)
    write_json(marker, expected)
    return run_root.resolve()


def prepare_context(workspace_root: Path, manifest: RunManifest, component: str) -> RunContext:
    """Create a component below an already validated release workspace."""

    run_root = manifest.output.root / manifest.release.release_id
    if run_root.is_symlink() or not run_root.is_dir():
        raise WorkspaceError(f"release workspace is not a real directory: {run_root}")
    resolved_run_root = run_root.resolve()
    marker = run_root / MARKER_NAME
    if marker.is_symlink() or not marker.is_file():
        raise WorkspaceError("release workspace has not been prepared")
    expected_marker: dict[str, Any] = {
        "schemaVersion": 1,
        "releaseId": manifest.release.release_id,
        "version": manifest.release.version,
        "profile": manifest.release.profile,
    }
    if read_json(marker) != expected_marker:
        raise WorkspaceError("release workspace marker does not match manifest")
    component_path = Path(component)
    if component_path.is_absolute():
        raise WorkspaceError(f"component path must be relative: {component}")
    context = RunContext(workspace_root.resolve(), resolved_run_root, component, manifest)
    _require_confined_directory(context.component_dir, resolved_run_root, "component")
    context.component_dir.mkdir(parents=True, exist_ok=True)
    _require_confined_directory(context.component_dir, resolved_run_root, "component")
    artifacts = context.component_dir / "artifacts"
    _require_confined_directory(artifacts, resolved_run_root, "component artifacts")
    artifacts.mkdir(exist_ok=True)
    _require_confined_directory(artifacts, resolved_run_root, "component artifacts")
    return context


def _require_confined_directory(path: Path, run_root: Path, description: str) -> None:
    """Reject symlinks, non-directories, and paths resolving outside the release root."""

    current = run_root
    try:
        relative = path.relative_to(run_root)
    except ValueError as exc:
        raise WorkspaceError(f"{description} path is outside release workspace: {path}") from exc
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise WorkspaceError(f"{description} path contains a symlink: {current}")
    try:
        path.resolve().relative_to(run_root)
    except ValueError as exc:
        raise WorkspaceError(f"{description} path escapes release workspace: {path}") from exc
    if path.exists() and not path.is_dir():
        raise WorkspaceError(f"{description} path is not a directory: {path}")


def relative_to_run(path: Path, context: RunContext) -> str:
    """Return a portable artifact reference below the release-run root."""

    resolved = path.resolve()
    try:
        return resolved.relative_to(context.run_root).as_posix()
    except ValueError as exc:
        raise WorkspaceError(f"artifact is outside release workspace: {path}") from exc
