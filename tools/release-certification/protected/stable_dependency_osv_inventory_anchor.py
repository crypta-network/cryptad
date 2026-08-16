#!/usr/bin/env python3
"""Retain and authenticate the exact PR-289 inventory used for OSV queries."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptad_certification.engines.stable_1_0_supply_chain_core import (  # noqa: E402
    semantic_digest,
)
from cryptad_certification.schema_validation import validate_schema  # noqa: E402


_REPOSITORY = "crypta-network/cryptad"
_VARIABLE = "STABLE_1_0_DEPENDENCY_OSV_INVENTORY_ANCHOR"
_READ_TOKEN = "CRYPTAD_STABLE_DEPENDENCY_OSV_INVENTORY_ANCHOR_READ_TOKEN"
_WRITE_TOKEN = "CRYPTAD_STABLE_DEPENDENCY_OSV_INVENTORY_ANCHOR_WRITE_TOKEN"
_SUPPLY_WORKFLOW = ".github/workflows/stable-1.0-supply-chain.yml"
_RETENTION_WORKFLOW = (
    ".github/workflows/stable-1.0-dependency-osv-inventory-retention.yml"
)
_ROOT = Path(__file__).resolve().parents[1]
_GENESIS = _ROOT / "stable-1.0-dependency-osv-inventory-anchor-genesis.json"
_ANCHOR_SCHEMA = "stable-1.0-dependency-osv-inventory-anchor-v1.schema.json"
_INVENTORY_SCHEMA = "stable-1.0-component-inventory-v1.schema.json"
_INVENTORY_FILE = "stable-1.0-component-inventory.json"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_SUPPLY_ARTIFACT = re.compile(
    r"stable-1\.0-supply-chain-[A-Za-z0-9][A-Za-z0-9._-]{0,127}-comparison\Z"
)
_RETENTION_ARTIFACT = re.compile(
    r"stable-1-0-dependency-osv-inventory-retention-[1-9][0-9]*-[1-9][0-9]*\Z"
)
_PROPOSAL_FILE = "stable-1.0-dependency-osv-inventory-activation-proposal.json"
_PROPOSAL_FIELDS = frozenset(
    {
        "schemaVersion",
        "kind",
        "repositoryIdentity",
        "mode",
        "expectedAnchorDigest",
        "sourceArtifact",
        "proposalDigest",
    }
)
_ARTIFACT_FIELDS = frozenset(
    {
        "workflow",
        "workflowCommit",
        "runId",
        "runAttempt",
        "artifactName",
        "artifactDigest",
    }
)
_RENEWAL_MARGIN = dt.timedelta(days=7)
_MAX_FILE_BYTES = 256 * 1024 * 1024
_MAX_BUNDLE_BYTES = 512 * 1024 * 1024


class InventoryAnchorError(RuntimeError):
    """A closed PR-289 inventory retention or authentication failure."""


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _semantic(value: dict[str, Any], field: str) -> str:
    payload = {key: child for key, child in value.items() if key != field}
    return "sha256:" + hashlib.sha256(_canonical(payload).rstrip(b"\n")).hexdigest()


def _file_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _load(path: Path, maximum: int = _MAX_FILE_BYTES) -> dict[str, Any]:
    try:
        stat = path.stat(follow_symlinks=False)
        if (
            path.is_symlink()
            or not path.is_file()
            or stat.st_nlink != 1
            or stat.st_size <= 0
            or stat.st_size > maximum
        ):
            raise InventoryAnchorError("dependency-osv-inventory-file-invalid")
        raw = path.read_bytes()
        if len(raw) != stat.st_size:
            raise InventoryAnchorError("dependency-osv-inventory-file-changed")
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InventoryAnchorError("dependency-osv-inventory-file-invalid") from exc
    if not isinstance(value, dict):
        raise InventoryAnchorError("dependency-osv-inventory-file-invalid")
    return value


def _utc(value: str, label: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise InventoryAnchorError(f"dependency-osv-inventory-{label}-invalid")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InventoryAnchorError(f"dependency-osv-inventory-{label}-invalid") from exc
    if parsed.tzinfo is None or parsed.microsecond != 0:
        raise InventoryAnchorError(f"dependency-osv-inventory-{label}-invalid")
    return parsed.astimezone(dt.timezone.utc)


def _gh(token_env: str, arguments: list[str]) -> str:
    token = os.environ.get(token_env, "")
    if len(token) < 12 or "\n" in token or "\r" in token:
        raise InventoryAnchorError("dependency-osv-inventory-token-missing")
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"GH_TOKEN", "GITHUB_TOKEN", _READ_TOKEN, _WRITE_TOKEN}
    }
    environment["GH_TOKEN"] = token
    try:
        completed = subprocess.run(
            ["gh", *arguments],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InventoryAnchorError("dependency-osv-inventory-github-failed") from exc
    return completed.stdout


def _validate_anchor(anchor: dict[str, Any]) -> None:
    if validate_schema(anchor, _ANCHOR_SCHEMA):
        raise InventoryAnchorError("dependency-osv-inventory-anchor-schema-invalid")
    if anchor.get("anchorDigest") != _semantic(anchor, "anchorDigest"):
        raise InventoryAnchorError("dependency-osv-inventory-anchor-digest-invalid")
    if anchor.get("initialized") is False:
        if anchor != _load(_GENESIS, 1024 * 1024):
            raise InventoryAnchorError("dependency-osv-inventory-genesis-invalid")
        return
    if int(anchor.get("anchorSequence", 0)) < 1:
        raise InventoryAnchorError("dependency-osv-inventory-anchor-sequence-invalid")
    inventory = anchor.get("inventory")
    origin = anchor.get("origin")
    current = anchor.get("currentArtifact")
    if not all(isinstance(row, dict) for row in (inventory, origin, current)):
        raise InventoryAnchorError("dependency-osv-inventory-anchor-active-invalid")
    if origin.get("workflow") != _SUPPLY_WORKFLOW:
        raise InventoryAnchorError("dependency-osv-inventory-origin-invalid")
    if origin.get("workflowCommit") != inventory.get("sourceCommit"):
        raise InventoryAnchorError("dependency-osv-inventory-origin-candidate-invalid")
    if current.get("workflow") not in {_SUPPLY_WORKFLOW, _RETENTION_WORKFLOW}:
        raise InventoryAnchorError("dependency-osv-inventory-current-invalid")
    activated = _utc(str(anchor.get("activatedAt")), "activation-time")
    expires = _utc(str(anchor.get("artifactExpiresAt")), "expiry")
    renewal = _utc(str(anchor.get("renewalRequiredAt")), "renewal-time")
    if renewal != expires - _RENEWAL_MARGIN or activated >= renewal:
        raise InventoryAnchorError("dependency-osv-inventory-retention-window-invalid")


def _read(
    repository: str,
    token_env: str,
    *,
    allow_renewal: bool,
    allow_uninitialized: bool = False,
) -> dict[str, Any]:
    if repository != _REPOSITORY:
        raise InventoryAnchorError("dependency-osv-inventory-repository-invalid")
    raw = _gh(token_env, ["api", f"repos/{repository}/actions/variables/{_VARIABLE}"])
    try:
        response = json.loads(raw)
        encoded = response["value"]
        anchor = json.loads(encoded)
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise InventoryAnchorError("dependency-osv-inventory-anchor-unavailable") from exc
    if (
        response.get("name") != _VARIABLE
        or not isinstance(encoded, str)
        or encoded.encode("utf-8") != _canonical(anchor).rstrip(b"\n")
    ):
        raise InventoryAnchorError("dependency-osv-inventory-anchor-noncanonical")
    _validate_anchor(anchor)
    if anchor.get("initialized") is not True and not allow_uninitialized:
        raise InventoryAnchorError("dependency-osv-inventory-anchor-uninitialized")
    if anchor.get("initialized") is not True:
        return anchor
    now = dt.datetime.now(dt.timezone.utc)
    boundary = anchor["artifactExpiresAt"] if allow_renewal else anchor["renewalRequiredAt"]
    if now >= _utc(str(boundary), "retention-boundary"):
        raise InventoryAnchorError("dependency-osv-inventory-retention-overdue")
    return anchor


def _artifact_metadata(
    token_env: str,
    repository: str,
    artifact: dict[str, Any],
    *,
    allow_in_progress: bool,
) -> dict[str, Any]:
    workflow = str(artifact.get("workflow"))
    commit = str(artifact.get("workflowCommit"))
    run_id = artifact.get("runId")
    attempt = artifact.get("runAttempt")
    name = str(artifact.get("artifactName"))
    digest = str(artifact.get("artifactDigest"))
    name_pattern = _SUPPLY_ARTIFACT if workflow == _SUPPLY_WORKFLOW else _RETENTION_ARTIFACT
    if (
        workflow not in {_SUPPLY_WORKFLOW, _RETENTION_WORKFLOW}
        or _COMMIT.fullmatch(commit) is None
        or type(run_id) is not int
        or run_id < 1
        or type(attempt) is not int
        or attempt < 1
        or name_pattern.fullmatch(name) is None
        or _DIGEST.fullmatch(digest) is None
    ):
        raise InventoryAnchorError("dependency-osv-inventory-coordinate-invalid")
    run = json.loads(
        _gh(
            token_env,
            ["api", f"repos/{repository}/actions/runs/{run_id}/attempts/{attempt}"],
        )
    )
    allowed_state = (
        run.get("status") == "in_progress" and allow_in_progress
    ) or (
        run.get("status") == "completed" and run.get("conclusion") == "success"
    )
    if (
        run.get("id") != run_id
        or run.get("run_attempt") != attempt
        or run.get("path") != workflow
        or run.get("head_sha") != commit
        or not allowed_state
    ):
        raise InventoryAnchorError("dependency-osv-inventory-run-invalid")
    artifacts = json.loads(
        _gh(
            token_env,
            ["api", f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100"],
        )
    ).get("artifacts", [])
    matches = [row for row in artifacts if isinstance(row, dict) and row.get("name") == name]
    if (
        len(matches) != 1
        or matches[0].get("expired") is not False
        or matches[0].get("digest") != digest
        or matches[0].get("workflow_run", {}).get("id") != run_id
        or not isinstance(matches[0].get("expires_at"), str)
    ):
        raise InventoryAnchorError("dependency-osv-inventory-artifact-invalid")
    return matches[0]


def _bundle_inventory(root: Path) -> tuple[dict[str, Any], str]:
    resolved = root.resolve()
    if not resolved.is_dir():
        raise InventoryAnchorError("dependency-osv-inventory-bundle-invalid")
    files: list[Path] = []
    total = 0
    seen: set[str] = set()
    for path in resolved.rglob("*"):
        stat = path.stat(follow_symlinks=False)
        if path.is_symlink() or (path.is_file() and stat.st_nlink != 1):
            raise InventoryAnchorError("dependency-osv-inventory-bundle-link-invalid")
        if path.is_dir():
            continue
        if not path.is_file():
            raise InventoryAnchorError("dependency-osv-inventory-bundle-member-invalid")
        relative = path.relative_to(resolved).as_posix()
        folded = relative.casefold()
        if folded in seen or relative.startswith("/") or ".." in Path(relative).parts:
            raise InventoryAnchorError("dependency-osv-inventory-bundle-name-invalid")
        seen.add(folded)
        total += stat.st_size
        if stat.st_size <= 0 or stat.st_size > _MAX_FILE_BYTES or total > _MAX_BUNDLE_BYTES:
            raise InventoryAnchorError("dependency-osv-inventory-bundle-oversized")
        if path.suffix.casefold() in {".zip", ".tar", ".tgz", ".gz"}:
            raise InventoryAnchorError("dependency-osv-inventory-bundle-archive-invalid")
        files.append(path)
    matches = [path for path in files if path.name == _INVENTORY_FILE]
    if len(matches) != 1:
        raise InventoryAnchorError("dependency-osv-inventory-bundle-inventory-ambiguous")
    inventory_path = matches[0]
    inventory = _load(inventory_path)
    if validate_schema(inventory, _INVENTORY_SCHEMA):
        raise InventoryAnchorError("dependency-osv-inventory-schema-invalid")
    if inventory.get("inventoryDigest") != semantic_digest(inventory, "inventoryDigest"):
        raise InventoryAnchorError("dependency-osv-inventory-digest-invalid")
    return inventory, _file_digest(inventory_path.read_bytes())


def _inventory_identity(inventory: dict[str, Any], byte_digest: str) -> dict[str, Any]:
    return {
        "releaseId": inventory["releaseId"],
        "buildVersion": inventory["buildVersion"],
        "sourceCommit": inventory["sourceCommit"],
        "policyDigest": inventory["policyDigest"],
        "inventoryDigest": inventory["inventoryDigest"],
        "inventoryByteDigest": byte_digest,
    }


def _proposal_errors(value: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    source = value.get("sourceArtifact")
    if set(value) != _PROPOSAL_FIELDS:
        errors.append("dependency-osv-inventory-proposal-fields-invalid")
    if (
        value.get("schemaVersion") != 1
        or value.get("kind")
        != "stable-1.0-dependency-osv-inventory-activation-proposal"
        or value.get("repositoryIdentity") != "github.com/crypta-network/cryptad"
        or value.get("mode") not in {"activate", "renew"}
        or _DIGEST.fullmatch(str(value.get("expectedAnchorDigest", ""))) is None
        or not isinstance(source, dict)
        or set(source) != _ARTIFACT_FIELDS
        or source.get("workflow") not in {_SUPPLY_WORKFLOW, _RETENTION_WORKFLOW}
        or _COMMIT.fullmatch(str(source.get("workflowCommit", ""))) is None
        or type(source.get("runId")) is not int
        or int(source.get("runId", 0)) < 1
        or type(source.get("runAttempt")) is not int
        or int(source.get("runAttempt", 0)) < 1
        or _DIGEST.fullmatch(str(source.get("artifactDigest", ""))) is None
    ):
        errors.append("dependency-osv-inventory-proposal-identity-invalid")
    elif value.get("mode") == "activate":
        if (
            source["workflow"] != _SUPPLY_WORKFLOW
            or _SUPPLY_ARTIFACT.fullmatch(str(source["artifactName"])) is None
        ):
            errors.append("dependency-osv-inventory-proposal-source-invalid")
    elif (
        source["workflow"] not in {_SUPPLY_WORKFLOW, _RETENTION_WORKFLOW}
        or (
            source["workflow"] == _SUPPLY_WORKFLOW
            and _SUPPLY_ARTIFACT.fullmatch(str(source["artifactName"])) is None
        )
        or (
            source["workflow"] == _RETENTION_WORKFLOW
            and _RETENTION_ARTIFACT.fullmatch(str(source["artifactName"])) is None
        )
    ):
        errors.append("dependency-osv-inventory-proposal-source-invalid")
    if value.get("proposalDigest") != _semantic(value, "proposalDigest"):
        errors.append("dependency-osv-inventory-proposal-digest-invalid")
    return sorted(dict.fromkeys(errors))


def _write_proposal_command(arguments: argparse.Namespace) -> None:
    source = {
        "workflow": arguments.source_workflow,
        "workflowCommit": arguments.source_workflow_commit,
        "runId": arguments.source_run_id,
        "runAttempt": arguments.source_run_attempt,
        "artifactName": arguments.source_artifact_name,
        "artifactDigest": arguments.source_artifact_digest,
    }
    proposal = {
        "schemaVersion": 1,
        "kind": "stable-1.0-dependency-osv-inventory-activation-proposal",
        "repositoryIdentity": "github.com/crypta-network/cryptad",
        "mode": arguments.mode,
        "expectedAnchorDigest": arguments.expected_anchor_digest,
        "sourceArtifact": source,
        "proposalDigest": "sha256:" + "0" * 64,
    }
    proposal["proposalDigest"] = _semantic(proposal, "proposalDigest")
    errors = _proposal_errors(proposal)
    if errors:
        raise InventoryAnchorError(errors[0])
    if arguments.out.name != _PROPOSAL_FILE:
        raise InventoryAnchorError("dependency-osv-inventory-proposal-output-invalid")
    try:
        arguments.out.write_bytes(_canonical(proposal))
    except OSError as exc:
        raise InventoryAnchorError("dependency-osv-inventory-proposal-output-invalid") from exc


def _finalize_command(arguments: argparse.Namespace) -> None:
    try:
        if arguments.proposal.parent.resolve(strict=True) != arguments.root.resolve(
            strict=True
        ):
            raise InventoryAnchorError(
                "dependency-osv-inventory-proposal-input-invalid"
            )
    except OSError as exc:
        raise InventoryAnchorError(
            "dependency-osv-inventory-proposal-input-invalid"
        ) from exc
    proposal = _load(arguments.proposal, 64 * 1024)
    errors = _proposal_errors(proposal)
    if errors:
        raise InventoryAnchorError(errors[0])
    if arguments.proposal.name != _PROPOSAL_FILE:
        raise InventoryAnchorError("dependency-osv-inventory-proposal-input-invalid")
    source = proposal["sourceArtifact"]
    _advance_command(
        argparse.Namespace(
            mode=proposal["mode"],
            repository=arguments.repository,
            expected_anchor_digest=proposal["expectedAnchorDigest"],
            root=arguments.root,
            source_workflow=source["workflow"],
            source_workflow_commit=source["workflowCommit"],
            source_run_id=source["runId"],
            source_run_attempt=source["runAttempt"],
            source_artifact_name=source["artifactName"],
            source_artifact_digest=source["artifactDigest"],
            workflow_commit=arguments.workflow_commit,
            run_id=arguments.run_id,
            run_attempt=arguments.run_attempt,
            artifact_name=arguments.artifact_name,
            artifact_digest=arguments.artifact_digest,
            activated_at=arguments.activated_at,
        )
    )


def _write_anchor(repository: str, anchor: dict[str, Any]) -> None:
    value = _canonical(anchor).decode("utf-8").rstrip("\n")
    _gh(
        _WRITE_TOKEN,
        [
            "api",
            "--method",
            "PATCH",
            f"repos/{repository}/actions/variables/{_VARIABLE}",
            "-f",
            f"name={_VARIABLE}",
            "-f",
            f"value={value}",
        ],
    )


def _read_command(arguments: argparse.Namespace) -> None:
    anchor = _read(
        arguments.repository,
        _READ_TOKEN,
        allow_renewal=arguments.allow_renewal,
        allow_uninitialized=arguments.allow_uninitialized,
    )
    arguments.out.write_bytes(_canonical(anchor))
    if arguments.github_output is not None and anchor.get("initialized") is True:
        current = anchor["currentArtifact"]
        lines = {
            "run-id": current["runId"],
            "run-attempt": current["runAttempt"],
            "artifact-name": current["artifactName"],
            "artifact-digest": current["artifactDigest"],
            "inventory-source-commit": anchor["inventory"]["sourceCommit"],
            "inventory-digest": anchor["inventory"]["inventoryDigest"],
        }
        with arguments.github_output.open("a", encoding="utf-8") as stream:
            for key, value in lines.items():
                stream.write(f"{key}={value}\n")


def _verify_command(arguments: argparse.Namespace) -> None:
    anchor = _read(arguments.repository, _READ_TOKEN, allow_renewal=False)
    _artifact_metadata(
        _READ_TOKEN,
        arguments.repository,
        anchor["currentArtifact"],
        allow_in_progress=False,
    )
    inventory, byte_digest = _bundle_inventory(arguments.root)
    if _inventory_identity(inventory, byte_digest) != anchor["inventory"]:
        raise InventoryAnchorError("dependency-osv-inventory-bundle-substituted")


def _validate_command(arguments: argparse.Namespace) -> None:
    _bundle_inventory(arguments.root)


def _authenticate_source_command(arguments: argparse.Namespace) -> None:
    source = {
        "workflow": arguments.source_workflow,
        "workflowCommit": arguments.source_workflow_commit,
        "runId": arguments.source_run_id,
        "runAttempt": arguments.source_run_attempt,
        "artifactName": arguments.source_artifact_name,
        "artifactDigest": arguments.source_artifact_digest,
    }
    _artifact_metadata(_READ_TOKEN, arguments.repository, source, allow_in_progress=False)
    if arguments.require_current:
        anchor = _read(
            arguments.repository,
            _READ_TOKEN,
            allow_renewal=True,
        )
        if source != anchor["currentArtifact"]:
            raise InventoryAnchorError("dependency-osv-inventory-renewal-source-invalid")


def _advance_command(arguments: argparse.Namespace) -> None:
    anchor = _read(
        arguments.repository,
        _WRITE_TOKEN,
        allow_renewal=True,
        allow_uninitialized=arguments.mode == "activate",
    )
    new_artifact = {
        "workflow": _RETENTION_WORKFLOW,
        "workflowCommit": arguments.workflow_commit,
        "runId": arguments.run_id,
        "runAttempt": arguments.run_attempt,
        "artifactName": arguments.artifact_name,
        "artifactDigest": arguments.artifact_digest,
    }
    if anchor.get("currentArtifact") == new_artifact:
        _artifact_metadata(
            _WRITE_TOKEN,
            arguments.repository,
            new_artifact,
            allow_in_progress=False,
        )
        return
    if anchor["anchorDigest"] != arguments.expected_anchor_digest:
        return
    inventory, byte_digest = _bundle_inventory(arguments.root)
    inventory_identity = _inventory_identity(inventory, byte_digest)
    source = {
        "workflow": arguments.source_workflow,
        "workflowCommit": arguments.source_workflow_commit,
        "runId": arguments.source_run_id,
        "runAttempt": arguments.source_run_attempt,
        "artifactName": arguments.source_artifact_name,
        "artifactDigest": arguments.source_artifact_digest,
    }
    source_metadata = _artifact_metadata(
        _WRITE_TOKEN, arguments.repository, source, allow_in_progress=False
    )
    if arguments.mode == "activate":
        if source["workflow"] != _SUPPLY_WORKFLOW:
            raise InventoryAnchorError("dependency-osv-inventory-activation-origin-invalid")
        if source["workflowCommit"] != inventory["sourceCommit"]:
            raise InventoryAnchorError("dependency-osv-inventory-origin-candidate-invalid")
        if source["artifactName"] != (
            f"stable-1.0-supply-chain-{inventory['releaseId']}-comparison"
        ):
            raise InventoryAnchorError("dependency-osv-inventory-origin-artifact-invalid")
        if anchor.get("initialized") is True and (
            inventory_identity == anchor["inventory"]
            or inventory_identity["buildVersion"]
            <= anchor["inventory"]["buildVersion"]
        ):
            raise InventoryAnchorError("dependency-osv-inventory-activation-downgrade")
        origin = source
    else:
        if source != anchor["currentArtifact"] or inventory_identity != anchor["inventory"]:
            raise InventoryAnchorError("dependency-osv-inventory-renewal-source-invalid")
        origin = anchor["origin"]
    new_metadata = _artifact_metadata(
        _WRITE_TOKEN, arguments.repository, new_artifact, allow_in_progress=False
    )
    activated = _utc(arguments.activated_at, "activation-time")
    now = dt.datetime.now(dt.timezone.utc)
    if activated > now or now - activated > dt.timedelta(minutes=30):
        raise InventoryAnchorError("dependency-osv-inventory-activation-time-invalid")
    expires = _utc(str(new_metadata["expires_at"]), "artifact-expiry")
    renewal = expires - _RENEWAL_MARGIN
    if activated >= renewal:
        raise InventoryAnchorError("dependency-osv-inventory-retention-window-invalid")
    successor = {
        "schemaVersion": 1,
        "kind": "stable-1.0-dependency-osv-inventory-anchor",
        "repositoryIdentity": "github.com/crypta-network/cryptad",
        "stableMilestone": "Stable 1.0",
        "initialized": True,
        "anchorSequence": int(anchor["anchorSequence"]) + 1,
        "inventory": inventory_identity,
        "origin": origin,
        "currentArtifact": new_artifact,
        "artifactExpiresAt": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "renewalRequiredAt": renewal.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "activatedAt": arguments.activated_at,
        "previousAnchorDigest": anchor["anchorDigest"],
        "anchorDigest": "sha256:" + "0" * 64,
    }
    successor["anchorDigest"] = _semantic(successor, "anchorDigest")
    _validate_anchor(successor)
    _write_anchor(arguments.repository, successor)
    confirmed = _read(arguments.repository, _WRITE_TOKEN, allow_renewal=True)
    if confirmed != successor:
        raise InventoryAnchorError("dependency-osv-inventory-anchor-write-unverified")
    if source_metadata.get("expired") is not False:
        raise InventoryAnchorError("dependency-osv-inventory-source-expired")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    read = sub.add_parser("read")
    read.add_argument("--repository", required=True)
    read.add_argument("--out", type=Path, required=True)
    read.add_argument("--github-output", type=Path)
    read.add_argument("--allow-renewal", action="store_true")
    read.add_argument("--allow-uninitialized", action="store_true")
    verify = sub.add_parser("verify")
    verify.add_argument("--repository", required=True)
    verify.add_argument("--root", type=Path, required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("--root", type=Path, required=True)
    authenticate = sub.add_parser("authenticate-source")
    authenticate.add_argument("--repository", required=True)
    authenticate.add_argument("--source-workflow", required=True)
    authenticate.add_argument("--source-workflow-commit", required=True)
    authenticate.add_argument("--source-run-id", type=int, required=True)
    authenticate.add_argument("--source-run-attempt", type=int, required=True)
    authenticate.add_argument("--source-artifact-name", required=True)
    authenticate.add_argument("--source-artifact-digest", required=True)
    authenticate.add_argument("--require-current", action="store_true")
    proposal = sub.add_parser("write-proposal")
    proposal.add_argument("--mode", choices=("activate", "renew"), required=True)
    proposal.add_argument("--expected-anchor-digest", required=True)
    proposal.add_argument("--source-workflow", required=True)
    proposal.add_argument("--source-workflow-commit", required=True)
    proposal.add_argument("--source-run-id", type=int, required=True)
    proposal.add_argument("--source-run-attempt", type=int, required=True)
    proposal.add_argument("--source-artifact-name", required=True)
    proposal.add_argument("--source-artifact-digest", required=True)
    proposal.add_argument("--out", type=Path, required=True)
    advance = sub.add_parser("advance")
    advance.add_argument("--mode", choices=("activate", "renew"), required=True)
    advance.add_argument("--repository", required=True)
    advance.add_argument("--expected-anchor-digest", required=True)
    advance.add_argument("--root", type=Path, required=True)
    advance.add_argument("--source-workflow", required=True)
    advance.add_argument("--source-workflow-commit", required=True)
    advance.add_argument("--source-run-id", type=int, required=True)
    advance.add_argument("--source-run-attempt", type=int, required=True)
    advance.add_argument("--source-artifact-name", required=True)
    advance.add_argument("--source-artifact-digest", required=True)
    advance.add_argument("--workflow-commit", required=True)
    advance.add_argument("--run-id", type=int, required=True)
    advance.add_argument("--run-attempt", type=int, required=True)
    advance.add_argument("--artifact-name", required=True)
    advance.add_argument("--artifact-digest", required=True)
    advance.add_argument("--activated-at", required=True)
    finalize = sub.add_parser("finalize")
    finalize.add_argument("--repository", required=True)
    finalize.add_argument("--proposal", type=Path, required=True)
    finalize.add_argument("--root", type=Path, required=True)
    finalize.add_argument("--workflow-commit", required=True)
    finalize.add_argument("--run-id", type=int, required=True)
    finalize.add_argument("--run-attempt", type=int, required=True)
    finalize.add_argument("--artifact-name", required=True)
    finalize.add_argument("--artifact-digest", required=True)
    finalize.add_argument("--activated-at", required=True)
    return parser


def main() -> int:
    try:
        arguments = _parser().parse_args()
        if arguments.command == "read":
            _read_command(arguments)
        elif arguments.command == "verify":
            _verify_command(arguments)
        elif arguments.command == "validate":
            _validate_command(arguments)
        elif arguments.command == "authenticate-source":
            _authenticate_source_command(arguments)
        elif arguments.command == "write-proposal":
            _write_proposal_command(arguments)
        elif arguments.command == "finalize":
            _finalize_command(arguments)
        else:
            _advance_command(arguments)
    except InventoryAnchorError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
