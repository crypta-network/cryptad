"""Immutable GitHub Release publication for Stable 1.0 supply-chain evidence.

The provider accepts only the closed PR-289 publication plan.  It authenticates the
canonical plan bytes and every local/public byte binding before uploading the first
missing GitHub Release asset.  Existing assets are accepted only when their exact
size, digest, name, and immutable download URI match; conflicting bytes are never
deleted or overwritten.

Workflow and wheel attestations are verified by the protected adapter before it
constructs :class:`AuthenticatedProducer` or :class:`AuthenticatedObserver`.  This
module preserves those authenticated identities in deterministic receipts and
refuses to operate on unauthenticated identity objects.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import mimetypes
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping
from urllib.parse import quote, urlencode

from .provider import (
    API_ROOT,
    REPOSITORY,
    UPLOAD_ROOT,
    ProviderError,
    StableMaintenanceBackend,
    _canonical_bytes,
    _digest,
)


SUPPLY_CHAIN_ASSET_FILES = {
    "build-materials": "stable-1.0-build-materials.json",
    "component-inventory": "stable-1.0-component-inventory.json",
    "component-reverse-index": "stable-1.0-component-reverse-index.json",
    "license-inventory": "stable-1.0-license-inventory.json",
    "reproducibility-report": "stable-1.0-reproducibility-report.json",
    "release-subject-inventory": "stable-1.0-release-subject-inventory.json",
    "sbom": "stable-1.0-sbom.spdx.json",
    "supply-chain-summary": "stable-1.0-supply-chain-summary.json",
}
SUPPLY_CHAIN_ROLES = tuple(SUPPLY_CHAIN_ASSET_FILES)
SUPPLY_CHAIN_WORKFLOW = (
    "github.com/crypta-network/cryptad/.github/workflows/"
    "stable-1.0-supply-chain.yml@"
)
PLAN_KEYS = frozenset(
    {
        "schemaVersion",
        "kind",
        "releaseId",
        "buildVersion",
        "tag",
        "sourceCommit",
        "sourceRef",
        "policyDigest",
        "summaryDigest",
        "assets",
        "overwriteAllowed",
        "allowedOperations",
        "sideEffectsPerformed",
        "planDigest",
    }
)
ASSET_KEYS = frozenset({"role", "fileName", "digest", "size", "uri"})
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
SOURCE_REF_RE = re.compile(
    r"(?:refs/(?:heads|tags)/[A-Za-z0-9._/-]+|commit:[0-9a-f]{40})"
)
BACKEND_IDENTITY_RE = re.compile(
    r"cryptad_stable_maintenance_backend:supply_chain_factory@sha256:[0-9a-f]{64}"
)
MAX_PUBLIC_ASSET_BYTES = 1_000_000_000


@dataclasses.dataclass(frozen=True)
class AuthenticatedProducer:
    """Protected adapter authentication bound into a publication receipt."""

    backend_identity: str
    workflow_identity: str
    attestation_digest: str
    authenticated: bool


@dataclasses.dataclass(frozen=True)
class AuthenticatedObserver:
    """Protected adapter authentication bound into a public observation."""

    observer_identity: str
    attestation_digest: str
    authenticated: bool


def _semantic_digest(value: Mapping[str, Any], field: str) -> str:
    payload = {key: child for key, child in value.items() if key != field}
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _digest(canonical)


def _canonical_time(value: str, label: str) -> str:
    if not isinstance(value, str) or len(value) > 32 or not value.endswith("Z"):
        raise ProviderError(label + "-invalid")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ProviderError(label + "-invalid") from exc
    if parsed.microsecond != 0 or parsed.utcoffset() != dt.timedelta(0):
        raise ProviderError(label + "-invalid")
    return parsed.isoformat().replace("+00:00", "Z")


def _regular_file(root: Path, name: str) -> Path:
    if not isinstance(name, str) or Path(name).name != name or name in {"", ".", ".."}:
        raise ProviderError("supply-chain-asset-name-invalid")
    if root.is_symlink() or not root.is_dir():
        raise ProviderError("supply-chain-asset-root-invalid")
    resolved_root = root.resolve(strict=True)
    path = resolved_root / name
    try:
        metadata = path.stat(follow_symlinks=False)
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ProviderError("supply-chain-asset-unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or resolved.parent != resolved_root
    ):
        raise ProviderError("supply-chain-asset-not-confined-regular-file")
    return resolved


def _authenticated_producer(
    producer: AuthenticatedProducer, source_commit: str
) -> AuthenticatedProducer:
    if (
        not isinstance(producer, AuthenticatedProducer)
        or producer.authenticated is not True
        or BACKEND_IDENTITY_RE.fullmatch(producer.backend_identity) is None
        or producer.workflow_identity != SUPPLY_CHAIN_WORKFLOW + source_commit
        or DIGEST_RE.fullmatch(producer.attestation_digest) is None
    ):
        raise ProviderError("supply-chain-producer-not-authenticated")
    return producer


def _authenticated_observer(
    observer: AuthenticatedObserver, source_commit: str
) -> AuthenticatedObserver:
    if (
        not isinstance(observer, AuthenticatedObserver)
        or observer.authenticated is not True
        or observer.observer_identity != SUPPLY_CHAIN_WORKFLOW + source_commit
        or DIGEST_RE.fullmatch(observer.attestation_digest) is None
    ):
        raise ProviderError("supply-chain-observer-not-authenticated")
    return observer


class SupplyChainPublicationBackend:
    """Publish and re-observe the eight closed Stable supply-chain artifacts."""

    def __init__(self, token: str, transport: Any | None = None) -> None:
        self._github = StableMaintenanceBackend(token, transport)
        self._transport = self._github._transport  # noqa: SLF001 - same trusted wheel boundary

    @staticmethod
    def _validate_plan(
        plan: Mapping[str, Any], canonical_plan_bytes: bytes
    ) -> tuple[dict[str, Any], ...]:
        if not isinstance(plan, Mapping) or set(plan) != PLAN_KEYS:
            raise ProviderError("supply-chain-publication-plan-shape-invalid")
        if canonical_plan_bytes != _canonical_bytes(plan):
            raise ProviderError("supply-chain-publication-plan-not-canonical")
        allowed_operations = plan.get("allowedOperations")
        if (
            plan.get("schemaVersion") != 1
            or plan.get("kind") != "stable-1.0-supply-chain-publication-plan"
            or not isinstance(plan.get("releaseId"), str)
            or not 1 <= len(str(plan["releaseId"])) <= 128
            or type(plan.get("buildVersion")) is not int
            or int(plan["buildVersion"]) < 1
            or int(plan["buildVersion"]) > 2_147_483_647
            or plan.get("tag") != f"v{plan['buildVersion']}"
            or not isinstance(plan.get("sourceCommit"), str)
            or COMMIT_RE.fullmatch(str(plan["sourceCommit"])) is None
            or SOURCE_REF_RE.fullmatch(str(plan.get("sourceRef", ""))) is None
            or DIGEST_RE.fullmatch(str(plan.get("policyDigest", ""))) is None
            or DIGEST_RE.fullmatch(str(plan.get("summaryDigest", ""))) is None
            or plan.get("overwriteAllowed") is not False
            or plan.get("sideEffectsPerformed") is not False
            or not isinstance(allowed_operations, list)
            or allowed_operations != ["created", "verified-existing"]
            or _semantic_digest(plan, "planDigest") != plan.get("planDigest")
        ):
            raise ProviderError("supply-chain-publication-plan-binding-invalid")

        raw_assets = plan.get("assets")
        if not isinstance(raw_assets, list) or len(raw_assets) != len(SUPPLY_CHAIN_ROLES):
            raise ProviderError("supply-chain-publication-role-set-invalid")
        assets: list[dict[str, Any]] = []
        for raw in raw_assets:
            if not isinstance(raw, Mapping) or set(raw) != ASSET_KEYS:
                raise ProviderError("supply-chain-publication-asset-shape-invalid")
            row = dict(raw)
            role = row.get("role")
            file_name = row.get("fileName")
            size = row.get("size")
            if (
                role not in SUPPLY_CHAIN_ASSET_FILES
                or file_name != SUPPLY_CHAIN_ASSET_FILES[role]
                or DIGEST_RE.fullmatch(str(row.get("digest", ""))) is None
                or type(size) is not int
                or size < 1
                or size > MAX_PUBLIC_ASSET_BYTES
                or row.get("uri")
                != (
                    "https://github.com/crypta-network/cryptad/releases/download/"
                    f"{plan['tag']}/{file_name}"
                )
            ):
                raise ProviderError("supply-chain-publication-asset-binding-invalid")
            assets.append(row)
        if (
            [row["role"] for row in assets] != list(SUPPLY_CHAIN_ROLES)
            or len({row["fileName"] for row in assets}) != len(assets)
            or len({row["uri"] for row in assets}) != len(assets)
        ):
            raise ProviderError("supply-chain-publication-role-set-invalid")
        return tuple(assets)

    def _release(self, plan: Mapping[str, Any]) -> dict[str, Any]:
        encoded = quote(str(plan["tag"]), safe="")
        reference_status, reference = self._github._github_json(  # noqa: SLF001
            "GET", f"/repos/{REPOSITORY}/git/ref/tags/{encoded}"
        )
        tag_object = reference.get("object")
        if (
            reference_status == 404
            or not isinstance(tag_object, Mapping)
            or tag_object.get("type") != "tag"
            or not isinstance(tag_object.get("sha"), str)
        ):
            raise ProviderError("supply-chain-github-tag-not-authenticated")
        _tag_status, tag = self._github._github_json(  # noqa: SLF001
            "GET", f"/repos/{REPOSITORY}/git/tags/{tag_object['sha']}"
        )
        target = tag.get("object")
        if (
            tag.get("tag") != plan.get("tag")
            or not isinstance(target, Mapping)
            or target.get("type") != "commit"
            or target.get("sha") != plan.get("sourceCommit")
        ):
            raise ProviderError("supply-chain-github-tag-not-authenticated")
        status, release = self._github._github_json(  # noqa: SLF001
            "GET", f"/repos/{REPOSITORY}/releases/tags/{encoded}"
        )
        expected_page = (
            f"https://github.com/{REPOSITORY}/releases/tag/{plan['tag']}"
        )
        if (
            status == 404
            or type(release.get("id")) is not int
            or int(release["id"]) < 1
            or release.get("tag_name") != plan.get("tag")
            or release.get("target_commitish") != plan.get("sourceCommit")
            or release.get("html_url") != expected_page
            or release.get("draft") is not False
            or release.get("prerelease") is not False
            or not isinstance(release.get("assets"), list)
        ):
            raise ProviderError("supply-chain-github-release-not-authenticated")
        return release

    def _observe(
        self, plan: Mapping[str, Any], assets: tuple[dict[str, Any], ...]
    ) -> dict[str, str]:
        release = self._release(plan)
        raw_rows = release["assets"]
        if any(not isinstance(row, Mapping) for row in raw_rows):
            raise ProviderError("supply-chain-github-assets-invalid")
        names = [row.get("name") for row in raw_rows]
        if len(names) != len(set(names)) or any(not isinstance(name, str) for name in names):
            raise ProviderError("supply-chain-github-assets-invalid")
        observed = {str(row["name"]): row for row in raw_rows}
        statuses: dict[str, str] = {}
        for planned in assets:
            role = str(planned["role"])
            row = observed.get(str(planned["fileName"]))
            if row is None:
                statuses[role] = "absent"
                continue
            asset_id = row.get("id")
            if (
                type(asset_id) is not int
                or asset_id < 1
                or row.get("size") != planned["size"]
                or row.get("browser_download_url") != planned["uri"]
            ):
                statuses[role] = "conflict"
                continue
            status, size, digest = self._transport.digest(
                f"{API_ROOT}/repos/{REPOSITORY}/releases/assets/{asset_id}",
                int(planned["size"]),
                headers={
                    "Accept": "application/octet-stream",
                    "Authorization": "Bearer " + self._github._token,  # noqa: SLF001
                    "User-Agent": "cryptad-stable-supply-chain-backend/1",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            statuses[role] = (
                "matching"
                if status == 200
                and size == planned["size"]
                and digest == planned["digest"]
                else "conflict"
            )
        return statuses

    @staticmethod
    def _local_assets(
        assets: tuple[dict[str, Any], ...], source_root: Path
    ) -> dict[str, Path]:
        paths: dict[str, Path] = {}
        for row in assets:
            path = _regular_file(source_root, str(row["fileName"]))
            data = path.read_bytes()
            if len(data) != row["size"] or _digest(data) != row["digest"]:
                raise ProviderError("supply-chain-local-asset-binding-changed")
            paths[str(row["role"])] = path
        return paths

    def publish(
        self,
        plan: Mapping[str, Any],
        canonical_plan_bytes: bytes,
        source_root: Path,
        producer: AuthenticatedProducer,
        generated_at: str,
    ) -> dict[str, Any]:
        """Create missing assets or verify identical existing bytes, then emit a receipt."""

        assets = self._validate_plan(plan, canonical_plan_bytes)
        producer = _authenticated_producer(producer, str(plan["sourceCommit"]))
        generated_at = _canonical_time(generated_at, "supply-chain-receipt-time")
        paths = self._local_assets(assets, source_root)
        initial = self._observe(plan, assets)
        if "conflict" in initial.values():
            raise ProviderError("supply-chain-publication-conflicting-existing-bytes")
        release = self._release(plan)
        release_id = int(release["id"])
        for row in assets:
            role = str(row["role"])
            if initial[role] == "matching":
                continue
            data = paths[role].read_bytes()
            uri = (
                f"{UPLOAD_ROOT}/repos/{REPOSITORY}/releases/{release_id}/assets?"
                + urlencode({"name": row["fileName"]})
            )
            status, _headers, _body = self._transport.request(
                "POST",
                uri,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": "Bearer " + self._github._token,  # noqa: SLF001
                    "Content-Type": mimetypes.guess_type(str(row["fileName"]))[0]
                    or "application/octet-stream",
                    "User-Agent": "cryptad-stable-supply-chain-backend/1",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                body=data,
            )
            if status not in {200, 201}:
                raise ProviderError("supply-chain-github-asset-upload-failed")
        final = self._observe(plan, assets)
        if any(status != "matching" for status in final.values()):
            raise ProviderError("supply-chain-publication-not-exact-after-upload")
        operations = [
            {
                "role": row["role"],
                "digest": row["digest"],
                "size": row["size"],
                "uri": row["uri"],
                "operation": (
                    "verified-existing" if initial[str(row["role"])] == "matching" else "created"
                ),
            }
            for row in assets
        ]
        receipt = {
            "schemaVersion": 1,
            "kind": "stable-1.0-supply-chain-publication-receipt",
            "releaseId": plan["releaseId"],
            "buildVersion": plan["buildVersion"],
            "tag": plan["tag"],
            "sourceCommit": plan["sourceCommit"],
            "sourceRef": plan["sourceRef"],
            "policyDigest": plan["policyDigest"],
            "planDigest": plan["planDigest"],
            "generatedAt": generated_at,
            "backendIdentity": producer.backend_identity,
            "workflowIdentity": producer.workflow_identity,
            "attestationDigest": producer.attestation_digest,
            "backendAuthenticated": True,
            "operations": operations,
            "receiptDigest": "sha256:" + "0" * 64,
        }
        receipt["receiptDigest"] = _semantic_digest(receipt, "receiptDigest")
        return receipt

    def observe(
        self,
        plan: Mapping[str, Any],
        canonical_plan_bytes: bytes,
        receipt_digest: str,
        observer: AuthenticatedObserver,
        observed_at: str,
    ) -> dict[str, Any]:
        """Re-fetch every exact public byte and emit a deterministic fresh observation."""

        assets = self._validate_plan(plan, canonical_plan_bytes)
        observer = _authenticated_observer(observer, str(plan["sourceCommit"]))
        observed_at = _canonical_time(observed_at, "supply-chain-observation-time")
        if DIGEST_RE.fullmatch(receipt_digest) is None:
            raise ProviderError("supply-chain-publication-receipt-digest-invalid")
        statuses = self._observe(plan, assets)
        if any(status != "matching" for status in statuses.values()):
            raise ProviderError("supply-chain-public-observation-not-exact")
        observation = {
            "schemaVersion": 1,
            "kind": "stable-1.0-supply-chain-public-observation",
            "releaseId": plan["releaseId"],
            "buildVersion": plan["buildVersion"],
            "tag": plan["tag"],
            "sourceCommit": plan["sourceCommit"],
            "sourceRef": plan["sourceRef"],
            "policyDigest": plan["policyDigest"],
            "receiptDigest": receipt_digest,
            "observedAt": observed_at,
            "observerIdentity": observer.observer_identity,
            "observerAttestationDigest": observer.attestation_digest,
            "observerAuthenticated": True,
            "assets": [
                {
                    "role": row["role"],
                    "digest": row["digest"],
                    "size": row["size"],
                    "uri": row["uri"],
                }
                for row in assets
            ],
            "observationDigest": "sha256:" + "0" * 64,
        }
        observation["observationDigest"] = _semantic_digest(
            observation, "observationDigest"
        )
        return observation


def supply_chain_factory() -> SupplyChainPublicationBackend:
    """Create the protected supply-chain backend from the workflow token only."""

    if os.environ.get("GITHUB_REPOSITORY") != REPOSITORY:
        raise ProviderError("publication-repository-mismatch")
    return SupplyChainPublicationBackend(os.environ.get("GITHUB_TOKEN", ""))
