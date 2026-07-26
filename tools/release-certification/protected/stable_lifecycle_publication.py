#!/usr/bin/env python3
"""Protected exact-byte publication boundary for Stable 1.0 lifecycle state.

The lifecycle certification engine is deliberately side-effect free.  This module is the only
adapter used by the protected lifecycle workflow.  It accepts an injected provider in tests and a
separately authenticated lifecycle provider on a protected runner.  Its provider protocol has no
tag, GitHub Release, catalog, CoreUpdater ``core-info.json``, branch, or release-candidate method.

The mutable lifecycle descriptor is safe to replace only by publishing the next exact edition.
Before a mutation, the adapter independently binds the descriptor bytes to the certification plan
and authorization, observes the public predecessor, and rejects replay, gaps, conflicts, and
unavailable state.  Matching exact state is idempotent success.  A protected insert value is
captured only for ``publish``, removed from the environment before provider loading, wrapped in an
opaque value, and never serialized or included in an error.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as dt
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import re
import stat
import sys
import sysconfig
from types import ModuleType
from typing import Any, Callable, Iterator, Mapping, Protocol, Sequence


_RELEASE_CERTIFICATION_ROOT = Path(__file__).resolve().parents[1]
if str(_RELEASE_CERTIFICATION_ROOT) not in sys.path:
    sys.path.insert(0, str(_RELEASE_CERTIFICATION_ROOT))

from cryptad_certification.schema_validation import validate_schema  # noqa: E402
from cryptad_certification.safe_text import recovery_guidance_error  # noqa: E402
from cryptad_certification.engines.stable_1_0_ga_core import (  # noqa: E402
    _has_unambiguous_publication_path,
    canonical_public_https_uri,
    is_public_https_uri,
)


DESCRIPTOR_FILE = "stable-1.0-support-lifecycle-descriptor.json"
PLAN_FILE = "stable-1.0-support-lifecycle-publication-plan.json"
AUTHORIZATION_FILE = "stable-1.0-support-lifecycle-authorization-summary.json"
LEDGER_FILE = "stable-1.0-support-lifecycle-ledger.json"
TRANSITION_FILE = "stable-1.0-support-lifecycle-transition-set.json"
INVENTORY_FILE = "stable-1.0-support-lifecycle-inventory.json"
PROVENANCE_FILE = "stable-1.0-support-lifecycle-provenance.json"
GENESIS_PROOF_FILE = "stable-1.0-support-lifecycle-genesis-proof.json"
RECEIPT_FILE = "stable-1.0-support-lifecycle-publication-receipt.json"
FAILURE_AUDIT_FILE = "stable-1.0-support-lifecycle-publication-failure-audit.json"
PREFLIGHT_FILE = "stable-1.0-support-lifecycle-publication-preflight.json"
OPERATION_SUMMARY_FILE = "stable-lifecycle-publication-summary.json"
_ALLOWED_COMPONENT_FILES = frozenset(
    {
        "redaction-report.json",
        "stable-1.0-catalog-app-profile-lifecycle-governance.json",
        "stable-1.0-platform-api-deprecation-governance.json",
        "stable-1.0-support-lifecycle-authorization-summary.json",
        "stable-1.0-support-lifecycle-checksums.txt",
        "stable-1.0-support-lifecycle-descriptor.json",
        "stable-1.0-support-lifecycle-inventory.json",
        "stable-1.0-support-lifecycle-genesis-proof.json",
        "stable-1.0-support-lifecycle-latest.json",
        "stable-1.0-support-lifecycle-ledger.json",
        "stable-1.0-support-lifecycle-provenance.json",
        "stable-1.0-support-lifecycle-publication-plan.json",
        "stable-1.0-support-lifecycle-publication-receipt.json",
        "stable-1.0-support-lifecycle-report.md",
        "stable-1.0-support-lifecycle-summary.json",
        "stable-1.0-support-lifecycle-transition-set.json",
    }
)

DESCRIPTOR_SCHEMA = "stable-1.0-support-lifecycle-descriptor-v1.schema.json"
PLAN_SCHEMA = "stable-1.0-support-lifecycle-publication-plan-v1.schema.json"
AUTHORIZATION_SCHEMA = "stable-1.0-support-lifecycle-authorization-v1.schema.json"
LEDGER_SCHEMA = "stable-1.0-support-lifecycle-ledger-v1.schema.json"
TRANSITION_SCHEMA = "stable-1.0-support-lifecycle-transition-set-v1.schema.json"
INVENTORY_SCHEMA = "stable-1.0-support-lifecycle-inventory-v1.schema.json"
PROVENANCE_SCHEMA = "stable-1.0-support-lifecycle-provenance-v1.schema.json"
GENESIS_PROOF_SCHEMA = "stable-1.0-support-lifecycle-genesis-proof-v1.schema.json"
GENESIS_PROOF_REQUEST_SCHEMA = (
    "stable-1.0-support-lifecycle-genesis-proof-request-v1.schema.json"
)
RECEIPT_SCHEMA = "stable-1.0-support-lifecycle-publication-receipt-v1.schema.json"
POLICY_SCHEMA = "stable-1.0-support-lifecycle-policy-v1.schema.json"

MODES = (
    "prove-genesis",
    "evaluate",
    "prepare-transition",
    "validate-authorization",
    "observe-authorized-state",
    "publish",
    "verify-publication",
)
LOCAL_MODES = frozenset({"evaluate", "prepare-transition", "validate-authorization"})
READ_ONLY_PROVIDER_MODES = frozenset(
    {"prove-genesis", "observe-authorized-state", "verify-publication"}
)
SIDE_EFFECT_FREE_MODES = LOCAL_MODES | READ_ONLY_PROVIDER_MODES
BACKEND_FACTORY_ENV = "CRYPTAD_STABLE_LIFECYCLE_PUBLICATION_BACKEND"
BACKEND_SITE_ENV = "CRYPTAD_STABLE_LIFECYCLE_PUBLICATION_BACKEND_SITE"
INSERT_INPUT_ENV = "CRYPTAD_STABLE_LIFECYCLE_PUBLICATION_INPUT"
INSERT_PURPOSE = "stable-support-lifecycle"
EXPECTED_DOC_NAME = "support-lifecycle"
EXPECTED_PLAN_OPERATION = "insert-or-verify-support-lifecycle"
EXPECTED_AUTHORIZATION_OPERATION = "publish-support-lifecycle"
MAX_JSON_BYTES = 16 * 1024 * 1024

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_SCHEMA_ROOT = Path(__file__).resolve().parents[1] / "schemas"
_POLICY_PATH = (
    Path(__file__).resolve().parents[1]
    / "stable-1.0-support-lifecycle-policy.json"
)
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_FACTORY_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$"
)
_ABSOLUTE_PATH_RE = re.compile(r"^(?:/|[A-Za-z]:[\\/]|\\\\)")
_SENSITIVE_TEXT_PATH_RE = re.compile(
    r"(?:^|[\s`\"'=:(])(?:/(?:home|Users|tmp|work|private)(?:/|$)|[A-Za-z]:[\\/])"
)
_PASS_REDACTION = {"status": "pass", "findingCount": 0, "findings": []}
_SENSITIVE_KEYS = frozenset(
    {
        "authorizationheader",
        "cookie",
        "identitymaterial",
        "inserturi",
        "localpath",
        "password",
        "privateinserturi",
        "privatekey",
        "rawadvisory",
        "rawappdata",
        "rawcontent",
        "rawdescriptorbody",
        "rawsupportbundle",
        "token",
    }
)
_ALLOWED_PROTECTED_KEY = "protectedInsertInputName"


class AdapterError(RuntimeError):
    """One bounded non-secret failure code from the protected adapter."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclasses.dataclass(frozen=True, repr=False)
class SecretMaterial:
    """Opaque lifecycle insert material that cannot render its value."""

    purpose: str
    value: str

    def __repr__(self) -> str:
        return "SecretMaterial(<protected>)"

    def __str__(self) -> str:
        return "<protected>"


@dataclasses.dataclass(frozen=True)
class LifecycleBundle:
    """Exact public descriptor, plan, and optional authorization inputs."""

    root: Path
    artifact_root: Path
    descriptor_path: Path
    descriptor: Mapping[str, Any]
    descriptor_bytes: bytes
    descriptor_byte_digest: str
    plan_path: Path
    plan: Mapping[str, Any]
    plan_digest: str
    ledger_path: Path
    ledger: Mapping[str, Any]
    transition_path: Path
    transition_set: Mapping[str, Any]
    inventory_path: Path
    inventory: Mapping[str, Any]
    provenance_path: Path
    provenance: Mapping[str, Any]
    authorization_path: Path | None
    authorization: Mapping[str, Any] | None
    authorization_digest: str | None
    genesis_proof_path: Path | None
    genesis_proof: Mapping[str, Any] | None


@dataclasses.dataclass(frozen=True)
class LifecycleAuthorityChain:
    """Minimal attested lifecycle authority chain needed for a fresh public read."""

    root: Path
    descriptor_path: Path
    descriptor: Mapping[str, Any]
    descriptor_bytes: bytes
    descriptor_byte_digest: str
    plan_path: Path
    plan: Mapping[str, Any]
    plan_digest: str
    ledger_path: Path
    ledger: Mapping[str, Any]
    authorization_path: Path
    authorization: Mapping[str, Any]
    authorization_digest: str
    publication_receipt_path: Path
    publication_receipt: Mapping[str, Any]


@dataclasses.dataclass(frozen=True)
class PublicationRequest:
    """Public exact-byte request passed to the lifecycle-only provider."""

    bundle: LifecycleBundle | LifecycleAuthorityChain

    @property
    def update_key_scope(self) -> str:
        return str(self.bundle.descriptor["updateKeyScope"])

    @property
    def edition(self) -> int:
        return int(self.bundle.descriptor["descriptorEdition"])

    @property
    def descriptor_digest(self) -> str:
        return str(self.bundle.descriptor["descriptorDigest"])


@dataclasses.dataclass(frozen=True)
class PublicObservation:
    """Bounded public state used for replay, conflict, and idempotency decisions."""

    status: str
    public_request_uri: str
    update_key_identity_digest: str
    update_key_scope: str
    update_key_doc_name: str
    descriptor_edition: int | None
    descriptor_digest: str | None
    descriptor_byte_digest: str | None
    previous_descriptor_edition: int | None
    previous_descriptor_digest: str | None


@dataclasses.dataclass(frozen=True)
class MaintenanceTipObservation:
    """Public latest-maintenance pointer identity observed immediately before mutation."""

    status: str
    public_uri: str | None
    pointer_digest: str | None
    release_id: str
    build_version: str
    baseline_digest: str
    publication_receipt_digest: str


@dataclasses.dataclass(frozen=True)
class GenesisObservation:
    """Bounded lifecycle-target observation used only for first publication."""

    status: str
    transport_status: int
    public_request_uri: str
    update_key_identity_digest: str
    update_key_scope: str
    update_key_doc_name: str


class ExternalOperations(Protocol):
    """Lifecycle-only provider surface; unrelated release mutations are impossible."""

    def observe_lifecycle(self, request: PublicationRequest) -> PublicObservation:
        """Return current public lifecycle state without mutation."""

    def observe_lifecycle_genesis(
        self, request: Mapping[str, Any]
    ) -> GenesisObservation:
        """Prove that the exact lifecycle target has never been published."""

    def observe_latest_maintenance_tip(
        self, request: PublicationRequest
    ) -> MaintenanceTipObservation:
        """Re-fetch the exact public maintenance pointer without mutation."""

    def publish_lifecycle(
        self, request: PublicationRequest, protected_input: SecretMaterial
    ) -> None:
        """Insert the request's exact descriptor bytes once or verify a concurrent match."""

    def verify_lifecycle(self, request: PublicationRequest) -> PublicObservation:
        """Re-fetch and independently verify the public descriptor after publication."""


@dataclasses.dataclass(frozen=True)
class CommandOutcome:
    """One adapter result and the canonical public artifacts to write."""

    passed: bool
    artifacts: Mapping[Path, Mapping[str, Any]]


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def _semantic_digest(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _byte_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def _timestamp(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _parse_timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(dt.timezone.utc)


def _strict_json(data: bytes) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise AdapterError("duplicate-json-field")
            result[key] = value
        return result

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except AdapterError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterError("malformed-json") from exc
    if not isinstance(value, dict):
        raise AdapterError("json-root-is-not-object")
    return value


def _regular_file(path: Path) -> None:
    try:
        mode = path.stat(follow_symlinks=False).st_mode
    except OSError as exc:
        raise AdapterError("unsafe-or-missing-file") from exc
    if path.is_symlink() or not stat.S_ISREG(mode):
        raise AdapterError("unsafe-or-missing-file")


def _scan_public(value: Any, *, key: str | None = None, secret: str | None = None) -> None:
    if key is not None:
        normalized = re.sub(r"[^a-z0-9]", "", key.lower())
        if normalized in _SENSITIVE_KEYS and key != _ALLOWED_PROTECTED_KEY:
            raise AdapterError("public-artifact-sensitive-field")
    if isinstance(value, Mapping):
        for child_key, child in value.items():
            if not isinstance(child_key, str):
                raise AdapterError("public-artifact-nonstring-field")
            _scan_public(child, key=child_key, secret=secret)
        return
    if isinstance(value, list):
        for child in value:
            _scan_public(child, secret=secret)
        return
    if not isinstance(value, str):
        return
    if key == "recoveryGuidance" and recovery_guidance_error(value) is not None:
        raise AdapterError("public-artifact-unsafe-recovery-guidance")
    if secret and secret in value:
        raise AdapterError("protected-input-leak")
    if any(ord(character) < 32 and character not in "\n\t" for character in value):
        raise AdapterError("public-artifact-control-character")
    lowered = value.lower()
    if "authorization: bearer " in lowered or "file://" in lowered:
        raise AdapterError("public-artifact-private-reference")
    if ("usk@" in lowered or "ssk@" in lowered) and "insert" in lowered:
        raise AdapterError("public-artifact-private-insert-uri")
    if _ABSOLUTE_PATH_RE.match(value) and key not in {"route", "endpoint"}:
        raise AdapterError("public-artifact-absolute-path")


def _read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    _regular_file(path)
    try:
        size = path.stat(follow_symlinks=False).st_size
        if size <= 0 or size > MAX_JSON_BYTES:
            raise AdapterError("json-size-outside-policy")
        data = path.read_bytes()
    except OSError as exc:
        raise AdapterError("unsafe-or-missing-file") from exc
    value = _strict_json(data)
    if data != _canonical_bytes(value):
        raise AdapterError("noncanonical-json-bytes")
    _scan_public(value)
    return value, data


def _artifact_root(root: Path) -> Path:
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise AdapterError("bundle-root-missing") from exc
    candidates = (
        resolved,
        resolved / "artifacts" / "legacy",
        resolved / "component" / "artifacts" / "legacy",
    )
    matches = [candidate for candidate in candidates if (candidate / DESCRIPTOR_FILE).is_file()]
    if len(matches) != 1:
        raise AdapterError("lifecycle-artifact-root-ambiguous")
    artifact_root = matches[0].resolve(strict=True)
    if not artifact_root.is_relative_to(resolved):
        raise AdapterError("lifecycle-artifact-root-outside-bundle")
    for path in artifact_root.rglob("*"):
        mode = path.stat(follow_symlinks=False).st_mode
        if path.is_symlink() or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise AdapterError("bundle-contains-link-or-special-file")
        relative = path.relative_to(artifact_root)
        if stat.S_ISDIR(mode) or len(relative.parts) != 1:
            raise AdapterError("bundle-contains-unexpected-component-entry")
        if relative.name not in _ALLOWED_COMPONENT_FILES:
            raise AdapterError("bundle-contains-unexpected-component-entry")
    return artifact_root


def _scan_public_file(path: Path) -> None:
    """Scan one canonical public JSON or bounded UTF-8 text artifact."""

    if path.suffix == ".json":
        _read_json(path)
        return
    _regular_file(path)
    try:
        size = path.stat(follow_symlinks=False).st_size
        if size <= 0 or size > MAX_JSON_BYTES:
            raise AdapterError("public-artifact-size-outside-policy")
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise AdapterError("public-artifact-unreadable") from exc
    _scan_public(text)
    for line in text.splitlines():
        _scan_public(line.strip())
        if _SENSITIVE_TEXT_PATH_RE.search(line):
            raise AdapterError("public-artifact-absolute-path")


def _scan_bundle(
    root: Path,
    artifact_root: Path,
    *,
    allow_root_publication_receipt: bool = False,
) -> None:
    """Reject unexpected siblings and scan every allowed public bundle artifact."""

    artifact_relative = artifact_root.relative_to(root)
    allowed_files = {
        artifact_relative / name for name in _ALLOWED_COMPONENT_FILES
    }
    allowed_directories: set[Path] = set()
    for index in range(1, len(artifact_relative.parts) + 1):
        allowed_directories.add(Path(*artifact_relative.parts[:index]))

    if artifact_relative.parts:
        component_root = artifact_root.parent.parent
        component_relative = component_root.relative_to(root)
        for name in ("summary.json", "redaction-report.json", "report.md"):
            allowed_files.add(component_relative / name)
        allowed_files.add(artifact_relative.parent / "legacy-summary.json")
        allowed_directories.add(Path("manifest"))
        allowed_files.add(Path("manifest/stable-lifecycle-manifest.json"))
        allowed_files.add(Path("stable-lifecycle-protected-evaluation.json"))
        allowed_files.add(Path("stable-lifecycle-authorization-validation.json"))
        if allow_root_publication_receipt:
            allowed_files.update(
                {
                    Path(RECEIPT_FILE),
                    Path(PREFLIGHT_FILE),
                    Path(OPERATION_SUMMARY_FILE),
                }
            )

    for path in sorted(root.rglob("*")):
        try:
            mode = path.stat(follow_symlinks=False).st_mode
        except OSError as exc:
            raise AdapterError("bundle-contains-link-or-special-file") from exc
        if path.is_symlink() or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise AdapterError("bundle-contains-link-or-special-file")
        relative = path.relative_to(root)
        if stat.S_ISDIR(mode):
            if relative not in allowed_directories:
                raise AdapterError("bundle-contains-unexpected-sibling-entry")
            continue
        if relative not in allowed_files:
            raise AdapterError("bundle-contains-unexpected-sibling-entry")
        _scan_public_file(path)


def _schema_errors(value: Mapping[str, Any], schema_name: str) -> list[str]:
    if not (_SCHEMA_ROOT / schema_name).is_file():
        raise AdapterError("lifecycle-schema-missing")
    try:
        return validate_schema(dict(value), schema_name)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise AdapterError("lifecycle-schema-unreadable") from exc


def _require_schema(value: Mapping[str, Any], schema_name: str) -> None:
    if _schema_errors(value, schema_name):
        raise AdapterError("artifact-schema-validation-failed")


def _maximum_authorization_validity(expected_policy_digest: Any) -> dt.timedelta:
    """Load the protected approval window from the exact reviewed lifecycle policy."""

    _regular_file(_POLICY_PATH)
    try:
        policy_bytes = _POLICY_PATH.read_bytes()
        if not policy_bytes or len(policy_bytes) > MAX_JSON_BYTES:
            raise AdapterError("authorization-policy-invalid")
        policy = _strict_json(policy_bytes)
    except OSError as exc:
        raise AdapterError("authorization-policy-invalid") from exc
    _scan_public(policy)
    _require_schema(policy, POLICY_SCHEMA)
    if _byte_digest(policy_bytes) != expected_policy_digest:
        raise AdapterError("authorization-policy-digest-mismatch")
    authorization = policy.get("authorization")
    maximum_hours = (
        authorization.get("maximumValidityHours")
        if isinstance(authorization, Mapping)
        else None
    )
    if type(maximum_hours) is not int or maximum_hours < 1:
        raise AdapterError("authorization-policy-invalid")
    return dt.timedelta(hours=maximum_hours)


def _maximum_genesis_proof_age(expected_policy_digest: Any) -> dt.timedelta:
    """Load the first-publication observation window from the reviewed policy."""

    _regular_file(_POLICY_PATH)
    try:
        policy_bytes = _POLICY_PATH.read_bytes()
        if not policy_bytes or len(policy_bytes) > MAX_JSON_BYTES:
            raise AdapterError("genesis-proof-policy-invalid")
        policy = _strict_json(policy_bytes)
    except OSError as exc:
        raise AdapterError("genesis-proof-policy-invalid") from exc
    _scan_public(policy)
    _require_schema(policy, POLICY_SCHEMA)
    if _byte_digest(policy_bytes) != expected_policy_digest:
        raise AdapterError("genesis-proof-policy-digest-mismatch")
    support_windows = policy.get("supportWindows")
    maximum_minutes = (
        support_windows.get("maximumGenesisProofAgeMinutes")
        if isinstance(support_windows, Mapping)
        else None
    )
    if type(maximum_minutes) is not int or maximum_minutes < 1:
        raise AdapterError("genesis-proof-policy-invalid")
    return dt.timedelta(minutes=maximum_minutes)


def _field(value: Mapping[str, Any], name: str, *aliases: str) -> Any:
    for candidate in (name, *aliases):
        if candidate in value:
            return value[candidate]
    raise AdapterError(f"missing-{name}")


def _authorization_body(value: Mapping[str, Any]) -> Mapping[str, Any]:
    nested = value.get("authorization")
    return nested if isinstance(nested, Mapping) else value


def _transition_set_digest(value: Mapping[str, Any]) -> str:
    return _semantic_digest(
        {key: item for key, item in value.items() if key != "transitionSetDigest"}
    )


def _validate_descriptor(descriptor: Mapping[str, Any]) -> None:
    _require_schema(descriptor, DESCRIPTOR_SCHEMA)
    expected = _semantic_digest(
        {key: item for key, item in descriptor.items() if key != "descriptorDigest"}
    )
    if descriptor.get("descriptorDigest") != expected:
        raise AdapterError("descriptor-semantic-digest-mismatch")
    edition = descriptor.get("descriptorEdition")
    previous_edition = descriptor.get("previousDescriptorEdition")
    previous_digest = descriptor.get("previousDescriptorDigest")
    if type(edition) is not int or edition < 1:
        raise AdapterError("descriptor-edition-invalid")
    if edition == 1:
        if previous_edition is not None or previous_digest is not None:
            raise AdapterError("descriptor-genesis-predecessor-invalid")
    elif (
        type(previous_edition) is not int
        or previous_edition != edition - 1
        or not isinstance(previous_digest, str)
        or _DIGEST_RE.fullmatch(previous_digest) is None
    ):
        raise AdapterError("descriptor-predecessor-binding-invalid")
    if (
        descriptor.get("stableMilestone") != "1.0"
        or descriptor.get("updateKeyDocName") != EXPECTED_DOC_NAME
        or not str(descriptor.get("updateKeyScope", "")).endswith(
            "/support-lifecycle/0"
        )
        or not _DIGEST_RE.fullmatch(str(descriptor.get("updateKeyIdentityDigest", "")))
        or not _DIGEST_RE.fullmatch(str(descriptor.get("ledgerDigest", "")))
        or descriptor.get("redaction") != _PASS_REDACTION
    ):
        raise AdapterError("descriptor-trust-binding-invalid")
    generated = _parse_timestamp(descriptor.get("generatedAt"))
    effective = _parse_timestamp(descriptor.get("effectiveAt"))
    stale = _parse_timestamp(descriptor.get("staleAt"))
    now = _now()
    if (
        generated is None
        or effective is None
        or stale is None
        or generated > now
        or effective > now
        or stale <= now
    ):
        raise AdapterError("descriptor-future-or-stale")
    entries = descriptor.get("entries")
    if not isinstance(entries, list) or any(
        not isinstance(entry, Mapping)
        or (status_effective := _parse_timestamp(entry.get("statusEffectiveAt")))
        is None
        or status_effective > effective
        for entry in entries
    ):
        raise AdapterError("descriptor-entry-future-effective")


def _validate_plan(
    plan: Mapping[str, Any], descriptor: Mapping[str, Any], descriptor_byte_digest: str
) -> None:
    _require_schema(plan, PLAN_SCHEMA)
    public_uri = plan.get("publicRequestUri")
    if (
        canonical_public_https_uri(public_uri) != public_uri
        or not is_public_https_uri(public_uri)
        or not _has_unambiguous_publication_path(public_uri)
    ):
        raise AdapterError("descriptor-public-uri-unsafe")
    pointer_uri = plan.get("latestMaintenancePointerPublicUri")
    pointer_digest = plan.get("latestMaintenancePointerDigest")
    if (
        canonical_public_https_uri(pointer_uri) != pointer_uri
        or not is_public_https_uri(pointer_uri)
        or not _has_unambiguous_publication_path(pointer_uri)
        or pointer_uri == public_uri
    ):
        raise AdapterError("maintenance-pointer-public-uri-unsafe")
    bindings = {
        "descriptorEdition": descriptor.get("descriptorEdition"),
        "descriptorDigest": descriptor.get("descriptorDigest"),
        "descriptorSizeBytes": len(_canonical_bytes(descriptor)),
        "previousDescriptorEdition": descriptor.get("previousDescriptorEdition"),
        "previousDescriptorDigest": descriptor.get("previousDescriptorDigest"),
        "ledgerDigest": descriptor.get("ledgerDigest"),
        "updateKeyIdentityDigest": descriptor.get("updateKeyIdentityDigest"),
        "updateKeyScope": descriptor.get("updateKeyScope"),
        "updateKeyDocName": descriptor.get("updateKeyDocName"),
    }
    for name, expected in bindings.items():
        if _field(plan, name) != expected:
            raise AdapterError(f"plan-{name}-mismatch")
    if descriptor_byte_digest != _byte_digest(_canonical_bytes(descriptor)):
        raise AdapterError("descriptor-byte-digest-mismatch")
    if plan.get("operation") != EXPECTED_PLAN_OPERATION:
        raise AdapterError("plan-operation-invalid")
    expected_plan_digest = _semantic_digest(
        {key: item for key, item in plan.items() if key != "publicationPlanDigest"}
    )
    if plan.get("publicationPlanDigest") != expected_plan_digest:
        raise AdapterError("publication-plan-digest-mismatch")
    if plan.get("conflictPolicy") != "verify-identical-or-fail-never-overwrite":
        raise AdapterError("plan-conflict-policy-invalid")
    if plan.get("sideEffectsPerformed") is not False:
        raise AdapterError("plan-side-effects-invalid")
    if plan.get("redaction") != _PASS_REDACTION:
        raise AdapterError("plan-redaction-invalid")


def _validate_authorization(
    authorization: Mapping[str, Any],
    plan: Mapping[str, Any],
    descriptor: Mapping[str, Any],
    ledger: Mapping[str, Any],
    transition_set: Mapping[str, Any],
    *,
    valid_at: dt.datetime | None = None,
) -> None:
    _require_schema(authorization, AUTHORIZATION_SCHEMA)
    body = _authorization_body(authorization)
    role = body.get("role")
    expected_role = (
        "stable-lifecycle-security-manager"
        if any(
            isinstance(row, Mapping) and row.get("toStatus") == "revoked"
            for row in transition_set.get("transitions", [])
        )
        else "stable-lifecycle-release-manager"
    )
    if role != expected_role:
        raise AdapterError("authorization-role-invalid")
    expected = {
        "targetDescriptorEdition": descriptor.get("descriptorEdition"),
        "targetDescriptorDigest": descriptor.get("descriptorDigest"),
        "targetLedgerDigest": descriptor.get("ledgerDigest"),
        "targetPublicRequestUri": plan.get("publicRequestUri"),
        "targetLatestMaintenancePointerPublicUri": plan.get(
            "latestMaintenancePointerPublicUri"
        ),
        "targetLatestMaintenancePointerDigest": plan.get(
            "latestMaintenancePointerDigest"
        ),
        "previousLedgerDigest": ledger.get("previousLedgerDigest"),
        "previousDescriptorDigest": descriptor.get("previousDescriptorDigest"),
        "transitionRequestDigest": transition_set.get("transitionRequestDigest"),
    }
    for name, expected_value in expected.items():
        if _field(body, name) != expected_value:
            raise AdapterError(f"authorization-{name}-mismatch")
    if body.get("operation") != EXPECTED_AUTHORIZATION_OPERATION:
        raise AdapterError("authorization-operation-scope-invalid")
    request_digest = _semantic_digest(
        {
            "operation": EXPECTED_AUTHORIZATION_OPERATION,
            "ledgerDigest": descriptor.get("ledgerDigest"),
            "descriptorDigest": descriptor.get("descriptorDigest"),
            "descriptorEdition": descriptor.get("descriptorEdition"),
            "publicRequestUri": plan.get("publicRequestUri"),
            "latestMaintenancePointerPublicUri": plan.get(
                "latestMaintenancePointerPublicUri"
            ),
            "latestMaintenancePointerDigest": plan.get(
                "latestMaintenancePointerDigest"
            ),
            "transitionRequestDigest": transition_set.get("transitionRequestDigest"),
            "previousLedgerDigest": ledger.get("previousLedgerDigest"),
            "previousDescriptorDigest": descriptor.get("previousDescriptorDigest"),
            "requiredRole": expected_role,
        }
    )
    if body.get("authorizationRequestDigest") != request_digest:
        raise AdapterError("authorization-request-digest-mismatch")
    expiry = _parse_timestamp(body.get("expiresAt"))
    issued = _parse_timestamp(body.get("generatedAt"))
    authorization_time = _now() if valid_at is None else valid_at
    if (
        issued is None
        or expiry is None
        or issued > authorization_time
        or expiry <= issued
        or expiry <= authorization_time
        or expiry - issued
        > _maximum_authorization_validity(ledger.get("policyDigest"))
    ):
        raise AdapterError("authorization-expired-or-malformed")
    if body.get("decision") != "approved":
        raise AdapterError("authorization-decision-invalid")
    if authorization.get("redaction", _PASS_REDACTION) != _PASS_REDACTION:
        raise AdapterError("authorization-redaction-invalid")


def _validate_descriptor_history_binding(
    inventory: Mapping[str, Any],
    ledger: Mapping[str, Any],
    descriptor: Mapping[str, Any],
    genesis_proof: Mapping[str, Any] | None,
) -> None:
    """Bind descriptor genesis to observed absence and successors to prior history."""

    if descriptor.get("descriptorEdition") == 1:
        if (
            ledger.get("previousLedgerDigest") is not None
            or descriptor.get("previousDescriptorEdition") is not None
            or descriptor.get("previousDescriptorDigest") is not None
            or genesis_proof is None
        ):
            raise AdapterError("descriptor-genesis-proof-or-history-invalid")
        return
    if (
        not isinstance(ledger.get("previousLedgerDigest"), str)
        or not isinstance(descriptor.get("previousDescriptorEdition"), int)
        or not isinstance(descriptor.get("previousDescriptorDigest"), str)
        or genesis_proof is not None
    ):
        raise AdapterError("descriptor-successor-history-binding-missing")


def _validate_genesis_proof(
    proof: Mapping[str, Any],
    inventory: Mapping[str, Any],
    descriptor: Mapping[str, Any],
    plan: Mapping[str, Any],
    policy_digest: Any,
    *,
    valid_at: dt.datetime | None = None,
) -> None:
    """Verify the provider-observed 404 against the exact edition-one inventory."""

    _require_schema(proof, GENESIS_PROOF_SCHEMA)
    expected_digest = _semantic_digest(
        {key: item for key, item in proof.items() if key != "proofDigest"}
    )
    entries = inventory.get("entries")
    if not isinstance(entries, list) or not entries or not isinstance(entries[-1], Mapping):
        raise AdapterError("genesis-proof-inventory-tip-invalid")
    tip = entries[-1]
    expected = {
        "generatedAt": inventory.get("generatedAt"),
        "stableMilestone": "1.0",
        "observationStatus": "absent",
        "transportStatus": 404,
        "publicRequestUri": plan.get("publicRequestUri"),
        "updateKeyIdentityDigest": descriptor.get("updateKeyIdentityDigest"),
        "updateKeyScope": descriptor.get("updateKeyScope"),
        "updateKeyDocName": descriptor.get("updateKeyDocName"),
        "inventoryDigest": inventory.get("inventoryDigest"),
        "gaRootDigest": inventory.get("gaRootDigest"),
        "latestPointerDigest": inventory.get("latestPointerDigest"),
        "chainDepth": inventory.get("chainDepth"),
        "releaseId": tip.get("releaseId"),
        "buildVersion": tip.get("buildVersion"),
        "baselineDigest": tip.get("baselineDigest"),
        "publicationReceiptDigest": tip.get("publicationReceiptDigest"),
    }
    if proof.get("proofDigest") != expected_digest or any(
        proof.get(name) != value for name, value in expected.items()
    ):
        raise AdapterError("genesis-proof-binding-invalid")
    observed = _parse_timestamp(proof.get("observedAt"))
    generated = _parse_timestamp(proof.get("generatedAt"))
    maximum_age = _maximum_genesis_proof_age(policy_digest)
    proof_time = _now() if valid_at is None else valid_at
    if (
        observed is None
        or generated is None
        or generated > observed
        or observed > proof_time
        or proof_time - observed > maximum_age
        or observed - generated > maximum_age
    ):
        raise AdapterError("genesis-proof-stale-or-malformed")


def _validate_ledger_runtime_guidance(
    ledger_entries: Sequence[Mapping[str, Any]],
) -> None:
    """Enforce the runtime's fail-closed replacement and recovery projection rules."""

    security_supported = {
        "current-stable",
        "supported-maintenance",
        "security-fixes-only",
    }
    revoked_builds = {
        row.get("buildVersion")
        for row in ledger_entries
        if row.get("lifecycleStatus") == "revoked"
    }
    if any(row.get("replacementBuild") in revoked_builds for row in ledger_entries):
        raise AdapterError("ledger-recommends-revoked-build")
    entries_by_build = {row.get("buildVersion"): row for row in ledger_entries}
    for row in ledger_entries:
        replacement = row.get("replacementBuild")
        if replacement is None:
            continue
        replacement_entry = entries_by_build.get(replacement)
        if (
            replacement == row.get("buildVersion")
            or not isinstance(replacement_entry, Mapping)
            or replacement_entry.get("lifecycleStatus") not in security_supported
        ):
            raise AdapterError("ledger-replacement-target-invalid")
    if any(
        row.get("replacementBuild") is not None
        and row.get("recoveryGuidance") is not None
        for row in ledger_entries
    ):
        raise AdapterError("ledger-replacement-and-recovery-guidance-ambiguous")
    has_current = any(
        row.get("lifecycleStatus") == "current-stable" for row in ledger_entries
    )
    has_recovery_only = any(
        row.get("replacementBuild") is None
        and row.get("recoveryGuidance") is not None
        for row in ledger_entries
    )
    if has_current and has_recovery_only:
        raise AdapterError("ledger-recovery-guidance-with-current-stable")


def _validate_inventory_bindings(
    inventory: Mapping[str, Any],
    ledger: Mapping[str, Any],
    descriptor: Mapping[str, Any],
    provenance: Mapping[str, Any],
    plan: Mapping[str, Any],
    genesis_proof: Mapping[str, Any] | None,
    *,
    valid_at: dt.datetime | None = None,
) -> None:
    """Bind the authenticated release tip to the ledger and descriptor projection."""

    _require_schema(inventory, INVENTORY_SCHEMA)
    _require_schema(provenance, PROVENANCE_SCHEMA)
    inventory_digest = _semantic_digest(
        {key: item for key, item in inventory.items() if key != "inventoryDigest"}
    )
    if inventory.get("inventoryDigest") != inventory_digest:
        raise AdapterError("inventory-semantic-digest-mismatch")
    if inventory.get("status") != "pass" or inventory.get("redaction") != _PASS_REDACTION:
        raise AdapterError("inventory-authentication-not-passing")
    _validate_descriptor_history_binding(inventory, ledger, descriptor, genesis_proof)
    if genesis_proof is not None:
        _validate_genesis_proof(
            genesis_proof,
            inventory,
            descriptor,
            plan,
            ledger.get("policyDigest"),
            valid_at=valid_at,
        )
    bindings = {
        ledger.get("inventoryDigest"),
        descriptor.get("inventoryDigest"),
        provenance.get("inventoryDigest"),
    }
    if bindings != {inventory_digest}:
        raise AdapterError("inventory-ledger-descriptor-binding-mismatch")
    if (
        provenance.get("gaRootDigest") != inventory.get("gaRootDigest")
        or provenance.get("ledgerDigest") != ledger.get("ledgerDigest")
        or provenance.get("descriptorDigest") != descriptor.get("descriptorDigest")
        or provenance.get("policyDigest") != ledger.get("policyDigest")
        or provenance.get("genesisProofDigest")
        != (genesis_proof.get("proofDigest") if genesis_proof is not None else None)
        or provenance.get("sideEffectsPerformed") is not False
        or provenance.get("redaction") != _PASS_REDACTION
    ):
        raise AdapterError("inventory-provenance-binding-mismatch")
    inventory_entries = inventory.get("entries")
    ledger_entries = ledger.get("entries")
    descriptor_entries = descriptor.get("entries")
    if not all(
        isinstance(rows, list) and rows
        for rows in (inventory_entries, ledger_entries, descriptor_entries)
    ):
        raise AdapterError("inventory-entry-set-invalid")
    assert isinstance(inventory_entries, list)
    assert isinstance(ledger_entries, list)
    assert isinstance(descriptor_entries, list)
    if len(inventory_entries) != len(ledger_entries) or len(ledger_entries) != len(
        descriptor_entries
    ):
        raise AdapterError("inventory-entry-set-mismatch")
    release_fields = (
        "releaseId",
        "buildVersion",
        "tag",
        "sourceCommit",
        "productDigest",
        "publicationReceiptDigest",
        "baselineDigest",
        "publishedAt",
    )
    descriptor_fields = release_fields + (
        "lifecycleStatus",
        "statusEffectiveAt",
        "fullSupportUntil",
        "securityFixesUntil",
        "deprecationEffectiveAt",
        "endOfSupportAt",
        "securityRevocationEffectiveAt",
        "replacementBuild",
        "recoveryGuidance",
        "advisoryIds",
        "reasonCodes",
    )
    for published, ledger_entry, descriptor_entry in zip(
        inventory_entries, ledger_entries, descriptor_entries, strict=True
    ):
        if not all(
            isinstance(row, Mapping)
            for row in (published, ledger_entry, descriptor_entry)
        ):
            raise AdapterError("inventory-entry-set-invalid")
        if any(published.get(field) != ledger_entry.get(field) for field in release_fields):
            raise AdapterError("inventory-ledger-release-identity-mismatch")
        if any(
            ledger_entry.get(field) != descriptor_entry.get(field)
            for field in descriptor_fields
        ):
            raise AdapterError("ledger-descriptor-entry-mismatch")
    _validate_ledger_runtime_guidance(ledger_entries)
    tip = inventory_entries[-1]
    tip_ledger_entry = ledger_entries[-1]
    current_ledger_entries = [
        row
        for row in ledger_entries
        if isinstance(row, Mapping) and row.get("lifecycleStatus") == "current-stable"
    ]
    emergency_tip_revoked = (
        tip_ledger_entry.get("lifecycleStatus") == "revoked"
        and not current_ledger_entries
        and descriptor.get("currentStableBuild") is None
    )
    emergency_replacement = tip_ledger_entry.get("replacementBuild")
    replacement_entry = next(
        (
            row
            for row in ledger_entries
            if isinstance(row, Mapping)
            and row.get("buildVersion") == emergency_replacement
        ),
        None,
    )
    emergency_recommendation_valid = (
        descriptor.get("recommendedBuild") is None
        and emergency_replacement is None
        and isinstance(tip_ledger_entry.get("recoveryGuidance"), str)
        or descriptor.get("recommendedBuild") == emergency_replacement
        and emergency_replacement is not None
        and tip_ledger_entry.get("recoveryGuidance") is None
        and isinstance(replacement_entry, Mapping)
        and replacement_entry.get("lifecycleStatus")
        in {"current-stable", "supported-maintenance", "security-fixes-only"}
    )
    normal_tip_selection = (
        len(current_ledger_entries) == 1
        and current_ledger_entries[0].get("buildVersion") == tip.get("buildVersion")
        and descriptor.get("currentStableBuild") == tip.get("buildVersion")
        and descriptor.get("recommendedBuild") == tip.get("buildVersion")
    )
    if (
        inventory.get("chainDepth") != tip.get("chainDepth")
        or provenance.get("maintenanceTipBaselineDigest")
        != tip.get("baselineDigest")
        or provenance.get("maintenanceTipReceiptDigest")
        != tip.get("publicationReceiptDigest")
        or not (
            normal_tip_selection
            or emergency_tip_revoked and emergency_recommendation_valid
        )
    ):
        raise AdapterError("authenticated-maintenance-tip-mismatch")
    if (
        inventory.get("chainDepth") == 0
        and (
            inventory.get("latestPointerDigest") is not None
            or plan.get("latestMaintenancePointerDigest") is not None
        )
    ) or (
        inventory.get("chainDepth") > 0
        and (
            not isinstance(inventory.get("latestPointerDigest"), str)
            or not isinstance(
                provenance.get("latestMaintenancePointerPublicUri"), str
            )
        )
    ):
        raise AdapterError("authenticated-latest-pointer-mismatch")
    if (
        plan.get("latestMaintenancePointerPublicUri")
        != provenance.get("latestMaintenancePointerPublicUri")
        or plan.get("latestMaintenancePointerDigest")
        != inventory.get("latestPointerDigest")
    ):
        raise AdapterError("authenticated-latest-pointer-target-mismatch")


def load_bundle(
    root: Path,
    *,
    require_authorization: bool,
    authorization_valid_at: dt.datetime | None = None,
    allow_root_publication_receipt: bool = False,
) -> LifecycleBundle:
    """Load and independently bind one canonical lifecycle publication bundle."""

    artifact_root = _artifact_root(root)
    _scan_bundle(
        root.resolve(strict=True),
        artifact_root,
        allow_root_publication_receipt=allow_root_publication_receipt,
    )
    descriptor_path = artifact_root / DESCRIPTOR_FILE
    plan_path = artifact_root / PLAN_FILE
    ledger_path = artifact_root / LEDGER_FILE
    transition_path = artifact_root / TRANSITION_FILE
    inventory_path = artifact_root / INVENTORY_FILE
    provenance_path = artifact_root / PROVENANCE_FILE
    genesis_proof_path = artifact_root / GENESIS_PROOF_FILE
    descriptor, descriptor_bytes = _read_json(descriptor_path)
    plan, _plan_bytes = _read_json(plan_path)
    ledger, _ledger_bytes = _read_json(ledger_path)
    transition_set, _transition_bytes = _read_json(transition_path)
    inventory, _inventory_bytes = _read_json(inventory_path)
    provenance, _provenance_bytes = _read_json(provenance_path)
    genesis_proof: Mapping[str, Any] | None = None
    if genesis_proof_path.exists():
        genesis_proof, _genesis_proof_bytes = _read_json(genesis_proof_path)
    descriptor_byte_digest = _byte_digest(descriptor_bytes)
    _validate_descriptor(descriptor)
    _validate_plan(plan, descriptor, descriptor_byte_digest)
    _require_schema(ledger, LEDGER_SCHEMA)
    _require_schema(transition_set, TRANSITION_SCHEMA)
    if ledger.get("ledgerDigest") != _semantic_digest(
        {key: item for key, item in ledger.items() if key != "ledgerDigest"}
    ):
        raise AdapterError("ledger-semantic-digest-mismatch")
    if transition_set.get("transitionSetDigest") != _transition_set_digest(
        transition_set
    ):
        raise AdapterError("transition-set-semantic-digest-mismatch")
    if ledger.get("ledgerDigest") != descriptor.get("ledgerDigest"):
        raise AdapterError("ledger-descriptor-digest-mismatch")
    if transition_set.get("resultingLedgerDigest") != ledger.get("ledgerDigest"):
        raise AdapterError("transition-resulting-ledger-digest-mismatch")
    if plan.get("transitionSetDigest") != transition_set.get("transitionSetDigest"):
        raise AdapterError("plan-transition-set-digest-mismatch")
    _validate_inventory_bindings(
        inventory,
        ledger,
        descriptor,
        provenance,
        plan,
        genesis_proof,
        valid_at=authorization_valid_at,
    )
    authorization_path = artifact_root / AUTHORIZATION_FILE
    authorization: Mapping[str, Any] | None = None
    authorization_digest: str | None = None
    if authorization_path.exists():
        authorization, authorization_bytes = _read_json(authorization_path)
        _require_schema(authorization, AUTHORIZATION_SCHEMA)
        if require_authorization or plan.get("publicationAuthorized") is True:
            _validate_authorization(
                authorization,
                plan,
                descriptor,
                ledger,
                transition_set,
                valid_at=authorization_valid_at,
            )
            authorization_digest = _byte_digest(authorization_bytes)
            if (
                plan.get("authorizationDigest") != authorization_digest
                or plan.get("publicationAuthorized") is not True
            ):
                raise AdapterError("plan-authorization-binding-mismatch")
            if any(
                not isinstance(row, Mapping)
                or row.get("authorizationDigest") != authorization_digest
                for row in transition_set.get("transitions", [])
            ):
                raise AdapterError("transition-authorization-binding-mismatch")
        elif (
            authorization.get("decision") != "pending"
            or plan.get("authorizationDigest") is not None
            or plan.get("publicationAuthorized") is not False
            or any(
                not isinstance(row, Mapping)
                or row.get("authorizationDigest") is not None
                for row in transition_set.get("transitions", [])
            )
        ):
            raise AdapterError("unauthorized-plan-claims-publication-authority")
    elif require_authorization:
        raise AdapterError("authorization-missing")
    elif (
        plan.get("authorizationDigest") is not None
        or plan.get("publicationAuthorized") is not False
    ):
        raise AdapterError("unauthorized-plan-claims-publication-authority")
    return LifecycleBundle(
        root.resolve(strict=True),
        artifact_root,
        descriptor_path,
        descriptor,
        descriptor_bytes,
        descriptor_byte_digest,
        plan_path,
        plan,
        str(plan["publicationPlanDigest"]),
        ledger_path,
        ledger,
        transition_path,
        transition_set,
        inventory_path,
        inventory,
        provenance_path,
        provenance,
        authorization_path if authorization is not None else None,
        authorization,
        authorization_digest,
        genesis_proof_path if genesis_proof is not None else None,
        genesis_proof,
    )


def load_authority_chain(root: Path) -> LifecycleAuthorityChain:
    """Load the five attested artifacts used by maintenance for an immediate public read."""

    resolved = root.resolve(strict=True)
    if root.is_symlink() or not resolved.is_dir():
        raise AdapterError("lifecycle-authority-chain-root-unsafe")
    expected_names = {
        LEDGER_FILE,
        DESCRIPTOR_FILE,
        AUTHORIZATION_FILE,
        PLAN_FILE,
        RECEIPT_FILE,
    }
    entries = list(resolved.iterdir())
    if (
        {entry.name for entry in entries} != expected_names
        or any(entry.is_symlink() or not entry.is_file() for entry in entries)
    ):
        raise AdapterError("lifecycle-authority-chain-layout-invalid")
    for entry in entries:
        _scan_public_file(entry)

    descriptor_path = resolved / DESCRIPTOR_FILE
    plan_path = resolved / PLAN_FILE
    ledger_path = resolved / LEDGER_FILE
    authorization_path = resolved / AUTHORIZATION_FILE
    receipt_path = resolved / RECEIPT_FILE
    descriptor, descriptor_bytes = _read_json(descriptor_path)
    plan, _plan_bytes = _read_json(plan_path)
    ledger, _ledger_bytes = _read_json(ledger_path)
    authorization, authorization_bytes = _read_json(authorization_path)
    receipt, _receipt_bytes = _read_json(receipt_path)
    descriptor_byte_digest = _byte_digest(descriptor_bytes)
    authorization_digest = _byte_digest(authorization_bytes)

    _validate_descriptor(descriptor)
    _validate_plan(plan, descriptor, descriptor_byte_digest)
    _require_schema(ledger, LEDGER_SCHEMA)
    _require_schema(authorization, AUTHORIZATION_SCHEMA)
    _require_schema(receipt, RECEIPT_SCHEMA)
    ledger_digest = _semantic_digest(
        {key: item for key, item in ledger.items() if key != "ledgerDigest"}
    )
    if (
        ledger.get("ledgerDigest") != ledger_digest
        or descriptor.get("ledgerDigest") != ledger_digest
    ):
        raise AdapterError("authority-chain-ledger-digest-mismatch")
    if (
        plan.get("authorizationDigest") != authorization_digest
        or plan.get("publicationAuthorized") is not True
        or authorization.get("decision") != "approved"
        or _field(authorization, "targetLedgerDigest") != ledger_digest
        or _field(authorization, "targetDescriptorDigest")
        != descriptor.get("descriptorDigest")
        or _field(authorization, "targetDescriptorEdition")
        != descriptor.get("descriptorEdition")
        or _field(authorization, "targetPublicRequestUri")
        != plan.get("publicRequestUri")
    ):
        raise AdapterError("authority-chain-authorization-mismatch")
    receipt_bindings = {
        "descriptorEdition": descriptor.get("descriptorEdition"),
        "descriptorDigest": descriptor.get("descriptorDigest"),
        "descriptorBytesDigest": descriptor_byte_digest,
        "ledgerDigest": ledger_digest,
        "previousDescriptorEdition": descriptor.get("previousDescriptorEdition"),
        "previousDescriptorDigest": descriptor.get("previousDescriptorDigest"),
        "updateKeyIdentityDigest": descriptor.get("updateKeyIdentityDigest"),
        "updateKeyScope": descriptor.get("updateKeyScope"),
        "updateKeyDocName": descriptor.get("updateKeyDocName"),
        "publicRequestUri": plan.get("publicRequestUri"),
        "publicationPlanDigest": plan.get("publicationPlanDigest"),
        "authorizationDigest": authorization_digest,
    }
    if (
        any(receipt.get(name) != value for name, value in receipt_bindings.items())
        or receipt.get("operation") not in {"inserted", "verified-existing"}
        or receipt.get("publicationState") != "publication-complete"
        or receipt.get("verificationStatus") != "verified"
        or receipt.get("conflict") is not False
        or receipt.get("redaction") != _PASS_REDACTION
    ):
        raise AdapterError("authority-chain-publication-receipt-mismatch")
    return LifecycleAuthorityChain(
        resolved,
        descriptor_path,
        descriptor,
        descriptor_bytes,
        descriptor_byte_digest,
        plan_path,
        plan,
        str(plan["publicationPlanDigest"]),
        ledger_path,
        ledger,
        authorization_path,
        authorization,
        authorization_digest,
        receipt_path,
        receipt,
    )


def _observation_value(observation: PublicObservation) -> dict[str, Any]:
    return {
        "status": observation.status,
        "publicRequestUri": observation.public_request_uri,
        "updateKeyIdentityDigest": observation.update_key_identity_digest,
        "updateKeyScope": observation.update_key_scope,
        "updateKeyDocName": observation.update_key_doc_name,
        "descriptorEdition": observation.descriptor_edition,
        "descriptorDigest": observation.descriptor_digest,
        "descriptorByteDigest": observation.descriptor_byte_digest,
        "previousDescriptorEdition": observation.previous_descriptor_edition,
        "previousDescriptorDigest": observation.previous_descriptor_digest,
    }


def _classify_observation(
    request: PublicationRequest, observation: PublicObservation
) -> str:
    if observation.status not in {"absent", "matching", "conflict", "unavailable"}:
        raise AdapterError("provider-observation-status-invalid")
    descriptor = request.bundle.descriptor
    if (
        observation.public_request_uri != request.bundle.plan["publicRequestUri"]
        or observation.update_key_identity_digest != descriptor["updateKeyIdentityDigest"]
        or observation.update_key_scope != descriptor["updateKeyScope"]
        or observation.update_key_doc_name != descriptor["updateKeyDocName"]
    ):
        raise AdapterError("provider-update-key-scope-mismatch")
    if observation.status == "unavailable":
        raise AdapterError("public-lifecycle-state-unavailable")
    if observation.status == "conflict":
        raise AdapterError("public-lifecycle-state-conflict")
    if observation.status == "matching":
        exact = (
            observation.descriptor_edition == descriptor["descriptorEdition"]
            and observation.descriptor_digest == descriptor["descriptorDigest"]
            and observation.descriptor_byte_digest
            == request.bundle.descriptor_byte_digest
            and observation.previous_descriptor_edition
            == descriptor["previousDescriptorEdition"]
            and observation.previous_descriptor_digest
            == descriptor["previousDescriptorDigest"]
        )
        if not exact:
            raise AdapterError("matching-public-state-is-not-exact")
        return "matching"
    if (
        observation.descriptor_edition != descriptor["previousDescriptorEdition"]
        or observation.descriptor_digest != descriptor["previousDescriptorDigest"]
    ):
        raise AdapterError("public-predecessor-edition-or-digest-mismatch")
    return "absent"


def _validate_maintenance_tip_observation(
    bundle: LifecycleBundle, observation: MaintenanceTipObservation
) -> None:
    """Require the public maintenance selector to still name the authorized inventory tip."""

    entries = bundle.inventory.get("entries")
    if not isinstance(entries, list) or not entries or not isinstance(entries[-1], Mapping):
        raise AdapterError("authenticated-maintenance-tip-missing")
    tip = entries[-1]
    depth = bundle.inventory.get("chainDepth")
    expected_uri = bundle.plan.get("latestMaintenancePointerPublicUri")
    expected_digest = bundle.plan.get("latestMaintenancePointerDigest")
    expected_identity = (
        str(tip.get("releaseId")),
        str(tip.get("buildVersion")),
        str(tip.get("baselineDigest")),
        str(tip.get("publicationReceiptDigest")),
    )
    observed_identity = (
        observation.release_id,
        observation.build_version,
        observation.baseline_digest,
        observation.publication_receipt_digest,
    )
    if depth == 0:
        if (
            observation.status != "absent"
            or observation.public_uri != expected_uri
            or observation.pointer_digest is not None
            or expected_digest is not None
            or observed_identity != expected_identity
        ):
            raise AdapterError("public-maintenance-tip-changed-before-publication")
        return
    if observation.status == "unavailable":
        raise AdapterError("public-maintenance-tip-unavailable")
    if observation.status not in {"matching", "conflict"}:
        raise AdapterError("maintenance-tip-observation-status-invalid")
    if (
        observation.status != "matching"
        or observation.public_uri != expected_uri
        or observation.pointer_digest != expected_digest
        or observed_identity != expected_identity
    ):
        raise AdapterError("public-maintenance-tip-changed-before-publication")


def _preflight_artifact(
    bundle: LifecycleBundle, observation: PublicObservation, state: str
) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-support-lifecycle-publication-preflight",
        "generatedAt": _timestamp(_now()),
        "stableMilestone": "1.0",
        "descriptorEdition": bundle.descriptor["descriptorEdition"],
        "descriptorDigest": bundle.descriptor["descriptorDigest"],
        "descriptorByteDigest": bundle.descriptor_byte_digest,
        "publicationPlanDigest": bundle.plan_digest,
        "authorizationDigest": bundle.authorization_digest,
        "status": "pass",
        "publicState": "matching-existing" if state == "matching" else "absent",
        "sideEffectsPerformed": False,
        "observation": _observation_value(observation),
        "redaction": dict(_PASS_REDACTION),
    }


def _receipt(
    bundle: LifecycleBundle,
    observation: PublicObservation,
    publication_status: str,
    *,
    generated_at: dt.datetime | None = None,
) -> dict[str, Any]:
    value = {
        "schemaVersion": 1,
        "kind": "stable-1.0-support-lifecycle-publication-receipt",
        "generatedAt": _timestamp(_now() if generated_at is None else generated_at),
        "stableMilestone": "1.0",
        "descriptorEdition": bundle.descriptor["descriptorEdition"],
        "descriptorDigest": bundle.descriptor["descriptorDigest"],
        "descriptorBytesDigest": bundle.descriptor_byte_digest,
        "ledgerDigest": bundle.descriptor["ledgerDigest"],
        "previousDescriptorEdition": bundle.descriptor["previousDescriptorEdition"],
        "previousDescriptorDigest": bundle.descriptor["previousDescriptorDigest"],
        "updateKeyIdentityDigest": bundle.descriptor["updateKeyIdentityDigest"],
        "updateKeyScope": bundle.descriptor["updateKeyScope"],
        "updateKeyDocName": bundle.descriptor["updateKeyDocName"],
        "publicRequestUri": bundle.plan["publicRequestUri"],
        "publicationPlanDigest": bundle.plan_digest,
        "authorizationDigest": bundle.authorization_digest,
        "operation": publication_status,
        "publicationState": "publication-complete",
        "verificationStatus": "verified",
        "conflict": False,
        "redaction": dict(_PASS_REDACTION),
    }
    return value


def _failure_audit(
    bundle: LifecycleBundle | None,
    *,
    attempted: bool,
    error_code: str,
) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-support-lifecycle-publication-failure-audit",
        "generatedAt": _timestamp(_now()),
        "stableMilestone": "1.0",
        "descriptorEdition": bundle.descriptor.get("descriptorEdition") if bundle else None,
        "descriptorDigest": bundle.descriptor.get("descriptorDigest") if bundle else None,
        "descriptorByteDigest": bundle.descriptor_byte_digest if bundle else None,
        "publicationPlanDigest": bundle.plan_digest if bundle else None,
        "authorizationDigest": bundle.authorization_digest if bundle else None,
        "publicationAttempted": attempted,
        "sideEffectsMayHaveOccurred": attempted,
        "failureCode": error_code,
        "recoveryAction": "observe-and-verify-exact-public-state-before-retry",
        "redaction": dict(_PASS_REDACTION),
    }


def evaluate_only(root: Path, out: Path, *, require_authorization: bool) -> CommandOutcome:
    """Validate exact local publication material without loading a provider."""

    bundle = load_bundle(root, require_authorization=require_authorization)
    if not require_authorization and bundle.authorization_digest is not None:
        raise AdapterError("local-preparation-cannot-consume-approved-authorization")
    value = {
        "schemaVersion": 1,
        "kind": "stable-1.0-support-lifecycle-protected-evaluation",
        "generatedAt": _timestamp(_now()),
        "stableMilestone": "1.0",
        "descriptorEdition": bundle.descriptor["descriptorEdition"],
        "descriptorDigest": bundle.descriptor["descriptorDigest"],
        "descriptorByteDigest": bundle.descriptor_byte_digest,
        "publicationPlanDigest": bundle.plan_digest,
        "authorizationDigest": bundle.authorization_digest,
        "status": "pass",
        "sideEffectsPerformed": False,
        "redaction": dict(_PASS_REDACTION),
    }
    return CommandOutcome(True, {out: value})


def prove_genesis(
    request_path: Path, operations: ExternalOperations, out: Path
) -> CommandOutcome:
    """Produce a short-lived proof only for an exact public HTTP 404 observation."""

    request, _request_bytes = _read_json(request_path)
    _require_schema(request, GENESIS_PROOF_REQUEST_SCHEMA)
    public_uri = request.get("publicRequestUri")
    if (
        canonical_public_https_uri(public_uri) != public_uri
        or not is_public_https_uri(public_uri)
        or not _has_unambiguous_publication_path(public_uri)
    ):
        raise AdapterError("genesis-proof-public-uri-unsafe")
    generated = _parse_timestamp(request.get("generatedAt"))
    now = _now()
    policy_bytes = _POLICY_PATH.read_bytes()
    maximum_age = _maximum_genesis_proof_age(_byte_digest(policy_bytes))
    if generated is None or generated > now or now - generated > maximum_age:
        raise AdapterError("genesis-proof-request-time-invalid")
    observation = operations.observe_lifecycle_genesis(request)
    expected_observation = {
        "public_request_uri": request.get("publicRequestUri"),
        "update_key_identity_digest": request.get("updateKeyIdentityDigest"),
        "update_key_scope": request.get("updateKeyScope"),
        "update_key_doc_name": request.get("updateKeyDocName"),
    }
    if any(
        getattr(observation, name, None) != expected
        for name, expected in expected_observation.items()
    ):
        raise AdapterError("genesis-proof-provider-binding-invalid")
    if observation.transport_status == 410 or observation.status == "tombstoned":
        raise AdapterError("genesis-proof-target-tombstoned")
    if observation.transport_status != 404 or observation.status != "absent":
        raise AdapterError("genesis-proof-target-not-never-published")
    proof = {
        **request,
        "kind": "stable-1.0-support-lifecycle-genesis-proof",
        "observedAt": _timestamp(now),
        "observationStatus": "absent",
        "transportStatus": 404,
    }
    proof["proofDigest"] = _semantic_digest(proof)
    _require_schema(proof, GENESIS_PROOF_SCHEMA)
    return CommandOutcome(True, {out: proof})


def _require_fresh_reauthentication(
    authorized: LifecycleBundle, reauthenticated: LifecycleBundle
) -> None:
    """Require a distinct immediate certification result for the exact authorized tip."""

    if authorized.artifact_root == reauthenticated.artifact_root:
        raise AdapterError("publication-reauthentication-not-distinct")
    exact_bindings = (
        (authorized.inventory, reauthenticated.inventory),
        (authorized.ledger, reauthenticated.ledger),
        (authorized.descriptor_bytes, reauthenticated.descriptor_bytes),
        (authorized.transition_set, reauthenticated.transition_set),
        (authorized.authorization_digest, reauthenticated.authorization_digest),
        (authorized.plan_digest, reauthenticated.plan_digest),
        (authorized.provenance, reauthenticated.provenance),
        (authorized.genesis_proof, reauthenticated.genesis_proof),
    )
    if any(expected != actual for expected, actual in exact_bindings):
        raise AdapterError("authenticated-maintenance-tip-changed-before-publication")


def _validate_bundle_authorization_at(
    bundle: LifecycleBundle, authorization_time: dt.datetime
) -> None:
    """Revalidate one exact approved bundle at a named mutation or receipt boundary."""

    if bundle.authorization is None:
        raise AdapterError("authorization-missing")
    _validate_authorization(
        bundle.authorization,
        bundle.plan,
        bundle.descriptor,
        bundle.ledger,
        bundle.transition_set,
        valid_at=authorization_time,
    )


def publish_exact(
    root: Path,
    reauthenticated_root: Path,
    operations: ExternalOperations,
    protected_input: SecretMaterial,
    receipt_path: Path,
    preflight_path: Path,
) -> CommandOutcome:
    """Publish once after exact preflight, then re-fetch and verify public bytes."""

    bundle: LifecycleBundle | None = None
    attempted = False
    try:
        if protected_input.purpose != INSERT_PURPOSE:
            raise AdapterError("protected-input-purpose-mismatch")
        bundle = load_bundle(root, require_authorization=True)
        reauthenticated = load_bundle(
            reauthenticated_root, require_authorization=True
        )
        _require_fresh_reauthentication(bundle, reauthenticated)
        request = PublicationRequest(bundle)
        before = operations.observe_lifecycle(request)
        state = _classify_observation(request, before)
        preflight = _preflight_artifact(bundle, before, state)
        maintenance_tip = operations.observe_latest_maintenance_tip(request)
        _validate_maintenance_tip_observation(bundle, maintenance_tip)
        # Recheck at the mutation boundary so a descriptor that expires during preflight is never
        # inserted merely because it was fresh when the bundle was first loaded.
        _validate_descriptor(bundle.descriptor)
        _validate_bundle_authorization_at(bundle, _now())
        if state == "absent":
            attempted = True
            operations.publish_lifecycle(request, protected_input)
        after = operations.verify_lifecycle(request)
        if _classify_observation(request, after) != "matching":
            raise AdapterError("publication-post-verification-not-matching")
        status = "verified-existing" if state == "matching" else "inserted"
        receipt_time = _now()
        _validate_bundle_authorization_at(bundle, receipt_time)
        receipt = _receipt(bundle, after, status, generated_at=receipt_time)
        _require_schema(receipt, RECEIPT_SCHEMA)
        return CommandOutcome(True, {preflight_path: preflight, receipt_path: receipt})
    except AdapterError as exc:
        audit_path = receipt_path.with_name(FAILURE_AUDIT_FILE)
        return CommandOutcome(
            False,
            {audit_path: _failure_audit(bundle, attempted=attempted, error_code=exc.code)},
        )
    except Exception:  # noqa: BLE001 - provider errors must become one redacted code.
        audit_path = receipt_path.with_name(FAILURE_AUDIT_FILE)
        return CommandOutcome(
            False,
            {
                audit_path: _failure_audit(
                    bundle,
                    attempted=attempted,
                    error_code="protected-provider-operation-failed",
                )
            },
        )


def _historical_publication_receipt(
    root: Path,
) -> tuple[Mapping[str, Any], dt.datetime]:
    """Load the attested receipt whose timestamp anchors the original approval use."""

    try:
        receipt_path = root.resolve(strict=True) / RECEIPT_FILE
    except OSError as exc:
        raise AdapterError("published-bundle-root-missing") from exc
    receipt, _receipt_bytes = _read_json(receipt_path)
    _require_schema(receipt, RECEIPT_SCHEMA)
    publication_time = _parse_timestamp(receipt.get("generatedAt"))
    if publication_time is None or publication_time > _now():
        raise AdapterError("publication-receipt-time-invalid")
    artifact_root = _artifact_root(root)
    authorization, _authorization_bytes = _read_json(
        artifact_root / AUTHORIZATION_FILE
    )
    _require_schema(authorization, AUTHORIZATION_SCHEMA)
    authorization_body = _authorization_body(authorization)
    issued = _parse_timestamp(authorization_body.get("generatedAt"))
    expiry = _parse_timestamp(authorization_body.get("expiresAt"))
    if (
        issued is None
        or expiry is None
        or publication_time < issued
        or publication_time >= expiry
    ):
        raise AdapterError("publication-receipt-outside-authorization-window")
    return receipt, publication_time


def _validate_historical_publication_receipt(
    receipt: Mapping[str, Any], bundle: LifecycleBundle
) -> None:
    """Bind an earlier successful publication receipt to the exact verified bundle."""

    bindings = {
        "descriptorEdition": bundle.descriptor.get("descriptorEdition"),
        "descriptorDigest": bundle.descriptor.get("descriptorDigest"),
        "descriptorBytesDigest": bundle.descriptor_byte_digest,
        "ledgerDigest": bundle.descriptor.get("ledgerDigest"),
        "previousDescriptorEdition": bundle.descriptor.get(
            "previousDescriptorEdition"
        ),
        "previousDescriptorDigest": bundle.descriptor.get("previousDescriptorDigest"),
        "updateKeyIdentityDigest": bundle.descriptor.get("updateKeyIdentityDigest"),
        "updateKeyScope": bundle.descriptor.get("updateKeyScope"),
        "updateKeyDocName": bundle.descriptor.get("updateKeyDocName"),
        "publicRequestUri": bundle.plan.get("publicRequestUri"),
        "publicationPlanDigest": bundle.plan_digest,
        "authorizationDigest": bundle.authorization_digest,
    }
    if (
        any(receipt.get(name) != value for name, value in bindings.items())
        or receipt.get("operation") not in {"inserted", "verified-existing"}
        or receipt.get("publicationState") != "publication-complete"
        or receipt.get("verificationStatus") != "verified"
        or receipt.get("conflict") is not False
        or receipt.get("redaction") != _PASS_REDACTION
    ):
        raise AdapterError("historical-publication-receipt-mismatch")


def verify_exact(
    root: Path, operations: ExternalOperations, receipt_path: Path
) -> CommandOutcome:
    """Read-only re-fetch of exact descriptor state and receipt verification."""

    historical_receipt, publication_time = _historical_publication_receipt(root)
    bundle = load_bundle(
        root,
        require_authorization=True,
        authorization_valid_at=publication_time,
        allow_root_publication_receipt=True,
    )
    _validate_historical_publication_receipt(historical_receipt, bundle)
    request = PublicationRequest(bundle)
    observation = operations.verify_lifecycle(request)
    if _classify_observation(request, observation) != "matching":
        raise AdapterError("verified-public-state-is-not-exact")
    receipt = _receipt(bundle, observation, "verified-existing")
    _require_schema(receipt, RECEIPT_SCHEMA)
    return CommandOutcome(True, {receipt_path: receipt})


def observe_authorized_state_exact(
    root: Path, operations: ExternalOperations, receipt_path: Path
) -> CommandOutcome:
    """Re-fetch the exact attested lifecycle authority tip without publication authority."""

    chain = load_authority_chain(root)
    request = PublicationRequest(chain)
    observation = operations.verify_lifecycle(request)
    if _classify_observation(request, observation) != "matching":
        raise AdapterError("observed-public-lifecycle-tip-is-not-authorized-state")
    receipt = _receipt(chain, observation, "verified-existing")
    _require_schema(receipt, RECEIPT_SCHEMA)
    return CommandOutcome(True, {receipt_path: receipt})


def _path_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _stdlib_roots() -> tuple[Path, ...]:
    roots: list[Path] = []
    for name in ("stdlib", "platstdlib"):
        value = sysconfig.get_paths().get(name)
        if value:
            resolved = Path(value).resolve()
            if resolved not in roots:
                roots.append(resolved)
    return tuple(roots)


_STDLIB_ROOTS = _stdlib_roots()


def _path_is_stdlib(path: Path) -> bool:
    return any(
        _path_within(path, root)
        and not {"site-packages", "dist-packages"}.intersection(
            path.resolve().relative_to(root).parts
        )
        for root in _STDLIB_ROOTS
    )


def _module_origin(module: ModuleType | None) -> Path | None:
    if module is None:
        return None
    value = getattr(module, "__file__", None)
    if not isinstance(value, str):
        return None
    try:
        return Path(value).resolve(strict=True)
    except OSError:
        return None


@contextlib.contextmanager
def _backend_scope(site: Path) -> Iterator[None]:
    original_path = list(sys.path)
    trusted = [str(site)]
    trusted.extend(
        raw
        for raw in original_path
        if raw and _path_is_stdlib(Path(raw).resolve()) and raw not in trusted
    )
    sys.path[:] = trusted
    importlib.invalidate_caches()
    try:
        yield
    finally:
        sys.path[:] = original_path
        importlib.invalidate_caches()


class _AuthenticatedBackend:
    def __init__(self, backend: ExternalOperations, site: Path) -> None:
        self._backend = backend
        self._site = site

    def __getattr__(self, name: str) -> Callable[..., Any]:
        if name not in {
            "observe_lifecycle",
            "observe_lifecycle_genesis",
            "observe_latest_maintenance_tip",
            "publish_lifecycle",
            "verify_lifecycle",
        }:
            raise AttributeError(name)

        def invoke(*args: Any, **kwargs: Any) -> Any:
            with _backend_scope(self._site):
                module = inspect.getmodule(type(self._backend))
                origin = _module_origin(module)
                if origin is None or not _path_within(origin, self._site):
                    raise AdapterError("lifecycle-backend-origin-invalid")
                operation = getattr(self._backend, name, None)
                if not callable(operation):
                    raise AdapterError("lifecycle-backend-contract-invalid")
                return operation(*args, **kwargs)

        return invoke


def _load_backend(environment: Mapping[str, str]) -> ExternalOperations:
    if INSERT_INPUT_ENV in environment or INSERT_INPUT_ENV in os.environ:
        raise AdapterError("protected-input-environment-not-scrubbed")
    factory_name = environment.get(BACKEND_FACTORY_ENV, "")
    site_value = environment.get(BACKEND_SITE_ENV, "")
    if _FACTORY_RE.fullmatch(factory_name) is None or not site_value:
        raise AdapterError("lifecycle-backend-not-materialized")
    try:
        site = Path(site_value).resolve(strict=True)
    except OSError as exc:
        raise AdapterError("lifecycle-backend-site-invalid") from exc
    if not site.is_dir() or _path_within(site, _REPOSITORY_ROOT):
        raise AdapterError("lifecycle-backend-site-invalid")
    module_name, attribute = factory_name.split(":", 1)
    sys.modules.pop(module_name, None)
    try:
        with _backend_scope(site):
            module = importlib.import_module(module_name)
            origin = _module_origin(module)
            if origin is None or not _path_within(origin, site):
                raise AdapterError("lifecycle-backend-origin-invalid")
            factory = getattr(module, attribute, None)
            if not callable(factory):
                raise AdapterError("lifecycle-backend-contract-invalid")
            backend = factory()
            backend_origin = _module_origin(inspect.getmodule(type(backend)))
            if backend_origin is None or not _path_within(backend_origin, site):
                raise AdapterError("lifecycle-backend-origin-invalid")
            for name in (
                "observe_lifecycle",
                "observe_lifecycle_genesis",
                "observe_latest_maintenance_tip",
                "publish_lifecycle",
                "verify_lifecycle",
            ):
                if not callable(getattr(backend, name, None)):
                    raise AdapterError("lifecycle-backend-contract-invalid")
    except AdapterError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise AdapterError("lifecycle-backend-load-failed") from exc
    return _AuthenticatedBackend(backend, site)


def _write(path: Path, value: Mapping[str, Any], secret: str | None = None) -> None:
    _scan_public(value, secret=secret)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            raise AdapterError("output-path-is-symlink")
        path.write_bytes(_canonical_bytes(value))
    except OSError as exc:
        raise AdapterError("output-write-failed") from exc


def _assert_context(mode: str, environment: Mapping[str, str]) -> None:
    event = environment.get("GITHUB_EVENT_NAME", "")
    if mode == "publish":
        if (
            environment.get("GITHUB_ACTIONS") != "true"
            or event != "workflow_dispatch"
            or environment.get("CRYPTAD_STABLE_LIFECYCLE_PROTECTED_ENVIRONMENT") != "true"
            or environment.get("GITHUB_WORKFLOW", "")
            != "Stable 1.0 Support Lifecycle"
        ):
            raise AdapterError("publish-requires-protected-workflow-dispatch")
    elif mode == "prove-genesis":
        if (
            environment.get("GITHUB_ACTIONS") != "true"
            or event != "workflow_dispatch"
            or environment.get("CRYPTAD_STABLE_LIFECYCLE_PROOF_ENVIRONMENT") != "true"
            or environment.get("GITHUB_WORKFLOW", "")
            != "Stable 1.0 Support Lifecycle"
        ):
            raise AdapterError("genesis-proof-requires-protected-workflow-dispatch")
    elif mode == "observe-authorized-state":
        if (
            environment.get("GITHUB_ACTIONS") != "true"
            or event != "workflow_dispatch"
            or environment.get("CRYPTAD_STABLE_LIFECYCLE_OBSERVATION_ENVIRONMENT")
            != "true"
            or environment.get("GITHUB_WORKFLOW", "")
            != "Stable 1.0 Maintenance Release"
        ):
            raise AdapterError(
                "lifecycle-observation-requires-protected-maintenance-workflow"
            )
    elif event == "pull_request" and mode not in SIDE_EFFECT_FREE_MODES:
        raise AdapterError("pull-request-publication-forbidden")


def _load_secret(name: str | None, environment: dict[str, str]) -> SecretMaterial:
    if name != INSERT_INPUT_ENV:
        raise AdapterError("lifecycle-insert-input-name-invalid")
    value = environment.pop(name, "")
    os.environ.pop(name, None)
    if not value or len(value) > 16 * 1024:
        raise AdapterError("lifecycle-insert-input-missing")
    return SecretMaterial(INSERT_PURPOSE, value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--mode", required=True, choices=MODES)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--authority-chain", type=Path)
    parser.add_argument("--genesis-request", type=Path)
    parser.add_argument("--reauthenticated-bundle", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--preflight", type=Path)
    parser.add_argument("--insert-input-env")
    parser.add_argument("--no-side-effects", action="store_true")
    parser.add_argument("--idempotency", choices=("exact-match-only",))
    parser.add_argument("--conflict-action", choices=("fail",))
    parser.add_argument("--forbid-overwrite", action="store_true")
    parser.add_argument("--verify-after-publication", action="store_true")
    return parser


def _validate_args(arguments: argparse.Namespace) -> None:
    if arguments.mode == "prove-genesis":
        if (
            arguments.genesis_request is None
            or arguments.bundle is not None
            or arguments.authority_chain is not None
            or not arguments.no_side_effects
            or arguments.insert_input_env is not None
            or arguments.reauthenticated_bundle is not None
            or arguments.receipt is not None
            or arguments.preflight is not None
            or arguments.idempotency is not None
            or arguments.conflict_action is not None
            or arguments.forbid_overwrite
            or arguments.verify_after_publication
        ):
            raise AdapterError("genesis-proof-command-contract-invalid")
    elif arguments.mode in LOCAL_MODES:
        if (
            arguments.bundle is None
            or arguments.authority_chain is not None
            or arguments.genesis_request is not None
            or not arguments.no_side_effects
            or arguments.insert_input_env is not None
            or arguments.reauthenticated_bundle is not None
        ):
            raise AdapterError("side-effect-free-command-contract-invalid")
        if any(
            value is not None
            for value in (
                arguments.receipt,
                arguments.preflight,
                arguments.idempotency,
                arguments.conflict_action,
            )
        ) or arguments.forbid_overwrite or arguments.verify_after_publication:
            raise AdapterError("side-effect-free-command-contract-invalid")
    elif arguments.mode in {"observe-authorized-state", "verify-publication"}:
        if (
            (arguments.mode == "verify-publication" and arguments.bundle is None)
            or (
                arguments.mode == "observe-authorized-state"
                and arguments.authority_chain is None
            )
            or (
                arguments.mode == "verify-publication"
                and arguments.authority_chain is not None
            )
            or (
                arguments.mode == "observe-authorized-state"
                and arguments.bundle is not None
            )
            or arguments.genesis_request is not None
            or arguments.receipt is None
            or not arguments.no_side_effects
            or arguments.insert_input_env is not None
            or arguments.reauthenticated_bundle is not None
            or arguments.preflight is not None
            or arguments.idempotency is not None
            or arguments.conflict_action is not None
            or arguments.forbid_overwrite
            or arguments.verify_after_publication
        ):
            raise AdapterError("verification-command-contract-invalid")
    else:
        if (
            arguments.bundle is None
            or arguments.authority_chain is not None
            or arguments.genesis_request is not None
            or arguments.receipt is None
        ):
            raise AdapterError("publication-command-contract-incomplete")
        if arguments.mode == "publish":
            if (
                arguments.preflight is None
                or arguments.reauthenticated_bundle is None
                or arguments.insert_input_env != INSERT_INPUT_ENV
                or arguments.idempotency != "exact-match-only"
                or arguments.conflict_action != "fail"
                or not arguments.forbid_overwrite
                or not arguments.verify_after_publication
                or arguments.no_side_effects
            ):
                raise AdapterError("publication-command-contract-incomplete")


def main(
    argv: Sequence[str] | None = None,
    *,
    operations: ExternalOperations | None = None,
    environ: Mapping[str, str] | None = None,
) -> int:
    """Execute one closed workflow-aligned lifecycle adapter operation."""

    environment = dict(os.environ if environ is None else environ)
    secret: SecretMaterial | None = None
    try:
        arguments = _parser().parse_args(argv)
        _assert_context(arguments.mode, environment)
        _validate_args(arguments)
        if arguments.mode in LOCAL_MODES:
            assert arguments.bundle is not None
            outcome = evaluate_only(
                arguments.bundle,
                arguments.out,
                require_authorization=arguments.mode == "validate-authorization",
            )
        else:
            if arguments.mode == "publish":
                secret = _load_secret(arguments.insert_input_env, environment)
            else:
                environment.pop(INSERT_INPUT_ENV, None)
                os.environ.pop(INSERT_INPUT_ENV, None)
            backend = operations or _load_backend(environment)
            if arguments.mode == "prove-genesis":
                assert arguments.genesis_request is not None
                outcome = prove_genesis(
                    arguments.genesis_request, backend, arguments.out
                )
            elif arguments.mode == "publish":
                assert secret is not None
                assert arguments.bundle is not None
                outcome = publish_exact(
                    arguments.bundle,
                    arguments.reauthenticated_bundle,
                    backend,
                    secret,
                    arguments.receipt,
                    arguments.preflight,
                )
            elif arguments.mode == "verify-publication":
                assert arguments.bundle is not None
                outcome = verify_exact(arguments.bundle, backend, arguments.receipt)
            else:
                assert arguments.authority_chain is not None
                outcome = observe_authorized_state_exact(
                    arguments.authority_chain, backend, arguments.receipt
                )
        for path, value in outcome.artifacts.items():
            _write(path, value, secret.value if secret else None)
        if arguments.out not in outcome.artifacts:
            receipt = outcome.artifacts.get(arguments.receipt)
            inserted = (
                isinstance(receipt, Mapping) and receipt.get("operation") == "inserted"
            )
            side_effects_may_have_occurred = any(
                isinstance(value, Mapping)
                and value.get("kind")
                == "stable-1.0-support-lifecycle-publication-failure-audit"
                and value.get("sideEffectsMayHaveOccurred") is True
                for value in outcome.artifacts.values()
            )
            summary = {
                "schemaVersion": 1,
                "kind": "stable-1.0-support-lifecycle-protected-operation",
                "generatedAt": _timestamp(_now()),
                "mode": arguments.mode,
                "status": "pass" if outcome.passed else "fail",
                "sideEffectsPerformed": inserted,
                "sideEffectsMayHaveOccurred": side_effects_may_have_occurred,
                "redaction": dict(_PASS_REDACTION),
            }
            _write(arguments.out, summary, secret.value if secret else None)
        return 0 if outcome.passed else 1
    except AdapterError as exc:
        print(f"stable lifecycle publication adapter failed closed: {exc.code}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
