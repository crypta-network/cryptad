"""Lifecycle-only provider for the protected Stable 1.0 support descriptor.

The public request URI is a mutable, authenticated projection of lifecycle state.  Observation
accepts only the exact authorized descriptor or its exact declared predecessor.  Publication uses
one purpose-bound protected deployment capability and then relies on a fresh public read for the
adapter's independent exact-byte verification.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
from typing import Any, Mapping

from .provider import ProviderError, StdlibTransport, _canonical_bytes, _strict_json


@dataclasses.dataclass(frozen=True)
class LifecycleObservation:
    """Closed public state returned to the protected lifecycle adapter."""

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
    """Closed public maintenance-tip observation returned before lifecycle mutation."""

    status: str
    public_uri: str | None
    pointer_digest: str | None
    release_id: str
    build_version: str
    baseline_digest: str
    publication_receipt_digest: str


@dataclasses.dataclass(frozen=True)
class GenesisObservation:
    """Closed first-publication observation; a tombstone is not absence."""

    status: str
    transport_status: int
    public_request_uri: str
    update_key_identity_digest: str
    update_key_scope: str
    update_key_doc_name: str


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _semantic_digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return _digest(encoded)


def _valid_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 71
        and all(character in "0123456789abcdef" for character in value[7:])
    )


class StableLifecycleBackend:
    """Exact-byte lifecycle provider with no release, tag, catalog, or key-blow methods."""

    def __init__(self, transport: Any | None = None) -> None:
        self._transport = transport or StdlibTransport()

    @staticmethod
    def _observation(
        request: Any,
        status: str,
        *,
        descriptor: Mapping[str, Any] | None = None,
        byte_digest: str | None = None,
    ) -> LifecycleObservation:
        plan = request.bundle.plan
        target = request.bundle.descriptor
        return LifecycleObservation(
            status=status,
            public_request_uri=str(plan["publicRequestUri"]),
            update_key_identity_digest=str(target["updateKeyIdentityDigest"]),
            update_key_scope=str(target["updateKeyScope"]),
            update_key_doc_name=str(target["updateKeyDocName"]),
            descriptor_edition=(
                descriptor.get("descriptorEdition") if descriptor is not None else None
            ),
            descriptor_digest=(
                descriptor.get("descriptorDigest") if descriptor is not None else None
            ),
            descriptor_byte_digest=byte_digest,
            previous_descriptor_edition=(
                descriptor.get("previousDescriptorEdition")
                if descriptor is not None
                else None
            ),
            previous_descriptor_digest=(
                descriptor.get("previousDescriptorDigest")
                if descriptor is not None
                else None
            ),
        )

    @staticmethod
    def _valid_descriptor(value: Mapping[str, Any], target: Mapping[str, Any]) -> bool:
        expected_digest = _semantic_digest(
            {key: item for key, item in value.items() if key != "descriptorDigest"}
        )
        return (
            value.get("schemaVersion") == 1
            and value.get("kind") == "stable-1.0-support-lifecycle-descriptor"
            and value.get("stableMilestone") == "1.0"
            and value.get("descriptorDigest") == expected_digest
            and value.get("updateKeyIdentityDigest")
            == target.get("updateKeyIdentityDigest")
            and value.get("updateKeyScope") == target.get("updateKeyScope")
            and value.get("updateKeyDocName") == target.get("updateKeyDocName")
        )

    def observe_lifecycle(self, request: Any) -> LifecycleObservation:
        """Fetch the public mutable descriptor and classify exact target/predecessor state."""

        uri = str(request.bundle.plan["publicRequestUri"])
        status, _headers, body = self._transport.request(
            "GET", uri, headers={"Accept": "application/json"}
        )
        if status == 404:
            return self._observation(request, "absent")
        if status == 410:
            return self._observation(request, "conflict")
        if status != 200:
            return self._observation(request, "unavailable")
        try:
            value = _strict_json(body, canonical=True)
        except ProviderError:
            return self._observation(request, "conflict")
        target = request.bundle.descriptor
        if not self._valid_descriptor(value, target):
            return self._observation(request, "conflict")
        byte_digest = _digest(body)
        if body == request.bundle.descriptor_bytes:
            return self._observation(
                request, "matching", descriptor=value, byte_digest=byte_digest
            )
        if (
            value.get("descriptorEdition") == target.get("previousDescriptorEdition")
            and value.get("descriptorDigest") == target.get("previousDescriptorDigest")
        ):
            return self._observation(
                request, "absent", descriptor=value, byte_digest=byte_digest
            )
        return self._observation(
            request, "conflict", descriptor=value, byte_digest=byte_digest
        )

    def observe_lifecycle_genesis(
        self, request: Mapping[str, Any]
    ) -> GenesisObservation:
        """Distinguish a never-published 404 from a deleted/tombstoned 410 target."""

        uri = str(request["publicRequestUri"])
        status, _headers, _body = self._transport.request(
            "GET", uri, headers={"Accept": "application/json"}
        )
        state = (
            "absent"
            if status == 404
            else "tombstoned"
            if status == 410
            else "occupied"
            if status == 200
            else "unavailable"
        )
        return GenesisObservation(
            state,
            status,
            uri,
            str(request["updateKeyIdentityDigest"]),
            str(request["updateKeyScope"]),
            str(request["updateKeyDocName"]),
        )

    def observe_latest_maintenance_tip(
        self, request: Any
    ) -> MaintenanceTipObservation:
        """Re-fetch the authorization-bound public maintenance pointer immediately."""

        plan = request.bundle.plan
        inventory = request.bundle.inventory
        entries = inventory.get("entries")
        if not isinstance(entries, list) or not entries or not isinstance(entries[-1], dict):
            raise ProviderError("lifecycle-inventory-tip-invalid")
        tip = entries[-1]
        uri = plan.get("latestMaintenancePointerPublicUri")
        expected_digest = plan.get("latestMaintenancePointerDigest")
        chain_depth = inventory.get("chainDepth")
        if not isinstance(uri, str) or (
            chain_depth == 0 and expected_digest is not None
        ) or (
            chain_depth != 0 and not isinstance(expected_digest, str)
        ):
            raise ProviderError("maintenance-pointer-target-missing")
        status, _headers, body = self._transport.request(
            "GET", uri, headers={"Accept": "application/json"}
        )
        if status == 404 and chain_depth == 0:
            return MaintenanceTipObservation(
                "absent",
                uri,
                None,
                str(tip.get("releaseId")),
                str(tip.get("buildVersion")),
                str(tip.get("baselineDigest")),
                str(tip.get("publicationReceiptDigest")),
            )
        if status == 410:
            return MaintenanceTipObservation(
                "conflict",
                uri,
                None,
                "",
                "",
                "",
                "",
            )
        if status != 200:
            return MaintenanceTipObservation(
                "unavailable",
                uri,
                None,
                "",
                "",
                "",
                "",
            )
        try:
            value = _strict_json(body, canonical=True)
        except ProviderError:
            return MaintenanceTipObservation(
                "conflict", uri, _digest(body), "", "", "", ""
            )
        legacy_fields = {
            "schemaVersion",
            "kind",
            "generatedAt",
            "releaseId",
            "buildVersion",
            "releaseClass",
            "baselineDigest",
            "baselineIdentityDigest",
            "publicationReceiptDigest",
            "publicationReceiptIdentityDigest",
            "lineageDigest",
            "historyDigest",
            "compareAndSwapPredecessorBaselineDigest",
            "status",
            "redaction",
        }
        train_aware_fields = legacy_fields | {"backportReleaseTrainDigest"}
        pointer_fields = set(value)
        fields_match = pointer_fields in (legacy_fields, train_aware_fields)
        train_digest_matches = (
            pointer_fields == legacy_fields
            or _valid_digest(value.get("backportReleaseTrainDigest"))
        )
        pointer_digest = _digest(body)
        matching = (
            fields_match
            and train_digest_matches
            and value.get("schemaVersion") == 1
            and value.get("kind") == "stable-1.0-maintenance-latest-published"
            and value.get("status") == "active"
            and value.get("redaction")
            == {"status": "pass", "findingCount": 0, "findings": []}
            and pointer_digest == expected_digest
            and value.get("releaseId") == tip.get("releaseId")
            and value.get("buildVersion") == tip.get("buildVersion")
            and value.get("baselineDigest") == tip.get("baselineDigest")
            and value.get("publicationReceiptDigest")
            == tip.get("publicationReceiptDigest")
        )
        return MaintenanceTipObservation(
            "matching" if matching else "conflict",
            uri,
            pointer_digest,
            str(value.get("releaseId", "")),
            str(value.get("buildVersion", "")),
            str(value.get("baselineDigest", "")),
            str(value.get("publicationReceiptDigest", "")),
        )

    def publish_lifecycle(self, request: Any, protected_input: Any) -> None:
        """Ask the protected deployment service to compare-and-swap exact bytes once."""

        if protected_input.purpose != "stable-support-lifecycle":
            raise ProviderError("lifecycle-capability-purpose-mismatch")
        descriptor = request.bundle.descriptor
        subject = {
            "schemaVersion": 1,
            "kind": "cryptad-stable-support-lifecycle-publication-request",
            "operation": "publish-support-lifecycle",
            "publicRequestUri": request.bundle.plan["publicRequestUri"],
            "descriptorEdition": descriptor["descriptorEdition"],
            "descriptorDigest": descriptor["descriptorDigest"],
            "descriptorBytesDigest": request.bundle.descriptor_byte_digest,
            "descriptorBytes": base64.b64encode(request.bundle.descriptor_bytes).decode(
                "ascii"
            ),
            "previousDescriptorEdition": descriptor["previousDescriptorEdition"],
            "previousDescriptorDigest": descriptor["previousDescriptorDigest"],
            "updateKeyIdentityDigest": descriptor["updateKeyIdentityDigest"],
            "updateKeyScope": descriptor["updateKeyScope"],
            "updateKeyDocName": descriptor["updateKeyDocName"],
            "authorizationDigest": request.bundle.authorization_digest,
            "publicationPlanDigest": request.bundle.plan_digest,
        }
        status, _headers, body = self._transport.request(
            "POST",
            protected_input.value,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            body=_canonical_bytes(subject),
        )
        if status != 200:
            raise ProviderError("lifecycle-publication-service-rejected")
        response = _strict_json(body, canonical=True)
        if (
            set(response)
            != {
                "schemaVersion",
                "kind",
                "status",
                "descriptorEdition",
                "descriptorDigest",
                "descriptorBytesDigest",
                "publicRequestUri",
            }
            or response.get("schemaVersion") != 1
            or response.get("kind")
            != "cryptad-stable-support-lifecycle-publication-result"
            or response.get("status") not in {"inserted", "matching"}
            or response.get("descriptorEdition") != descriptor["descriptorEdition"]
            or response.get("descriptorDigest") != descriptor["descriptorDigest"]
            or response.get("descriptorBytesDigest")
            != request.bundle.descriptor_byte_digest
            or response.get("publicRequestUri")
            != request.bundle.plan["publicRequestUri"]
        ):
            raise ProviderError("lifecycle-publication-result-invalid")

    def verify_lifecycle(self, request: Any) -> LifecycleObservation:
        """Re-fetch the public mutable descriptor without protected material."""

        return self.observe_lifecycle(request)


def lifecycle_factory() -> StableLifecycleBackend:
    """Create the lifecycle-only provider; no token or insert material is read here."""

    return StableLifecycleBackend()
