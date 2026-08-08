"""Standard-library protected publication provider for Stable maintenance releases.

GitHub tag, Release, and asset operations are performed directly. Catalog, CoreUpdater, and
latest-pointer infrastructure use the versioned deployment-service protocol documented beside the
release-certification tooling. Target capability URLs are accepted only through the adapter's
purpose-bound ``SecretMaterial`` argument and are never retained or rendered.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import http.client
import ipaddress
import json
import mimetypes
import os
from pathlib import Path
import socket
import ssl
from typing import Any, Mapping
from urllib.parse import quote, urlencode, urlsplit


REPOSITORY = "crypta-network/cryptad"
API_ROOT = "https://api.github.com"
UPLOAD_ROOT = "https://uploads.github.com"
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
TARGETS = (
    "artifactBase",
    "tag",
    "githubRelease",
    "assets",
    "stableCatalog",
    "coreUpdate",
)
STATUSES = frozenset({"absent", "matching", "conflict", "unavailable"})


class ProviderError(RuntimeError):
    """One public-safe fail-closed provider failure."""


@dataclasses.dataclass(frozen=True)
class Snapshot:
    predecessor_pointer_digest: str | None
    targets: Mapping[str, str]
    latest_candidate_identity_digest: str | None = None


@dataclasses.dataclass(frozen=True)
class PointerSnapshot:
    status: str
    pointer_digest: str | None
    active_baseline_digest: str | None
    candidate_identity_digest: str | None = None


@dataclasses.dataclass(frozen=True)
class VerificationMaterial:
    maintenance_receipt: Mapping[str, Any]
    core_update_receipt: Mapping[str, Any]
    successor_baseline: Mapping[str, Any]
    history_entry: Mapping[str, Any]


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _strict_json(data: bytes, *, canonical: bool) -> dict[str, Any]:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ProviderError("deployment-response-duplicate-field")
            result[key] = value
        return result

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderError("deployment-response-malformed") from exc
    if not isinstance(value, dict):
        raise ProviderError("deployment-response-not-object")
    if canonical and data != _canonical_bytes(value):
        raise ProviderError("deployment-response-not-canonical")
    return value


def _canonical_https_uri(value: Any) -> str:
    if not isinstance(value, str) or value != value.strip() or "\\" in value:
        raise ProviderError("public-uri-invalid")
    parsed = urlsplit(value)
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise ProviderError("public-uri-invalid") from exc
    path_parts = parsed.path.split("/")[1:]
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port != 443
        or any(part in {".", ".."} for part in path_parts)
        or any(not part for part in path_parts[:-1])
    ):
        raise ProviderError("public-uri-invalid")
    host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    authority = host if ":" not in host else f"[{host}]"
    canonical = f"https://{authority}{parsed.path}"
    if parsed.query:
        canonical += "?" + parsed.query
    if canonical != value:
        raise ProviderError("public-uri-not-canonical")
    return canonical


def _global_addresses(host: str, port: int) -> tuple[str, ...]:
    try:
        rows = socket.getaddrinfo(
            host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
    except OSError as exc:
        raise ProviderError("public-host-resolution-failed") from exc
    addresses: list[str] = []
    for row in rows:
        address = str(ipaddress.ip_address(row[4][0]))
        if not ipaddress.ip_address(address).is_global:
            raise ProviderError("public-host-resolution-not-global")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ProviderError("public-host-resolution-empty")
    return tuple(addresses)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname: str, address: str, port: int, timeout: float) -> None:
        super().__init__(hostname, port=port, timeout=timeout, context=ssl.create_default_context())
        self._address = address

    def connect(self) -> None:
        raw = socket.create_connection((self._address, self.port), self.timeout)
        try:
            peer = ipaddress.ip_address(raw.getpeername()[0])
            if str(peer) != str(ipaddress.ip_address(self._address)) or not peer.is_global:
                raise OSError("connected peer differs from pinned public address")
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class StdlibTransport:
    """HTTPS transport with global-address pinning, TLS hostname checks, and no redirects."""

    def request(
        self,
        method: str,
        uri: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> tuple[int, Mapping[str, str], bytes]:
        canonical = _canonical_https_uri(uri)
        parsed = urlsplit(canonical)
        host = str(parsed.hostname)
        port = parsed.port or 443
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        failures: list[BaseException] = []
        for address in _global_addresses(host, port):
            connection = _PinnedHTTPSConnection(host, address, port, 30.0)
            try:
                connection.request(method, path, body=body, headers=dict(headers or {}))
                response = connection.getresponse()
                if 300 <= response.status < 400:
                    raise ProviderError("http-redirect-forbidden")
                length = response.getheader("Content-Length")
                if length is not None and int(length) > MAX_RESPONSE_BYTES:
                    raise ProviderError("http-response-too-large")
                data = response.read(MAX_RESPONSE_BYTES + 1)
                if len(data) > MAX_RESPONSE_BYTES:
                    raise ProviderError("http-response-too-large")
                return (
                    response.status,
                    {key.lower(): value for key, value in response.getheaders()},
                    data,
                )
            except ProviderError:
                raise
            except (OSError, http.client.HTTPException, ValueError) as exc:
                failures.append(exc)
            finally:
                connection.close()
        raise ProviderError("https-request-unavailable") from (
            failures[-1] if failures else None
        )

    def digest(
        self,
        uri: str,
        expected_size: int,
        *,
        headers: Mapping[str, str] | None = None,
        redirect_budget: int = 1,
    ) -> tuple[int, int, str | None]:
        """Stream one exact public object without materializing release-sized bytes."""

        if not isinstance(expected_size, int) or expected_size < 1:
            raise ProviderError("download-expected-size-invalid")
        canonical = _canonical_https_uri(uri)
        parsed = urlsplit(canonical)
        host = str(parsed.hostname)
        port = parsed.port or 443
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        failures: list[BaseException] = []
        for address in _global_addresses(host, port):
            connection = _PinnedHTTPSConnection(host, address, port, 30.0)
            try:
                connection.request("GET", path, headers=dict(headers or {}))
                response = connection.getresponse()
                if 300 <= response.status < 400:
                    if redirect_budget != 1:
                        raise ProviderError("download-redirect-forbidden")
                    location = response.getheader("Location")
                    if not isinstance(location, str):
                        raise ProviderError("download-redirect-invalid")
                    redirected = _canonical_https_uri(location)
                    safe_headers = {
                        key: value
                        for key, value in dict(headers or {}).items()
                        if key.lower() != "authorization"
                    }
                    return self.digest(
                        redirected,
                        expected_size,
                        headers=safe_headers,
                        redirect_budget=0,
                    )
                if response.status != 200:
                    response.read(min(MAX_RESPONSE_BYTES, 64 * 1024))
                    return response.status, 0, None
                length = response.getheader("Content-Length")
                if length is not None and int(length) != expected_size:
                    return response.status, int(length), None
                digest = hashlib.sha256()
                size = 0
                while True:
                    chunk = response.read(min(1024 * 1024, expected_size + 1 - size))
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > expected_size:
                        return response.status, size, None
                    digest.update(chunk)
                return response.status, size, "sha256:" + digest.hexdigest()
            except ProviderError:
                raise
            except (OSError, http.client.HTTPException, ValueError) as exc:
                failures.append(exc)
            finally:
                connection.close()
        raise ProviderError("https-download-unavailable") from (
            failures[-1] if failures else None
        )


class StableMaintenanceBackend:
    """Concrete exact-byte provider used only by the protected publication adapter."""

    def __init__(self, token: str, transport: Any | None = None) -> None:
        if len(token) < 12 or "\r" in token or "\n" in token:
            raise ProviderError("github-token-not-materialized")
        self._token = token
        self._transport = transport or StdlibTransport()

    def _github(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        content_type: str = "application/json",
    ) -> tuple[int, Mapping[str, str], bytes]:
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + self._token,
            "Content-Type": content_type,
            "User-Agent": "cryptad-stable-maintenance-backend/1",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        return self._transport.request(method, API_ROOT + path, headers=headers, body=body)

    def _github_json(
        self, method: str, path: str, value: Any | None = None
    ) -> tuple[int, dict[str, Any]]:
        body = _canonical_bytes(value) if value is not None else None
        status, _headers, data = self._github(method, path, body=body)
        if status == 404:
            return status, {}
        if status < 200 or status >= 300:
            raise ProviderError("github-api-operation-failed")
        return status, _strict_json(data, canonical=False)

    @staticmethod
    def _tag_message(request: Any) -> str:
        return (
            f"Cryptad Stable 1.0 {request.release_class} build "
            f"{request.build_version}"
        )

    @staticmethod
    def _release_title(request: Any) -> str:
        return f"Cryptad {request.bundle.plan['expectedTag']}"

    def _tag_status(self, request: Any) -> str:
        encoded = quote(str(request.bundle.plan["expectedTag"]), safe="")
        status, reference = self._github_json(
            "GET", f"/repos/{REPOSITORY}/git/ref/tags/{encoded}"
        )
        if status == 404:
            return "absent"
        obj = reference.get("object")
        if not isinstance(obj, Mapping) or obj.get("type") != "tag":
            return "conflict"
        _status, tag = self._github_json(
            "GET", f"/repos/{REPOSITORY}/git/tags/{obj.get('sha')}"
        )
        target = tag.get("object")
        return (
            "matching"
            if tag.get("tag") == request.bundle.plan.get("expectedTag")
            and tag.get("message") == self._tag_message(request)
            and isinstance(target, Mapping)
            and target.get("type") == "commit"
            and target.get("sha") == request.bundle.plan.get("sourceCommit")
            else "conflict"
        )

    def _release(self, request: Any) -> tuple[str, dict[str, Any]]:
        encoded = quote(str(request.bundle.plan["expectedTag"]), safe="")
        status, release = self._github_json(
            "GET", f"/repos/{REPOSITORY}/releases/tags/{encoded}"
        )
        if status == 404:
            return "absent", {}
        notes = (request.bundle.legacy / "stable-1.0-maintenance-release-notes.md").read_text(
            encoding="utf-8"
        )
        expected_page = request.bundle.plan.get("githubReleasePageUri")
        matching = (
            release.get("tag_name") == request.bundle.plan.get("expectedTag")
            and release.get("target_commitish") == request.bundle.plan.get("sourceCommit")
            and release.get("name") == self._release_title(request)
            and release.get("html_url") == expected_page
            and release.get("body") == notes
            and release.get("draft") is False
            and release.get("prerelease") is False
        )
        return ("matching" if matching else "conflict"), release

    def _observed_assets(
        self, request: Any, release: Mapping[str, Any]
    ) -> tuple[str, frozenset[str]]:
        """Authenticate the exact uploaded subset while preserving target-level state."""

        if not release:
            return "absent", frozenset()
        rows = release.get("assets")
        if not isinstance(rows, list):
            return "conflict", frozenset()
        observed_names = [
            row.get("name") for row in rows if isinstance(row, Mapping)
        ]
        planned_rows = request.bundle.plan.get("assets", [])
        companion_rows = request.bundle.plan.get("supplyChainCompanionAssets", [])
        if not isinstance(planned_rows, list) or not isinstance(companion_rows, list):
            return "conflict", frozenset()
        planned_names = [
            row.get("fileName") for row in planned_rows if isinstance(row, Mapping)
        ]
        companion_names = [
            row.get("fileName") for row in companion_rows if isinstance(row, Mapping)
        ]
        expected_rows = planned_rows + companion_rows
        expected_names = planned_names + companion_names
        if (
            len(observed_names) != len(rows)
            or len(set(observed_names)) != len(observed_names)
            or len(planned_names) != len(planned_rows)
            or len(set(planned_names)) != len(planned_names)
            or len(companion_names) != len(companion_rows)
            or len(set(expected_names)) != len(expected_names)
        ):
            return "conflict", frozenset()
        observed = {row.get("name"): row for row in rows}
        planned = {row.get("fileName"): row for row in expected_rows}
        if not set(observed).issubset(planned):
            return "conflict", frozenset()
        for name, row in observed.items():
            expected = planned[name]
            asset_id = row.get("id")
            if (
                row.get("size") != expected.get("sizeBytes")
                or type(asset_id) is not int
                or asset_id < 1
            ):
                return "conflict", frozenset()
            status, size, digest = self._transport.digest(
                f"{API_ROOT}/repos/{REPOSITORY}/releases/assets/{asset_id}",
                int(expected["sizeBytes"]),
                headers={
                    "Accept": "application/octet-stream",
                    "Authorization": "Bearer " + self._token,
                    "User-Agent": "cryptad-stable-maintenance-backend/1",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            if (
                status != 200
                or size != expected.get("sizeBytes")
                or digest != expected.get("digest")
            ):
                return "conflict", frozenset()
        observed_set = frozenset(str(name) for name in observed)
        return (
            "matching" if set(planned_names).issubset(observed) else "absent",
            observed_set,
        )

    def _assets_status(self, request: Any, release: Mapping[str, Any]) -> str:
        status, _observed = self._observed_assets(request, release)
        return status

    def _artifact_status(self, request: Any) -> str:
        statuses: list[str] = []
        for row in request.bundle.plan.get("assets", []):
            status, size, digest = self._transport.digest(
                str(row.get("publicUri")),
                int(row.get("sizeBytes")),
                headers={"User-Agent": "cryptad-stable-maintenance-backend/1"},
            )
            if status == 404:
                statuses.append("absent")
            elif (
                status == 200
                and size == row.get("sizeBytes")
                and digest == row.get("digest")
            ):
                statuses.append("matching")
            else:
                statuses.append("conflict")
        if statuses and all(value == "absent" for value in statuses):
            return "absent"
        if statuses and all(value == "matching" for value in statuses):
            return "matching"
        return "conflict"

    @staticmethod
    def _service_subject(request: Any) -> dict[str, Any]:
        return {
            "releaseId": request.release_id,
            "buildVersion": request.build_version,
            "releaseClass": request.release_class,
            "candidateIdentityDigest": request.candidate_identity_digest,
            "publicationPlan": dict(request.bundle.plan),
            "coreInfo": dict(request.bundle.core_info),
            "lineage": dict(request.bundle.lineage),
        }

    @staticmethod
    def _record_binding(
        path: Path,
        record: Mapping[str, Any],
        *,
        expected_digest: Any = None,
    ) -> dict[str, Any]:
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise ProviderError("verification-input-unavailable") from exc
        if data != _canonical_bytes(record):
            raise ProviderError("verification-input-not-canonical")
        digest = _digest(data)
        if expected_digest is not None and expected_digest != digest:
            raise ProviderError("verification-input-digest-mismatch")
        return {"digest": digest, "record": dict(record)}

    @classmethod
    def _file_record_binding(
        cls,
        path: Path,
        *,
        expected_digest: Any = None,
    ) -> dict[str, Any]:
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise ProviderError("verification-input-unavailable") from exc
        record = _strict_json(data, canonical=True)
        digest = _digest(data)
        if expected_digest is not None and expected_digest != digest:
            raise ProviderError("verification-input-digest-mismatch")
        return {"digest": digest, "record": record}

    @classmethod
    def _verification_subject(cls, request: Any) -> dict[str, Any]:
        """Return the public-safe records needed to reproduce successor state exactly."""

        bundle = request.bundle
        provenance_path = bundle.legacy / "stable-1.0-maintenance-provenance.json"
        provenance = cls._file_record_binding(
            provenance_path,
            expected_digest=bundle.plan.get("provenanceDigest"),
        )
        provenance_record = provenance["record"]
        closure_expected_digest = bundle.lineage.get("predecessor", {}).get(
            "hotfixFollowUpClosureDigest"
        )
        if (bundle.follow_up_closure_path is None) != (
            bundle.follow_up_closure is None
        ):
            raise ProviderError("verification-input-incomplete")
        if bundle.follow_up_closure_path is None:
            if closure_expected_digest is not None:
                raise ProviderError("verification-input-unavailable")
            closure_binding = None
        else:
            closure_binding = cls._record_binding(
                bundle.follow_up_closure_path,
                bundle.follow_up_closure,
                expected_digest=closure_expected_digest,
            )
        if (bundle.follow_up_obligation_path is None) != (
            bundle.follow_up_obligation is None
        ):
            raise ProviderError("verification-input-incomplete")
        obligation_expected_digest = bundle.authorization.get(
            "hotfixFollowUpObligationDigest"
        )
        if bundle.follow_up_obligation_path is None:
            if obligation_expected_digest is not None:
                raise ProviderError("verification-input-unavailable")
            obligation_binding = None
        else:
            obligation_binding = cls._record_binding(
                bundle.follow_up_obligation_path,
                bundle.follow_up_obligation,
                expected_digest=obligation_expected_digest,
            )
        records: dict[str, Any] = {
            "publicationPlan": cls._record_binding(bundle.plan_path, bundle.plan),
            "candidate": cls._record_binding(bundle.candidate_path, bundle.candidate),
            "candidateInput": cls._record_binding(
                bundle.candidate_input_path,
                bundle.candidate_input,
                expected_digest=bundle.candidate.get("candidateInputDigest"),
            ),
            "lineage": cls._record_binding(
                bundle.lineage_path,
                bundle.lineage,
                expected_digest=provenance_record.get("lineageDigest"),
            ),
            "corePublicationPlan": cls._record_binding(
                bundle.core_plan_path,
                bundle.core_plan,
            ),
            "coreInfo": cls._record_binding(
                bundle.core_info_path,
                bundle.core_info,
                expected_digest=bundle.plan.get("coreInfoDigest"),
            ),
            "gaBaseline": cls._record_binding(
                bundle.ga_baseline_path,
                bundle.ga_baseline,
                expected_digest=bundle.lineage.get("gaRoot", {}).get(
                    "maintenanceBaselineDigest"
                ),
            ),
            "predecessorBaseline": cls._record_binding(
                bundle.predecessor_baseline_path,
                bundle.predecessor_baseline,
                expected_digest=provenance_record.get("predecessorBaselineDigest"),
            ),
            "evidence": cls._record_binding(
                bundle.evidence_path,
                bundle.evidence,
                expected_digest=provenance_record.get("evidenceDigest"),
            ),
            "provenance": provenance,
            "hotfixFollowUpObligation": obligation_binding,
            "hotfixFollowUpClosure": closure_binding,
        }
        subject = cls._service_subject(request)
        subject["verificationInputs"] = records
        return subject

    def _service(self, uri: str, operation: str, subject: Mapping[str, Any]) -> dict[str, Any]:
        request = {
            "schemaVersion": 1,
            "kind": "cryptad-stable-maintenance-deployment-request",
            "operation": operation,
            "subject": dict(subject),
        }
        status, _headers, data = self._transport.request(
            "POST",
            uri,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "cryptad-stable-maintenance-backend/1",
            },
            body=_canonical_bytes(request),
        )
        if status != 200:
            raise ProviderError("deployment-service-operation-failed")
        return _strict_json(data, canonical=True)

    def _deployment_observation(self, request: Any) -> dict[str, Any]:
        response = self._service(
            str(request.bundle.plan["deploymentServicePublicUri"]),
            "observe-publication",
            self._service_subject(request),
        )
        expected_keys = {
            "schemaVersion",
            "kind",
            "predecessorPointerDigest",
            "latestCandidateIdentityDigest",
            "targets",
        }
        targets = response.get("targets")
        if (
            set(response) != expected_keys
            or response.get("schemaVersion") != 1
            or response.get("kind")
            != "cryptad-stable-maintenance-deployment-observation"
            or not isinstance(targets, Mapping)
            or set(targets) != {"stableCatalog", "coreUpdate"}
            or any(value not in STATUSES for value in targets.values())
        ):
            raise ProviderError("deployment-observation-invalid")
        return response

    def observe_public_state(self, request: Any) -> Snapshot:
        tag = self._tag_status(request)
        release_status, release = self._release(request)
        assets = self._assets_status(request, release)
        artifact_base = self._artifact_status(request)
        deployment = self._deployment_observation(request)
        remote_targets = deployment["targets"]
        return Snapshot(
            deployment.get("predecessorPointerDigest"),
            {
                "artifactBase": artifact_base,
                "tag": tag,
                "githubRelease": release_status,
                "assets": assets,
                "stableCatalog": remote_targets["stableCatalog"],
                "coreUpdate": remote_targets["coreUpdate"],
            },
            deployment.get("latestCandidateIdentityDigest"),
        )

    def _create_tag(self, request: Any) -> None:
        _status, tag = self._github_json(
            "POST",
            f"/repos/{REPOSITORY}/git/tags",
            {
                "tag": request.bundle.plan["expectedTag"],
                "message": self._tag_message(request),
                "object": request.bundle.plan["sourceCommit"],
                "type": "commit",
            },
        )
        sha = tag.get("sha")
        if not isinstance(sha, str):
            raise ProviderError("github-tag-object-not-created")
        self._github_json(
            "POST",
            f"/repos/{REPOSITORY}/git/refs",
            {"ref": f"refs/tags/{request.bundle.plan['expectedTag']}", "sha": sha},
        )

    def _create_release(self, request: Any) -> None:
        notes = (request.bundle.legacy / "stable-1.0-maintenance-release-notes.md").read_text(
            encoding="utf-8"
        )
        self._github_json(
            "POST",
            f"/repos/{REPOSITORY}/releases",
            {
                "tag_name": request.bundle.plan["expectedTag"],
                "target_commitish": request.bundle.plan["sourceCommit"],
                "name": self._release_title(request),
                "body": notes,
                "draft": False,
                "prerelease": False,
            },
        )

    def _upload_assets(self, request: Any) -> None:
        status, release = self._release(request)
        if status != "matching" or not isinstance(release.get("id"), int):
            raise ProviderError("github-release-not-ready-for-assets")
        asset_status, observed_names = self._observed_assets(request, release)
        if asset_status == "conflict":
            raise ProviderError("github-release-assets-conflict")
        for row in request.bundle.plan.get("assets", []):
            name = str(row["fileName"])
            if name in observed_names:
                continue
            path = request.bundle.legacy / name
            data = path.read_bytes()
            if len(data) != row.get("sizeBytes") or _digest(data) != row.get("digest"):
                raise ProviderError("asset-byte-binding-changed")
            uri = (
                f"{UPLOAD_ROOT}/repos/{REPOSITORY}/releases/{release['id']}/assets?"
                + urlencode({"name": name})
            )
            status_code, _headers, _body = self._transport.request(
                "POST",
                uri,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": "Bearer " + self._token,
                    "Content-Type": mimetypes.guess_type(name)[0]
                    or "application/octet-stream",
                    "User-Agent": "cryptad-stable-maintenance-backend/1",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                body=data,
            )
            if status_code not in {200, 201}:
                raise ProviderError("github-asset-upload-failed")

    def _capability_mutation(
        self, target: str, request: Any, protected_input: Any
    ) -> None:
        expected_purpose = {
            "stableCatalog": "stable-catalog",
            "coreUpdate": "core-update",
        }[target]
        if protected_input is None or protected_input.purpose != expected_purpose:
            raise ProviderError("target-capability-purpose-mismatch")
        payload: dict[str, Any] = self._service_subject(request)
        if target == "stableCatalog":
            catalog = request.bundle.candidate_input["stableCatalog"]
            payload["catalogBytes"] = base64.b64encode(
                (request.bundle.legacy / catalog["fileName"]).read_bytes()
            ).decode("ascii")
            payload["signatureBytes"] = base64.b64encode(
                (request.bundle.legacy / catalog["signatureFileName"]).read_bytes()
            ).decode("ascii")
        else:
            payload["descriptorBytes"] = base64.b64encode(
                request.bundle.core_info_path.read_bytes()
            ).decode("ascii")
        response = self._service(
            protected_input.value,
            "publish-" + ("stable-catalog" if target == "stableCatalog" else "core-update"),
            payload,
        )
        if (
            set(response)
            != {"schemaVersion", "kind", "target", "candidateIdentityDigest", "status"}
            or response.get("schemaVersion") != 1
            or response.get("kind") != "cryptad-stable-maintenance-deployment-mutation"
            or response.get("target") != target
            or response.get("candidateIdentityDigest") != request.candidate_identity_digest
            or response.get("status") not in {"created", "matching"}
        ):
            raise ProviderError("deployment-mutation-result-invalid")

    def publish_target(self, target: str, request: Any, protected_input: Any) -> None:
        if target not in TARGETS:
            raise ProviderError("unknown-publication-target")
        if target in {"tag", "githubRelease", "assets", "artifactBase"} and protected_input is not None:
            raise ProviderError("untargeted-protected-input")
        if target == "tag":
            self._create_tag(request)
        elif target == "githubRelease":
            self._create_release(request)
        elif target == "assets":
            self._upload_assets(request)
        elif target == "artifactBase":
            if self._artifact_status(request) != "matching":
                raise ProviderError("artifact-base-not-backed-by-exact-assets")
        else:
            self._capability_mutation(target, request, protected_input)

    def verify_publication(self, request: Any) -> VerificationMaterial:
        response = self._service(
            str(request.bundle.plan["deploymentServicePublicUri"]),
            "verify-publication",
            self._verification_subject(request),
        )
        expected = {
            "schemaVersion",
            "kind",
            "maintenanceReceipt",
            "coreUpdateReceipt",
            "successorBaseline",
            "historyEntry",
        }
        if (
            set(response) != expected
            or response.get("schemaVersion") != 1
            or response.get("kind") != "cryptad-stable-maintenance-deployment-verification"
            or any(
                not isinstance(response.get(key), Mapping)
                for key in expected - {"schemaVersion", "kind"}
            )
        ):
            raise ProviderError("deployment-verification-invalid")
        return VerificationMaterial(
            response["maintenanceReceipt"],
            response["coreUpdateReceipt"],
            response["successorBaseline"],
            response["historyEntry"],
        )

    def observe_latest_pointer(self, request: Any) -> PointerSnapshot:
        subject = {
            "releaseId": request.receipt.get("releaseId"),
            "candidateIdentityDigest": request.receipt.get("candidateIdentityDigest"),
            "latestPointerPublicUri": request.receipt.get("latestPointerPublicUri"),
        }
        response = self._service(
            str(request.receipt["deploymentServicePublicUri"]),
            "observe-latest-pointer",
            subject,
        )
        expected = {
            "schemaVersion",
            "kind",
            "status",
            "pointerDigest",
            "activeBaselineDigest",
            "candidateIdentityDigest",
        }
        if (
            set(response) != expected
            or response.get("schemaVersion") != 1
            or response.get("kind") != "cryptad-stable-maintenance-pointer-observation"
            or response.get("status") not in {"observed", "unavailable"}
        ):
            raise ProviderError("pointer-observation-invalid")
        return PointerSnapshot(
            response["status"],
            response["pointerDigest"],
            response["activeBaselineDigest"],
            response["candidateIdentityDigest"],
        )

    def activate_latest(self, request: Any, protected_input: Any) -> None:
        if protected_input.purpose != "maintenance-state":
            raise ProviderError("maintenance-state-capability-purpose-mismatch")
        subject = {
            "releaseId": request.receipt.get("releaseId"),
            "candidateIdentityDigest": request.receipt.get("candidateIdentityDigest"),
            "expectedPointerDigest": request.expected_pointer_digest,
            "activatedPointerDigest": request.activated_pointer_digest,
            "activatedPointerBytes": base64.b64encode(
                request.activated_pointer_bytes
            ).decode("ascii"),
            "latestPointerPublicUri": request.receipt.get("latestPointerPublicUri"),
        }
        response = self._service(
            protected_input.value, "activate-latest-pointer", subject
        )
        if (
            set(response)
            != {"schemaVersion", "kind", "status", "activatedPointerDigest"}
            or response.get("schemaVersion") != 1
            or response.get("kind") != "cryptad-stable-maintenance-pointer-activation"
            or response.get("status") not in {"activated", "matching"}
            or response.get("activatedPointerDigest")
            != request.activated_pointer_digest
        ):
            raise ProviderError("pointer-activation-result-invalid")


def factory() -> StableMaintenanceBackend:
    """Create the production backend from the workflow's GitHub token only."""

    if os.environ.get("GITHUB_REPOSITORY") != REPOSITORY:
        raise ProviderError("publication-repository-mismatch")
    return StableMaintenanceBackend(os.environ.get("GITHUB_TOKEN", ""))


create_backend = factory
