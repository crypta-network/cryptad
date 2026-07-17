"""Exact-byte selection and policy validation for Stable 1.0 GA promotion."""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import ipaddress
import json
import re
import socket
import stat
import tarfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterable
from urllib.parse import urlparse, urlsplit, urlunsplit

from cryptad_certification.envelope import validate_envelope
from cryptad_certification.io import read_json
from cryptad_certification.models import RunContext
from cryptad_certification.redaction import scan_value
from cryptad_certification.schema_validation import validate_schema

from .stable_1_0_rc_artifacts import verify_deterministic_archive
from .stable_1_0_rc_core import (
    BUILD_VERSION_RE,
    COMMIT_RE,
    DIGEST_RE,
    ValidationState,
    _configured_path,
    file_digest,
    parse_timestamp,
    placeholder_findings,
    semantic_digest,
)
from .stable_1_0_rc_freeze import freeze_content_digest, validate_freeze_shape

SCHEMA_VERSION = 1
TOOL_NAME = "stable-1.0-ga"
TOOL_VERSION = 1
STABLE_MILESTONE = "1.0"

SUMMARY_FILE = "stable-1.0-ga-promotion-summary.json"
REPORT_FILE = "stable-1.0-ga-go-no-go.md"
VALIDATION_FILE = "stable-1.0-ga-validation.json"
VALIDATION_IDENTITY_FILE = "stable-1.0-ga-validation-authorization-identity.json"
AUTHORIZATION_FILE = "stable-1.0-ga-authorization-summary.json"
KNOWN_LIMITATIONS_FILE = "stable-1.0-ga-known-limitations.json"
RELEASE_NOTES_FILE = "stable-1.0-ga-release-notes.md"
PUBLICATION_PLAN_FILE = "stable-1.0-ga-publication-plan.json"
PUBLICATION_RECEIPT_FILE = "stable-1.0-ga-publication-receipt.json"
MAINTENANCE_BASELINE_FILE = "stable-1.0-maintenance-baseline.json"
CHECKSUMS_FILE = "stable-1.0-ga-checksums.txt"
PROVENANCE_FILE = "stable-1.0-ga-provenance.json"
REDACTION_REPORT_FILE = "redaction-report.json"

LINEAGE_SCHEMA = "stable-1.0-rc-lineage-v1.schema.json"
RC_VALIDATION_SCHEMA = "stable-1.0-rc-validation-v1.schema.json"
AUTHORIZATION_SCHEMA = "stable-1.0-ga-authorization-v1.schema.json"
GA_VALIDATION_SCHEMA = "stable-1.0-ga-validation-v1.schema.json"
PROMOTION_SCHEMA = "stable-1.0-ga-promotion-v1.schema.json"
PUBLICATION_RECEIPT_SCHEMA = "stable-1.0-ga-publication-receipt-v1.schema.json"
MAINTENANCE_BASELINE_SCHEMA = "stable-1.0-maintenance-baseline-v1.schema.json"

RC_ARTIFACT_INPUTS = (
    "selectedStableRcFreeze",
    "selectedStableRcFreezeSidecar",
    "selectedStableRcArchive",
    "selectedStableRcProduct",
    "selectedStableRcChecksums",
    "selectedStableRcProvenance",
)
AUTHORIZATION_SCOPE = (
    "git-tag",
    "github-release",
    "release-assets",
    "stable-catalog-confirmation",
    "post-publication-verification",
)
PUBLICATION_STATES = (
    "validated",
    "publication-authorized",
    "publication-complete",
    "publication-verification-failed",
)


def canonical_artifact_base_uri(value: Any) -> str:
    """Return the publication plan's canonical public artifact base URI."""

    return str(value or "").rstrip("/") + "/"


def canonical_public_https_uri(value: Any) -> str:
    """Canonicalize unambiguous HTTPS authority spellings without changing paths."""

    text = str(value or "")
    try:
        parsed = urlsplit(text)
        port = parsed.port
    except ValueError:
        return text
    hostname = parsed.hostname
    if (
        parsed.scheme.lower() != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.query
        or parsed.fragment
        or any(character.isspace() or ord(character) < 32 for character in text)
    ):
        return text
    try:
        address = ipaddress.ip_address(hostname)
        canonical_hostname = str(address)
        netloc = f"[{canonical_hostname}]" if address.version == 6 else canonical_hostname
    except ValueError:
        try:
            canonical_hostname = hostname.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            return text
        if not canonical_hostname:
            return text
        netloc = canonical_hostname
    return urlunsplit(("https", netloc, parsed.path, "", ""))


def is_supported_catalog_publication_uri(value: Any) -> bool:
    """Return whether a catalog URI has one unambiguous supported HTTPS path."""

    canonical = canonical_public_https_uri(value)
    if not is_public_https_uri(canonical) or "\\" in canonical:
        return False
    parsed = urlsplit(canonical)
    path = parsed.path
    segments = path.split("/")
    return (
        path.startswith("/")
        and "//" not in path
        and "%" not in path
        and all(segment not in {".", ".."} for segment in segments)
        and path.endswith(
            (
                "/cryptad-app-catalog.properties",
                "/first-party-catalog.properties",
            )
        )
    )


def is_public_https_uri(value: Any) -> bool:
    """Return whether one credential-free HTTPS URI resolves only to public addresses."""

    if not isinstance(value, str) or not value:
        return False
    parsed = urlparse(value)
    hostname = parsed.hostname or ""
    try:
        safe_port = parsed.port in {None, 443}
    except ValueError:
        safe_port = False
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or not hostname
        or hostname in {"localhost", "localhost.localdomain"}
        or hostname.endswith(".local")
        or parsed.username is not None
        or parsed.password is not None
        or not safe_port
        or parsed.query
        or parsed.fragment
        or any(character.isspace() or ord(character) < 32 for character in value)
    ):
        return False
    try:
        return ipaddress.ip_address(hostname).is_global
    except ValueError:
        try:
            addresses = {
                row[4][0]
                for row in socket.getaddrinfo(
                    hostname,
                    443,
                    type=socket.SOCK_STREAM,
                )
            }
        except OSError:
            return False
        return bool(addresses) and all(
            ipaddress.ip_address(address).is_global for address in addresses
        )


def canonical_publication_targets(context: RunContext) -> dict[str, Any]:
    """Return the closed, timestamp-free publication destinations for authorization."""

    metadata = context.manifest.policies.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    primary = metadata.get("catalogPrimaryUri")
    raw_mirrors = metadata.get("catalogMirrorUris")
    rollback = metadata.get("catalogRollbackUri")
    mirrors = (
        [
            canonical_public_https_uri(item.strip())
            for item in raw_mirrors.split(",")
            if item.strip()
        ]
        if isinstance(raw_mirrors, str)
        else []
    )
    build_version = context.manifest.release.version
    return {
        "expectedTag": f"v{build_version}",
        "expectedReleaseBranch": f"release/{build_version}",
        "artifactBaseUri": canonical_artifact_base_uri(
            context.manifest.policies.get("artifactBaseUri")
        ),
        "catalog": {
            "channel": "stable",
            "primaryUri": (
                canonical_public_https_uri(primary) if isinstance(primary, str) else ""
            ),
            "mirrorUris": mirrors,
            "rollbackUri": (
                canonical_public_https_uri(rollback) if isinstance(rollback, str) else ""
            ),
        },
    }


@dataclasses.dataclass(frozen=True)
class SelectedRc:
    """Authenticated PR-283 inputs and their exact byte identities."""

    summary_path: Path
    freeze_path: Path
    sidecar_path: Path
    archive_path: Path
    product_path: Path
    checksums_path: Path
    provenance_path: Path
    summary_envelope: dict[str, Any]
    summary: dict[str, Any]
    freeze: dict[str, Any]
    provenance: dict[str, Any]
    archive_digest: str
    product_digest: str
    freeze_file_digest: str
    checksums_digest: str
    provenance_digest: str


def _is_regular_file(path: Path) -> bool:
    try:
        mode = path.stat(follow_symlinks=False).st_mode
    except OSError:
        return False
    return stat.S_ISREG(mode) and not path.is_symlink()


def configured_input_path(context: RunContext, key: str, *, required: bool = True) -> Path | None:
    """Resolve one manifest input without following any symlinked path component."""

    path = _configured_path(context, key)
    if path is None:
        if required:
            raise ValueError(f"required Stable GA input is missing: {key}")
        return None
    if not _is_regular_file(path):
        raise ValueError(f"Stable GA input is missing or is not a regular file: {key}")
    return path


def load_json_input(context: RunContext, key: str, *, required: bool = True) -> tuple[Path, dict[str, Any]] | None:
    """Load one redaction-safe JSON input and retain its exact file path."""

    path = configured_input_path(context, key, required=required)
    if path is None:
        return None

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for name, item in pairs:
            if name in result:
                raise ValueError(f"Stable GA input contains duplicate JSON field: {key}")
            result[name] = item
        return result

    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_keys,
    )
    if not isinstance(value, dict):
        raise ValueError(f"Stable GA input must be a JSON object: {key}")
    redaction_findings = (
        public_audit_redaction_findings(value)
        if key in {"stableGaAuthorization", "stableGaPolicy"}
        else scan_value(value)
    )
    if redaction_findings or placeholder_findings(value):
        raise ValueError(f"Stable GA input is redaction-unsafe or contains placeholders: {key}")
    return path, value


def public_audit_redaction_view(value: Any) -> Any:
    """Rename only closed public-approval field labels before generic value scanning.

    The shared scanner must treat arbitrary authorization-shaped fields as secret-bearing. Stable
    GA's closed schemas intentionally expose an approval role and a digest-only approval summary
    for public audit. Renaming those labels for scanning preserves recursive value inspection,
    including token/header patterns, without weakening the generic scanner for other artifacts.
    """

    if isinstance(value, dict):
        renamed: dict[str, Any] = {}
        for key, child in value.items():
            safe_key = {
                "authorization": "publicApproval",
                "authorizationRole": "publicApprovalRole",
                "authorizationDigest": "publicApprovalDigest",
                "authorizationDigestTarget": "publicApprovalDigestTarget",
                "gaAuthorizationDigest": "gaPublicApprovalDigest",
                "validationAuthorizationIdentityDigest": (
                    "validationPublicApprovalIdentityDigest"
                ),
            }.get(str(key), str(key))
            renamed[safe_key] = public_audit_redaction_view(child)
        return renamed
    if isinstance(value, list):
        return [public_audit_redaction_view(child) for child in value]
    return value


def public_audit_redaction_findings(value: Any) -> list[dict[str, str]]:
    """Scan one closed GA public-audit record without treating its role label as a secret."""

    return scan_value(public_audit_redaction_view(value))


def _block_errors(
    state: ValidationState,
    issue_id: str,
    evidence_id: str,
    errors: Iterable[str],
    remediation: str,
) -> None:
    existing = {
        (
            row.get("id"),
            row.get("evidenceId"),
            row.get("summary"),
            row.get("remediation"),
            row.get("waivable"),
        )
        for row in state.blockers
        if isinstance(row, dict)
    }
    for error in errors:
        summary = error.rstrip(".") + "."
        identity = (issue_id, evidence_id, summary, remediation, False)
        if identity in existing:
            continue
        state.block(issue_id, evidence_id, summary, remediation)
        existing.add(identity)


def _expected_identity(context: RunContext) -> dict[str, str]:
    version = context.manifest.release.version
    commit = context.manifest.policies.get("candidateSourceCommit")
    source_ref = context.manifest.policies.get("candidateSourceRef")
    if not isinstance(version, str) or BUILD_VERSION_RE.fullmatch(version) is None:
        raise ValueError("Stable GA build version is not a positive integer string")
    if not isinstance(commit, str) or COMMIT_RE.fullmatch(commit) is None:
        raise ValueError("Stable GA source commit is malformed")
    if not isinstance(source_ref, str) or not source_ref:
        raise ValueError("Stable GA source ref is missing")
    return {
        "releaseId": context.manifest.release.release_id,
        "buildVersion": version,
        "sourceCommit": commit,
        "sourceRef": source_ref,
    }


def _validate_rc_envelope(
    envelope: dict[str, Any],
    expected: dict[str, str],
) -> list[str]:
    errors: list[str] = []
    try:
        validate_envelope(envelope, "stable-1.0-rc", expected["releaseId"])
    except ValueError as exc:
        return [str(exc)]
    subject = envelope.get("subject", {})
    result = envelope.get("result", {})
    redaction = envelope.get("redaction", {})
    expected_subject = {
        "releaseId": expected["releaseId"],
        "version": expected["buildVersion"],
        "profile": "stable-review",
        "component": "stable-rc",
    }
    if subject != expected_subject:
        errors.append("selected Stable RC envelope subject is not the exact candidate")
    if result.get("status") != "pass":
        errors.append("selected Stable RC envelope result.status is not pass")
    if result.get("promotionReady") is not True:
        errors.append("selected Stable RC envelope result.promotionReady is not true")
    if result.get("exitCode") != 0:
        errors.append("selected Stable RC envelope result.exitCode is not zero")
    if redaction.get("status") != "pass" or redaction.get("findingCount") != 0:
        errors.append("selected Stable RC envelope redaction did not pass with zero findings")
    payload = envelope.get("payload")
    legacy = payload.get("legacy") if isinstance(payload, dict) else None
    if not isinstance(legacy, dict):
        errors.append("selected Stable RC envelope omits its native summary")
        return errors
    if scan_value(legacy) or placeholder_findings(legacy):
        errors.append(
            "selected Stable RC native summary contains redaction findings or placeholders"
        )
    if legacy.get("status") != "pass" or legacy.get("promotionReady") is not True:
        errors.append("selected Stable RC native summary is not passing and promotion ready")
    if legacy.get("nonRelease") is not False or legacy.get("stableReady") is not True:
        errors.append("selected Stable RC native summary is non-release or not Stable ready")
    if legacy.get("decision") not in {"go", "go-with-waivers"}:
        errors.append("selected Stable RC final decision is not go or go-with-waivers")
    if result.get("decision") != legacy.get("decision"):
        errors.append("selected Stable RC envelope result and native decision differ")
    freeze = legacy.get("freeze") if isinstance(legacy.get("freeze"), dict) else {}
    if freeze.get("status") != "pass" or freeze.get("driftStatus") != "no-drift":
        errors.append("selected Stable RC freeze is not passing with no-drift")
    native_redaction = legacy.get("redaction") if isinstance(legacy.get("redaction"), dict) else {}
    if legacy.get("redactionStatus") != "pass" or native_redaction.get("status") != "pass":
        errors.append("selected Stable RC native redaction did not pass")
    return errors


def _parse_sidecar(path: Path, freeze_path: Path) -> list[str]:
    expected = file_digest(freeze_path).removeprefix("sha256:") + f"  {freeze_path.name}"
    try:
        rows = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return ["selected Stable RC freeze sidecar is not readable UTF-8"]
    return [] if rows == [expected] else ["selected Stable RC freeze sidecar does not bind the exact freeze bytes"]


def _parse_external_checksums(path: Path, root: Path) -> tuple[dict[str, str], list[str]]:
    parsed: dict[str, str] = {}
    errors: list[str] = []
    try:
        rows = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return {}, ["selected Stable RC checksums are not readable UTF-8"]
    for number, row in enumerate(rows, start=1):
        digest, separator, name = row.partition("  ")
        relative = Path(name)
        if (
            not separator
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not name
            or name in parsed
            or relative.is_absolute()
            or len(relative.parts) != 1
            or ".." in relative.parts
        ):
            errors.append(f"selected Stable RC checksums line {number} is malformed")
            continue
        target = root / relative
        if not _is_regular_file(target):
            errors.append(f"selected Stable RC checksum target is missing or unsafe: {name}")
            continue
        try:
            target.resolve().relative_to(root.resolve())
        except ValueError:
            errors.append(f"selected Stable RC checksum target escapes its artifact root: {name}")
            continue
        normalized = "sha256:" + digest
        parsed[name] = normalized
        if file_digest(target) != normalized:
            errors.append(f"selected Stable RC checksum mismatch: {name}")
    return parsed, errors


def _archive_member_bytes(archive: tarfile.TarFile, name: str) -> bytes | None:
    try:
        member = archive.getmember(name)
    except KeyError:
        return None
    stream = archive.extractfile(member)
    return None if stream is None else stream.read()


def _validate_archive_identity(
    selected: SelectedRc,
    checksum_names: set[str],
) -> list[str]:
    errors = verify_deterministic_archive(selected.archive_path)
    layout = selected.provenance.get("archiveLayout")
    members = layout.get("members") if isinstance(layout, dict) else None
    if not isinstance(members, list) or any(not isinstance(item, str) for item in members):
        return [*errors, "selected Stable RC provenance archive layout is malformed"]
    expected_members = {f"stable-1.0-rc/{item}" for item in members}
    expected_external = {
        selected.archive_path.name,
        selected.product_path.name,
        *(
            Path(item).name
            for item in members
            if item.startswith("metadata/")
        ),
    }
    if checksum_names != expected_external:
        errors.append("selected Stable RC external checksum allowlist does not match provenance")
    try:
        with tarfile.open(selected.archive_path, "r:gz") as archive:
            actual_members = {member.name for member in archive.getmembers()}
            if actual_members != expected_members:
                errors.append("selected Stable RC archive member allowlist does not match provenance")
            artifact_root = selected.freeze_path.parent
            native_summary_name = "stable-1.0-rc-promotion-summary.json"
            nested_native_summary = (
                selected.summary_path.parent
                / "artifacts"
                / "legacy"
                / native_summary_name
            )
            flat_native_summary = artifact_root / native_summary_name
            native_summary_source = (
                nested_native_summary
                if _is_regular_file(nested_native_summary)
                else flat_native_summary
            )
            comparisons = {
                f"stable-1.0-rc/payload/{selected.product_path.name}": selected.product_path,
                "stable-1.0-rc/metadata/stable-1.0-rc-freeze.json": selected.freeze_path,
                "stable-1.0-rc/metadata/stable-1.0-rc-freeze.sha256": selected.sidecar_path,
                f"stable-1.0-rc/metadata/{native_summary_name}": native_summary_source,
                "stable-1.0-rc/metadata/provenance.json": selected.provenance_path,
            }
            for item in members:
                if not item.startswith("metadata/"):
                    continue
                member_name = f"stable-1.0-rc/{item}"
                comparisons.setdefault(member_name, artifact_root / Path(item).name)
            for member_name, source in comparisons.items():
                archived = _archive_member_bytes(archive, member_name)
                if archived is None:
                    errors.append(f"selected Stable RC archive omits required member: {member_name}")
                    continue
                if member_name == f"stable-1.0-rc/metadata/{native_summary_name}":
                    # The archive member must repeat the native payload wrapped by the v2 common
                    # envelope in both normal and flattened Actions artifact layouts. When a
                    # standalone native summary is present, the byte comparison below binds it too.
                    try:
                        archived_value = json.loads(archived.decode("utf-8"))
                    except (UnicodeDecodeError, ValueError):
                        errors.append("selected Stable RC archive native summary is malformed")
                    else:
                        if archived_value != selected.summary:
                            errors.append("selected Stable RC archive native summary differs from the v2 payload")
                    if not _is_regular_file(source):
                        continue
                if not _is_regular_file(source) or archived != source.read_bytes():
                    errors.append(f"selected Stable RC archive member differs from selected bytes: {member_name}")
    except (OSError, tarfile.TarError):
        errors.append("selected Stable RC archive cannot be opened")
    from cryptad_certification.engines import production_beta_release as production_engine

    settings = SimpleNamespace(workspace_root=selected.product_path.parent)
    for finding in production_engine.scan_tarball(selected.product_path, settings):
        errors.append(
            "selected Stable RC product contains an unsafe nested member of kind "
            + str(finding.get("kind", "unknown"))
        )
    return errors


def authenticate_selected_rc(context: RunContext, state: ValidationState) -> SelectedRc:
    """Authenticate one exact, promotable PR-283 RC artifact set."""

    expected = _expected_identity(context)
    summary_path = configured_input_path(context, "selectedStableRcSummary")
    if summary_path is None:
        raise ValueError("selected Stable RC summary is missing")
    summary_envelope = read_json(summary_path)
    if not isinstance(summary_envelope, dict):
        raise ValueError("selected Stable RC summary is malformed")
    _block_errors(
        state,
        "stable-1.0-ga.selected-rc-envelope",
        "stable-1.0-ga.rc-selection",
        _validate_rc_envelope(summary_envelope, expected),
        "Select the exact passing Stable RC v2 component summary.",
    )
    payload = summary_envelope.get("payload")
    summary = payload.get("legacy") if isinstance(payload, dict) else None
    if not isinstance(summary, dict):
        raise ValueError("selected Stable RC native summary is missing")

    paths = {key: configured_input_path(context, key) for key in RC_ARTIFACT_INPUTS}
    if any(path is None for path in paths.values()):
        raise ValueError("selected Stable RC artifact set is incomplete")
    freeze_path = paths["selectedStableRcFreeze"]
    assert freeze_path is not None
    artifact_root = freeze_path.parent.resolve()
    for key, path in paths.items():
        assert path is not None
        if path.parent.resolve() != artifact_root:
            state.block(
                "stable-1.0-ga.selected-rc-confinement",
                "stable-1.0-ga.rc-selection",
                f"Selected Stable RC artifact {key} is outside the single confined artifact root.",
                "Materialize the exact authenticated RC component into one confined directory.",
            )

    freeze = read_json(freeze_path)
    if not isinstance(freeze, dict):
        raise ValueError("selected Stable RC freeze is malformed")
    freeze_errors = validate_freeze_shape(freeze)
    if freeze.get("contentDigest") != freeze_content_digest(freeze):
        freeze_errors.append("selected Stable RC freeze canonical content digest is incorrect")
    candidate = freeze.get("candidate") if isinstance(freeze.get("candidate"), dict) else {}
    for key in ("releaseId", "buildVersion", "sourceCommit", "sourceRef"):
        if candidate.get(key) != expected[key]:
            freeze_errors.append(f"selected Stable RC freeze candidate {key} does not match")
    _block_errors(
        state,
        "stable-1.0-ga.selected-rc-freeze",
        "stable-1.0-ga.rc-selection",
        freeze_errors,
        "Return to the PR-283 workflow and select its exact latest successful freeze.",
    )

    sidecar_path = paths["selectedStableRcFreezeSidecar"]
    assert sidecar_path is not None
    _block_errors(
        state,
        "stable-1.0-ga.selected-rc-sidecar",
        "stable-1.0-ga.archive-integrity",
        _parse_sidecar(sidecar_path, freeze_path),
        "Use the sidecar generated beside the selected freeze.",
    )
    provenance_path = paths["selectedStableRcProvenance"]
    assert provenance_path is not None
    provenance = read_json(provenance_path)
    if not isinstance(provenance, dict):
        raise ValueError("selected Stable RC provenance is malformed")
    product_path = paths["selectedStableRcProduct"]
    archive_path = paths["selectedStableRcArchive"]
    checksums_path = paths["selectedStableRcChecksums"]
    assert product_path is not None and archive_path is not None and checksums_path is not None
    product_digest = file_digest(product_path)
    archive_digest = file_digest(archive_path)
    provenance_errors: list[str] = []
    if provenance.get("schemaVersion") != 1 or provenance.get("kind") != "stable-1.0-rc-provenance":
        provenance_errors.append("selected Stable RC provenance kind or schema is invalid")
    if provenance.get("releaseId") != expected["releaseId"] or provenance.get("buildVersion") != expected["buildVersion"]:
        provenance_errors.append("selected Stable RC provenance release/build binding differs")
    source = provenance.get("source") if isinstance(provenance.get("source"), dict) else {}
    if source.get("commit") != expected["sourceCommit"] or source.get("ref") != expected["sourceRef"]:
        provenance_errors.append("selected Stable RC provenance source binding differs")
    freeze_binding = provenance.get("freeze") if isinstance(provenance.get("freeze"), dict) else {}
    if freeze_binding.get("contentDigest") != freeze.get("contentDigest") or freeze_binding.get("fileDigest") != file_digest(freeze_path):
        provenance_errors.append("selected Stable RC provenance freeze binding differs")
    distribution = provenance.get("productionDistribution") if isinstance(provenance.get("productionDistribution"), dict) else {}
    if distribution.get("digest") != product_digest or candidate.get("productionDistributionDigest") != product_digest:
        provenance_errors.append("selected Stable RC product digest differs across freeze/provenance/file")
    if distribution.get("file") != f"payload/{product_path.name}":
        provenance_errors.append("selected Stable RC provenance product filename is not canonical")
    if provenance.get("redaction") != {"status": "pass", "findingCount": 0}:
        provenance_errors.append("selected Stable RC provenance redaction did not pass")
    _block_errors(
        state,
        "stable-1.0-ga.selected-rc-provenance",
        "stable-1.0-ga.provenance",
        provenance_errors,
        "Use the provenance generated with the selected RC artifact.",
    )
    checksums, checksum_errors = _parse_external_checksums(checksums_path, artifact_root)
    for name, digest in (
        (archive_path.name, archive_digest),
        (product_path.name, product_digest),
        (freeze_path.name, file_digest(freeze_path)),
        (provenance_path.name, file_digest(provenance_path)),
    ):
        if checksums.get(name) != digest:
            checksum_errors.append(f"selected Stable RC checksums do not bind {name}")
    _block_errors(
        state,
        "stable-1.0-ga.selected-rc-checksums",
        "stable-1.0-ga.archive-integrity",
        checksum_errors,
        "Use the exact external checksum set generated by PR-283.",
    )
    selected = SelectedRc(
        summary_path=summary_path,
        freeze_path=freeze_path,
        sidecar_path=sidecar_path,
        archive_path=archive_path,
        product_path=product_path,
        checksums_path=checksums_path,
        provenance_path=provenance_path,
        summary_envelope=summary_envelope,
        summary=summary,
        freeze=freeze,
        provenance=provenance,
        archive_digest=archive_digest,
        product_digest=product_digest,
        freeze_file_digest=file_digest(freeze_path),
        checksums_digest=file_digest(checksums_path),
        provenance_digest=file_digest(provenance_path),
    )
    _block_errors(
        state,
        "stable-1.0-ga.selected-rc-archive",
        "stable-1.0-ga.archive-integrity",
        _validate_archive_identity(selected, set(checksums)),
        "Restore the exact PR-283 outer archive and immutable product; do not rebuild them.",
    )
    return selected


def validate_lineage(
    context: RunContext,
    selected: SelectedRc,
    lineage: dict[str, Any],
    state: ValidationState,
) -> None:
    """Require a protected latest-successful RC lineage attestation."""

    errors = validate_schema(lineage, LINEAGE_SCHEMA)
    expected = _expected_identity(context)
    for key in ("releaseId", "buildVersion", "sourceCommit", "sourceRef"):
        if lineage.get(key) != expected[key]:
            errors.append(f"Stable RC lineage {key} does not match the candidate")
    if lineage.get("profile") != "stable-review" or lineage.get("component") != "stable-rc":
        errors.append("Stable RC lineage profile/component is not stable-review/stable-rc")
    if lineage.get("status") != "pass":
        errors.append("Stable RC lineage status is not pass")
    selected_row = lineage.get("selectedFreeze") if isinstance(lineage.get("selectedFreeze"), dict) else {}
    latest_row = lineage.get("latestSuccessfulFreeze") if isinstance(lineage.get("latestSuccessfulFreeze"), dict) else {}
    expected_digests = {
        "freezeDigest": selected.freeze.get("contentDigest"),
        "freezeFileDigest": selected.freeze_file_digest,
        "archiveDigest": selected.archive_digest,
        "productDistributionDigest": selected.product_digest,
        "sourceCommit": expected["sourceCommit"],
    }
    for key, value in expected_digests.items():
        if selected_row.get(key) != value or latest_row.get(key) != value:
            errors.append(f"Stable RC lineage does not bind the latest selected {key}")
    if selected_row != latest_row:
        errors.append("selected Stable RC freeze is not the exact latest successful freeze")
    history = lineage.get("history")
    successful = [row for row in history if isinstance(row, dict) and row.get("successful") is True] if isinstance(history, list) else []
    if not successful:
        errors.append("Stable RC lineage has no successful protected history")
    else:
        ordinals = [row.get("ordinal") for row in history if isinstance(row, dict)]
        if (
            any(type(ordinal) is not int for ordinal in ordinals)
            or ordinals != sorted(ordinals)
            or len(ordinals) != len(set(ordinals))
        ):
            errors.append("Stable RC lineage history ordinals are ambiguous or out of order")
        latest_history = max(successful, key=lambda row: int(row.get("ordinal", -1)))
        if any(latest_history.get(key) != value for key, value in expected_digests.items()):
            errors.append("Stable RC lineage history ends at a different successful freeze")
        if any(
            latest_history.get(key) != selected_row.get(key)
            for key in (
                "freezeDigest",
                "freezeFileDigest",
                "archiveDigest",
                "productDistributionDigest",
                "sourceCommit",
                "workflow",
            )
        ):
            errors.append("Stable RC lineage history does not end at the selected protected run")
        freeze_mode = selected.provenance.get("freezeMode")
        if latest_history.get("freezeMode") != freeze_mode:
            errors.append("Stable RC lineage freeze mode differs from selected provenance")
        comparison_baseline = selected.provenance.get("comparisonBaseline")
        if freeze_mode == "first-freeze" and comparison_baseline is not None:
            errors.append("first Stable RC freeze unexpectedly declares a comparison baseline")
        elif freeze_mode == "refreeze" and (
            not isinstance(comparison_baseline, dict)
            or set(comparison_baseline) != {"fileDigest", "contentDigest"}
            or any(
                not isinstance(comparison_baseline.get(key), str)
                or DIGEST_RE.fullmatch(comparison_baseline[key]) is None
                for key in ("fileDigest", "contentDigest")
            )
        ):
            errors.append("Stable RC refreeze omits its exact prior-freeze comparison binding")
        elif freeze_mode not in {"first-freeze", "refreeze"}:
            errors.append("Stable RC provenance freeze mode is invalid")
    exception_digest = semantic_digest(selected.freeze.get("acceptedFreezeExceptions", []))
    if lineage.get("acceptedFreezeExceptionHistoryDigest") != exception_digest:
        errors.append("Stable RC lineage accepted freeze-exception history differs")
    if scan_value(lineage):
        errors.append("Stable RC lineage contains redaction findings")
    _block_errors(
        state,
        "stable-1.0-ga.rc-lineage",
        "stable-1.0-ga.rc-lineage",
        errors,
        "Regenerate the lineage attestation from the latest successful protected Stable RC run.",
    )


def _binding_errors(value: Any, expected: dict[str, Any], path: str = "scenarios") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        binding = value.get("binding")
        if isinstance(binding, dict):
            for key, expected_value in expected.items():
                if binding.get(key) != expected_value:
                    errors.append(f"{path}.binding.{key} does not bind the selected RC")
        for key, child in value.items():
            errors.extend(_binding_errors(child, expected, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(_binding_errors(child, expected, f"{path}[{index}]"))
    return errors


def authenticate_upgrade_predecessor(
    context: RunContext,
    selected: SelectedRc,
    state: ValidationState,
) -> dict[str, str]:
    """Authenticate the exact predecessor envelope frozen by the selected Stable RC."""

    path, envelope = load_json_input(context, "previousCandidate") or (None, {})
    if path is None:
        raise ValueError("Stable GA previousCandidate input is missing")
    expected = _expected_identity(context)
    errors: list[str] = []
    try:
        validate_envelope(
            envelope,
            "migrated-v1-previous-candidate",
            expected["releaseId"],
        )
    except ValueError as exc:
        errors.append(str(exc))
    subject = envelope.get("subject") if isinstance(envelope.get("subject"), dict) else {}
    if subject != {
        "releaseId": expected["releaseId"],
        "version": expected["buildVersion"],
        "profile": "stable-review",
        "component": "migration/previous-candidate",
    }:
        errors.append("frozen predecessor envelope subject differs from the selected candidate")
    result = envelope.get("result") if isinstance(envelope.get("result"), dict) else {}
    if result.get("status") != "pass" or result.get("exitCode") != 0:
        errors.append("frozen predecessor envelope result is not passing")
    redaction = (
        envelope.get("redaction")
        if isinstance(envelope.get("redaction"), dict)
        else {}
    )
    if redaction.get("status") != "pass" or redaction.get("findingCount") != 0:
        errors.append("frozen predecessor envelope redaction did not pass")
    payload = envelope.get("payload") if isinstance(envelope.get("payload"), dict) else {}
    legacy = payload.get("legacy") if isinstance(payload.get("legacy"), dict) else {}
    if not legacy:
        errors.append("frozen predecessor envelope omits payload.legacy")
    elif scan_value(legacy) or placeholder_findings(legacy):
        errors.append("frozen predecessor payload contains redaction findings or placeholders")

    digest = file_digest(path)
    frozen_digest = selected.freeze.get("candidate", {}).get("previousCandidateDigest")
    provenance_digest = selected.provenance.get("inputs", {}).get("previousCandidate")
    if digest != frozen_digest or digest != provenance_digest:
        errors.append("previousCandidate bytes differ from the exact predecessor frozen by PR-283")
    release_id = legacy.get("releaseId")
    build_version = legacy.get("version")
    if not isinstance(release_id, str) or not release_id:
        errors.append("frozen predecessor releaseId is malformed")
        release_id = "invalid"
    if isinstance(build_version, int) and not isinstance(build_version, bool):
        build_version = str(build_version)
    if not isinstance(build_version, str) or BUILD_VERSION_RE.fullmatch(build_version) is None:
        errors.append("frozen predecessor build version is malformed")
        build_version = "1"
    expected_release_id = context.manifest.policies.get("expectedPreviousReleaseId")
    if release_id != expected_release_id:
        errors.append("frozen predecessor releaseId differs from the manifest selection")
    product_digest = context.manifest.policies.get("expectedPreviousProductDigest")
    if not isinstance(product_digest, str) or DIGEST_RE.fullmatch(product_digest) is None:
        errors.append("required predecessor product digest is missing or malformed")
        product_digest = "sha256:" + "0" * 64
    _block_errors(
        state,
        "stable-1.0-ga.upgrade-predecessor",
        "stable-1.0-ga.upgrade-predecessor",
        errors,
        "Select the exact PR-283 predecessor envelope and authoritative published product digest.",
    )
    return {
        "releaseId": release_id,
        "buildVersion": build_version,
        "previousCandidateDigest": digest,
        "productDistributionDigest": product_digest,
    }


def build_ga_validation_record(
    context: RunContext,
    selected: SelectedRc,
    lineage_digest: str,
    rc_validation: dict[str, Any],
    rc_validation_digest: str,
    upgrade_predecessor: dict[str, str],
    authorization: dict[str, Any] | None,
    authorization_digest: str,
    authorization_valid: bool,
    carried_waivers: list[dict[str, Any]],
    state: ValidationState,
) -> dict[str, Any]:
    """Build the deterministic, authorized Stable GA validation record."""

    candidate = selected.freeze.get("candidate", {})
    catalog = selected.freeze.get("stableCatalog", {})
    limitations = selected.freeze.get("limitationsAndPolicy", {})
    generated = parse_timestamp(rc_validation.get("generatedAt"))
    ended = parse_timestamp(rc_validation.get("validationEndedAt"))
    evidence_age_days = (
        int((generated - ended).total_seconds() // 86400)
        if generated is not None and ended is not None and generated >= ended
        else 0
    )
    validation_passed = not state.blockers
    promotion_ready = validation_passed and authorization_valid
    decision = (
        "go-with-waivers"
        if promotion_ready and carried_waivers
        else "go"
        if promotion_ready
        else "no-go"
    )
    authorization = authorization if isinstance(authorization, dict) else {}
    publication_targets_digest = semantic_digest(
        canonical_publication_targets(context)
    )

    def surface(value: Any) -> dict[str, Any]:
        digest = semantic_digest(value)
        return {
            "status": "pass",
            "frozenDigest": digest,
            "currentDigest": digest,
            "drift": False,
        }

    record = {
        "schemaVersion": 1,
        "kind": "stable-1.0-ga-validation",
        "generatedAt": rc_validation.get("generatedAt"),
        "state": "publication-authorized" if promotion_ready else "validated",
        "releaseId": context.manifest.release.release_id,
        "buildVersion": context.manifest.release.version,
        "profile": "stable-review",
        "component": "stable-ga",
        "sourceCommit": candidate.get("sourceCommit"),
        "sourceRef": candidate.get("sourceRef"),
        "status": "pass" if validation_passed else "fail",
        "promotionReady": promotion_ready,
        "nonRelease": False,
        "decision": decision,
        "selectedRc": {
            "status": selected.summary.get("status"),
            "promotionReady": selected.summary.get("promotionReady"),
            "nonRelease": selected.summary.get("nonRelease"),
            "driftStatus": selected.summary.get("freeze", {}).get("driftStatus"),
            "finalDecision": selected.summary.get("decision"),
            "lineageDigest": lineage_digest,
            "freezeDigest": selected.freeze.get("contentDigest"),
            "archiveDigest": selected.archive_digest,
            "productDistributionDigest": selected.product_digest,
            "catalogDigest": catalog.get("catalogDigest"),
            "catalogRevision": catalog.get("revision"),
        },
        "postFreezeValidation": {
            "status": rc_validation.get("status"),
            "exactRcBinding": rc_validation.get("exactRcBinding"),
            "validationDigest": rc_validation_digest,
            "evidenceAgeDays": evidence_age_days,
            "requiredUpgradePredecessor": upgrade_predecessor,
        },
        "authorization": {
            "status": "authorized" if authorization_valid else "missing" if not authorization else "invalid",
            "authorizationId": authorization.get("authorizationId") if authorization_valid else None,
            "authorizationDigest": authorization_digest,
            "publicationTargetsDigest": publication_targets_digest,
            "allowedPublicationScope": (
                authorization.get("allowedPublicationScope") if authorization_valid else []
            ),
        },
        "payloadIdentity": {
            "rcProductDigest": selected.product_digest,
            "gaProductDigest": selected.product_digest,
            "bitIdentical": True,
            "rebuildPerformed": False,
        },
        "frozenSurfaces": {
            "platformApi": surface(selected.freeze.get("platformApi")),
            "stableCatalog": surface(catalog),
            "firstPartyApps": surface(selected.freeze.get("firstPartyApps")),
            "contentProfiles": surface(selected.freeze.get("contentFormatProfiles")),
            "limitations": surface(limitations),
        },
        "acceptedRcWaivers": carried_waivers,
        "blockers": [
            {
                "id": str(row.get("id", "stable-1.0-ga.unknown")),
                "summary": str(row.get("summary", "Stable GA validation failed.")),
                "nonWaivable": row.get("waivable") is not True,
            }
            for row in state.blockers
        ],
        "redaction": {
            "status": "pass",
            "findingCount": 0,
            "findings": [],
        },
    }
    return record


def ga_validation_authorization_identity(
    context: RunContext,
    selected: SelectedRc,
    lineage_digest: str,
    rc_validation: dict[str, Any],
    rc_validation_digest: str,
    upgrade_predecessor: dict[str, str],
    carried_waivers: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return the non-circular semantic record that an approval must authorize."""

    catalog = selected.freeze.get("stableCatalog", {})
    publication_targets = canonical_publication_targets(context)
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-ga-validation-authorization-identity",
        "releaseId": context.manifest.release.release_id,
        "buildVersion": context.manifest.release.version,
        "profile": "stable-review",
        "component": "stable-ga",
        "sourceCommit": selected.freeze.get("candidate", {}).get("sourceCommit"),
        "sourceRef": selected.freeze.get("candidate", {}).get("sourceRef"),
        "lineageDigest": lineage_digest,
        "freezeDigest": selected.freeze.get("contentDigest"),
        "freezeFileDigest": selected.freeze_file_digest,
        "archiveDigest": selected.archive_digest,
        "productDistributionDigest": selected.product_digest,
        "checksumsDigest": selected.checksums_digest,
        "provenanceDigest": selected.provenance_digest,
        "postFreezeValidationDigest": rc_validation_digest,
        "postFreezeValidationGeneratedAt": rc_validation.get("generatedAt"),
        "requiredUpgradePredecessor": upgrade_predecessor,
        "catalogDigest": catalog.get("catalogDigest"),
        "catalogRevision": catalog.get("revision"),
        "platformApiDigest": semantic_digest(selected.freeze.get("platformApi")),
        "firstPartyAppsDigest": semantic_digest(selected.freeze.get("firstPartyApps")),
        "contentProfilesDigest": semantic_digest(
            selected.freeze.get("contentFormatProfiles")
        ),
        "limitationsDigest": semantic_digest(
            selected.freeze.get("limitationsAndPolicy")
        ),
        "publicationTargets": publication_targets,
        "publicationTargetsDigest": semantic_digest(publication_targets),
        "acceptedRcWaivers": carried_waivers,
        "payloadIdentity": {
            "rcProductDigest": selected.product_digest,
            "gaProductDigest": selected.product_digest,
            "bitIdentical": True,
            "rebuildPerformed": False,
        },
    }


def validate_post_freeze(
    context: RunContext,
    selected: SelectedRc,
    lineage: dict[str, Any],
    value: dict[str, Any],
    upgrade_predecessor: dict[str, str],
    policy: dict[str, Any],
    policy_digest: str,
    now: dt.datetime,
    state: ValidationState,
) -> None:
    """Validate production post-freeze scenarios bound to the exact selected bytes."""

    errors = validate_schema(value, RC_VALIDATION_SCHEMA)
    expected = _expected_identity(context)
    candidate = selected.freeze.get("candidate", {})
    catalog = selected.freeze.get("stableCatalog", {})
    top_expected = {
        "releaseId": expected["releaseId"],
        "buildVersion": expected["buildVersion"],
        "sourceCommit": expected["sourceCommit"],
        "sourceRef": expected["sourceRef"],
        "profile": "stable-review",
        "freezeDigest": selected.freeze.get("contentDigest"),
        "productDistributionDigest": selected.product_digest,
        "archiveDigest": selected.archive_digest,
        "status": "pass",
        "exactRcBinding": True,
        "fixtureOnly": False,
        "simulatedOnly": False,
        "nonRelease": False,
    }
    for key, expected_value in top_expected.items():
        if value.get(key) != expected_value:
            errors.append(f"post-freeze validation {key} does not match {expected_value!r}")
    validation_catalog = value.get("stableCatalog") if isinstance(value.get("stableCatalog"), dict) else {}
    for key, expected_value in {
        "catalogId": catalog.get("catalogId"),
        "channel": "stable",
        "revision": catalog.get("revision"),
        "catalogDigest": catalog.get("catalogDigest"),
        "signatureDigest": catalog.get("signatureDigest"),
        "signingKeyId": catalog.get("catalogSigningKeyId"),
    }.items():
        if validation_catalog.get(key) != expected_value:
            errors.append(f"post-freeze validation stableCatalog.{key} differs from the freeze")
    policy_contract = policy.get("postFreezeValidation") if isinstance(policy.get("postFreezeValidation"), dict) else {}
    validation_policy = value.get("policy") if isinstance(value.get("policy"), dict) else {}
    for key, expected_value in {
        "policyDigest": policy_digest,
        "minimumLiveSoakDurationSeconds": policy_contract.get("minimumLiveSoakDurationSeconds"),
        "maximumEvidenceAgeDays": policy_contract.get("maximumEvidenceAgeDays"),
        "minimumNodeCount": policy_contract.get("minimumNodeCount"),
        "minimumOperationCount": policy_contract.get("minimumOperationCount"),
    }.items():
        if validation_policy.get(key) != expected_value:
            errors.append(f"post-freeze validation policy.{key} differs from authoritative policy")
    expected_binding = {
        "releaseId": expected["releaseId"],
        "buildVersion": expected["buildVersion"],
        "sourceCommit": expected["sourceCommit"],
        "freezeDigest": selected.freeze.get("contentDigest"),
        "productDistributionDigest": selected.product_digest,
        "archiveDigest": selected.archive_digest,
        "catalogDigest": catalog.get("catalogDigest"),
        "catalogRevision": catalog.get("revision"),
    }
    errors.extend(_binding_errors(value.get("scenarios"), expected_binding))
    started = parse_timestamp(value.get("validationStartedAt"))
    ended = parse_timestamp(value.get("validationEndedAt"))
    generated = parse_timestamp(value.get("generatedAt"))
    freeze_completed = parse_timestamp(lineage.get("generatedAt"))
    maximum_age = policy_contract.get("maximumEvidenceAgeDays")
    if started is None or ended is None or ended < started:
        errors.append("post-freeze validation time window is malformed")
    if ended is not None and generated is not None and generated < ended:
        errors.append("post-freeze validation generatedAt precedes validation completion")
    if generated is None or generated > now:
        errors.append("post-freeze validation generatedAt is missing or in the future")
    elif type(maximum_age) is int and now - generated > dt.timedelta(days=maximum_age):
        errors.append("post-freeze validation is stale under the GA policy")
    if freeze_completed is None or freeze_completed > now:
        errors.append("selected protected Stable RC freeze completion time is invalid")
    elif started is not None and started < freeze_completed:
        errors.append("post-freeze validation began before the selected protected freeze completed")
    artifact_timestamp = parse_timestamp(catalog.get("artifactTimestamp"))
    if started is not None and artifact_timestamp is not None and started < artifact_timestamp:
        errors.append("post-freeze validation began before the frozen catalog artifact timestamp")
    scenarios = value.get("scenarios") if isinstance(value.get("scenarios"), dict) else {}
    upgrade = (
        scenarios.get("upgradeRollbackStatePreservation")
        if isinstance(scenarios.get("upgradeRollbackStatePreservation"), dict)
        else {}
    )
    for key, expected_value in {
        "previousCandidateDigest": upgrade_predecessor.get("previousCandidateDigest"),
        "previousReleaseId": upgrade_predecessor.get("releaseId"),
        "previousBuildVersion": upgrade_predecessor.get("buildVersion"),
        "previousProductDigest": upgrade_predecessor.get("productDistributionDigest"),
    }.items():
        if upgrade.get(key) != expected_value:
            errors.append(
                f"post-freeze upgrade predecessor {key} differs from the authorized predecessor"
            )
    long_soak = scenarios.get("longSoak") if isinstance(scenarios.get("longSoak"), dict) else {}
    minimum_duration = policy_contract.get("minimumLiveSoakDurationSeconds")
    if type(minimum_duration) is int and (
        type(long_soak.get("actualDurationSeconds")) is not int
        or long_soak.get("actualDurationSeconds", -1) < minimum_duration
    ):
        errors.append("post-freeze live long soak is shorter than authoritative policy")
    long_soak_started = parse_timestamp(long_soak.get("startedAt"))
    long_soak_ended = parse_timestamp(long_soak.get("endedAt"))
    if long_soak_started is not None and long_soak_ended is not None:
        long_soak_interval = int((long_soak_ended - long_soak_started).total_seconds())
        if (
            type(long_soak.get("actualDurationSeconds")) is int
            and long_soak_interval < long_soak["actualDurationSeconds"]
        ):
            errors.append("post-freeze live long-soak interval is shorter than its recorded duration")
        if type(minimum_duration) is int and long_soak_interval < minimum_duration:
            errors.append("post-freeze live long-soak interval is shorter than authoritative policy")
    if type(long_soak.get("nodeCount")) is not int or long_soak.get(
        "nodeCount", -1
    ) < policy_contract.get("minimumNodeCount", 0):
        errors.append("post-freeze live long soak uses fewer nodes than authoritative policy")
    if type(long_soak.get("operationCount")) is not int or long_soak.get(
        "operationCount", -1
    ) < policy_contract.get("minimumOperationCount", 0):
        errors.append("post-freeze live long soak uses fewer operations than authoritative policy")
    installation = (
        scenarios.get("installationPackaging")
        if isinstance(scenarios.get("installationPackaging"), dict)
        else {}
    )
    targets = installation.get("targets")
    if not isinstance(targets, list) or not targets:
        errors.append("post-freeze installation/package validation has no protected targets")
    elif installation.get("requiredTargetCount") != len(targets) or installation.get(
        "validatedTargetCount"
    ) != len(targets):
        errors.append("post-freeze installation/package target matrix is incomplete")
    else:
        target_pairs = {
            (row.get("operatingSystem"), row.get("packageType"))
            for row in targets
            if isinstance(row, dict)
        }
        required_systems = policy_contract.get("requiredOperatingSystems")
        required_types = policy_contract.get("requiredPackageTypesByOperatingSystem")
        if not isinstance(required_systems, list) or not isinstance(required_types, dict):
            errors.append("authoritative installation/package target policy is malformed")
        else:
            for operating_system in required_systems:
                package_types = required_types.get(operating_system)
                if not isinstance(package_types, list) or any(
                    (operating_system, package_type) not in target_pairs
                    for package_type in package_types
                ):
                    errors.append(
                        "post-freeze installation/package target matrix omits a required "
                        f"{operating_system} package type"
                    )
    window_keys = {
        "longSoak": "longSoakDays",
        "installationPackaging": "installationPackagingDays",
        "upgradeRollbackStatePreservation": "upgradeRollbackMigrationDays",
        "liveNetwork": "liveNetworkDays",
        "interoperability": "interoperabilityDays",
        "performance": "performanceDays",
        "sandboxProvider": "sandboxDays",
        "securityResponse": "securityDrillsDays",
        "supportDiagnostics": "supportDiagnosticsDays",
        "catalogOperations": "catalogOperationsDays",
    }
    configured_windows = policy_contract.get("requiredEvidenceWindows")
    configured_windows = configured_windows if isinstance(configured_windows, dict) else {}
    evidence_digests: list[str] = []
    for scenario_id, window_key in window_keys.items():
        scenario = scenarios.get(scenario_id)
        if not isinstance(scenario, dict):
            continue
        evidence_rows = (
            [row for row in scenario.get("targets", []) if isinstance(row, dict)]
            if scenario_id == "installationPackaging"
            else [scenario]
        )
        window_days = configured_windows.get(window_key)
        for evidence_row in evidence_rows:
            scenario_started = parse_timestamp(evidence_row.get("startedAt"))
            scenario_ended = parse_timestamp(evidence_row.get("endedAt"))
            if (
                scenario_started is None
                or scenario_ended is None
                or scenario_ended < scenario_started
                or (started is not None and scenario_started < started)
                or (ended is not None and scenario_ended > ended)
                or (
                    freeze_completed is not None
                    and scenario_started < freeze_completed
                )
                or (generated is not None and scenario_ended > generated)
                or (
                    artifact_timestamp is not None
                    and scenario_started < artifact_timestamp
                )
            ):
                errors.append(
                    f"post-freeze scenario {scenario_id} has an invalid time window"
                )
            if (
                type(window_days) is int
                and scenario_ended is not None
                and now - scenario_ended > dt.timedelta(days=window_days)
            ):
                errors.append(f"post-freeze scenario {scenario_id} is stale under policy")
            evidence_digest = evidence_row.get("evidenceDigest")
            if isinstance(evidence_digest, str):
                evidence_digests.append(evidence_digest)
    if len(evidence_digests) != len(set(evidence_digests)):
        errors.append("post-freeze scenarios reuse ambiguous evidence digests")
    if scan_value(value) or placeholder_findings(value):
        errors.append("post-freeze validation contains redaction findings or placeholders")
    _block_errors(
        state,
        "stable-1.0-ga.post-freeze-validation",
        "stable-1.0-ga.post-freeze-validation",
        errors,
        "Rerun every required production scenario against the exact frozen product bytes.",
    )


def validate_authorization(
    context: RunContext,
    selected: SelectedRc,
    ga_validation_authorization_identity: dict[str, Any],
    authorization: dict[str, Any] | None,
    policy: dict[str, Any],
    now: dt.datetime,
    state: ValidationState,
) -> None:
    """Validate explicit, scoped, unexpired GA publication authorization."""

    if authorization is None:
        state.block(
            "stable-1.0-ga.authorization-missing",
            "stable-1.0-ga.authorization",
            "Stable GA authorization is missing.",
            "Review the deterministic GA validation record and provide protected authorization.",
        )
        return
    errors = validate_schema(authorization, AUTHORIZATION_SCHEMA)
    expected = _expected_identity(context)
    catalog = selected.freeze.get("stableCatalog", {})
    expected_fields = {
        "releaseId": expected["releaseId"],
        "buildVersion": expected["buildVersion"],
        "sourceCommit": expected["sourceCommit"],
        "freezeDigest": selected.freeze.get("contentDigest"),
        "archiveDigest": selected.archive_digest,
        "productDistributionDigest": selected.product_digest,
        "catalogDigest": catalog.get("catalogDigest"),
        "catalogRevision": catalog.get("revision"),
        "gaValidationDigest": semantic_digest(ga_validation_authorization_identity),
        "publicationTargets": ga_validation_authorization_identity.get(
            "publicationTargets"
        ),
        "publicationTargetsDigest": ga_validation_authorization_identity.get(
            "publicationTargetsDigest"
        ),
        "status": "authorized",
    }
    for key, expected_value in expected_fields.items():
        if authorization.get(key) != expected_value:
            errors.append(f"Stable GA authorization {key} does not bind the validated candidate")
    authorization_policy = policy.get("authorization") if isinstance(policy.get("authorization"), dict) else {}
    if authorization.get("authorizationRole") != authorization_policy.get("requiredRole"):
        errors.append("Stable GA authorization role is under-authorized")
    if tuple(authorization.get("allowedPublicationScope", [])) != AUTHORIZATION_SCOPE:
        errors.append("Stable GA authorization publication scope is missing, reordered, or over-broad")
    approver = authorization.get("approverIdentity")
    normalized_approver = (
        approver.strip().casefold() if isinstance(approver, str) else ""
    )
    if (
        not normalized_approver
        or normalized_approver
        in {"unknown", "placeholder", "release-manager", "approver"}
        or placeholder_findings(approver)
    ):
        errors.append("Stable GA authorization approver identity is a placeholder")
    approved = parse_timestamp(authorization.get("approvedAt"))
    expires = parse_timestamp(authorization.get("expiresAt"))
    authorization_generated = parse_timestamp(authorization.get("generatedAt"))
    validated_at = parse_timestamp(
        ga_validation_authorization_identity.get("postFreezeValidationGeneratedAt")
    )
    review_hours = authorization.get("reviewWindowHours")
    if approved is None or expires is None or approved > now or expires <= now or expires <= approved:
        errors.append("Stable GA authorization approval/expiration window is invalid")
    elif type(review_hours) is int and expires - approved > dt.timedelta(hours=review_hours):
        errors.append("Stable GA authorization exceeds its declared review window")
    if (
        authorization_generated is None
        or authorization_generated > now
        or (approved is not None and authorization_generated < approved)
    ):
        errors.append("Stable GA authorization generatedAt is invalid")
    if validated_at is None or (approved is not None and approved < validated_at):
        errors.append("Stable GA authorization predates final exact-RC validation")
    if public_audit_redaction_findings(authorization) or placeholder_findings(authorization):
        errors.append("Stable GA authorization contains redaction findings or placeholders")
    _block_errors(
        state,
        "stable-1.0-ga.authorization",
        "stable-1.0-ga.authorization",
        errors,
        "Obtain a current Stable release-manager authorization for the exact GA validation digest.",
    )


def validate_carried_waivers(
    selected: SelectedRc,
    policy: dict[str, Any],
    now: dt.datetime,
    state: ValidationState,
) -> list[dict[str, Any]]:
    """Carry only RC waivers that policy explicitly permits for Stable GA."""

    waivers = selected.summary.get("acceptedWaivers")
    raw = [row for row in waivers if isinstance(row, dict)] if isinstance(waivers, list) else []
    allowed = policy.get("allowedRcWaiverIds")
    allowed_ids = set(allowed) if isinstance(allowed, list) else set()
    errors: list[str] = []
    carried: list[dict[str, Any]] = []
    for row in raw:
        waiver_id = row.get("id") or row.get("waiverId")
        if waiver_id not in allowed_ids:
            errors.append("an accepted RC waiver is not explicitly allowed for Stable GA")
        expires = parse_timestamp(row.get("expiresAt") or row.get("reviewBy"))
        if expires is None or expires <= now:
            errors.append("an accepted RC waiver expired before Stable GA authorization")
        if row.get("validationErrors") not in (None, []) or row.get("active") is False:
            errors.append("an accepted RC waiver is no longer valid")
        used_by = row.get("usedBy")
        if isinstance(used_by, list) and any(
            isinstance(item, str)
            and any(
                marker in item.lower()
                for marker in (
                    "redaction",
                    "signing",
                    "provenance",
                    "archive",
                    "integrity",
                    "candidate",
                    "binding",
                    "platform-api",
                    "api-compat",
                    "catalog",
                    "reviewer",
                    "sandbox",
                    "security",
                    "live-network",
                    "interop",
                    "upgrade",
                    "rollback",
                    "migration",
                    "backup",
                    "restore",
                )
            )
            for item in used_by
        ):
            errors.append("an accepted RC waiver attempts to cover a non-waivable GA blocker")
        if isinstance(waiver_id, str) and expires is not None:
            carried.append(
                {
                    "id": waiver_id,
                    "source": "stable-rc",
                    "status": "accepted",
                    "scope": str(row.get("scope") or row.get("reason") or "Stable RC waiver"),
                    "expiresAt": expires.replace(microsecond=0).isoformat().replace(
                        "+00:00", "Z"
                    ),
                    "stableGaAllowed": True,
                }
            )
    _block_errors(
        state,
        "stable-1.0-ga.carried-waivers",
        "stable-1.0-ga.final-decision",
        errors,
        "Remove the waiver or return to PR-283 for a corrected and fully refrozen candidate.",
    )
    return carried


def publication_receipt_errors(
    receipt: dict[str, Any],
    context: RunContext,
    selected: SelectedRc,
    lineage: dict[str, Any],
    promotion_identity_digest: str,
    release_notes_digest: str,
    planned_assets: list[dict[str, Any]],
) -> list[str]:
    """Return exact-state mismatches in one post-publication receipt."""

    errors = validate_schema(receipt, PUBLICATION_RECEIPT_SCHEMA)
    expected = _expected_identity(context)
    catalog = selected.freeze.get("stableCatalog", {})
    for key, expected_value in {
        "releaseId": expected["releaseId"],
        "buildVersion": expected["buildVersion"],
        "sourceCommit": expected["sourceCommit"],
        "publicationState": "publication-complete",
        "freezeDigest": selected.freeze.get("contentDigest"),
        "productDistributionDigest": selected.product_digest,
        "archiveDigest": selected.archive_digest,
        "gaPromotionSummaryDigest": promotion_identity_digest,
        "releaseNotesDigest": release_notes_digest,
        "finalVerificationStatus": "pass",
    }.items():
        if receipt.get(key) != expected_value:
            errors.append(f"publication receipt {key} does not match the authorized GA state")
    if receipt.get("operation") not in {"created", "verified-existing"}:
        errors.append("publication receipt operation is not a completed idempotent publication")
    if "failureCategory" in receipt:
        errors.append("completed publication receipt carries a contradictory failure category")
    tag = receipt.get("tag") if isinstance(receipt.get("tag"), dict) else {}
    if tag.get("name") != f"v{expected['buildVersion']}" or tag.get("targetCommit") != expected["sourceCommit"] or tag.get("annotated") is not True or tag.get("verificationStatus") != "pass":
        errors.append("publication receipt tag is not the authorized annotated tag")
    github_release = receipt.get("githubRelease") if isinstance(receipt.get("githubRelease"), dict) else {}
    selected_freeze = lineage.get("selectedFreeze") if isinstance(lineage.get("selectedFreeze"), dict) else {}
    selected_workflow = selected_freeze.get("workflow") if isinstance(selected_freeze.get("workflow"), dict) else {}
    expected_repository = selected_workflow.get("repository")
    expected_public_url = (
        f"https://github.com/{expected_repository}/releases/tag/v{expected['buildVersion']}"
        if isinstance(expected_repository, str)
        else None
    )
    if (
        github_release.get("publicUrl") != expected_public_url
        or github_release.get("releaseNotesDigest") != release_notes_digest
        or github_release.get("verificationStatus") != "pass"
    ):
        errors.append("publication receipt GitHub Release verification does not match")
    receipt_workflow = receipt.get("workflow") if isinstance(receipt.get("workflow"), dict) else {}
    if (
        expected_repository is None
        or receipt_workflow.get("repository") != expected_repository
    ):
        errors.append("publication receipt workflow repository does not match the selected RC lineage")
    artifact_base_uri = canonical_artifact_base_uri(
        context.manifest.policies.get("artifactBaseUri")
    )
    if receipt.get("artifactBaseUri") != artifact_base_uri:
        errors.append("publication receipt artifact base URI differs from the publication plan")
    expected_assets = {
        row["name"]: (row["sizeBytes"], row["digest"])
        for row in planned_assets
    }
    asset_rows = [
        row
        for row in receipt.get("assets", [])
        if isinstance(row, dict)
    ]
    actual_assets = {
        row.get("name"): (row.get("sizeBytes"), row.get("digest"))
        for row in asset_rows
    }
    expected_public_uris = {
        name: f"{artifact_base_uri}{name}"
        for name in expected_assets
    }
    public_observation = (
        receipt.get("publicStateObservation")
        if isinstance(receipt.get("publicStateObservation"), dict)
        else {}
    )
    tag_observation = (
        public_observation.get("tag")
        if isinstance(public_observation.get("tag"), dict)
        else {}
    )
    release_observation = (
        public_observation.get("githubRelease")
        if isinstance(public_observation.get("githubRelease"), dict)
        else {}
    )
    asset_observation = (
        public_observation.get("releaseAssets")
        if isinstance(public_observation.get("releaseAssets"), dict)
        else {}
    )
    if (
        len(asset_rows) != len(expected_assets)
        or len(actual_assets) != len(asset_rows)
        or any(row.get("verificationStatus") != "pass" for row in asset_rows)
        or any(
            row.get("publicUri") != expected_public_uris.get(row.get("name"))
            for row in asset_rows
        )
        or actual_assets != expected_assets
        or tag_observation.get("status") != "verified"
        or release_observation.get("status") != "verified"
        or asset_observation.get("status") != "verified"
        or asset_observation.get("observedCount") != len(expected_assets)
        or asset_observation.get("missingPlannedAssets") != []
        or asset_observation.get("unexpectedCount") != 0
        or asset_observation.get("unexpectedNameDigests") != []
    ):
        errors.append("publication receipt asset allowlist or digests differ from the publication plan")
    receipt_catalog = receipt.get("catalog") if isinstance(receipt.get("catalog"), dict) else {}
    key_rotation = catalog.get("keyRotationStatus") if isinstance(catalog.get("keyRotationStatus"), dict) else {}
    for key, expected_value in {
        "catalogId": catalog.get("catalogId"),
        "channel": "stable",
        "revision": catalog.get("revision"),
        "catalogDigest": catalog.get("catalogDigest"),
        "signatureDigest": catalog.get("signatureDigest"),
        "signingKeyId": catalog.get("catalogSigningKeyId"),
        "artifactTimestamp": catalog.get("artifactTimestamp"),
        "keyRotationStatus": key_rotation.get("status"),
        "advisoryCount": catalog.get("securityAdvisoryCount"),
        "denylistCount": catalog.get("denylistCount"),
        "verificationStatus": "pass",
    }.items():
        if receipt_catalog.get(key) != expected_value:
            errors.append(f"publication receipt catalog {key} differs from frozen state")
    primary = receipt_catalog.get("primary") if isinstance(receipt_catalog.get("primary"), dict) else {}
    mirrors = receipt_catalog.get("mirrors") if isinstance(receipt_catalog.get("mirrors"), list) else []
    target_catalog = canonical_publication_targets(context)["catalog"]
    expected_primary_uri = target_catalog["primaryUri"]
    expected_mirrors = [
        (f"mirror-{index}", uri)
        for index, uri in enumerate(target_catalog["mirrorUris"], start=1)
    ]
    actual_mirrors = [
        (row.get("locationId"), row.get("publicUri"))
        if isinstance(row, dict)
        else (None, None)
        for row in mirrors
    ]
    if (
        primary.get("locationId") != "primary"
        or primary.get("publicUri") != expected_primary_uri
        or primary.get("digest") != catalog.get("catalogDigest")
        or primary.get("signatureVerified") is not True
        or primary.get("verificationStatus") != "pass"
    ):
        errors.append("publication receipt primary catalog bytes/signature differ")
    if (
        actual_mirrors != expected_mirrors
        or any(
            not isinstance(row, dict)
            or row.get("digest") != catalog.get("catalogDigest")
            or row.get("signatureVerified") is not True
            or row.get("transportFallbackOnly") is not True
            or row.get("verificationStatus") != "pass"
            for row in mirrors
        )
    ):
        errors.append("publication receipt mirror catalog bytes/signatures differ")
    rollback = receipt_catalog.get("rollback") if isinstance(receipt_catalog.get("rollback"), dict) else {}
    frozen_rollback = catalog.get("verifiedRollback") if isinstance(catalog.get("verifiedRollback"), dict) else {}
    if (
        rollback.get("revision") != frozen_rollback.get("revision")
        or rollback.get("digest") != frozen_rollback.get("digest")
        or rollback.get("publicUri") != target_catalog.get("rollbackUri")
        or rollback.get("signingKeyId") != catalog.get("catalogSigningKeyId")
        or DIGEST_RE.fullmatch(str(rollback.get("signatureDigest", ""))) is None
        or rollback.get("signatureVerified") is not True
        or rollback.get("verificationStatus") != "pass"
    ):
        errors.append("publication receipt rollback catalog state differs from the freeze")
    if scan_value(receipt) or placeholder_findings(receipt):
        errors.append("publication receipt contains redaction findings or placeholders")
    return errors


def sanitized_public_asset_observation(
    observed_assets: Any,
    planned_assets: Any,
) -> dict[str, Any]:
    """Summarize remote asset names without retaining any unexpected raw name."""

    if not isinstance(observed_assets, list) or not isinstance(planned_assets, list):
        raise ValueError("public asset observation is malformed")
    observed_names: list[str] = []
    for row in observed_assets:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str):
            raise ValueError("public asset observation is malformed")
        observed_names.append(row["name"])
    planned_names: list[str] = []
    for row in planned_assets:
        name = row.get("name") if isinstance(row, dict) else None
        if not isinstance(name, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) is None:
            raise ValueError("planned public asset identity is malformed")
        planned_names.append(name)
    if len(set(observed_names)) != len(observed_names) or len(set(planned_names)) != len(
        planned_names
    ):
        raise ValueError("public asset observation contains duplicate names")
    observed_set = set(observed_names)
    planned_set = set(planned_names)
    unexpected_names = observed_set - planned_set
    return {
        "status": "observed",
        "observedCount": len(observed_names),
        "missingPlannedAssets": sorted(planned_set - observed_set),
        "unexpectedCount": len(unexpected_names),
        "unexpectedNameDigests": sorted(
            "sha256:" + hashlib.sha256(name.encode("utf-8")).hexdigest()
            for name in unexpected_names
        ),
    }


def sha256_bytes(value: bytes) -> str:
    """Return a normalized SHA-256 digest for in-archive bytes."""

    return "sha256:" + hashlib.sha256(value).hexdigest()
