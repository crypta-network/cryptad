"""Side-effect-free verification of local federated catalog evidence.

The engine authenticates bounded signed discovery records and a protected runtime observation. It
never fetches discovery data, changes local trust, contacts a node, publishes a catalog, or mutates
GitHub. Operational closeout additionally requires exact protected PR-291 through PR-294 artifact
coordinates; fixtures and self-tests can reach only fixture verification.
"""

from __future__ import annotations

import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit

from ..io import read_json, read_json_bytes, write_json, write_text
from ..redaction import scan_value
from ..schema_validation import validate_schema
from . import stable_1_0_third_party_pilot as pilot


EXECUTION_SCHEMA = "stable-1.0-federated-catalog-execution-v1.schema.json"
DESCRIPTOR_SCHEMA = "stable-1.0-catalog-discovery-descriptor-v1.schema.json"
ENDORSEMENT_SCHEMA = "stable-1.0-catalog-endorsement-v1.schema.json"
RUNTIME_SCHEMA = "stable-1.0-federated-catalog-runtime-observation-v1.schema.json"
SUMMARY_SCHEMA = "stable-1.0-federated-catalog-summary-v1.schema.json"
AUTHORITY_SUMMARY_SCHEMAS = {
    "protectedRelease": "stable-1.0-protected-release-execution-summary-v1.schema.json",
    "independentReproducibility": "stable-1.0-independent-reproducibility-summary-v1.schema.json",
    "catalogAuthority": "stable-1.0-catalog-authority-summary-v1.schema.json",
    "thirdPartyPilot": "stable-1.0-third-party-app-pilot-summary-v1.schema.json",
}
POLICY_FILE = "stable-1.0-federated-catalog-policy.json"

MODES = (
    "preflight",
    "verify-discovery",
    "verify-local-trust",
    "verify-conflicts",
    "verify-runtime",
    "closeout",
)
SUMMARY_FILE = "stable-1.0-federated-catalog-summary.json"
REPORT_FILE = "stable-1.0-federated-catalog-report.md"
REDACTION_FILE = "stable-1.0-federated-catalog-redaction-report.json"
MODE_FILES = {
    "preflight": "stable-1.0-federated-catalog-preflight.json",
    "verify-discovery": "stable-1.0-catalog-discovery-summary.json",
    "verify-local-trust": "stable-1.0-local-catalog-trust-summary.json",
    "verify-conflicts": "stable-1.0-catalog-conflict-summary.json",
    "verify-runtime": "stable-1.0-federated-catalog-runtime-summary.json",
    "closeout": SUMMARY_FILE,
}
ZERO_DIGEST = "sha256:" + "0" * 64
OPERATIONAL_STATES = frozenset(
    {
        "discovery-authenticated",
        "local-trust-configured",
        "conflict-policy-verified",
        "runtime-federation-verified",
        "operational-federation-complete",
    }
)
SIGNATURE_DOMAINS = {
    "stable-1.0-federated-catalog-runtime-observation":
        "cryptad.stable-1.0.federated-catalog-runtime-observation.v1",
}
AUTHORITY_WORKFLOW_KEYS = {
    "protectedRelease": "protectedRelease",
    "independentReproducibility": "independentReproducibility",
    "catalogAuthority": "catalogAuthority",
    "thirdPartyPilot": "thirdPartyPilot",
}

_RUNTIME_INSTANT = re.compile(
    r"^(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})T"
    r"(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?"
    r"(?P<zone>Z|[+-][0-9]{2}:[0-9]{2})$"
)
_INVALID_URI_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_INVALID_JAVA_URI_CHARACTER = re.compile(r'[\x00-\x20<>"{}|\\^`]')
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _semantic_digest(value: dict[str, Any], field: str) -> str:
    normalized = copy.deepcopy(value)
    normalized[field] = ZERO_DIGEST
    normalized.pop("signatureBase64", None)
    return _digest_bytes(_canonical_bytes(normalized))


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} is missing or malformed")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} is malformed") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} has no timezone offset")
    return parsed.astimezone(timezone.utc)


def _runtime_instant_text(value: Any) -> Any:
    """Render an ISO instant as java.time.Instant.toString() renders it."""

    if not isinstance(value, str):
        return value
    matched = _RUNTIME_INSTANT.fullmatch(value)
    if matched is None:
        return value
    zone = matched.group("zone")
    try:
        if zone == "Z":
            offset = timezone.utc
        else:
            offset_hours = int(zone[1:3])
            offset_minutes = int(zone[4:6])
            if offset_hours > 18 or offset_minutes > 59 or (
                offset_hours == 18 and offset_minutes != 0
            ):
                return value
            direction = 1 if zone[0] == "+" else -1
            offset = timezone(
                direction * timedelta(hours=offset_hours, minutes=offset_minutes)
            )
        parsed = datetime.fromisoformat(
            f"{matched.group('date')}T{matched.group('time')}"
        ).replace(tzinfo=offset)
    except ValueError:
        return value
    normalized = parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    fraction = matched.group("fraction")
    if fraction is None or int(fraction) == 0:
        return normalized + "Z"
    nanoseconds = int(fraction.ljust(9, "0"))
    digits = 3 if nanoseconds % 1_000_000 == 0 else 6 if nanoseconds % 1_000 == 0 else 9
    return f"{normalized}.{nanoseconds:09d}"[: len(normalized) + 1 + digits] + "Z"


def _confined_path(
    workspace: Path, requested: Path, label: str, *, directory: bool
) -> Path:
    candidate = requested if requested.is_absolute() else workspace / requested
    current = workspace
    try:
        relative = candidate.relative_to(workspace)
    except ValueError as exc:
        raise ValueError(f"{label} is outside the workspace") from exc
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"{label} contains a symlink")
    resolved = candidate.resolve()
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise ValueError(f"{label} escapes the workspace") from exc
    if directory:
        if not resolved.is_dir():
            raise ValueError(f"{label} is not a directory")
    elif not resolved.is_file():
        raise ValueError(f"{label} is not a regular file")
    return resolved


def _output_directory(workspace: Path, requested: Path) -> Path:
    candidate = requested if requested.is_absolute() else workspace / requested
    try:
        relative = candidate.relative_to(workspace)
    except ValueError as exc:
        raise ValueError("federated catalog output is outside the workspace") from exc
    current = workspace
    for part in relative.parts[:-1]:
        current /= part
        if current.is_symlink():
            raise ValueError("federated catalog output parent contains a symlink")
        if current.exists() and not current.is_dir():
            raise ValueError("federated catalog output parent is not a directory")
    parent = candidate.parent
    parent.mkdir(parents=True, exist_ok=True)
    _confined_path(workspace, parent, "federated catalog output parent", directory=True)
    if candidate.is_symlink() or (candidate.exists() and not candidate.is_dir()):
        raise ValueError("federated catalog output is not a real directory")
    candidate.mkdir(exist_ok=True)
    resolved = _confined_path(
        workspace, candidate, "federated catalog output", directory=True
    )
    if any(resolved.iterdir()):
        raise ValueError("federated catalog output directory must be empty")
    return resolved


def _policy(workspace: Path) -> tuple[dict[str, Any], str]:
    value = read_json(workspace / "tools" / "release-certification" / POLICY_FILE)
    if not isinstance(value, dict):
        raise ValueError("federated catalog policy is malformed")
    expected = _semantic_digest(value, "policyDigest")
    if value.get("policyDigest") != expected:
        raise ValueError("federated catalog policy digest is invalid")
    return value, expected


def _evaluation_time(contract: dict[str, Any], policy: dict[str, Any]) -> datetime:
    declared = _timestamp(contract["evaluationTime"], "evaluation time")
    if contract["fixtureOnly"] or contract["selfTest"]:
        return declared
    current = datetime.now(timezone.utc).replace(microsecond=0)
    skew = timedelta(seconds=policy["freshness"]["maximumClockSkewSeconds"])
    if declared > current + skew:
        raise ValueError("operational federation evaluation time is in the future")
    return current


def _redaction_view(value: Any) -> Any:
    public_fields = {
        "issuerPublicKeySpkiBase64",
        "observerPublicKeySpkiBase64",
        "signatureBase64",
    }
    if isinstance(value, dict):
        return {
            key: "<public-cryptographic-value>"
            if key in public_fields
            else _redaction_view(child)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_redaction_view(child) for child in value]
    return value


def _bound_json(
    evidence_dir: Path | None,
    binding: dict[str, Any] | None,
    schema: str,
    label: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    if binding is None:
        return None, [f"{label} is not bound"]
    if evidence_dir is None:
        return None, [f"{label} requires a confined evidence directory"]
    path = evidence_dir / binding["fileName"]
    try:
        resolved = _confined_path(evidence_dir, path, label, directory=False)
        size = resolved.stat().st_size
        if size != binding["size"]:
            return None, [f"{label} size differs from its binding"]
        if schema in (DESCRIPTOR_SCHEMA, ENDORSEMENT_SCHEMA) and size > 64 * 1024:
            return None, [f"{label} exceeds the runtime signed-document size limit"]
        encoded = resolved.read_bytes()
        if _digest_bytes(encoded) != binding["digest"]:
            return None, [f"{label} digest differs from its binding"]
        value = read_json_bytes(encoded, label)
    except (OSError, ValueError) as exc:
        return None, [str(exc)]
    if not isinstance(value, dict):
        return None, [f"{label} is not a JSON object"]
    errors = validate_schema(value, schema)
    if scan_value(_redaction_view(value)):
        errors.append(f"{label} contains prohibited or unredacted material")
    return value, [f"{label}: {error}" for error in errors]


def _evidence_member_errors(
    evidence_dir: Path,
    contract_path: Path,
    contract: dict[str, Any],
    policy: dict[str, Any],
) -> list[str]:
    """Reject every archive member not named by the closed execution contract."""

    expected: set[str] = set()
    descriptor = contract["evidence"]["descriptor"]
    if descriptor is not None:
        expected.add(descriptor["fileName"])
    expected.update(item["fileName"] for item in contract["evidence"]["endorsements"])
    runtime = contract["evidence"]["runtimeObservation"]
    if runtime is not None:
        expected.add(runtime["fileName"])
    for authority in contract["authorities"].values():
        summary = authority["summary"]
        if summary is not None:
            expected.add(summary["fileName"])
    try:
        contract_relative = contract_path.relative_to(evidence_dir)
    except ValueError:
        contract_relative = None
    if contract_relative is not None:
        expected.add(contract_relative.as_posix())

    errors: list[str] = []
    observed: set[str] = set()
    total_size = 0
    for member in evidence_dir.rglob("*"):
        relative = member.relative_to(evidence_dir).as_posix()
        if member.is_symlink():
            errors.append(f"federation evidence member is a symlink: {relative}")
            continue
        if member.is_dir():
            errors.append(f"federation evidence contains an unexpected directory: {relative}")
            continue
        observed.add(relative)
        if relative not in expected:
            errors.append(f"federation evidence contains an unbound member: {relative}")
            continue
        try:
            encoded = member.read_bytes()
            total_size += len(encoded)
            value = read_json_bytes(encoded, f"federation evidence member {relative}")
        except (OSError, ValueError) as exc:
            errors.append(str(exc))
            continue
        if scan_value(_redaction_view(value)):
            errors.append(f"federation evidence member is not redaction-safe: {relative}")
    for missing in sorted(expected - observed):
        errors.append(f"federation evidence is missing a bound member: {missing}")
    if len(observed) > 256:
        errors.append("federation evidence exceeds the member-count limit")
    if total_size > 64 * 1024 * 1024:
        errors.append("federation evidence exceeds the expanded-size limit")
    if (
        len(contract["evidence"]["endorsements"])
        > policy["limits"]["maximumEndorsements"]
    ):
        errors.append("federation evidence exceeds the endorsement-count limit")
    maximum_file_size = policy["limits"]["maximumEvidenceBytes"]
    for binding in (
        [descriptor] if descriptor is not None else []
    ) + list(contract["evidence"]["endorsements"]) + (
        [runtime] if runtime is not None else []
    ) + [
        authority["summary"]
        for authority in contract["authorities"].values()
        if authority["summary"] is not None
    ]:
        if binding["size"] > maximum_file_size:
            errors.append(f"bound evidence exceeds the per-file limit: {binding['fileName']}")
    return errors


def _signature_subject(value: dict[str, Any]) -> bytes:
    normalized = copy.deepcopy(value)
    normalized.pop("signatureBase64", None)
    domain = SIGNATURE_DOMAINS.get(str(normalized.get("kind")))
    if domain is None:
        raise ValueError("federation record has an unknown signature domain")
    return domain.encode("ascii") + b"\x00" + _canonical_bytes(normalized)


def _public_identity_errors(
    value: dict[str, Any], key_field: str, fingerprint_field: str, label: str
) -> list[str]:
    try:
        encoded = base64.b64decode(value[key_field], validate=True)
    except (KeyError, TypeError, ValueError):
        return [f"{label} public key is malformed"]
    if _digest_bytes(encoded) != value.get(fingerprint_field):
        return [f"{label} public key fingerprint differs"]
    return []


def _signed_record_errors(
    value: dict[str, Any], digest_field: str, key_field: str, label: str
) -> list[str]:
    errors = _public_identity_errors(
        value,
        key_field,
        "issuerFingerprint" if key_field == "issuerPublicKeySpkiBase64" else "observerFingerprint",
        label,
    )
    if value.get(digest_field) != _semantic_digest(value, digest_field):
        errors.append(f"{label} self-digest differs")
    errors.extend(
        pilot._verify(
            value.get(key_field, ""),
            _signature_subject(value),
            value.get("signatureBase64"),
            label,
        )
    )
    return errors


def _runtime_document_bytes(value: Any) -> bytes:
    """Match CatalogSignedDocumentSupport.jsonBytes exactly, including its final newline."""
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=False,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _runtime_descriptor_content(value: dict[str, Any]) -> dict[str, Any]:
    subject = value["subject"]
    display = value["display"]
    transparency = value["transparency"]
    validity = value["validity"]
    issuer = value["issuer"]
    normalized_transparency = {
        key: transparency[key]
        for key in (
            "reviewerSetDigestSha256",
            "reviewerSetUri",
            "publisherPolicyDigestSha256",
            "publisherPolicyUri",
        )
        if key in transparency
    }
    normalized_validity = {
        "issuedAt": _runtime_instant_text(validity["issuedAt"]),
        "expiresAt": _runtime_instant_text(validity["expiresAt"]),
    }
    for key in ("predecessorDigestSha256", "successorDigestSha256"):
        if key in validity:
            normalized_validity[key] = validity[key]
    return {
        "schemaVersion": value["schemaVersion"],
        "descriptorId": value["descriptorId"],
        "subject": {
            "catalogId": subject["catalogId"],
            "signerKeyId": subject["signerKeyId"],
            "signerFingerprintSha256": subject["signerFingerprintSha256"],
            "sourceHints": subject["sourceHints"],
            "channels": subject["channels"],
        },
        "display": {
            "name": display["name"],
            "summary": display["summary"],
            "providerId": display["providerId"],
        },
        "transparency": normalized_transparency,
        "validity": normalized_validity,
        "issuer": {
            "issuerId": issuer["issuerId"],
            "keyId": issuer["keyId"],
            "keyFingerprintSha256": issuer["keyFingerprintSha256"],
        },
    }


def _runtime_endorsement_content(value: dict[str, Any]) -> dict[str, Any]:
    subject = value["subject"]
    evidence = value["evidence"]
    validity = value["validity"]
    issuer = value["issuer"]
    normalized_evidence = {
        key: evidence[key]
        for key in ("reviewerSetDigestSha256", "publisherPolicyDigestSha256")
        if key in evidence
    }
    normalized_evidence["labels"] = evidence["labels"]
    if "reason" in evidence:
        normalized_evidence["reason"] = evidence["reason"]
    return {
        "schemaVersion": value["schemaVersion"],
        "endorsementId": value["endorsementId"],
        "subject": {
            "catalogId": subject["catalogId"],
            "signerFingerprintSha256": subject["signerFingerprintSha256"],
            "descriptorDigestSha256": subject["descriptorDigestSha256"],
        },
        "evidence": normalized_evidence,
        "validity": {
            "issuedAt": _runtime_instant_text(validity["issuedAt"]),
            "expiresAt": _runtime_instant_text(validity["expiresAt"]),
        },
        "issuer": {
            "issuerId": issuer["issuerId"],
            "keyId": issuer["keyId"],
            "keyFingerprintSha256": issuer["keyFingerprintSha256"],
        },
    }


def _runtime_signed_document_errors(
    value: dict[str, Any],
    binding: dict[str, Any],
    content: dict[str, Any],
    label: str,
) -> list[str]:
    key = binding.get("issuerPublicKeySpkiBase64", "")
    try:
        encoded = base64.b64decode(key, validate=True)
    except (TypeError, ValueError):
        return [f"{label} public key is malformed"]
    errors: list[str] = []
    fingerprint = hashlib.sha256(encoded).hexdigest()
    if value["issuer"]["keyFingerprintSha256"] != fingerprint:
        errors.append(f"{label} public key fingerprint differs")
    expected_digest = hashlib.sha256(_runtime_document_bytes(content)).hexdigest()
    if value.get("selfDigestSha256") != expected_digest:
        errors.append(f"{label} self-digest differs")
    signed = dict(content)
    signed["selfDigestSha256"] = value.get("selfDigestSha256")
    errors.extend(
        pilot._verify(
            key,
            _runtime_document_bytes(signed),
            value.get("signature", {}).get("valueBase64"),
            label,
        )
    )
    return errors


def _qualified_runtime_digest(value: dict[str, Any]) -> str:
    return "sha256:" + value["selfDigestSha256"]


def _freshness_errors(
    issued_at: Any,
    expires_at: Any,
    evaluation: datetime,
    maximum_age: int,
    label: str,
) -> list[str]:
    try:
        issued = _timestamp(issued_at, f"{label} issuedAt")
        expires = _timestamp(expires_at, f"{label} expiresAt")
    except ValueError as exc:
        return [str(exc)]
    errors: list[str] = []
    if issued > evaluation:
        errors.append(f"{label} is issued in the future")
    if expires <= evaluation or expires <= issued:
        errors.append(f"{label} is stale or has an invalid validity interval")
    if evaluation - issued > timedelta(seconds=maximum_age):
        errors.append(f"{label} exceeds the maximum age")
    return errors


def _source_hint_errors(hints: list[str]) -> list[str]:
    errors: list[str] = []
    for hint in hints:
        try:
            scheme = urlsplit(hint).scheme.casefold()
        except ValueError:
            scheme = ""
        if scheme == "https":
            if not _valid_public_https_uri(hint):
                errors.append("descriptor HTTPS source hint is not public and canonical")
        elif scheme != "crypta" or not _valid_crypta_catalog_hint(hint):
            errors.append("descriptor source hint uses an unsupported scheme")
    return errors


def _valid_public_https_uri(value: str) -> bool:
    """Apply the Java URI syntax and public-host constraints used by the runtime."""

    if (
        "?" in value
        or "#" in value
        or _INVALID_URI_ESCAPE.search(value)
        or _INVALID_JAVA_URI_CHARACTER.search(value)
    ):
        return False
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
    except ValueError:
        return False
    if (
        parsed.scheme.casefold() != "https"
        or not hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.query
        or not _valid_https_authority(parsed.netloc)
        or not _valid_runtime_host_syntax(hostname)
    ):
        return False
    return _public_host(hostname)


def _valid_https_authority(authority: str) -> bool:
    if not authority or "@" in authority:
        return False
    if authority.startswith("["):
        closing = authority.find("]")
        if closing < 0:
            return False
        suffix = authority[closing + 1 :]
        return not suffix or suffix == ":" or (
            suffix.startswith(":") and suffix[1:].isdigit()
        )
    if authority.count(":") > 1:
        return False
    if ":" not in authority:
        return True
    port = authority.rsplit(":", 1)[1]
    return not port or port.isdigit()


def _valid_runtime_host_syntax(hostname: str) -> bool:
    host = hostname.removesuffix(".")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if not host or ":" in host or "%" in host or not host.isascii():
        return False
    labels = host.split(".")
    if any(_DNS_LABEL.fullmatch(label) is None for label in labels):
        return False
    return len(labels) == 1 or labels[-1][0].isalpha()


def _public_host(hostname: str) -> bool:
    host = hostname.casefold().strip("[]").removesuffix(".")
    if (
        host == "localhost"
        or host.endswith((".localhost", ".local", ".internal"))
    ):
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return ":" not in host and not (
            bool(host) and all(value.isdigit() or value == "." for value in host)
        )
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if isinstance(address, ipaddress.IPv4Address):
        blocked_v4 = (
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/4",
            "240.0.0.0/4",
        )
        return not any(address in ipaddress.ip_network(value) for value in blocked_v4)
    global_v6 = ipaddress.ip_network("2000::/3")
    blocked_v6 = (
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "3fff::/20",
    )
    return address in global_v6 and not any(
        address in ipaddress.ip_network(value) for value in blocked_v6
    )


def _valid_crypta_catalog_hint(hint: str) -> bool:
    if "#" in hint:
        return False
    body = hint[len("crypta:") :]
    if body.startswith(("USK@", "SSK@")):
        return "?" not in body and 0 < body.rfind("/") < len(body) - 1
    if not body.startswith("CHK@") or body.count("?signature=") != 1:
        return False
    catalog_key, signature_key = body.split("?signature=", 1)
    return (
        catalog_key.startswith("CHK@")
        and signature_key.startswith("CHK@")
        and "?" not in catalog_key
        and "?" not in signature_key
        and "&" not in signature_key
    )


def _validity_interval_errors(
    issued_at: Any, expires_at: Any, label: str
) -> list[str]:
    try:
        issued = _timestamp(issued_at, f"{label} issuedAt")
        expires = _timestamp(expires_at, f"{label} expiresAt")
    except ValueError as exc:
        return [str(exc)]
    if expires - issued > timedelta(days=90):
        return [f"{label} validity exceeds the runtime 90-day limit"]
    return []


def _public_reference_errors(value: str, label: str) -> list[str]:
    try:
        scheme = urlsplit(value).scheme.casefold()
    except ValueError:
        scheme = ""
    if scheme == "https":
        if not _valid_public_https_uri(value):
            return [f"{label} is not a canonical public HTTPS reference"]
        return []
    body = value[len("crypta:") :] if value.startswith("crypta:") else ""
    if scheme != "crypta" or "#" in value or not body.startswith(("CHK@", "SSK@", "USK@")):
        return [f"{label} is not a supported public reference"]
    return []


def _descriptor_errors(
    descriptor: dict[str, Any],
    binding: dict[str, Any],
    evaluation: datetime,
    policy: dict[str, Any],
) -> list[str]:
    errors = _runtime_signed_document_errors(
        descriptor,
        binding,
        _runtime_descriptor_content(descriptor),
        "discovery descriptor",
    )
    errors.extend(_source_hint_errors(descriptor["subject"]["sourceHints"]))
    for field in ("reviewerSetUri", "publisherPolicyUri"):
        if field in descriptor["transparency"]:
            errors.extend(
                _public_reference_errors(
                    descriptor["transparency"][field], f"descriptor {field}"
                )
            )
    errors.extend(
        _validity_interval_errors(
            descriptor["validity"]["issuedAt"],
            descriptor["validity"]["expiresAt"],
            "discovery descriptor",
        )
    )
    errors.extend(
        _freshness_errors(
            descriptor["validity"]["issuedAt"],
            descriptor["validity"]["expiresAt"],
            evaluation,
            policy["freshness"]["maximumDescriptorAgeSeconds"],
            "discovery descriptor",
        )
    )
    return errors


def _endorsement_errors(
    endorsement: dict[str, Any],
    binding: dict[str, Any],
    descriptor: dict[str, Any],
    evaluation: datetime,
    policy: dict[str, Any],
) -> list[str]:
    errors = _runtime_signed_document_errors(
        endorsement,
        binding,
        _runtime_endorsement_content(endorsement),
        "catalog endorsement",
    )
    if (
        endorsement["subject"]["catalogId"] != descriptor["subject"]["catalogId"]
        or endorsement["subject"]["signerFingerprintSha256"]
        != descriptor["subject"]["signerFingerprintSha256"]
        or endorsement["subject"]["descriptorDigestSha256"]
        != descriptor["selfDigestSha256"]
    ):
        errors.append("catalog endorsement subject differs from the descriptor")
    errors.extend(
        _validity_interval_errors(
            endorsement["validity"]["issuedAt"],
            endorsement["validity"]["expiresAt"],
            "catalog endorsement",
        )
    )
    errors.extend(
        _freshness_errors(
            endorsement["validity"]["issuedAt"],
            endorsement["validity"]["expiresAt"],
            evaluation,
            policy["freshness"]["maximumDescriptorAgeSeconds"],
            "catalog endorsement",
        )
    )
    return errors


def _runtime_errors(
    observation: dict[str, Any],
    binding: dict[str, Any],
    contract: dict[str, Any],
    descriptor: dict[str, Any],
    endorsements: list[dict[str, Any]],
    evaluation: datetime,
    policy: dict[str, Any],
) -> list[str]:
    errors = _runtime_authority_errors(observation, binding, contract, policy)
    errors.extend(_signed_record_errors(
        observation,
        "receiptDigest",
        "observerPublicKeySpkiBase64",
        "federated catalog runtime observation",
    ))
    if observation["executionId"] != contract["executionId"]:
        errors.append("runtime observation execution identity differs")
    if not (contract["fixtureOnly"] or contract["selfTest"]):
        runtime_identities = (
            observation["executionId"],
            observation["provenance"]["artifactName"],
            observation["provenance"]["environment"],
            *(item["catalogId"] for item in observation["catalogs"]),
        )
        markers = ("fixture", "sample", "template", "self-test", "selftest", "test-only")
        if any(
            marker in str(value).casefold()
            for value in runtime_identities
            for marker in markers
        ):
            errors.append("fixture, sample, template, or test runtime identity cannot be operational")
    expected_authorities = {
        name: contract["authorities"][name]["summaryDigest"]
        for name in AUTHORITY_WORKFLOW_KEYS
    }
    if observation["authorityDigests"] != expected_authorities:
        errors.append("runtime observation authority roots differ")
    if observation["discovery"]["descriptorDigest"] != _qualified_runtime_digest(descriptor):
        errors.append("runtime observation descriptor digest differs")
    expected_endorsements = sorted(_qualified_runtime_digest(item) for item in endorsements)
    if sorted(observation["discovery"]["endorsementDigests"]) != expected_endorsements:
        errors.append("runtime observation endorsement set differs")
    if observation["catalogCount"] != len(observation["catalogs"]):
        errors.append("runtime observation catalog count differs")
    catalog_ids = [item["catalogId"] for item in observation["catalogs"]]
    binding_ids = [item["trustBindingId"] for item in observation["catalogs"]]
    if len(catalog_ids) != len(set(catalog_ids)):
        errors.append("runtime observation aliases a catalog ID")
    if len(binding_ids) != len(set(binding_ids)):
        errors.append("runtime observation aliases a local trust binding")
    if descriptor["subject"]["catalogId"] not in catalog_ids:
        errors.append("discovered catalog is absent from the runtime topology")
    active = sum(item["status"] == "active" for item in observation["catalogs"])
    if observation["activeCatalogCount"] != active:
        errors.append("runtime observation active catalog count differs")
    errors.extend(
        _freshness_errors(
            observation["observedAt"],
            observation["expiresAt"],
            evaluation,
            policy["freshness"]["maximumRuntimeObservationAgeSeconds"],
            "federated catalog runtime observation",
        )
    )
    return errors


def _runtime_authority_errors(
    observation: dict[str, Any],
    binding: dict[str, Any],
    contract: dict[str, Any],
    policy: dict[str, Any],
) -> list[str]:
    """Bind a signed receipt to an independently protected observer producer."""

    errors: list[str] = []
    if (
        observation["observerKeyId"] != binding["observerKeyId"]
        or observation["observerFingerprint"] != binding["observerFingerprint"]
        or observation["observerPublicKeySpkiBase64"]
        != binding["observerPublicKeySpkiBase64"]
    ):
        errors.append("runtime observer identity differs from its independent binding")

    collected = observation["provenance"]
    receipt = binding["receiptProvenance"]
    source_commit = contract["repository"]["sourceCommit"]
    expected = policy["runtimeAuthority"]
    shared_coordinates = (
        "repositoryIdentity",
        "workflowPath",
        "workflowCommit",
        "runId",
        "runAttempt",
        "environment",
        "conclusion",
    )
    if any(collected[field] != receipt[field] for field in shared_coordinates):
        errors.append("runtime observation and signed-receipt producer coordinates differ")
    for label, provenance in (("observation", collected), ("receipt", receipt)):
        if (
            provenance["repositoryIdentity"] != policy["repositoryIdentity"]
            or provenance["workflowPath"] != expected["workflowPath"]
            or provenance["workflowCommit"] != source_commit
            or provenance["environment"] != expected["environment"]
            or provenance["conclusion"] != "success"
        ):
            errors.append(
                f"runtime {label} provenance is not the protected observer producer"
            )
    if collected["artifactName"] == receipt["artifactName"]:
        errors.append("runtime observation and signed receipt artifacts are not role-separated")
    if (
        collected["artifactDigest"] == ZERO_DIGEST
        or receipt["artifactDigest"] == ZERO_DIGEST
    ):
        errors.append("runtime producer artifact digest is unset")
    return errors


def _authority_summary_errors(
    name: str,
    summary: dict[str, Any],
    binding: dict[str, Any],
    contract: dict[str, Any],
) -> list[str]:
    authority = contract["authorities"][name]
    release = contract["release"]
    source_commit = contract["repository"]["sourceCommit"]
    errors: list[str] = []
    if name == "protectedRelease":
        if authority["summaryDigest"] != binding["digest"]:
            errors.append("protectedRelease summary file digest differs")
        if (
            summary["mode"] != "closeout"
            or summary["status"] != "pass"
            or summary["lifecycleState"] != "publicly-observed"
            or summary["candidateCommit"] != source_commit
            or summary["releaseId"] != release["releaseId"]
            or summary["buildVersion"] != release["buildVersion"]
            or summary["redaction"]["status"] != "pass"
            or summary["findings"]
        ):
            errors.append("protectedRelease summary is not an exact successful closeout")
        classifications = summary["evidenceClassification"]
        if (
            classifications["protectedRcOperation"] != "completed"
            or classifications["gaValidation"] != "completed"
            or classifications["gaPublication"] != "completed"
            or classifications["publicObservation"] != "completed"
            or classifications["independentReproducibility"]
            != "independently-reproduced"
        ):
            errors.append("protectedRelease summary lacks completed protected authorities")
        return errors

    expected_digest = _semantic_digest(summary, "summaryDigest")
    if summary.get("summaryDigest") != expected_digest:
        errors.append(f"{name} summary self digest is invalid")
    if authority["summaryDigest"] != summary.get("summaryDigest"):
        errors.append(f"{name} summary digest differs")
    expected_build = int(release["buildVersion"])
    if (
        summary.get("releaseId") != release["releaseId"]
        or summary.get("buildVersion") != expected_build
        or summary.get("sourceCommit") != source_commit
    ):
        errors.append(f"{name} summary release identity differs")

    if name == "independentReproducibility":
        if (
            summary["operationMode"] != "closeout"
            or summary["lifecycleState"] != "independently-reproduced"
            or summary["status"] != "independently-reproduced"
            or summary["comparisonStatus"] != "pass"
            or summary["evidenceClassification"] != "authenticated-external-provider"
            or summary["fixture"]
            or summary["selfTest"]
            or not summary["operational"]
            or summary["redaction"]["status"] != "pass"
            or summary["blockers"]
        ):
            errors.append(
                "independentReproducibility summary is not an authenticated operational closeout"
            )
    elif name == "catalogAuthority":
        if (
            summary["mode"] != "closeout"
            or summary["status"] != "pass"
            or summary["fixtureOnly"]
            or summary["blockers"]
            or any(value != "pass" for value in summary["checks"].values())
        ):
            errors.append("catalogAuthority summary is not a successful protected closeout")
        if (
            summary["protectedReleaseSummaryDigest"]
            != contract["authorities"]["protectedRelease"]["summaryDigest"]
            or summary["independentReproducibilitySummaryDigest"]
            != contract["authorities"]["independentReproducibility"]["summaryDigest"]
        ):
            errors.append("catalogAuthority summary predecessor roots differ")
    elif name == "thirdPartyPilot":
        if (
            summary["mode"] != "closeout"
            or summary["status"] != "pass"
            or summary["state"] != "operational-pilot-complete"
            or summary["fixtureOnly"]
            or summary["selfTest"]
            or not summary["operational"]
            or not summary["operationalPilotComplete"]
            or summary["blockers"]
        ):
            errors.append("thirdPartyPilot summary is not an operational closeout")
        expected_roots = {
            predecessor: contract["authorities"][predecessor]["summaryDigest"]
            for predecessor in (
                "protectedRelease",
                "independentReproducibility",
                "catalogAuthority",
            )
        }
        if any(
            summary["authorityDigests"][predecessor] != digest
            for predecessor, digest in expected_roots.items()
        ):
            errors.append("thirdPartyPilot summary predecessor roots differ")
    return errors


def _authority_errors(
    contract: dict[str, Any], policy: dict[str, Any], evidence_dir: Path | None
) -> list[str]:
    errors: list[str] = []
    required = policy["requiredAuthorityWorkflows"]
    for name, workflow_key in AUTHORITY_WORKFLOW_KEYS.items():
        authority = contract["authorities"][name]
        provenance = authority["provenance"]
        if authority["operational"] is not True:
            errors.append(f"{name} authority is not operational")
        if provenance["repositoryIdentity"] != policy["repositoryIdentity"]:
            errors.append(f"{name} authority repository differs")
        if provenance["workflowPath"] != required[workflow_key]:
            errors.append(f"{name} authority workflow differs")
        if provenance["workflowCommit"] != contract["repository"]["sourceCommit"]:
            errors.append(f"{name} authority source commit differs")
        if provenance["artifactDigest"] != authority["artifactDigest"]:
            errors.append(f"{name} authority artifact digest differs")
        if authority["summaryDigest"] == ZERO_DIGEST:
            errors.append(f"{name} authority summary digest is unset")
        summary, summary_errors = _bound_json(
            evidence_dir,
            authority["summary"],
            AUTHORITY_SUMMARY_SCHEMAS[name],
            f"{name} predecessor summary",
        )
        errors.extend(summary_errors)
        if summary is not None and not summary_errors:
            errors.extend(
                _authority_summary_errors(
                    name, summary, authority["summary"], contract
                )
            )
    return errors


def _operational_identity_errors(contract: dict[str, Any]) -> list[str]:
    """Reject test-shaped identities even when caller classification flags are false."""

    markers = ("fixture", "sample", "template", "self-test", "selftest", "test-only")
    identities = (
        contract["executionId"],
        contract["release"]["releaseId"],
        *(item["provenance"]["artifactName"] for item in contract["authorities"].values()),
        *(item["provenance"]["environment"] for item in contract["authorities"].values()),
    )
    if any(marker in str(value).casefold() for value in identities for marker in markers):
        return ["fixture, sample, template, or test identity cannot be operational"]
    return []


def _blocker(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")
    return (normalized or "verification-failed")[:160]


def _report(summary: dict[str, Any]) -> str:
    lines = [
        "# Stable 1.0 federated catalog verification",
        "",
        f"- Execution: `{summary['executionId']}`",
        f"- Mode: `{summary['mode']}`",
        f"- Status: `{summary['status']}`",
        f"- State: `{summary['state']}`",
        f"- Operational: `{'yes' if summary['operational'] else 'no'}`",
        "",
        "This side-effect-free report does not prove public federation or protected runtime execution unless the operational closeout state is present and every protected authority coordinate was authenticated.",
        "",
        "## Checks",
        "",
    ]
    lines.extend(f"- `{row['id']}`: `{row['status']}`" for row in summary["checks"])
    if summary["blockers"]:
        lines.extend(("", "## Blockers", ""))
        lines.extend(f"- `{item}`" for item in summary["blockers"])
    return "\n".join(lines) + "\n"


def run(
    workspace_root: Path,
    execution_contract: Path,
    mode: str,
    out_dir: Path | None = None,
    evidence_dir: Path | None = None,
) -> int:
    """Verify one federation phase and emit only bounded redacted local evidence."""

    if mode not in MODES:
        raise ValueError("unsupported federated catalog mode")
    workspace = workspace_root.resolve()
    contract_path = _confined_path(
        workspace, execution_contract, "federated catalog contract", directory=False
    )
    contract = read_json(contract_path)
    if not isinstance(contract, dict):
        raise ValueError("federated catalog contract is not an object")
    schema_errors = validate_schema(contract, EXECUTION_SCHEMA)
    if schema_errors:
        raise ValueError(
            "federated catalog contract failed its closed schema: "
            + "; ".join(schema_errors[:8])
        )
    if scan_value(contract):
        raise ValueError("federated catalog contract contains prohibited material")
    policy, policy_digest = _policy(workspace)
    if contract["policyDigest"] != policy_digest:
        raise ValueError("federated catalog contract binds another policy")
    evaluation = _evaluation_time(contract, policy)
    fixture = contract["fixtureOnly"] or contract["selfTest"]
    errors: list[str] = []
    if fixture and contract["requestedState"] in OPERATIONAL_STATES:
        errors.append("fixture or self-test contract requests an operational state")
    if not fixture:
        errors.extend(_operational_identity_errors(contract))

    resolved_evidence = None
    if evidence_dir is not None:
        resolved_evidence = _confined_path(
            workspace, evidence_dir, "federated catalog evidence directory", directory=True
        )
        errors.extend(
            _evidence_member_errors(
                resolved_evidence, contract_path, contract, policy
            )
        )

    rank = MODES.index(mode)
    descriptor: dict[str, Any] | None = None
    endorsements: list[dict[str, Any]] = []
    observation: dict[str, Any] | None = None
    stage_ok = {name: False for name in ("preflight", "discovery", "trust", "conflicts", "runtime", "roots")}
    stage_ok["preflight"] = not errors

    if rank >= 1:
        descriptor, stage_errors = _bound_json(
            resolved_evidence,
            contract["evidence"]["descriptor"],
            DESCRIPTOR_SCHEMA,
            "discovery descriptor",
        )
        if descriptor is not None and not stage_errors:
            stage_errors.extend(
                _descriptor_errors(
                    descriptor,
                    contract["evidence"]["descriptor"],
                    evaluation,
                    policy,
                )
            )
        endorsement_ids: set[str] = set()
        endorsement_digests: set[str] = set()
        for index, binding in enumerate(contract["evidence"]["endorsements"]):
            endorsement, item_errors = _bound_json(
                resolved_evidence,
                binding,
                ENDORSEMENT_SCHEMA,
                f"catalog endorsement {index}",
            )
            if endorsement is not None and not item_errors and descriptor is not None:
                item_errors.extend(
                    _endorsement_errors(
                        endorsement, binding, descriptor, evaluation, policy
                    )
                )
                if endorsement["endorsementId"] in endorsement_ids:
                    item_errors.append("catalog endorsement ID is duplicated")
                if endorsement["selfDigestSha256"] in endorsement_digests:
                    item_errors.append("catalog endorsement digest is duplicated")
                endorsement_ids.add(endorsement["endorsementId"])
                endorsement_digests.add(endorsement["selfDigestSha256"])
                endorsements.append(endorsement)
            stage_errors.extend(item_errors)
        if not stage_ok["preflight"]:
            stage_errors.append("discovery verification is blocked by invalid preflight")
        errors.extend(stage_errors)
        stage_ok["discovery"] = stage_ok["preflight"] and not stage_errors

    if rank >= 2:
        observation, stage_errors = _bound_json(
            resolved_evidence,
            contract["evidence"]["runtimeObservation"],
            RUNTIME_SCHEMA,
            "federated catalog runtime observation",
        )
        if descriptor is not None and observation is not None and not stage_errors:
            stage_errors.extend(
                _runtime_errors(
                    observation,
                    contract["evidence"]["runtimeObservation"],
                    contract,
                    descriptor,
                    endorsements,
                    evaluation,
                    policy,
                )
            )
        if not stage_ok["discovery"]:
            stage_errors.append("local trust verification is blocked by invalid discovery")
        errors.extend(stage_errors)
        stage_ok["trust"] = stage_ok["discovery"] and not stage_errors

    if rank >= 3:
        stage_errors = []
        if not stage_ok["trust"]:
            stage_errors.append("conflict verification is blocked by invalid local trust")
        elif observation is None or observation["conflictCounts"]["unresolvedHard"] < 1:
            stage_errors.append("runtime observation lacks an unresolved hard conflict")
        errors.extend(stage_errors)
        stage_ok["conflicts"] = stage_ok["trust"] and not stage_errors

    if rank >= 4:
        stage_errors = []
        if not stage_ok["conflicts"]:
            stage_errors.append("runtime verification is blocked by invalid conflict evidence")
        elif observation is None or observation["partial"] or observation["status"] != "pass":
            stage_errors.append("runtime observation is partial or failed")
        errors.extend(stage_errors)
        stage_ok["runtime"] = stage_ok["conflicts"] and not stage_errors

    if rank >= 5:
        if fixture and stage_ok["runtime"]:
            stage_errors = []
        elif stage_ok["runtime"]:
            stage_errors = _authority_errors(contract, policy, resolved_evidence)
        else:
            stage_errors = ["authority closeout is blocked by invalid runtime evidence"]
        errors.extend(stage_errors)
        stage_ok["roots"] = stage_ok["runtime"] and not stage_errors

    errors = sorted(set(errors))
    if errors:
        status = "partial" if any(stage_ok.values()) else "fail"
        state = "partial" if any(stage_ok.values()) else "blocked"
    elif fixture and rank >= 1:
        status = "pass"
        state = "fixture-verification-complete"
    else:
        status = "pass"
        state = (
            "implementation-complete",
            "discovery-authenticated",
            "local-trust-configured",
            "conflict-policy-verified",
            "runtime-federation-verified",
            "operational-federation-complete",
        )[rank]
    operational = state == "operational-federation-complete"

    descriptor_digest = _qualified_runtime_digest(descriptor) if descriptor else None
    endorsement_digests = sorted(
        _qualified_runtime_digest(item) for item in endorsements
    )
    runtime_digest = observation.get("receiptDigest") if observation else None
    check_stages = ("preflight", "discovery", "trust", "conflicts", "runtime", "roots")
    check_digests = (None, descriptor_digest, runtime_digest, runtime_digest, runtime_digest, None)
    checks = []
    for index, name in enumerate(check_stages):
        if index > rank:
            check_status = "pending"
        elif stage_ok[name]:
            check_status = "fixture-only" if fixture and name != "preflight" else "pass"
        else:
            check_status = "fail"
        checks.append({"id": f"federated-catalog.{name}", "status": check_status, "digest": check_digests[index]})

    summary: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": "stable-1.0-federated-catalog-summary",
        "executionId": contract["executionId"],
        "releaseId": contract["release"]["releaseId"],
        "buildVersion": contract["release"]["buildVersion"],
        "sourceCommit": contract["repository"]["sourceCommit"],
        "mode": mode,
        "status": status,
        "state": state,
        "implementationComplete": stage_ok["preflight"],
        "fixtureVerificationComplete": fixture and rank >= 1 and not errors,
        "discoveryAuthenticated": stage_ok["discovery"] and not fixture,
        "localTrustConfigured": stage_ok["trust"] and not fixture,
        "conflictPolicyVerified": stage_ok["conflicts"] and not fixture,
        "runtimeFederationVerified": stage_ok["runtime"] and not fixture,
        "operationalFederationComplete": operational,
        "fixtureOnly": contract["fixtureOnly"],
        "selfTest": contract["selfTest"],
        "operational": operational,
        "policyDigest": policy_digest,
        "authorityDigests": {
            name: contract["authorities"][name]["summaryDigest"]
            for name in AUTHORITY_WORKFLOW_KEYS
        },
        "descriptorDigest": descriptor_digest,
        "endorsementDigests": endorsement_digests,
        "runtimeObservationDigest": runtime_digest,
        "checks": checks,
        "blockers": sorted({_blocker(error) for error in errors})[:128],
        "summaryDigest": ZERO_DIGEST,
    }
    summary["summaryDigest"] = _semantic_digest(summary, "summaryDigest")
    schema_findings = validate_schema(summary, SUMMARY_SCHEMA)
    if schema_findings:
        raise ValueError(
            "generated federated catalog summary failed its closed schema: "
            + "; ".join(schema_findings[:8])
        )
    report = _report(summary)
    if scan_value([summary, report]):
        raise ValueError("generated federated catalog outputs failed redaction validation")

    output = _output_directory(
        workspace,
        out_dir
        or Path("build/release-certification/stable-federated-catalog") / mode,
    )
    write_json(output / MODE_FILES[mode], summary)
    if MODE_FILES[mode] != SUMMARY_FILE:
        write_json(output / SUMMARY_FILE, summary)
    write_text(output / REPORT_FILE, report)
    write_json(
        output / REDACTION_FILE,
        {
            "schemaVersion": 1,
            "kind": "stable-1.0-federated-catalog-redaction",
            "status": "pass",
            "findingCount": 0,
            "findings": [],
        },
    )
    return 0 if status == "pass" else 1
