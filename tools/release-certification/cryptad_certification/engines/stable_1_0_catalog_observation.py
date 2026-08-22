"""Construct a protected Stable catalog observation receipt from already fetched bytes."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from ..io import read_json_bytes
from ..schema_validation import validate_schema
from . import stable_1_0_catalog_authority as authority


def _safe_bytes(path: Path, label: str, maximum: int) -> bytes:
    """Read one bounded regular single-link file without following an unsafe target."""

    if maximum < 1 or path.is_symlink():
        raise ValueError(f"{label} is missing or unsafe")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{label} is missing or unsafe") from exc
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= maximum
        ):
            raise ValueError(f"{label} is outside its byte bound or unsafe")
        value = stream.read(maximum + 1)
        if len(value) != metadata.st_size or len(value) > maximum:
            raise ValueError(f"{label} changed while it was read or exceeded its byte bound")
        return value


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _revision_digest(catalog: bytes, signature: bytes) -> str:
    """Return the runtime revision digest for one exact catalog/signature pair."""

    digest = hashlib.sha256()
    for sidecar in (catalog, signature):
        digest.update(len(sidecar).to_bytes(4, byteorder="big", signed=False))
        digest.update(sidecar)
    return "sha256:" + digest.hexdigest()


def _json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = _safe_bytes(path, label, 1024 * 1024)
    value = read_json_bytes(raw, label)
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not an object")
    return value, raw


def _health_errors(
    health: dict[str, Any],
    subject: dict[str, Any],
    revision_digest: str,
    collection_started_at: dt.datetime,
    collection_completed_at: dt.datetime,
) -> list[str]:
    """Verify a preconfigured observer reports a successful exact catalog refresh."""

    if set(health) != {"health"} or not isinstance(health["health"], dict):
        return ["scheduler health response does not use the closed health envelope"]
    body = health["health"]
    errors: list[str] = []
    if (
        body.get("catalogId") != subject["catalogId"]
        or body.get("catalogDigest") != revision_digest
        or body.get("signatureKeyId") != subject["signingKeyId"]
        or body.get("status") != "success"
    ):
        errors.append("scheduler health does not bind the exact current catalog")
    sources = body.get("sourceHealth")
    if not isinstance(sources, list):
        return errors + ["scheduler health does not contain bounded source observations"]
    exact: list[dict[str, Any]] = []
    for row in sources:
        if (
            not isinstance(row, dict)
            or row.get("lastFetchStatus") != "success"
            or row.get("lastCatalogDigest") != revision_digest
            or row.get("lastSignatureKeyId") != subject["signingKeyId"]
        ):
            continue
        try:
            successful_at = authority._timestamp(row["lastSuccessfulRefreshAt"])
            attempted_at = authority._timestamp(row["lastAttemptAt"])
        except (AttributeError, KeyError, TypeError, ValueError):
            continue
        if (
            attempted_at == successful_at
            and collection_started_at <= successful_at <= collection_completed_at
        ):
            exact.append(row)
    roles = {row.get("role") for row in exact}
    if "primary" not in roles or "mirror" not in roles:
        errors.append(
            "scheduler health lacks fresh exact successful primary and mirror refreshes "
            "inside the protected collection window"
        )
    return errors


def _collection_window(
    manifest: dict[str, Any],
    observed_at: str,
    collection_started_at: str,
    collection_completed_at: str,
) -> tuple[dt.datetime, dt.datetime]:
    """Validate the protected collection clock and signer through actual completion."""

    reviewed = authority._timestamp(observed_at)
    started = authority._timestamp(collection_started_at)
    completed = authority._timestamp(collection_completed_at)
    maximum_window = dt.timedelta(minutes=15)
    if reviewed > started or started - reviewed > maximum_window:
        raise ValueError("reviewed observation time is stale at protected collection start")
    if completed < started or completed - reviewed > maximum_window:
        raise ValueError("protected collection did not complete inside the reviewed time window")
    catalog = manifest["catalog"]
    signer = next(
        (
            key
            for key in manifest["keyset"]["keys"]
            if key.get("keyId") == catalog["signingKeyId"]
        ),
        None,
    )
    if (
        signer is None
        or signer.get("role") != "catalog-signing"
        or signer.get("lifecycle") != "active"
        or signer.get("compromiseState") != "uncompromised"
        or not authority._key_valid_at(signer, completed)
    ):
        raise ValueError(
            "catalog signer is not active and authorized through collection completion"
        )
    return started, completed


def construct_receipt(
    manifest: dict[str, Any],
    plan: dict[str, Any],
    live: dict[str, Any],
    evidence_dir: Path,
    fetched_dir: Path,
    health: dict[str, Any],
    observed_at: str,
    collection_started_at: str,
    collection_completed_at: str,
) -> dict[str, Any]:
    """Validate exact fetched subjects and return one closed, redacted receipt."""

    errors = validate_schema(manifest, authority.EXECUTION_SCHEMA)
    errors.extend(validate_schema(plan, authority.PUBLICATION_PLAN_SCHEMA))
    if errors:
        raise ValueError("catalog observation inputs are schema-invalid")
    release = manifest["release"]
    catalog = manifest["catalog"]
    publication = manifest["publication"]
    subject = authority._catalog_subject(catalog)
    started, completed = _collection_window(
        manifest, observed_at, collection_started_at, collection_completed_at
    )
    if (
        manifest["fixtureOnly"]
        or plan.get("release") != release
        or plan.get("catalog") != catalog
        or plan.get("networkPrimary") != publication["networkPrimary"]
        or plan.get("mirrors") != publication["mirrors"]
        or plan.get("planDigest") != authority._semantic_digest(plan, "planDigest")
    ):
        raise ValueError("publication plan does not bind the reviewed operational subject")
    expected_catalog = _safe_bytes(
        evidence_dir / authority.FROZEN_CATALOG_FILE,
        "frozen catalog",
        1024 * 1024,
    )
    expected_signature = _safe_bytes(
        evidence_dir / authority.FROZEN_SIGNATURE_FILE,
        "frozen catalog signature",
        64 * 1024,
    )
    if (
        _digest(expected_catalog) != subject["catalogDigest"]
        or len(expected_catalog) != subject["catalogSize"]
        or _digest(expected_signature) != subject["signatureDigest"]
        or len(expected_signature) != subject["signatureSize"]
    ):
        raise ValueError("authenticated frozen sidecars do not match the publication subject")
    primary = publication["networkPrimary"]
    if (
        live.get("mode") != "live"
        or live.get("catalogId") != subject["catalogId"]
        or live.get("publicCatalogSource") != primary["publicUri"]
        or live.get("catalogSha256") != subject["catalogDigest"].removeprefix("sha256:")
        or live.get("signatureSha256") != subject["signatureDigest"].removeprefix("sha256:")
        or live.get("catalogSigningKeyId") != subject["signingKeyId"]
        or live.get("postPublishVerificationStatus") != "verified"
    ):
        raise ValueError("live publication result does not bind an exact primary fetch")
    locations = [primary, *publication["mirrors"]]
    observations: list[dict[str, Any]] = []
    for location in locations:
        location_id = location["locationId"]
        observed_catalog = _safe_bytes(
            fetched_dir / f"{location_id}.catalog", f"{location_id} catalog", 1024 * 1024
        )
        observed_signature = _safe_bytes(
            fetched_dir / f"{location_id}.signature",
            f"{location_id} signature",
            64 * 1024,
        )
        if observed_catalog != expected_catalog or observed_signature != expected_signature:
            raise ValueError(
                f"{location_id} did not return the exact catalog and signature siblings"
            )
        observations.append(
            {
                "locationId": location_id,
                "observedAt": observed_at,
                "status": "exact-match",
                **subject,
            }
        )
    if observations != publication["observations"]:
        raise ValueError("protected observation instant does not match the reviewed manifest")
    health_findings = _health_errors(
        health,
        subject,
        _revision_digest(expected_catalog, expected_signature),
        started,
        completed,
    )
    if health_findings:
        raise ValueError("; ".join(health_findings))
    receipt: dict[str, Any] = {
        "kind": "stable-1.0-catalog-mirror-observation",
        "releaseId": release["releaseId"],
        "buildVersion": release["buildVersion"],
        "sourceCommit": release["sourceCommit"],
        "catalogSubject": subject,
        "collectionStartedAt": collection_started_at,
        "collectionCompletedAt": collection_completed_at,
        "observations": observations,
        "schedulerRefreshVerificationStatus": "pass",
        "status": "pass",
        "receiptDigest": None,
    }
    receipt["receiptDigest"] = authority._semantic_digest(receipt, "receiptDigest")
    if validate_schema(receipt, authority.MIRROR_OBSERVATION_SCHEMA):
        raise ValueError("constructed mirror observation receipt is schema-invalid")
    if authority._sensitive_findings(receipt):
        raise ValueError("constructed mirror observation receipt failed redaction validation")
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authority-manifest", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--fetched-dir", type=Path, required=True)
    parser.add_argument("--scheduler-health", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--collection-started-at", required=True)
    parser.add_argument("--collection-completed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        manifest, _ = _json(args.authority_manifest, "authority manifest")
        plan, _ = _json(
            args.evidence_dir / authority.PUBLICATION_PLAN_FILE, "catalog publication plan"
        )
        live, _ = _json(args.evidence_dir / authority.LIVE_PUBLICATION_FILE, "live publication")
        health, _ = _json(args.scheduler_health, "scheduler health")
        receipt = construct_receipt(
            manifest,
            plan,
            live,
            args.evidence_dir,
            args.fetched_dir,
            health,
            args.observed_at,
            args.collection_started_at,
            args.collection_completed_at,
        )
        raw = json.dumps(
            receipt, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True
        ).encode("utf-8") + b"\n"
        output = args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.is_symlink() or (output.exists() and not output.is_file()):
            raise ValueError("mirror observation output is unsafe")
        output.write_bytes(raw)
        return 0
    except (KeyError, OSError, TypeError, ValueError) as exc:
        print(f"catalog mirror observation failed: {exc}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
