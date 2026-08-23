"""Authenticate a PR-293 artifact for Stable protected-release closeout."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

from ..io import read_json_bytes
from ..redaction import scan_value
from .stable_1_0_supply_chain_archive import inspect_archive_safety


WORKFLOW = ".github/workflows/stable-1.0-catalog-authority.yml"
ENVIRONMENT = "stable-1-0-catalog-authority-closeout"
SUMMARY_MEMBER = "stable-1.0-catalog-authority-summary.json"
REPORT_MEMBER = "stable-1.0-catalog-authority-report.md"
REDACTION_MEMBER = "stable-1.0-catalog-authority-redaction-report.json"
STATES = frozenset(
    {
        "implementation-complete",
        "fixture-verification-complete",
        "ceremony-authenticated",
        "network-primary-published",
        "mirrors-observed",
        "rotation-drill-complete",
        "rollback-drill-complete",
        "public-key-transparency-published",
        "blocked",
        "partial",
    }
)
OPERATIONAL_STATES = STATES.difference(
    {"implementation-complete", "fixture-verification-complete", "blocked", "partial"}
)
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
ZERO_DIGEST = "sha256:" + "0" * 64


def _file_digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return "sha256:" + hasher.hexdigest()


def _semantic_digest(value: Any) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _summary_errors(
    summary: dict[str, Any],
    *,
    contract_root: str,
    release_id: str,
    build_version: int,
    source_commit: str,
    selected_rc: dict[str, Any] | None,
    frozen_catalog: dict[str, Any] | None,
    independent_digests: dict[str, Any] | None,
) -> list[str]:
    required_fields = {
        "schemaVersion",
        "kind",
        "mode",
        "releaseId",
        "buildVersion",
        "sourceCommit",
        "policyDigest",
        "protectedReleaseSummaryDigest",
        "protectedReleaseContractDigest",
        "independentReproducibilitySummaryDigest",
        "independentReproducibilityResultDigest",
        "independentSubjectInventoryDigest",
        "keysetDigest",
        "catalogSubject",
        "checks",
        "fixtureOnly",
        "operational",
        "state",
        "status",
        "blockers",
        "generatedAt",
        "summaryDigest",
    }
    errors: list[str] = []
    if set(summary) != required_fields:
        errors.append("catalog authority summary has an unexpected or incomplete shape")
    if (
        summary.get("schemaVersion") != 1
        or summary.get("kind") != "stable-1.0-catalog-authority-summary"
        or summary.get("mode") != "closeout"
    ):
        errors.append("catalog authority summary identity differs from the closeout contract")
    state = summary.get("state")
    if state not in STATES:
        errors.append("catalog authority summary has an unknown state")
    status = summary.get("status")
    blockers = summary.get("blockers")
    if status not in {"pass", "fail"} or not isinstance(blockers, list) or any(
        not isinstance(item, str) or not item or len(item) > 512 for item in blockers
    ):
        errors.append("catalog authority summary has malformed status or blockers")
    elif status == "pass" and blockers:
        errors.append("passing catalog authority summary has blockers")
    elif status == "fail" and state != "blocked":
        errors.append("failed catalog authority summary is not blocked")
    checks = summary.get("checks")
    expected_checks = {
        "ceremony",
        "publication",
        "rotationAndRollbackDrills",
        "roleSpecificRegistries",
        "redaction",
    }
    if (
        not isinstance(checks, dict)
        or set(checks) != expected_checks
        or any(value not in {"pass", "fail"} for value in checks.values())
    ):
        errors.append("catalog authority summary checks have an invalid closed shape")
    elif status == "pass" and any(value != "pass" for value in checks.values()):
        errors.append("passing catalog authority summary contains a failed check")
    fixture_only = summary.get("fixtureOnly")
    operational = summary.get("operational")
    if type(fixture_only) is not bool or type(operational) is not bool:
        errors.append("catalog authority summary classification flags are malformed")
    elif fixture_only and (operational or state != "fixture-verification-complete"):
        errors.append("fixture catalog authority summary claims a non-fixture state")
    elif state == "fixture-verification-complete" and not fixture_only:
        errors.append("catalog authority fixture state lacks fixture classification")
    elif state in OPERATIONAL_STATES and not operational:
        errors.append("catalog authority operational state lacks protected evidence")
    elif operational and state not in OPERATIONAL_STATES:
        errors.append("catalog authority non-operational state claims completion")
    digest_fields = {
        "policyDigest",
        "protectedReleaseSummaryDigest",
        "protectedReleaseContractDigest",
        "independentReproducibilitySummaryDigest",
        "independentReproducibilityResultDigest",
        "independentSubjectInventoryDigest",
        "keysetDigest",
        "summaryDigest",
    }
    if any(
        not isinstance(summary.get(field), str)
        or DIGEST_RE.fullmatch(summary[field]) is None
        or summary[field] == ZERO_DIGEST
        for field in digest_fields
    ):
        errors.append("catalog authority summary contains an invalid or unset digest")
    else:
        canonical = copy.deepcopy(summary)
        canonical["summaryDigest"] = ZERO_DIGEST
        if summary["summaryDigest"] != _semantic_digest(canonical):
            errors.append("catalog authority summary self-digest differs")
    generated_at = summary.get("generatedAt")
    try:
        if not isinstance(generated_at, str):
            raise ValueError("missing timestamp")
        if datetime.fromisoformat(generated_at.replace("Z", "+00:00")).tzinfo is None:
            raise ValueError("missing timezone")
    except ValueError:
        errors.append("catalog authority summary timestamp is malformed")
    if (
        summary.get("releaseId") != release_id
        or summary.get("buildVersion") != build_version
        or summary.get("sourceCommit") != source_commit
        or summary.get("protectedReleaseContractDigest") != contract_root
    ):
        errors.append("catalog authority summary differs from the exact PR-291 release root")
    if independent_digests is None or any(
        summary.get(summary_field) != independent_digests.get(independent_field)
        for summary_field, independent_field in (
            ("independentReproducibilitySummaryDigest", "summaryDigest"),
            ("independentReproducibilityResultDigest", "resultDigest"),
            ("independentSubjectInventoryDigest", "subjectInventoryDigest"),
        )
    ):
        errors.append("catalog authority summary differs from the exact PR-292 result")
    catalog = summary.get("catalogSubject")
    expected_catalog_fields = {
        "catalogId",
        "channel",
        "revision",
        "uskEdition",
        "catalogDigest",
        "catalogSize",
        "signatureDigest",
        "signatureSize",
        "signingKeyId",
        "signingKeyFingerprintSha256",
    }
    if (
        not isinstance(selected_rc, dict)
        or not isinstance(catalog, dict)
        or set(catalog) != expected_catalog_fields
        or not isinstance(frozen_catalog, dict)
    ):
        errors.append("catalog authority summary lacks the authenticated frozen catalog subject")
    elif (
        catalog.get("catalogId") != frozen_catalog.get("catalogId")
        or catalog.get("channel") != frozen_catalog.get("channel")
        or catalog.get("revision") != selected_rc.get("catalogRevision")
        or catalog.get("revision") != frozen_catalog.get("revision")
        or catalog.get("uskEdition") != frozen_catalog.get("edition")
        or catalog.get("catalogDigest") != selected_rc.get("catalogDigest")
        or catalog.get("catalogDigest") != frozen_catalog.get("catalogDigest")
        or catalog.get("signatureDigest") != frozen_catalog.get("signatureDigest")
        or catalog.get("signingKeyId") != frozen_catalog.get("catalogSigningKeyId")
        or not isinstance(catalog.get("catalogSize"), int)
        or catalog["catalogSize"] <= 0
        or not isinstance(catalog.get("signatureSize"), int)
        or catalog["signatureSize"] <= 0
        or not isinstance(catalog.get("signingKeyFingerprintSha256"), str)
        or DIGEST_RE.fullmatch(catalog["signingKeyFingerprintSha256"]) is None
    ):
        errors.append("catalog authority summary catalog differs from the authenticated RC freeze")
    if scan_value(summary):
        errors.append("catalog authority summary contains redaction findings")
    return sorted(set(errors))


def verify_artifact(
    archive_path: Path,
    *,
    expected_digest: str,
    contract_root: str,
    release_id: str,
    build_version: int,
    source_commit: str,
    selected_rc: dict[str, Any] | None,
    frozen_catalog: dict[str, Any] | None,
    independent_digests: dict[str, Any] | None,
) -> tuple[str, list[str]]:
    """Authenticate the exact bounded artifact and return its truthful state."""

    errors: list[str] = []
    if _file_digest(archive_path) != expected_digest:
        errors.append("catalog authority artifact differs from the exact Actions artifact digest")
    if archive_path.suffix.lower() != ".zip":
        return "blocked", [*errors, "catalog authority artifact is not a ZIP archive"]
    try:
        inspect_archive_safety(
            archive_path,
            maximum_entries=4,
            maximum_expanded_bytes=5_000_000,
            reject_links=True,
            reject_nested_archives=True,
        )
        with zipfile.ZipFile(archive_path) as archive:
            members = [row for row in archive.infolist() if not row.is_dir()]
            expected_names = {SUMMARY_MEMBER, REPORT_MEMBER, REDACTION_MEMBER}
            if {row.filename for row in members} != expected_names or len(members) != 3:
                return "blocked", [
                    *errors,
                    "catalog authority artifact does not contain the exact closeout member set",
                ]
            by_name = {row.filename: row for row in members}
            summary = read_json_bytes(archive.read(by_name[SUMMARY_MEMBER]), "catalog authority summary")
            redaction = read_json_bytes(
                archive.read(by_name[REDACTION_MEMBER]), "catalog authority redaction report"
            )
            report = archive.read(by_name[REPORT_MEMBER]).decode("utf-8")
        expected_redaction = {
            "schemaVersion": 1,
            "kind": "stable-1.0-catalog-authority-redaction",
            "status": "pass",
            "findingCount": 0,
            "findings": [],
            "publicKeyMaterialLimitedTo": [
                "stable-1.0-public-key-transparency.json",
                "stable-1.0-catalog-trusted-keys.properties",
                "stable-1.0-app-trusted-keys.properties",
                "stable-1.0-reviewer-trusted-keys.properties",
            ],
        }
        if not isinstance(summary, dict):
            errors.append("catalog authority summary is not a JSON object")
            return "blocked", errors
        if redaction != expected_redaction:
            errors.append("catalog authority artifact lacks its exact passing redaction report")
        if scan_value([summary, redaction, report]):
            errors.append("catalog authority artifact contains redaction findings")
        errors.extend(
            _summary_errors(
                summary,
                contract_root=contract_root,
                release_id=release_id,
                build_version=build_version,
                source_commit=source_commit,
                selected_rc=selected_rc,
                frozen_catalog=frozen_catalog,
                independent_digests=independent_digests,
            )
        )
        return "blocked" if errors else summary["state"], sorted(set(errors))
    except (
        EOFError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        NotImplementedError,
        OSError,
        RuntimeError,
        ValueError,
        zipfile.BadZipFile,
    ):
        return "blocked", [*errors, "catalog authority artifact is unsafe or malformed"]
