"""Canonical Stable 1.0 release-candidate execution and release-freeze engine."""

from __future__ import annotations

import datetime as dt
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from cryptad_certification.io import read_json, write_json, write_text
from cryptad_certification.models import RunContext
from cryptad_certification.redaction import scan_value
from cryptad_certification.workspace import reset_confined_directory

from .stable_1_0_rc_artifacts import (
    build_redaction_report,
    create_deterministic_archive,
    render_freeze_report,
    render_go_no_go,
    render_release_notes,
    verify_checksums,
    verify_deterministic_archive,
    write_checksums,
    write_named_checksums,
)
from .stable_1_0_rc_core import (
    CHECKSUMS_FILE,
    DRIFT_REPORT_FILE,
    EVIDENCE_IDS,
    FINAL_DECISION_EVIDENCE_ID,
    FREEZE_FILE,
    FREEZE_REPORT_FILE,
    FREEZE_SIDECAR_FILE,
    KNOWN_LIMITATIONS_FILE,
    PROVENANCE_FILE,
    REDACTION_REPORT_FILE,
    RELEASE_NOTES_FILE,
    REPORT_FILE,
    SCHEMA_VERSION,
    STABLE_MILESTONE,
    SUMMARY_FILE,
    SUPPORTING_VERIFIER_FILES,
    TOOL_NAME,
    TOOL_VERSION,
    LoadedInput,
    ValidationState,
    file_digest,
    load_candidate_inputs,
    load_existing_input,
    load_raw_input,
    parse_timestamp,
    placeholder_findings,
    source_identity,
    validate_prerequisites,
)
from .stable_1_0_rc_freeze import (
    assemble_freeze,
    build_catalog_and_apps_freeze,
    build_limitations_freeze,
    build_platform_api_freeze,
    compare_freezes,
    export_content_profiles,
    merge_accepted_exception_history,
    production_native_root,
    safe_artifact,
    validate_exception_collection,
    validate_freeze_shape,
)


def run(context: RunContext) -> tuple[int, Path, Path]:
    """Execute Stable RC validation, freeze, packaging, and final verification."""

    out = reset_confined_directory(
        context.component_dir / "artifacts" / "legacy",
        context.run_root,
        "Stable RC native output",
    )
    summary_path = out / SUMMARY_FILE
    report_path = out / REPORT_FILE
    state = ValidationState()
    try:
        code = _run(context, out, state)
    except Exception:  # noqa: BLE001 - a release gate must always fail closed
        # Validation deliberately continues after recording independent blockers so reviewers get
        # one complete remediation list. A malformed protected input can therefore reach a later
        # builder before all of its nested shape has been consumed. Never let such a structural
        # error escape without the sanitized native no-go evidence required by the v2 adapter.
        state.block(
            "stable-1.0-rc.execution-input",
            "stable-1.0-rc.prerequisites",
            "Stable RC execution could not validate a required protected input or artifact.",
            "Correct the candidate-bound input and rerun the complete Stable RC workflow.",
        )
        out = reset_confined_directory(
            context.component_dir / "artifacts" / "legacy",
            context.run_root,
            "Stable RC failed native output",
        )
        _write_fail_closed_artifacts(
            context,
            out,
            state,
            redaction_status="fail",
        )
        code = 1
    return code, summary_path, report_path


def _run(context: RunContext, out: Path, state: ValidationState) -> int:
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    production_input = load_existing_input(context, "productionBeta")
    native_root = production_native_root(production_input.path)
    inputs = load_candidate_inputs(context, native_root)
    catalog_operations = _require_raw(context, "stableCatalogOperations")
    readiness_policy = _require_raw(context, "stableReadinessPolicy")
    stable_known = _require_raw(context, "stableKnownLimitations")
    public_issues = _require_raw(context, "publicBetaKnownIssues")
    for loaded in (stable_known, public_issues):
        if scan_value(loaded.value):
            state.block(
                f"stable-1.0-rc.redaction.{loaded.key}",
                "stable-1.0-rc.redaction",
                f"Input {loaded.key} contains redaction findings.",
                "Replace the input with a redaction-safe candidate-bound summary.",
            )
        if placeholder_findings(loaded.value):
            state.block(
                f"stable-1.0-rc.placeholder.{loaded.key}",
                "stable-1.0-rc.redaction",
                f"Input {loaded.key} contains production placeholder metadata.",
                "Replace example and REPLACE_ME metadata before Stable RC execution.",
            )
    # Make policy freshness available to the shared PR-282 readiness validation wrapper.
    inputs["stableReadinessPolicy"] = readiness_policy
    previous_freeze_input = load_raw_input(context, "previousStableRcFreeze", required=False)
    freeze_mode = _freeze_mode(context, previous_freeze_input, state)
    exception_input = load_raw_input(context, "stableRcFreezeExceptions", required=False)
    exceptions, exception_errors = validate_exception_collection(
        exception_input.value if exception_input else None,
        context.manifest.release.release_id,
        str(context.manifest.release.version or ""),
        now,
    )
    for error in exception_errors:
        state.block(
            "stable-1.0-rc.freeze-exception",
            "stable-1.0-rc.freeze-verification",
            error + ".",
            "Replace the exception collection with an authorized, current, narrowly scoped record.",
        )
    previous_freeze = previous_freeze_input.value if previous_freeze_input else None
    comparison_baseline = _comparison_baseline_binding(previous_freeze_input)
    accepted_exception_history = merge_accepted_exception_history(previous_freeze, exceptions)
    validate_prerequisites(context, inputs, catalog_operations, now, state)
    source = source_identity(context, inputs["releaseCertification"].value)
    if catalog_operations.value.get("sourceCommit") != source.commit:
        state.block(
            "stable-1.0-rc.catalog-source-binding",
            "stable-1.0-rc.candidate-binding",
            "Protected catalog-operations evidence is bound to a different source commit.",
            "Regenerate catalog-operations evidence from the candidate commit.",
        )

    platform, current_contract, _platform_diff = build_platform_api_freeze(
        context,
        native_root,
        out,
        state,
    )
    allowed_records = inputs["stableReadiness"].value.get("allowedLimitations")
    if not isinstance(allowed_records, list):
        raise ValueError("Stable readiness allowedLimitations is malformed")
    allowed_ids = {
        str(row.get("id"))
        for row in allowed_records
        if isinstance(row, dict) and row.get("id")
    }
    stable_catalog, first_party_apps = build_catalog_and_apps_freeze(
        native_root,
        current_contract,
        catalog_operations.value,
        out,
        allowed_ids,
        state,
        inputs["productionBeta"].value.get("signingProfile"),
    )
    content_profiles, _content_export = export_content_profiles(
        native_root,
        out,
        inputs["appPlatform"].value,
        state,
    )
    limitations = build_limitations_freeze(
        inputs["stableReadiness"].value,
        readiness_policy,
        stable_known,
        public_issues,
        inputs["appPlatform"].value,
        inputs["securityDrills"].digest,
        state,
    )
    production_archive = _copy_production_distribution(
        native_root,
        inputs["productionBeta"].value,
        out,
    )
    _validate_production_distribution(native_root, production_archive, context, state)
    production_distribution_digest = file_digest(production_archive)
    freeze = assemble_freeze(
        context=context,
        source=source,
        inputs=inputs,
        catalog_operations=catalog_operations,
        platform_api=platform,
        stable_catalog=stable_catalog,
        first_party_apps=first_party_apps,
        content_profiles=content_profiles,
        limitations=limitations,
        accepted_exceptions=accepted_exception_history,
        production_distribution_digest=production_distribution_digest,
    )
    freeze_errors = validate_freeze_shape(freeze)
    if freeze_errors:
        state.block(
            "stable-1.0-rc.generated-freeze-schema",
            "stable-1.0-rc.freeze-generation",
            "The generated Stable RC freeze does not conform to the v1 freeze schema.",
            "Correct the protected source artifacts and regenerate the complete Stable RC freeze.",
        )
        raise ValueError("generated Stable RC freeze failed schema validation")
    initial_drift = compare_freezes(previous_freeze, freeze, exceptions)
    initial_drift["comparisonBaseline"] = comparison_baseline
    initial_drift["freezeMode"] = freeze_mode
    drift = _finalize_drift(initial_drift)
    if drift["status"] != "no-drift":
        state.block(
            "stable-1.0-rc.freeze-drift",
            "stable-1.0-rc.freeze-verification",
            f"Stable RC freeze verification ended in {drift['status']}.",
            "Resolve drift or provide an authorized blocker/security exception, then regenerate every final artifact.",
        )
    write_json(out / FREEZE_FILE, freeze)
    write_text(
        out / FREEZE_SIDECAR_FILE,
        f"{file_digest(out / FREEZE_FILE).removeprefix('sha256:')}  {FREEZE_FILE}",
    )
    write_json(out / DRIFT_REPORT_FILE, drift)
    write_text(out / FREEZE_REPORT_FILE, render_freeze_report(freeze, drift))
    known_artifact = {
        "schemaVersion": 1,
        "kind": "stable-1.0-rc-known-limitations",
        "releaseId": context.manifest.release.release_id,
        "buildVersion": context.manifest.release.version,
        "allowedLimitations": limitations["allowedLimitations"],
        "allowedLimitationsDigest": limitations["allowedLimitationsDigest"],
        "disallowedLimitationCount": limitations["disallowedLimitationCount"],
        "betaOnlyLimitationCount": limitations["betaOnlyLimitationCount"],
    }
    write_json(out / KNOWN_LIMITATIONS_FILE, known_artifact)
    release_notes = render_release_notes(
        freeze,
        inputs["previousCandidate"].value,
        _accepted_waivers(inputs["goNoGo"].value),
        accepted_exception_history,
        public_known_issues=public_issues.value,
        stable_readiness=inputs["stableReadiness"].value,
        operational_inputs={key: loaded.value for key, loaded in inputs.items()},
        drift=drift,
    )
    write_text(out / RELEASE_NOTES_FILE, release_notes)

    provenance = _provenance(
        context,
        source,
        freeze,
        inputs,
        catalog_operations,
        previous_freeze_input,
        production_archive,
        freeze_mode,
    )
    write_json(out / PROVENANCE_FILE, provenance)
    redaction_values: list[tuple[str, Any]] = [
        (FREEZE_FILE, freeze),
        (DRIFT_REPORT_FILE, drift),
        (KNOWN_LIMITATIONS_FILE, known_artifact),
        (PROVENANCE_FILE, provenance),
        (RELEASE_NOTES_FILE, release_notes),
    ]
    redaction_values.extend(
        (name, read_json(out / name)) for name in SUPPORTING_VERIFIER_FILES
    )
    redaction = build_redaction_report(redaction_values)
    if redaction["status"] != "pass":
        state.block(
            "stable-1.0-rc.generated-redaction",
            "stable-1.0-rc.redaction",
            "Generated Stable RC artifacts failed redaction validation.",
            "Remove unsafe source metadata and regenerate the complete RC.",
        )
    write_json(out / REDACTION_REPORT_FILE, redaction)
    archive = out / f"cryptad-stable-1.0-rc-{context.manifest.release.version}.tar.gz"
    summary = _promotion_summary(context, freeze, drift, state, redaction, inputs)
    summary["artifacts"]["archive"] = archive.name
    summary["artifacts"]["productionDistribution"] = production_archive.name
    write_json(out / SUMMARY_FILE, summary)
    write_text(out / REPORT_FILE, render_go_no_go(summary))

    payload_checksum = out / "payload-checksums.txt"
    internal_members = _archive_metadata_paths(out)
    write_named_checksums(
        payload_checksum,
        [
            (f"payload/{production_archive.name}", production_archive),
            *[(f"metadata/{path.name}", path) for path in internal_members],
        ],
    )
    archive_members = [
        (f"payload/{production_archive.name}", production_archive),
        *[(f"metadata/{path.name}", path) for path in internal_members],
        (payload_checksum.name, payload_checksum),
    ]
    create_deterministic_archive(archive, archive_members)
    reproducibility_copy = out / f".{archive.name}.reproducibility-check"
    create_deterministic_archive(reproducibility_copy, archive_members)
    if file_digest(reproducibility_copy) != file_digest(archive):
        state.block(
            "stable-1.0-rc.archive-reproducibility",
            "stable-1.0-rc.archive-hygiene",
            "Stable RC archive bytes are not reproducible.",
            "Fix archive normalization before promotion.",
        )
    reproducibility_copy.unlink(missing_ok=True)
    archive_errors = verify_deterministic_archive(archive)
    for error in archive_errors:
        state.block(
            "stable-1.0-rc.archive-hygiene",
            "stable-1.0-rc.archive-hygiene",
            error + ".",
            "Remove the unsafe member and rebuild the normalized archive.",
        )
    checksum_members = [archive, production_archive, *internal_members]
    write_checksums(out / CHECKSUMS_FILE, checksum_members)
    for error in verify_checksums(out / CHECKSUMS_FILE):
        state.block(
            "stable-1.0-rc.checksum-verification",
            "stable-1.0-rc.archive-hygiene",
            error + ".",
            "Regenerate checksums from the exact packaged bytes.",
        )

    final_summary = _promotion_summary(context, freeze, drift, state, redaction, inputs)
    final_summary["artifacts"]["archive"] = archive.name
    final_summary["artifacts"]["productionDistribution"] = production_archive.name
    write_json(out / SUMMARY_FILE, final_summary)
    write_text(out / REPORT_FILE, render_go_no_go(final_summary))
    # The reviewer archive must contain the final promotion decision. Rebuild once, then checksums.
    write_named_checksums(
        payload_checksum,
        [
            (f"payload/{production_archive.name}", production_archive),
            *[(f"metadata/{path.name}", path) for path in _archive_metadata_paths(out)],
        ],
    )
    create_deterministic_archive(
        archive,
        [
            (f"payload/{production_archive.name}", production_archive),
            *[(f"metadata/{path.name}", path) for path in _archive_metadata_paths(out)],
            (payload_checksum.name, payload_checksum),
        ],
    )
    payload_checksum.unlink(missing_ok=True)
    write_checksums(out / CHECKSUMS_FILE, [archive, production_archive, *_archive_metadata_paths(out)])
    final_reproducibility_copy = out / f".{archive.name}.final-reproducibility-check"
    # Recreate the same final archive from a temporary checksum file to prove byte stability.
    write_named_checksums(
        payload_checksum,
        [
            (f"payload/{production_archive.name}", production_archive),
            *[(f"metadata/{path.name}", path) for path in _archive_metadata_paths(out)],
        ],
    )
    create_deterministic_archive(
        final_reproducibility_copy,
        [
            (f"payload/{production_archive.name}", production_archive),
            *[(f"metadata/{path.name}", path) for path in _archive_metadata_paths(out)],
            (payload_checksum.name, payload_checksum),
        ],
    )
    final_errors = [
        *verify_deterministic_archive(archive),
        *verify_checksums(out / CHECKSUMS_FILE),
    ]
    if file_digest(final_reproducibility_copy) != file_digest(archive):
        final_errors.append("final archive reproducibility verification failed")
    final_reproducibility_copy.unlink(missing_ok=True)
    payload_checksum.unlink(missing_ok=True)
    if final_errors:
        for error in final_errors:
            state.block(
                "stable-1.0-rc.final-package-verification",
                "stable-1.0-rc.archive-hygiene",
                error + ".",
                "Regenerate the normalized archive and checksums before promotion.",
            )
        archive.unlink(missing_ok=True)
        final_summary = _promotion_summary(context, freeze, drift, state, redaction, inputs)
        final_summary["artifacts"]["productionDistribution"] = production_archive.name
        write_json(out / SUMMARY_FILE, final_summary)
        write_text(out / REPORT_FILE, render_go_no_go(final_summary))
        write_checksums(out / CHECKSUMS_FILE, [production_archive, *_archive_metadata_paths(out)])
        return 1
    return 0 if final_summary["promotionReady"] is True else 1


def _require_raw(context: RunContext, key: str) -> LoadedInput:
    loaded = load_raw_input(context, key)
    if loaded is None:
        raise ValueError(f"required Stable RC input is missing: {key}")
    return loaded


def _freeze_mode(
    context: RunContext,
    previous_freeze: LoadedInput | None,
    state: ValidationState,
) -> str:
    """Validate and return the explicit Stable RC freeze-lineage mode."""

    policies = context.manifest.policies
    mode = policies.get("stableRcFreezeMode") if isinstance(policies, dict) else None
    valid = mode in {"first-freeze", "refreeze"}
    if not valid:
        state.block(
            "stable-1.0-rc.freeze-mode",
            "stable-1.0-rc.freeze-verification",
            "Stable RC freeze mode is missing or invalid.",
            "Select first-freeze for the initial baseline or refreeze with the prior freeze.",
        )
        return "invalid"
    if mode == "first-freeze" and previous_freeze is not None:
        state.block(
            "stable-1.0-rc.first-freeze-with-baseline",
            "stable-1.0-rc.freeze-verification",
            "First-freeze mode was supplied with a previous Stable RC freeze.",
            "Use refreeze mode whenever a previous Stable RC freeze exists.",
        )
    if mode == "refreeze" and previous_freeze is None:
        state.block(
            "stable-1.0-rc.refreeze-without-baseline",
            "stable-1.0-rc.freeze-verification",
            "Refreeze mode is missing the previous Stable RC freeze.",
            "Supply the exact previous freeze before verifying or regenerating the candidate.",
        )
    return str(mode)


def _finalize_drift(initial: dict[str, Any]) -> dict[str, Any]:
    status = initial.get("status")
    if status == "approved-freeze-exception":
        return {
            **initial,
            "initialStatus": status,
            "status": "no-drift",
            "regenerated": True,
        }
    return {
        **initial,
        "initialStatus": status,
        "regenerated": False,
    }


def _accepted_waivers(go_no_go: dict[str, Any]) -> list[dict[str, Any]]:
    waivers = go_no_go.get("waivers")
    if not isinstance(waivers, list):
        return []
    return [
        row
        for row in waivers
        if isinstance(row, dict)
        and row.get("active") is True
        and row.get("appliesToMode") is True
        and row.get("validationErrors") == []
        and isinstance(row.get("usedBy"), list)
        and bool(row["usedBy"])
    ]


def _copy_production_distribution(native_root: Path, production: dict[str, Any], out: Path) -> Path:
    artifacts = production.get("artifacts") if isinstance(production.get("artifacts"), dict) else {}
    relative = artifacts.get("stableRcDistribution")
    if not isinstance(relative, str) or not relative:
        raise ValueError(
            "production-beta summary omits its deterministic Stable RC distribution"
        )
    source = safe_artifact(native_root, relative)
    target = out / source.name
    if target.is_symlink():
        raise ValueError("Stable RC production distribution target is unsafe")
    shutil.copyfile(source, target)
    return target


def _validate_production_distribution(
    native_root: Path,
    copied_archive: Path,
    context: RunContext,
    state: ValidationState,
) -> None:
    checksums = safe_artifact(native_root, "dist/checksums.txt")
    for error in verify_checksums(
        checksums,
        required_targets={copied_archive.name: copied_archive},
    ):
        state.block(
            "stable-1.0-rc.production-checksum",
            "stable-1.0-rc.archive-hygiene",
            error + ".",
            "Regenerate the production distribution and its checksum.",
        )
    from cryptad_certification.engines import production_beta_release as production_engine

    settings = SimpleNamespace(workspace_root=context.workspace_root)
    for finding in production_engine.scan_tarball(copied_archive, settings):
        state.block(
            "stable-1.0-rc.production-archive-hygiene",
            "stable-1.0-rc.archive-hygiene",
            f"Production distribution contains unsafe member kind {finding.get('kind', 'unknown')}.",
            "Remove unsafe paths, nested archives, or secret-like material and repackage.",
        )


def _provenance(
    context: RunContext,
    source: Any,
    freeze: dict[str, Any],
    inputs: dict[str, LoadedInput],
    catalog_operations: LoadedInput,
    previous_freeze: LoadedInput | None,
    production_archive: Path,
    freeze_mode: str,
) -> dict[str, Any]:
    build = str(context.manifest.release.version)
    metadata_members = [
        FREEZE_FILE,
        FREEZE_SIDECAR_FILE,
        FREEZE_REPORT_FILE,
        SUMMARY_FILE,
        REPORT_FILE,
        KNOWN_LIMITATIONS_FILE,
        RELEASE_NOTES_FILE,
        DRIFT_REPORT_FILE,
        PROVENANCE_FILE,
        REDACTION_REPORT_FILE,
        *SUPPORTING_VERIFIER_FILES,
        "payload-checksums.txt",
    ]
    provenance_inputs = {
        **{key: row.digest for key, row in sorted(inputs.items())},
        "stableCatalogOperations": catalog_operations.digest,
    }
    if previous_freeze is not None:
        provenance_inputs["previousStableRcFreeze"] = previous_freeze.digest
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-rc-provenance",
        "releaseId": context.manifest.release.release_id,
        "buildVersion": build,
        "freezeMode": freeze_mode,
        "source": {"commit": source.commit, "ref": source.ref, "digest": source.digest},
        "freeze": {
            "file": FREEZE_FILE,
            "contentDigest": freeze["contentDigest"],
            "fileDigest": file_digest(context.component_dir / "artifacts/legacy" / FREEZE_FILE),
        },
        "comparisonBaseline": _comparison_baseline_binding(previous_freeze),
        "productionDistribution": {
            "file": f"payload/{production_archive.name}",
            "digest": file_digest(production_archive),
        },
        "inputs": provenance_inputs,
        "archiveLayout": {
            "format": "deterministic-tar-gzip-v1",
            "root": "stable-1.0-rc",
            "normalized": True,
            "members": sorted(
                [
                    f"payload/{production_archive.name}",
                    *[f"metadata/{name}" for name in metadata_members if name != "payload-checksums.txt"],
                    "payload-checksums.txt",
                ]
            ),
        },
        "redaction": {"status": "pass", "findingCount": 0},
    }


def _comparison_baseline_binding(previous_freeze: LoadedInput | None) -> dict[str, str] | None:
    """Bind drift verification to the exact prior freeze bytes and canonical content."""

    if previous_freeze is None:
        return None
    content_digest = previous_freeze.value.get("contentDigest")
    if not isinstance(content_digest, str):
        raise ValueError("previous Stable RC freeze contentDigest is missing")
    return {
        "fileDigest": previous_freeze.digest,
        "contentDigest": content_digest,
    }


def _archive_metadata_paths(out: Path) -> list[Path]:
    return [
        out / FREEZE_FILE,
        out / FREEZE_SIDECAR_FILE,
        out / FREEZE_REPORT_FILE,
        out / SUMMARY_FILE,
        out / REPORT_FILE,
        out / KNOWN_LIMITATIONS_FILE,
        out / RELEASE_NOTES_FILE,
        out / DRIFT_REPORT_FILE,
        out / PROVENANCE_FILE,
        out / REDACTION_REPORT_FILE,
        *(out / name for name in SUPPORTING_VERIFIER_FILES),
    ]


def _promotion_summary(
    context: RunContext,
    freeze: dict[str, Any],
    drift: dict[str, Any],
    state: ValidationState,
    redaction: dict[str, Any],
    inputs: dict[str, LoadedInput],
) -> dict[str, Any]:
    stable = inputs["stableReadiness"].value
    production_decision = inputs["goNoGo"].value.get("decision")
    pass_result = (
        not state.blockers
        and stable.get("stableReady") is True
        and drift.get("status") == "no-drift"
        and redaction.get("status") == "pass"
    )
    decision = production_decision if pass_result and production_decision in {"go", "go-with-waivers"} else "no-go"
    evidence = []
    for evidence_id in EVIDENCE_IDS:
        failed = (
            evidence_id == FINAL_DECISION_EVIDENCE_ID and not pass_result
        ) or any(row.get("evidenceId") == evidence_id for row in state.blockers)
        evidence.append(
            {
                "id": evidence_id,
                "status": "fail" if failed else "pass",
                "summary": "Stable RC gate failed." if failed else "Stable RC gate passed.",
            }
        )
    return {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "stable-1.0-rc",
        "tool": TOOL_NAME,
        "toolVersion": TOOL_VERSION,
        "generatedAt": stable.get("generatedAt") or inputs["productionBeta"].value.get("generatedAt"),
        "releaseId": context.manifest.release.release_id,
        "buildVersion": context.manifest.release.version,
        "stableMilestone": STABLE_MILESTONE,
        "status": "pass" if pass_result else "fail",
        "promotionReady": pass_result,
        "nonRelease": not pass_result,
        "stableReady": stable.get("stableReady") is True,
        "stableReadinessDecision": stable.get("decision"),
        "decision": decision,
        "freeze": {
            "mode": drift.get("freezeMode"),
            "status": "pass" if drift.get("status") == "no-drift" else "fail",
            "driftStatus": drift.get("status"),
            "initialDriftStatus": drift.get("initialStatus"),
            "regenerated": drift.get("regenerated") is True,
            "contentDigest": freeze.get("contentDigest"),
        },
        "redactionStatus": redaction.get("status"),
        "blockerCount": len(state.blockers),
        "warningCount": len(state.warnings),
        "allowedLimitationCount": len(stable.get("allowedLimitations", [])),
        "acceptedWaiverCount": len(_accepted_waivers(inputs["goNoGo"].value)),
        "acceptedFreezeExceptionCount": len(freeze.get("acceptedFreezeExceptions", [])),
        "blockers": state.blockers,
        "warnings": state.warnings,
        "allowedLimitations": stable.get("allowedLimitations", []),
        "acceptedWaivers": _accepted_waivers(inputs["goNoGo"].value),
        "acceptedFreezeExceptions": freeze.get("acceptedFreezeExceptions", []),
        "evidence": evidence,
        "redaction": redaction,
        "artifacts": {
            "freeze": FREEZE_FILE,
            "freezeSidecar": FREEZE_SIDECAR_FILE,
            "freezeReport": FREEZE_REPORT_FILE,
            "driftReport": DRIFT_REPORT_FILE,
            "knownLimitations": KNOWN_LIMITATIONS_FILE,
            "releaseNotes": RELEASE_NOTES_FILE,
            "goNoGo": REPORT_FILE,
            "checksums": CHECKSUMS_FILE,
            "provenance": PROVENANCE_FILE,
            "redactionReport": REDACTION_REPORT_FILE,
        },
    }


def _write_fail_closed_artifacts(
    context: RunContext,
    out: Path,
    state: ValidationState,
    *,
    redaction_status: str,
) -> None:
    redaction = {
        "schemaVersion": 1,
        "status": redaction_status,
        "findingCount": 0 if redaction_status == "pass" else 1,
        "findings": []
        if redaction_status == "pass"
        else [{"category": "protected-input", "summary": "Unsafe protected input was rejected."}],
        "guarantees": {"unsafeInputExcluded": True},
    }
    summary = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "stable-1.0-rc",
        "tool": TOOL_NAME,
        "toolVersion": TOOL_VERSION,
        "generatedAt": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "releaseId": context.manifest.release.release_id,
        "buildVersion": context.manifest.release.version,
        "stableMilestone": STABLE_MILESTONE,
        "status": "fail",
        "promotionReady": False,
        "nonRelease": True,
        "stableReady": False,
        "stableReadinessDecision": "not-ready",
        "decision": "no-go",
        "freeze": {"mode": "invalid", "status": "fail", "driftStatus": "invalid-freeze", "initialDriftStatus": "invalid-freeze", "regenerated": False},
        "redactionStatus": redaction_status,
        "blockerCount": len(state.blockers),
        "warningCount": len(state.warnings),
        "allowedLimitationCount": 0,
        "acceptedWaiverCount": 0,
        "acceptedFreezeExceptionCount": 0,
        "blockers": state.blockers,
        "warnings": state.warnings,
        "allowedLimitations": [],
        "acceptedWaivers": [],
        "acceptedFreezeExceptions": [],
        "evidence": [
            {"id": evidence_id, "status": "fail", "summary": "Stable RC execution failed closed."}
            for evidence_id in EVIDENCE_IDS
        ],
        "redaction": redaction,
        "artifacts": {"goNoGo": REPORT_FILE, "redactionReport": REDACTION_REPORT_FILE},
    }
    write_json(out / SUMMARY_FILE, summary)
    write_text(out / REPORT_FILE, render_go_no_go(summary))
    write_json(out / REDACTION_REPORT_FILE, redaction)
