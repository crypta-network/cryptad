"""Implementation segment for the inputs portion of ``production_beta_go_no_go_dashboard.py``."""

from __future__ import annotations

def load_inputs_from_fixture(args: argparse.Namespace, workspace_root: Path) -> tuple[dict[str, Any], dict[str, Path], list[Path], dict[str, Any] | None, str, str, str]:
    fixture_path = args.fixtures if args.fixtures.is_absolute() else workspace_root / args.fixtures
    fixture = load_fixture(fixture_path)
    inputs = fixture.get("inputs")
    if not isinstance(inputs, dict):
        raise SystemExit(f"Fixture {fixture_path} must contain an inputs object.")
    waiver_value = fixture.get("waivers") if isinstance(fixture.get("waivers"), dict) else None
    mode = args.mode or str(fixture.get("mode", "release-candidate"))
    generated_at = args.generated_at or str(fixture.get("generatedAt", DEFAULT_GENERATED_AT))
    release_id = args.release_id or str(fixture.get("releaseId", fixture_path.stem))
    inputs = rebind_inherited_fixture_security_drills_summary(
        inputs,
        fixture_path,
        release_id,
        mode,
        generated_at,
    )
    return inputs, {}, [fixture_path], waiver_value, release_id, mode, generated_at

def rebind_inherited_fixture_security_drills_summary(
    inputs: dict[str, Any],
    fixture_path: Path,
    release_id: str,
    mode: str,
    generated_at: str,
) -> dict[str, Any]:
    """Keep inherited pass-fixture drill summaries bound to the child fixture candidate."""
    raw_fixture = read_json(fixture_path)
    raw_inputs = raw_fixture.get("inputs") if isinstance(raw_fixture, dict) else None
    if isinstance(raw_inputs, dict) and "securityDrillsSummary" in raw_inputs:
        return inputs
    summary = inputs.get("securityDrillsSummary")
    if not isinstance(summary, dict):
        return inputs
    if summary.get("kind") != "cryptad-security-response-drills-summary":
        return inputs
    rebound = json.loads(json.dumps(inputs))
    rebound_summary = rebound.get("securityDrillsSummary")
    if isinstance(rebound_summary, dict):
        rebound_summary["releaseId"] = release_id
        rebound_summary["generatedAt"] = generated_at
        if mode in security_response_runbook.RELEASE_DRILL_MODES:
            rebound_summary["mode"] = mode
    return rebound

def load_fixture(fixture_path: Path, seen: set[Path] | None = None) -> dict[str, Any]:
    resolved = fixture_path.resolve()
    active = set() if seen is None else seen
    if resolved in active:
        raise SystemExit(f"Fixture inheritance cycle includes {resolved}.")
    active.add(resolved)
    fixture = read_json(resolved)
    if fixture is None:
        raise SystemExit(f"Fixture {resolved} is missing or malformed.")
    extends = fixture.get("extends")
    if isinstance(extends, str) and extends.strip():
        base_path = (resolved.parent / extends).resolve()
        base = load_fixture(base_path, active)
        fixture = deep_merge(base, fixture)
        fixture.pop("extends", None)
    active.remove(resolved)
    return fixture

def deep_merge(base: Any, override: Any) -> Any:
    if isinstance(base, dict) and isinstance(override, dict):
        result = dict(base)
        for key, value in override.items():
            if key == "extends":
                continue
            result[key] = deep_merge(result.get(key), value)
        return result
    return override

def infer_release_id(inputs: dict[str, Any]) -> str:
    prod = inputs.get("productionBetaSummary")
    if isinstance(prod, dict):
        release_id = prod.get("releaseId")
        if isinstance(release_id, str) and release_id.strip():
            return release_id
        version = prod.get("version")
        if version:
            return f"crypta-production-beta-{version}"
    cert = inputs.get("releaseCertificationSummary")
    if isinstance(cert, dict):
        metadata = cert.get("metadata") if isinstance(cert.get("metadata"), dict) else {}
        release_id = metadata.get("releaseId")
        if isinstance(release_id, str) and release_id.strip():
            return release_id
        release_version = metadata.get("releaseVersion") or metadata.get("version")
        if release_version:
            return f"crypta-production-beta-{release_version}"
    return "crypta-production-beta-candidate"

def input_missing_issue(name: str, mode: str) -> Issue:
    required = name in CRITICAL_INPUTS_BY_MODE.get(mode, ())
    severity = "blocker" if required else "warning"
    return Issue(
        id=f"input.{name}.missing",
        evidence_id=f"input.{name}",
        domain_id="production-beta-release-pipeline",
        severity=severity,
        title=f"{name} input is missing",
        summary=f"{name} was not provided or could not be parsed.",
        source=name,
        waivable=not required,
        category="missing-input",
    )

def production_summary_issues(summary: dict[str, Any] | None, mode: str) -> list[Issue]:
    if not isinstance(summary, dict):
        return []
    issues: list[Issue] = []
    status = normalize_status(summary.get("status"))
    promotion = summary.get("promotion") if isinstance(summary.get("promotion"), dict) else {}
    gates = promotion.get("gates") if isinstance(promotion.get("gates"), list) else []
    has_failed_promotion_gate = any(
        isinstance(gate, dict) and normalize_status(gate.get("status")) != "pass" for gate in gates
    )
    failures = summary.get("failures") if isinstance(summary.get("failures"), list) else []
    redaction = summary.get("redaction") if isinstance(summary.get("redaction"), dict) else {}
    redaction_status = normalize_status(redaction.get("status") if isinstance(redaction, dict) else "missing")
    if redaction_status != "pass":
        issues.append(
            Issue(
                id="production-beta.redaction.status",
                evidence_id="redaction.status",
                domain_id="redaction-artifact-hygiene",
                severity="critical",
                title="Production beta redaction failed",
                summary=f"Production beta artifact redaction status is {redaction_status}.",
                source="production-beta-summary",
                waivable=False,
                category="redaction",
            )
        )
    unexplained_failure = status == "fail" and (failures or not has_failed_promotion_gate)
    malformed_or_nonready_status = status not in {"pass", "fail"}
    if mode == "production-beta" and (malformed_or_nonready_status or unexplained_failure):
        detail = ""
        if failures:
            detail = f" First failure: {failures[0]}."
        issues.append(
            Issue(
                id="production-beta.summary.status",
                evidence_id="production-beta.summary",
                domain_id="production-beta-release-pipeline",
                severity="blocker",
                title="Production beta summary is not passing",
                summary=f"Production beta summary status is {status}.{detail}",
                source="production-beta-summary",
                waivable=False,
                category="pipeline",
            )
        )
    elif unexplained_failure:
        detail = ""
        if failures:
            detail = f" First failure: {failures[0]}."
        issues.append(
            Issue(
                id="production-beta.summary.status",
                evidence_id="production-beta.summary",
                domain_id="production-beta-release-pipeline",
                severity="blocker",
                title="Production beta summary failed",
                summary=f"Production beta summary status is fail.{detail}",
                source="production-beta-summary",
                waivable=False,
                category="pipeline",
            )
        )
    if mode == "production-beta" and summary.get("promotionReady") is not True and not has_failed_promotion_gate:
        issues.append(
            Issue(
                id="production-beta.summary.promotion-ready",
                evidence_id="production-beta.promotion-ready",
                domain_id="production-beta-release-pipeline",
                severity="blocker",
                title="Production beta summary is not promotion-ready",
                summary=f"Production beta summary promotionReady is {summary.get('promotionReady')}.",
                source="production-beta-summary",
                waivable=False,
                category="pipeline",
            )
        )
    profile = summary.get("signingProfile") if isinstance(summary.get("signingProfile"), dict) else {}
    if summary.get("nonRelease") is not False:
        issues.append(
            Issue(
                id="production-beta.non-release",
                evidence_id="production-beta.non-release",
                domain_id="production-beta-release-pipeline",
                severity="critical",
                title="Candidate is not a release artifact",
                summary="Launchable dashboard decisions require productionBetaSummary.nonRelease to be false.",
                source="production-beta-summary",
                waivable=False,
                category="pipeline",
            )
        )
    if mode == "production-beta" and (profile.get("kind") != "production" or profile.get("generatedTestKeys") is True):
        issues.append(
            Issue(
                id="production-beta.test-signing",
                evidence_id="production-beta.test-signing",
                domain_id="catalog-and-app-signing",
                severity="critical",
                title="Production beta candidate is not using production signing",
                summary="Production beta mode cannot use test-only or generated signing material.",
                source="production-beta-summary",
                waivable=False,
                category="signing",
            )
        )
    for gate in gates:
        if not isinstance(gate, dict) or normalize_status(gate.get("status")) == "pass":
            continue
        gate_id = str(gate.get("id", "promotion-gate"))
        evidence_id = canonical_evidence_id(gate_id)
        source = str(gate.get("source", "promotion"))
        mode_non_waivable_ids = non_waivable_evidence_ids_for_mode(mode)
        nonwaivable = (
            gate_id in mode_non_waivable_ids
            or evidence_id in mode_non_waivable_ids
            or is_redaction_evidence(gate_id)
            or is_redaction_evidence(evidence_id)
        )
        if mode == "production-beta" and (gate_id == "signing.production-keys" or "test-signing" in gate_id):
            nonwaivable = True
        if mode == "production-beta" and gate_id in {
            "build.production-beta-complete",
            "workspace.clean-production-beta",
            "fixture-evidence.strict-mode",
        }:
            nonwaivable = True
        issues.append(
            Issue(
                id=f"promotion.{gate_id}",
                evidence_id=evidence_id,
                domain_id=domain_for_gate(evidence_id, source),
                severity="critical" if nonwaivable else "blocker",
                title=f"{gate_id} failed",
                summary=str(gate.get("summary", "Promotion gate failed.")),
                source=source,
                waivable=not nonwaivable,
                category="promotion-gate",
            )
        )
    return issues

def domain_for_gate(gate_id: str, source: str) -> str:
    if gate_id.startswith("live.") or source == "live-network-beta-smoke":
        return "live-network-beta-smoke"
    if gate_id.startswith("multi-node-beta") or source == "multi-node-beta-soak":
        return "multi-node-beta-soak"
    if "signing" in gate_id or "catalog" in gate_id or "review" in gate_id:
        return "catalog-and-app-signing"
    if gate_id.startswith("ecosystem."):
        return "release-certification"
    if "workspace" in gate_id or "build" in gate_id or "fixture" in gate_id:
        return "production-beta-release-pipeline"
    return "production-beta-release-pipeline"

def release_certification_issues(summary: dict[str, Any] | None, mode: str) -> list[Issue]:
    if not isinstance(summary, dict):
        return []
    issues: list[Issue] = []
    evidence_entries = summary.get("evidence") if isinstance(summary.get("evidence"), list) else []
    for entry in evidence_entries:
        if not isinstance(entry, dict):
            continue
        evidence_id = str(entry.get("id", ""))
        if evidence_id != "release-certification.ecosystem-rc-gate":
            continue
        issue = issue_for_evidence("release-certification", evidence_id, entry, mode)
        if issue is not None:
            issues.append(issue)
    if summary.get("releaseCandidatePassed") is not True:
        issues.append(
            Issue(
                id="release-certification.release-candidate-passed",
                evidence_id="release-certification.ecosystem-rc-gate",
                domain_id="release-certification",
                severity="blocker",
                title="Release certification did not pass",
                summary=f"Release certification decision is {summary.get('promotionDecision', 'FAIL')}.",
                source="release-certification-summary",
                waivable=True,
                category="release-certification",
            )
        )
    gates = summary.get("ecosystemGates") if isinstance(summary.get("ecosystemGates"), list) else []
    for gate in gates:
        if not isinstance(gate, dict):
            continue
        if normalize_status(gate.get("status")) == "pass":
            continue
        gate_id = str(gate.get("id", "ecosystem-gate"))
        details = gate.get("details") if isinstance(gate.get("details"), dict) else {}
        unwaivable = bool(details.get("unwaivableFailureEvidenceIds")) or is_redaction_evidence(gate_id)
        issues.append(
            Issue(
                id=f"release-certification.{gate_id}",
                evidence_id=gate_id,
                domain_id="release-certification",
                severity="critical" if unwaivable else ("blocker" if gate.get("releaseBlocker") else "warning"),
                title=f"{gate_id} is not passing",
                summary=str(gate.get("summary", "Ecosystem gate is not passing.")),
                source="release-certification-summary",
                waivable=not unwaivable and bool(gate.get("releaseBlocker", True)),
                category="release-certification",
            )
        )
    return issues

def parse_release_blocker_count(value: Any) -> tuple[int, bool]:
    if value is None or value == "":
        return 0, False
    if isinstance(value, bool):
        return 0, True
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text or not text.isdigit():
            return 0, True
        parsed = int(text)
    else:
        return 0, True
    if parsed < 0:
        return 0, True
    return parsed, False

def stable_summary_record_errors(
    summary: dict[str, Any],
    field_name: str,
    count_field_name: str,
    parsed_count: int,
    malformed_count: bool,
) -> list[str]:
    value = summary.get(field_name)
    if not isinstance(value, list):
        return [f"{field_name} must be a list"]
    errors: list[str] = []
    record_count = len(value)
    if record_count:
        errors.append(f"{field_name} contains {record_count} record(s)")
    if not malformed_count and parsed_count != record_count:
        errors.append(f"{count_field_name} is {parsed_count} but {field_name} contains {record_count}")
    return errors

def stable_summary_allowed_limitation_metadata_errors(record: Any, label: str) -> list[str]:
    if not isinstance(record, dict):
        return [f"{label} must be an object"]
    errors: list[str] = []
    for field in ("id", "title", "category", "classification", "status", "summary", "boundedBy"):
        if not isinstance(record.get(field), str) or not str(record.get(field)).strip():
            errors.append(f"{label}.{field} must be a non-empty string")
    classification = str(record.get("classification", "")).strip().lower()
    if classification and classification != "allowed-for-stable-1.0":
        errors.append(f"{label}.classification must be allowed-for-stable-1.0")
    evidence_ids = record.get("evidenceIds")
    if not isinstance(evidence_ids, list) or not evidence_ids:
        errors.append(f"{label}.evidenceIds must be a non-empty list")
    elif any(not isinstance(item, str) or not item.strip() for item in evidence_ids):
        errors.append(f"{label}.evidenceIds must contain only non-empty strings")
    return errors

def stable_summary_domain_id_errors(summary: dict[str, Any]) -> list[str]:
    domains = summary.get("domains")
    if not isinstance(domains, list) or not domains:
        return []
    domain_ids = [
        str(domain.get("id", "")).strip()
        for domain in domains
        if isinstance(domain, dict) and str(domain.get("id", "")).strip()
    ]
    expected_ids = set(STABLE_1_0_READINESS_DOMAIN_IDS)
    actual_ids = set(domain_ids)
    errors: list[str] = []
    missing_ids = sorted(expected_ids - actual_ids)
    if missing_ids:
        errors.append("domains are missing required IDs: " + ", ".join(missing_ids))
    duplicate_ids = sorted(
        domain_id for domain_id in actual_ids if domain_ids.count(domain_id) > 1
    )
    if duplicate_ids:
        errors.append("domains contain duplicate IDs: " + ", ".join(duplicate_ids))
    unexpected_ids = sorted(actual_ids - expected_ids)
    if unexpected_ids:
        errors.append("domains contain unexpected IDs: " + ", ".join(unexpected_ids))
    return errors

def stable_summary_domain_allowed_limitation_consistency_errors(
    summary: dict[str, Any],
) -> list[str]:
    domains = summary.get("domains")
    top_level_limitations = summary.get("allowedLimitations")
    if not isinstance(domains, list) or not isinstance(top_level_limitations, list):
        return []
    errors: list[str] = []
    for index, domain in enumerate(domains):
        if not isinstance(domain, dict):
            continue
        domain_id = str(domain.get("id") or f"domains[{index}]")
        allowed_limitations = domain.get("allowedLimitations")
        if not isinstance(allowed_limitations, list):
            continue
        limitation_records = [
            limitation for limitation in allowed_limitations if isinstance(limitation, dict)
        ]
        status = normalize_status(domain.get("status", "missing"))
        if limitation_records and status == "pass":
            errors.append(
                f"domain {domain_id} status is pass but contains "
                f"{len(limitation_records)} allowed limitation(s)"
            )
        for allowed_index, limitation in enumerate(allowed_limitations):
            if isinstance(limitation, dict) and limitation not in top_level_limitations:
                errors.append(
                    f"domain {domain_id} allowedLimitations[{allowed_index}] "
                    "is not present in top-level allowedLimitations"
                )
    return errors

def stable_summary_domain_errors(summary: dict[str, Any]) -> list[str]:
    domains = summary.get("domains")
    if not isinstance(domains, list):
        return ["domains must be a non-empty list"]
    if not domains:
        return ["domains must not be empty"]
    errors = stable_summary_domain_id_errors(summary)
    for index, domain in enumerate(domains):
        if not isinstance(domain, dict):
            errors.append(f"domains[{index}] must be an object")
            continue
        domain_id = str(domain.get("id") or f"domains[{index}]")
        status = normalize_status(domain.get("status", "missing"))
        if status in {"fail", "missing", "skip"}:
            errors.append(f"domain {domain_id} status is {status}")
        blockers = domain.get("blockers")
        if blockers is not None and not isinstance(blockers, list):
            errors.append(f"domain {domain_id} blockers must be a list")
        elif isinstance(blockers, list) and blockers:
            errors.append(f"domain {domain_id} contains {len(blockers)} blocker(s)")
        for field_name in ("warnings", "allowedLimitations"):
            if field_name in domain and not isinstance(domain.get(field_name), list):
                errors.append(f"domain {domain_id} {field_name} must be a list")
        warnings = domain.get("warnings")
        allowed_limitations = domain.get("allowedLimitations")
        if (
            status == "warn"
            and not (isinstance(warnings, list) and warnings)
            and not (isinstance(allowed_limitations, list) and allowed_limitations)
        ):
            errors.append(
                f"domain {domain_id} status is warn but contains no warnings or allowed limitations"
            )
        if isinstance(allowed_limitations, list):
            for allowed_index, limitation in enumerate(allowed_limitations):
                errors.extend(
                    stable_summary_allowed_limitation_metadata_errors(
                        limitation,
                        f"domain {domain_id} allowedLimitations[{allowed_index}]",
                    )
                )
    errors.extend(stable_summary_domain_allowed_limitation_consistency_errors(summary))
    return errors

def stable_summary_warning_labels(summary: dict[str, Any]) -> list[str]:
    labels: list[str] = []

    def append_warnings(value: Any, prefix: str) -> None:
        if not isinstance(value, list):
            return
        for index, warning in enumerate(value):
            fallback = f"{prefix}[{index}]"
            if isinstance(warning, dict):
                label = warning.get("id") or warning.get("evidenceId") or fallback
            else:
                label = fallback
            labels.append(str(label))

    append_warnings(summary.get("warnings"), "warnings")
    domains = summary.get("domains")
    if isinstance(domains, list):
        for index, domain in enumerate(domains):
            if not isinstance(domain, dict):
                continue
            domain_id = str(domain.get("id") or f"domains[{index}]")
            append_warnings(domain.get("warnings"), f"domain {domain_id} warnings")
    return list(dict.fromkeys(labels))

def stable_summary_warning_record_errors(
    summary: dict[str, Any],
    parsed_count: int,
    malformed_count: bool,
) -> list[str]:
    warnings = summary.get("warnings")
    if not isinstance(warnings, list):
        return ["warnings must be a list"]
    errors = [
        f"warnings[{index}] must be an object"
        for index, warning in enumerate(warnings)
        if not isinstance(warning, dict)
    ]
    warning_record_count = len(warnings)
    domain_warning_record_count = 0
    domains = summary.get("domains")
    if isinstance(domains, list):
        domain_warning_record_count = sum(
            len(domain.get("warnings", []))
            for domain in domains
            if isinstance(domain, dict) and isinstance(domain.get("warnings", []), list)
        )
        errors.extend(
            f"domains[{domain_index}].warnings[{warning_index}] must be an object"
            for domain_index, domain in enumerate(domains)
            if isinstance(domain, dict) and isinstance(domain.get("warnings", []), list)
            for warning_index, warning in enumerate(domain.get("warnings", []))
            if not isinstance(warning, dict)
        )
    if not malformed_count and parsed_count != warning_record_count:
        errors.append(
            f"warningCount is {parsed_count} but warnings contains {warning_record_count} record(s)"
        )
    if not malformed_count and parsed_count != domain_warning_record_count:
        errors.append(
            "warningCount is "
            f"{parsed_count} but domains contain {domain_warning_record_count} warning record(s)"
        )
    return errors

def stable_summary_redaction_domain_errors(summary: dict[str, Any]) -> list[str]:
    domains = summary.get("domains")
    if not isinstance(domains, list):
        return []
    errors: list[str] = []
    for index, domain in enumerate(domains):
        if not isinstance(domain, dict):
            continue
        domain_id = str(domain.get("id") or f"domains[{index}]")
        evidence_ids = domain.get("evidenceIds")
        blocker_rows = domain.get("blockers")
        blocker_evidence_ids = [
            str(blocker.get("evidenceId", ""))
            for blocker in blocker_rows
            if isinstance(blocker, dict)
        ] if isinstance(blocker_rows, list) else []
        redaction_domain = (
            domain_id == "redaction"
            or (
                isinstance(evidence_ids, list)
                and "stable-1.0.redaction" in [str(evidence_id) for evidence_id in evidence_ids]
            )
            or "stable-1.0.redaction" in blocker_evidence_ids
        )
        if not redaction_domain:
            continue
        status = normalize_status(domain.get("status", "missing"))
        if status != "pass":
            errors.append(f"domain {domain_id} status is {status}")
        if isinstance(blocker_rows, list) and blocker_rows:
            errors.append(f"domain {domain_id} contains {len(blocker_rows)} blocker(s)")
    return errors

def ecosystem_matrix_issues(matrix: dict[str, Any] | None) -> list[Issue]:
    if not isinstance(matrix, dict):
        return []
    issues: list[Issue] = []
    status = normalize_status(matrix.get("status"))
    release_blocker_count, malformed_release_blocker_count = parse_release_blocker_count(
        matrix.get("releaseBlockerCount", 0)
    )
    if status not in {"pass", "warn"} or malformed_release_blocker_count or release_blocker_count > 0:
        details: list[str] = []
        if status not in {"pass", "warn"}:
            details.append(f"status is {status}")
        if malformed_release_blocker_count:
            details.append("releaseBlockerCount is not a non-negative integer")
        elif release_blocker_count > 0:
            details.append(f"releaseBlockerCount is {release_blocker_count}")
        detail = "; ".join(details) if details else "contains release blockers"
        issues.append(
            Issue(
                id="ecosystem-matrix.release-blockers",
                evidence_id="release-certification.ecosystem-matrix",
                domain_id="ecosystem-rc-certification-matrix",
                severity="blocker",
                title="Ecosystem matrix has release blockers",
                summary=f"Ecosystem certification matrix {detail}.",
                source="ecosystem-certification-matrix",
                waivable=not malformed_release_blocker_count,
                category="ecosystem-matrix",
            )
        )
    coverage = matrix.get("coverage") if isinstance(matrix.get("coverage"), dict) else {}
    if coverage.get("redactionPassed") is False:
        issues.append(
            Issue(
                id="ecosystem-matrix.redaction",
                evidence_id="production-beta.dashboard-redaction",
                domain_id="redaction-artifact-hygiene",
                severity="critical",
                title="Ecosystem matrix redaction failed",
                summary="Ecosystem matrix coverage reports redactionPassed=false.",
                source="ecosystem-certification-matrix",
                waivable=False,
                category="redaction",
            )
        )
    rows = matrix.get("rows") if isinstance(matrix.get("rows"), list) else []
    for row in rows:
        if not isinstance(row, dict):
            continue
        status = normalize_status(row.get("status"))
        details = row.get("details") if isinstance(row.get("details"), dict) else {}
        if (
            row.get("id") == "stable-1-0-readiness"
            and status == "skip"
            and row.get("releaseBlocker") is not True
            and (
                details.get("notRequested") is True
                or "not requested" in str(row.get("summary", "")).lower()
            )
        ):
            continue
        if status in {"pass", "warn"} and row.get("releaseBlocker") is not True:
            continue
        row_id = str(row.get("id", "matrix-row"))
        redaction_row = row_id == "redaction-and-private-artifacts" or is_redaction_evidence(row_id)
        issues.append(
            Issue(
                id=f"ecosystem-matrix.{row_id}",
                evidence_id=row_id,
                domain_id="ecosystem-rc-certification-matrix",
                severity="critical" if redaction_row else ("blocker" if row.get("releaseBlocker") else "warning"),
                title=f"{row_id} matrix row is not passing",
                summary=str(row.get("recommendation") or row.get("title") or "Matrix row is not passing."),
                source="ecosystem-certification-matrix",
                waivable=not redaction_row and bool(row.get("releaseBlocker", True)),
                category="ecosystem-matrix",
            )
        )
    return issues

NETWORK_SCALE_REDACTION_FLAGS = (
    "rawFetchedContentExcluded",
    "privateInsertUrisExcluded",
    "tokensExcluded",
    "absolutePathsExcluded",
    "queueHtmlExcluded",
)

def network_scale_redaction_failed(redaction: Any) -> bool:
    if not isinstance(redaction, dict):
        return True
    redaction_status = normalize_status(redaction.get("status"))
    findings = redaction.get("findings")
    findings_malformed = "findings" in redaction and not isinstance(findings, list)
    finding_count, finding_count_malformed = parse_release_blocker_count(
        redaction.get("findingCount", 0)
    )
    return (
        redaction_status != "pass"
        or findings_malformed
        or bool(findings)
        or finding_count_malformed
        or finding_count > 0
        or any(redaction.get(key) is not True for key in NETWORK_SCALE_REDACTION_FLAGS)
        or recursive_redaction_failure(redaction)
    )

def network_scale_issues(summary: dict[str, Any] | None, mode: str) -> list[Issue]:
    if not isinstance(summary, dict):
        return []
    issues: list[Issue] = []
    status = normalize_status(summary.get("status"))
    if status != "pass":
        issues.append(
            Issue(
                id="network-scale-soak.status",
                evidence_id="network-scale.rc-soak-summary",
                domain_id="network-scale-soak",
                severity="blocker" if mode != "developer-dry-run" else "warning",
                title="Network-scale soak is not passing",
                summary=f"Network-scale soak status is {status}.",
                source="network-scale-soak-summary",
                waivable=mode != "production-beta",
                category="network-scale",
            )
        )
    findings = []
    if network_scale_redaction_failed(summary.get("redaction")):
        findings.append("redaction")
    budget = summary.get("budgets")
    if not isinstance(budget, dict) or any(
        budget.get(key) is not True
        for key in (
            "globalFetchBudgetEnforced",
            "perAppFetchBudgetEnforced",
            "concurrencyLeasesReleased",
        )
    ):
        findings.append("budgets")
    if findings:
        issues.append(
            Issue(
                id="network-scale-soak.redaction-or-budget",
                evidence_id="network-scale.redaction",
                domain_id="network-scale-soak",
                severity="critical",
                title="Network-scale soak redaction or budget checks failed",
                summary=f"Network-scale soak sections failed: {', '.join(sorted(findings))}.",
                source="network-scale-soak-summary",
                waivable=False,
                category="redaction",
            )
        )
    return issues

def non_bool_int(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None

def compact_text(value: Any) -> str:
    return str(value).strip() if value is not None and not isinstance(value, bool) else ""

def catalog_edition_field(catalog_channel: str) -> str:
    return "stableChannelEdition" if catalog_channel == "stable" else "betaChannelEdition"

def previous_candidate_upgrade_current_binding_failures(
    upgrade: dict[str, Any],
    production_summary: dict[str, Any] | None,
) -> list[str]:
    if not isinstance(production_summary, dict):
        return ["productionBetaSummary"]
    failures: list[str] = []
    expected_version = compact_text(production_summary.get("version"))
    if not expected_version:
        failures.append("productionBetaSummary.version")
    elif compact_text(upgrade.get("currentVersion")) != expected_version:
        failures.append("currentVersion")

    expected_channel = compact_text(production_summary.get("catalogChannel"))
    if not expected_channel:
        failures.append("productionBetaSummary.catalogChannel")
        return failures
    if expected_channel not in {"stable", "beta"}:
        failures.append("productionBetaSummary.catalogChannel")
        return failures
    if compact_text(upgrade.get("currentCatalogChannel")) != expected_channel:
        failures.append("currentCatalogChannel")

    metadata = production_summary.get("previousCandidateMetadata")
    catalog = metadata.get("catalog") if isinstance(metadata, dict) else None
    edition_field = catalog_edition_field(expected_channel)
    expected_edition = non_bool_int(catalog.get(edition_field)) if isinstance(catalog, dict) else None
    if expected_edition is None:
        failures.append(f"productionBetaSummary.previousCandidateMetadata.catalog.{edition_field}")
        return failures
    if non_bool_int(upgrade.get("currentCatalogEdition")) != expected_edition:
        failures.append("currentCatalogEdition")
    return failures

def multi_node_issues(
    summary: dict[str, Any] | None,
    mode: str,
    production_summary: dict[str, Any] | None = None,
) -> list[Issue]:
    if not isinstance(summary, dict):
        return []
    issues: list[Issue] = []
    status = normalize_status(summary.get("status"))
    if status != "pass" or summary.get("promotionReady") is not True:
        issues.append(
            Issue(
                id="multi-node-beta-soak.status",
                evidence_id="multi-node-beta.soak",
                domain_id="multi-node-beta-soak",
                severity="blocker" if mode != "developer-dry-run" else "warning",
                title="Multi-node beta soak is not promotion-ready",
                summary=f"Multi-node beta soak status is {status}; promotionReady={summary.get('promotionReady')}.",
                source="multi-node-beta-soak-summary",
                waivable=mode != "production-beta",
                category="multi-node",
            )
        )
    redaction = summary.get("redaction") if isinstance(summary.get("redaction"), dict) else {}
    if normalize_status(redaction.get("status")) != "pass":
        issues.append(
            Issue(
                id="multi-node-beta-soak.redaction",
                evidence_id="multi-node-beta.redaction",
                domain_id="multi-node-beta-soak",
                severity="critical",
                title="Multi-node beta soak redaction failed",
                summary=f"Multi-node beta redaction status is {normalize_status(redaction.get('status'))}.",
                source="multi-node-beta-soak-summary",
                waivable=False,
                category="redaction",
            )
        )
    scenario_statuses = summary.get("scenarioStatuses")
    if isinstance(scenario_statuses, dict):
        for scenario_id, scenario_status in sorted(scenario_statuses.items()):
            if normalize_status(scenario_status) != "pass":
                evidence_id = multi_node_beta_soak.SCENARIO_EVIDENCE_IDS.get(
                    scenario_id,
                    f"multi-node-beta.{scenario_id}",
                )
                issues.append(
                    Issue(
                        id=f"multi-node-beta-soak.{scenario_id}",
                        evidence_id=evidence_id,
                        domain_id="multi-node-beta-soak",
                        severity="blocker",
                        title=f"{scenario_id} scenario is not passing",
                        summary=f"{scenario_id} status is {scenario_status}.",
                        source="multi-node-beta-soak-summary",
                        waivable=mode != "production-beta",
                        category="multi-node",
                    )
                )
    upgrade = summary.get("previousCandidateUpgrade")
    if mode == "production-beta":
        if not isinstance(upgrade, dict):
            issues.append(
                Issue(
                    id="multi-node-beta-soak.previous-candidate-summary",
                    evidence_id="multi-node-beta.previous-candidate-summary",
                    domain_id="multi-node-beta-soak",
                    severity="blocker",
                    title="Previous beta candidate upgrade evidence is missing",
                    summary="Production beta requires compact previous-candidate upgrade evidence in the multi-node summary.",
                    source="multi-node-beta-soak-summary",
                    waivable=False,
                    category="multi-node",
                )
            )
        else:
            expected = {
                "status": "pass",
                "previousSummaryConfigured": True,
                "previousSummaryProvided": True,
                "previousSummaryValid": True,
                "currentUpgradePathRepresented": True,
                "firstPartyAppMigrationStatus": "pass",
                "backupBeforeUpdateStatus": "pass",
                "restoreIntoCleanNodeStatus": "pass",
                "socialInboxMigrationStatus": "pass",
                "trustGraphMigrationStatus": "pass",
                "supportBundleRedactionStatus": "pass",
                "rollbackStatus": "pass",
                "rawDataIncluded": False,
            }
            failed_fields = [
                field
                for field, expected_value in expected.items()
                if upgrade.get(field) != expected_value
            ]
            validation_errors = upgrade.get("previousSummaryValidationErrors")
            if not isinstance(validation_errors, list):
                validation_errors = ["previousSummaryValidationErrors missing"]
            if failed_fields or validation_errors:
                issues.append(
                    Issue(
                        id="multi-node-beta-soak.previous-candidate-summary",
                        evidence_id="multi-node-beta.previous-candidate-summary",
                        domain_id="multi-node-beta-soak",
                        severity="blocker",
                        title="Previous beta candidate upgrade evidence is not production-ready",
                        summary=(
                            "Previous-candidate upgrade evidence has failing fields: "
                            + ", ".join(failed_fields or ["validation"])
                        ),
                        source="multi-node-beta-soak-summary",
                        waivable=False,
                        category="multi-node",
                    )
                )
            binding_failures = previous_candidate_upgrade_current_binding_failures(
                upgrade,
                production_summary,
            )
            if binding_failures:
                issues.append(
                    Issue(
                        id="multi-node-beta-soak.previous-candidate-current-binding",
                        evidence_id="multi-node-beta.previous-candidate-upgrade-binding",
                        domain_id="multi-node-beta-soak",
                        severity="blocker",
                        title="Previous beta candidate upgrade evidence is bound to a different current candidate",
                        summary=(
                            "Previous-candidate upgrade evidence does not match the production summary fields: "
                            + ", ".join(binding_failures)
                        ),
                        source="multi-node-beta-soak-summary",
                        waivable=False,
                        category="multi-node",
                    )
                )
    return issues

def security_response_issues(summary: dict[str, Any] | None) -> list[Issue]:
    if not isinstance(summary, dict):
        return []
    if normalize_status(summary.get("status")) == "pass":
        return []
    return [
        Issue(
            id="security-response-runbook.status",
            evidence_id="production-security.response-runbook",
            domain_id="production-security-response",
            severity="blocker",
            title="Production security response runbook is not passing",
            summary=f"Security response summary status is {normalize_status(summary.get('status'))}.",
            source="security-response-summary",
            waivable=True,
            category="security-response",
        )
    ]

def build_domain_rows(
    inputs: dict[str, Any],
    paths: dict[str, Path],
    workspace_root: Path,
    out_dir: Path,
    all_issues: list[Issue],
    all_evidence: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    issues_by_domain: dict[str, list[Issue]] = {}
    for issue in all_issues:
        issues_by_domain.setdefault(issue.domain_id, []).append(issue)
    for spec in DOMAIN_SPECS:
        domain_id = str(spec["id"])
        evidence_ids = list(spec["evidenceIds"])
        artifact_refs: list[str] = []
        for input_name in spec.get("artifactInputs", ()):
            path = paths.get(str(input_name))
            if path is not None:
                artifact_refs.append(display_path(path, workspace_root))
        source_issues = issues_by_domain.get(domain_id, [])
        status = domain_status(source_issues)
        rows.append(
            {
                "id": domain_id,
                "title": spec["title"],
                "status": status,
                "severity": "required",
                "evidenceIds": evidence_ids,
                "artifactRefs": sorted(dict.fromkeys(artifact_refs)),
                "summary": domain_summary(domain_id, status, source_issues, evidence_ids, all_evidence),
            }
        )
    return rows

def domain_summary(
    domain_id: str,
    status: str,
    issues: list[Issue],
    evidence_ids: list[str],
    all_evidence: dict[str, dict[str, Any]],
) -> str:
    if status == "pass":
        reported = [evidence_id for evidence_id in evidence_ids if evidence_id in all_evidence]
        if reported:
            return f"{len(reported)} evidence item(s) reported and passing."
        if domain_id == "redaction-artifact-hygiene":
            return "Dashboard input and output redaction scan passed."
        return "Domain passed."
    if status == "waived":
        return "Blocking findings are covered by explicit valid waivers."
    if issues:
        first = sorted(issues, key=lambda issue: (issue.severity != "critical", issue.id))[0]
        return first.summary
    return "Domain is not passing."

def compact_security_drills(
    summary: dict[str, Any] | None,
    production: bool = False,
    strict: bool = False,
    now: dt.datetime | None = None,
    expected_release_id: str | None = None,
    expected_mode: str | None = None,
    artifact_validation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(summary, dict):
        return {
            "status": "missing",
            "promotionReady": False,
            "expectedReleaseId": expected_release_id or "not-required",
            "requiredScenarioCount": len(security_response_runbook.REQUIRED_DRILLS),
            "passedScenarioCount": 0,
            "failedScenarioCount": 0,
            "missingScenarioCount": len(security_response_runbook.REQUIRED_DRILLS),
            "staleScenarioCount": 0,
            "malformedScenarioCount": 0,
            "redactionStatus": "missing",
            "releaseNotesTemplateStatus": "missing",
            "advisoryTemplateStatus": "missing",
            "supportBundleIntakeRedactionStatus": "missing",
        }
    if summary.get("kind") != "cryptad-security-response-drills-summary":
        return {
            "status": "fail",
            "promotionReady": False,
            "requiredScenarios": list(security_response_runbook.REQUIRED_DRILLS),
            "passedScenarios": [],
            "failedScenarios": [],
            "missingScenarios": list(security_response_runbook.REQUIRED_DRILLS),
            "staleScenarios": [],
            "malformedScenarios": [str(summary.get("scenario", summary.get("kind", "unknown")))],
            "requiredScenarioCount": len(security_response_runbook.REQUIRED_DRILLS),
            "passedScenarioCount": 0,
            "failedScenarioCount": 0,
            "missingScenarioCount": len(security_response_runbook.REQUIRED_DRILLS),
            "staleScenarioCount": 0,
            "malformedScenarioCount": 1,
            "redactionStatus": "fail",
            "releaseNotesTemplateStatus": "missing",
            "advisoryTemplateStatus": "missing",
            "supportBundleIntakeRedactionStatus": "missing",
            "fixtureOnly": bool(summary.get("fixtureOnly")),
            "nonRelease": bool(summary.get("nonRelease")),
            "releaseId": summary.get("releaseId", "missing"),
            "expectedReleaseId": expected_release_id or "not-required",
            "releaseIdMatchesDashboard": False,
        }
    counts = summary.get("counts") if isinstance(summary.get("counts"), dict) else {}
    redaction = summary.get("redaction") if isinstance(summary.get("redaction"), dict) else {}
    release_notes = summary.get("releaseNotes") if isinstance(summary.get("releaseNotes"), dict) else {}
    advisory_template = (
        summary.get("advisoryTemplate") if isinstance(summary.get("advisoryTemplate"), dict) else {}
    )
    validation = security_response_runbook.validate_drills_summary(
        summary,
        production=production,
        strict=strict,
        now=now,
        expected_mode=expected_mode,
    )
    validation_errors = list(validation.get("errors", [])) if isinstance(validation.get("errors"), list) else []
    release_id = summary.get("releaseId")
    release_id_matches = not (
        strict
        and expected_release_id
        and release_id != expected_release_id
    )
    if not release_id_matches:
        validation_errors.append(f"releaseId must match dashboard candidate {expected_release_id}")
    artifact_errors = (
        artifact_validation.get("errors")
        if isinstance(artifact_validation, dict)
        and isinstance(artifact_validation.get("errors"), list)
        else []
    )
    validation_errors.extend(str(error) for error in artifact_errors)
    computed_status = normalize_status(summary.get("status"))
    artifacts_valid = (
        artifact_validation is None
        or artifact_validation.get("status") == "pass"
    )
    if validation.get("status") != "pass" or not release_id_matches or not artifacts_valid:
        computed_status = "fail"
    passed_scenarios = summary.get("passedScenarios") if isinstance(summary.get("passedScenarios"), list) else []
    failed_scenarios = summary.get("failedScenarios") if isinstance(summary.get("failedScenarios"), list) else []
    missing_scenarios = summary.get("missingScenarios") if isinstance(summary.get("missingScenarios"), list) else []
    stale_scenarios = summary.get("staleScenarios") if isinstance(summary.get("staleScenarios"), list) else []
    malformed_scenarios = summary.get("malformedScenarios") if isinstance(summary.get("malformedScenarios"), list) else []
    support_status = "pass" if "support-bundle-intake-redaction" in passed_scenarios else "missing"
    if "support-bundle-intake-redaction" in failed_scenarios:
        support_status = "fail"
    elif "support-bundle-intake-redaction" in stale_scenarios:
        support_status = "stale"
    elif "support-bundle-intake-redaction" in malformed_scenarios:
        support_status = "fail"
    return {
        "status": computed_status,
        "promotionReady": (
            bool(summary.get("promotionReady"))
            and validation.get("status") == "pass"
            and release_id_matches
            and artifacts_valid
        ),
        "releaseId": release_id if isinstance(release_id, str) else "missing",
        "expectedReleaseId": expected_release_id or "not-required",
        "releaseIdMatchesDashboard": release_id_matches,
        "requiredScenarios": summary.get("requiredScenarios", []),
        "passedScenarios": passed_scenarios,
        "failedScenarios": failed_scenarios,
        "missingScenarios": missing_scenarios,
        "staleScenarios": stale_scenarios,
        "malformedScenarios": malformed_scenarios,
        "requiredScenarioCount": safe_int_count(
            counts.get("required"),
            len(security_response_runbook.REQUIRED_DRILLS),
        ),
        "passedScenarioCount": safe_int_count(counts.get("passed"), len(passed_scenarios)),
        "failedScenarioCount": safe_int_count(counts.get("failed"), len(failed_scenarios)),
        "missingScenarioCount": safe_int_count(counts.get("missing"), len(missing_scenarios)),
        "staleScenarioCount": safe_int_count(counts.get("stale"), len(stale_scenarios)),
        "malformedScenarioCount": safe_int_count(
            counts.get("malformed"),
            len(malformed_scenarios),
        ),
        "redactionStatus": normalize_status(redaction.get("status")),
        "criticalBlockers": len(failed_scenarios) + len(missing_scenarios) + len(stale_scenarios) + len(malformed_scenarios),
        "releaseNotesTemplateStatus": normalize_status(release_notes.get("templateStatus")),
        "advisoryTemplateStatus": normalize_status(advisory_template.get("templateStatus")),
        "supportBundleIntakeRedactionStatus": support_status,
        "fixtureOnly": bool(summary.get("fixtureOnly")),
        "nonRelease": bool(summary.get("nonRelease")),
        "artifactValidation": artifact_validation or {},
        "validationErrors": validation_errors,
    }

def compact_stable_readiness(
    summary: dict[str, Any] | None,
    required: bool = False,
    expected_release_id: str | None = None,
) -> dict[str, Any]:
    if not isinstance(summary, dict):
        return {
            "status": "missing",
            "decision": "not-attached",
            "stableReady": False,
            "required": required,
            "releaseId": "missing",
            "expectedReleaseId": expected_release_id if required and expected_release_id else "not-required",
            "releaseIdMatchesDashboard": False if required and expected_release_id else True,
            "blockerCount": 0,
            "warningCount": 0,
            "allowedLimitationCount": 0,
            "disallowedLimitationCount": 0,
            "redactionStatus": "missing",
        }
    redaction = summary.get("redaction") if isinstance(summary.get("redaction"), dict) else {}
    release_id = summary.get("releaseId")
    release_id_matches = not (
        expected_release_id
        and (not isinstance(release_id, str) or release_id != expected_release_id)
    )
    return {
        "status": normalize_status(summary.get("status")),
        "decision": str(summary.get("decision", "not-ready")),
        "stableReady": summary.get("stableReady") is True,
        "required": required,
        "releaseId": release_id if isinstance(release_id, str) else "missing",
        "expectedReleaseId": expected_release_id or "not-required",
        "releaseIdMatchesDashboard": release_id_matches,
        "blockerCount": safe_int_count(summary.get("blockerCount"), 0),
        "warningCount": safe_int_count(summary.get("warningCount"), 0),
        "allowedLimitationCount": safe_int_count(summary.get("allowedLimitationCount"), 0),
        "disallowedLimitationCount": safe_int_count(summary.get("disallowedLimitationCount"), 0),
        "redactionStatus": normalize_status(redaction.get("status", "missing")),
    }

def safe_int_count(value: Any, fallback: int) -> int:
    if isinstance(value, bool):
        return fallback
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback

def scope_applies(scope: str, mode: str) -> bool:
    normalized = scope.strip().lower()
    if normalized in {"all", "all-modes", "any"}:
        return True
    if normalized in {mode, f"{mode}-only"}:
        return True
    if normalized == "release-candidate-and-production-beta" and mode in {"release-candidate", "production-beta"}:
        return True
    if normalized == "release-candidate-only" and mode == "release-candidate":
        return True
    if normalized == "production-beta-only" and mode == "production-beta":
        return True
    return False

def release_certification_scope(entry: dict[str, Any]) -> str:
    scope = str(entry.get("scope", "")).strip()
    if scope:
        return scope
    allow_release_candidate = entry.get("allowReleaseCandidate")
    if isinstance(allow_release_candidate, bool):
        return "release-candidate" if allow_release_candidate else "developer-dry-run"
    return ""

def release_certification_owner(entry: dict[str, Any]) -> str:
    owner = str(entry.get("owner", "")).strip()
    if owner:
        return owner
    if "reason" in entry or "allowReleaseCandidate" in entry:
        return str(entry.get("approvedBy", "")).strip() or "release-certification"
    return ""

def release_certification_record_scope(record: dict[str, Any]) -> str:
    scope = str(record.get("scope", "")).strip()
    if scope:
        return scope
    if record.get("allowReleaseCandidate") is True or record.get("appliesToReleaseCandidate") is True:
        return "release-candidate"
    return "developer-dry-run"

def release_certification_record_applies(record: dict[str, Any], mode: str) -> bool:
    if mode == "production-beta":
        return release_certification_record_scope(record).strip().lower() in {
            "production-beta",
            "production-beta-only",
            "release-candidate-and-production-beta",
            "all",
            "all-modes",
            "any",
        }
    if mode == "release-candidate":
        return record.get("allowReleaseCandidate") is True or record.get("appliesToReleaseCandidate") is True
    return True

def release_certification_waiver_records(
    summary: dict[str, Any] | None,
    mode: str,
    now: dt.datetime,
    workspace_root: Path,
    out_dir: Path,
) -> list[Waiver]:
    if not isinstance(summary, dict):
        return []
    records = summary.get("waiverRecords")
    if not isinstance(records, list):
        return []
    waivers: list[Waiver] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        waiver_id = str(record.get("id", "")).strip()
        evidence_id = str(record.get("evidenceId", waiver_id)).strip()
        if not waiver_id and not evidence_id:
            continue
        status = str(record.get("status", "approved")).strip().lower()
        expired = record.get("expired") is True
        applies = release_certification_record_applies(record, mode)
        expires_at = str(record.get("expiresAt", "")).strip()
        expiry = parse_time(expires_at)
        validation_error = str(record.get("validationError", "")).strip()
        validation_errors: list[str] = []
        if validation_error:
            validation_errors.append(validation_error)
        if not expires_at:
            validation_errors.append("expiresAt is required")
        elif expiry is None:
            validation_errors.append("expiresAt must be an ISO-8601 timestamp")
        elif expiry <= now:
            validation_errors.append("waiver is expired")
        active = (
            record.get("active") is True
            and status == "approved"
            and not expired
            and applies
            and not validation_errors
        )
        safe_errors = tuple(scrub_text(error, workspace_root, out_dir) for error in validation_errors)
        waivers.append(
            Waiver(
                id=scrub_text(waiver_id or evidence_id or f"release-certification-waiver-{index}", workspace_root, out_dir),
                evidence_id=scrub_text(evidence_id or waiver_id or f"release-certification-waiver-{index}", workspace_root, out_dir),
                severity="blocker",
                scope=scrub_text(release_certification_record_scope(record), workspace_root, out_dir),
                rationale=scrub_text(str(record.get("reason", record.get("rationale", ""))).strip(), workspace_root, out_dir),
                approved_by=scrub_text(str(record.get("approvedBy", "")).strip(), workspace_root, out_dir),
                owner=scrub_text(str(record.get("owner", "release-certification")).strip() or "release-certification", workspace_root, out_dir),
                created_at=scrub_text(str(record.get("createdAt", "")).strip(), workspace_root, out_dir),
                expires_at=scrub_text(expires_at, workspace_root, out_dir),
                references=(),
                source=scrub_text(str(record.get("source", "release-certification")).strip() or "release-certification", workspace_root, out_dir),
                active=active,
                applies_to_mode=applies,
                external_risk_accepted=False,
                validation_errors=safe_errors,
            )
        )
    return waivers

def severity_covers(waiver: Waiver, issue: Issue) -> bool:
    return SEVERITY_RANK.get(waiver.severity, -1) >= SEVERITY_RANK.get(issue.severity, 99)

def issue_is_non_waivable_in_mode(issue: Issue, mode: str) -> bool:
    if issue.severity == "critical":
        return True
    mode_non_waivable_ids = non_waivable_evidence_ids_for_mode(mode)
    return issue.id in mode_non_waivable_ids or issue.evidence_id in mode_non_waivable_ids

def load_waivers(
    value: dict[str, Any] | None,
    source: str,
    mode: str,
    now: dt.datetime,
    known_ids: set[str],
    workspace_root: Path,
    out_dir: Path,
) -> tuple[list[Waiver], list[Issue]]:
    if value is None:
        return [], []
    errors: list[Issue] = []
    if value.get("__loadError"):
        return [], [
            Issue(
                id="waiver.file.invalid",
                evidence_id="production-beta.waiver-validation",
                domain_id="redaction-artifact-hygiene",
                severity="blocker",
                title="Waiver file is invalid",
                summary=scrub_text(str(value["__loadError"]), workspace_root, out_dir),
                source=source,
                waivable=False,
                category="waiver-validation",
            )
        ]
    records_value = value.get("waivers")
    schema_version = value.get("schemaVersion", value.get("version"))
    if schema_version != 1 or not isinstance(records_value, list):
        return [], [
            Issue(
                id="waiver.schema.invalid",
                evidence_id="production-beta.waiver-validation",
                domain_id="redaction-artifact-hygiene",
                severity="blocker",
                title="Waiver file is invalid",
                summary="Waiver file must use schemaVersion/version 1 and a waivers array.",
                source=source,
                waivable=False,
                category="waiver-validation",
            )
        ]
    waivers: list[Waiver] = []
    for index, entry in enumerate(records_value):
        validation_errors: list[str] = []
        if not isinstance(entry, dict):
            validation_errors.append("entry must be an object")
            entry = {}
        waiver_id = str(entry.get("id", "")).strip()
        evidence_id = str(entry.get("evidenceId", waiver_id)).strip()
        severity = str(entry.get("severity", "blocker")).strip().lower()
        scope = release_certification_scope(entry)
        rationale = str(entry.get("rationale", entry.get("reason", ""))).strip()
        approved_by = str(entry.get("approvedBy", "")).strip()
        owner = release_certification_owner(entry)
        created_at = str(entry.get("createdAt", "")).strip()
        expires_at = str(entry.get("expiresAt", "")).strip()
        references_value = entry.get("references", [])
        references = tuple(str(item) for item in references_value) if isinstance(references_value, list) else ()
        external_risk_accepted = entry.get("externalRiskAccepted") is True
        status = str(entry.get("status", "approved")).strip().lower()
        applies = scope_applies(scope, mode) if scope else False
        expiry = parse_time(expires_at)
        if not waiver_id:
            validation_errors.append("id is required")
        if not evidence_id:
            validation_errors.append("evidenceId is required")
        if severity not in SEVERITIES:
            validation_errors.append("severity must be info, warning, blocker, or critical")
        if not scope:
            validation_errors.append("scope is required")
        if not rationale:
            validation_errors.append("rationale is required")
        if not approved_by:
            validation_errors.append("approvedBy is required")
        if not owner:
            validation_errors.append("owner is required")
        if status != "approved":
            validation_errors.append("status must be approved")
        if not isinstance(references_value, list):
            validation_errors.append("references must be an array when provided")
        if not expires_at:
            validation_errors.append("expiresAt is required")
        elif expiry is None:
            validation_errors.append("expiresAt must be an ISO-8601 timestamp")
        elif expiry <= now:
            validation_errors.append("waiver is expired")
        if not applies:
            validation_errors.append(f"scope does not apply to {mode}")
        if evidence_id and evidence_id not in known_ids and not external_risk_accepted:
            validation_errors.append("evidenceId is unknown and externalRiskAccepted is not true")
        if mode == "production-beta" and evidence_id_is_non_waivable_in_mode(evidence_id, mode):
            validation_errors.append("target is non-waivable in production-beta mode")
        active = not validation_errors
        safe_errors = tuple(scrub_text(error, workspace_root, out_dir) for error in validation_errors)
        waiver = Waiver(
            id=scrub_text(waiver_id or f"{source}#{index}", workspace_root, out_dir),
            evidence_id=scrub_text(evidence_id or waiver_id or f"{source}#{index}", workspace_root, out_dir),
            severity=severity if severity in SEVERITIES else "blocker",
            scope=scrub_text(scope, workspace_root, out_dir),
            rationale=scrub_text(rationale, workspace_root, out_dir),
            approved_by=scrub_text(approved_by, workspace_root, out_dir),
            owner=scrub_text(owner, workspace_root, out_dir),
            created_at=scrub_text(created_at, workspace_root, out_dir),
            expires_at=scrub_text(expires_at if expiry is not None else expires_at, workspace_root, out_dir),
            references=tuple(scrub_text(reference, workspace_root, out_dir) for reference in references),
            source=source,
            active=active,
            applies_to_mode=applies,
            external_risk_accepted=external_risk_accepted,
            validation_errors=safe_errors,
        )
        waivers.append(waiver)
        if validation_errors:
            errors.append(
                Issue(
                    id=f"waiver.{waiver.id}.invalid",
                    evidence_id="production-beta.waiver-validation",
                    domain_id="redaction-artifact-hygiene",
                    severity="blocker",
                    title=f"Waiver {waiver.id} is invalid",
                    summary="; ".join(safe_errors),
                    source=source,
                    waivable=False,
                    category="waiver-validation",
                )
            )
    return waivers, errors

def apply_waivers(issues: list[Issue], waivers: list[Waiver], mode: str) -> tuple[list[Issue], list[Waiver], list[Issue]]:
    applied: list[Issue] = []
    usage: dict[str, list[str]] = {waiver.id: [] for waiver in waivers}
    validation_issues: list[Issue] = []
    for issue in issues:
        if issue.waived_by:
            matching = next(
                (
                    waiver
                    for waiver in waivers
                    if waiver.active
                    and waiver.id == issue.waived_by
                    and waiver.matches(issue)
                    and severity_covers(waiver, issue)
                ),
                None,
            )
            if matching is None or issue_is_non_waivable_in_mode(issue, mode):
                validation_issues.append(
                    Issue(
                        id=f"waiver.{issue.waived_by}.missing-or-invalid",
                        evidence_id="production-beta.waiver-validation",
                        domain_id="redaction-artifact-hygiene",
                        severity="blocker",
                        title="Applied waiver is missing or invalid",
                        summary=f"Evidence {issue.evidence_id} references waiver {issue.waived_by}, but no matching active waiver record is valid.",
                        source=issue.source,
                        waivable=False,
                        category="waiver-validation",
                    )
                )
                applied.append(dataclasses.replace(issue, waived_by=""))
                continue
            usage.setdefault(matching.id, []).append(issue.id)
            applied.append(dataclasses.replace(issue, waived_by=matching.id))
            continue
        if issue.severity not in {"blocker", "critical"} or not issue.waivable:
            applied.append(issue)
            continue
        matching = None
        under_severity = None
        for waiver in reversed(waivers):
            if not waiver.active or not waiver.matches(issue):
                continue
            if not severity_covers(waiver, issue):
                under_severity = waiver
                continue
            matching = waiver
            break
        if matching is None:
            if under_severity is not None:
                validation_issues.append(
                    Issue(
                        id=f"waiver.{under_severity.id}.severity-too-low",
                        evidence_id="production-beta.waiver-validation",
                        domain_id="redaction-artifact-hygiene",
                        severity="blocker",
                        title="Waiver severity is lower than finding severity",
                        summary=(
                            f"Waiver {under_severity.id} is approved for {under_severity.severity} "
                            f"but {issue.evidence_id} is {issue.severity}."
                        ),
                        source=under_severity.source,
                        waivable=False,
                        category="waiver-validation",
                    )
                )
            applied.append(issue)
            continue
        if issue_is_non_waivable_in_mode(issue, mode):
            validation_issues.append(
                Issue(
                    id=f"waiver.{matching.id}.non-waivable-target",
                    evidence_id="production-beta.waiver-validation",
                    domain_id="redaction-artifact-hygiene",
                    severity="blocker",
                    title="Waiver targets a non-waivable finding",
                    summary=f"Waiver {matching.id} cannot waive {issue.evidence_id}.",
                    source=matching.source,
                    waivable=False,
                    category="waiver-validation",
                )
            )
            applied.append(issue)
            continue
        usage[matching.id].append(issue.id)
        applied.append(dataclasses.replace(issue, waived_by=matching.id))
    used_waivers = [waiver.with_usage(usage.get(waiver.id, [])) for waiver in waivers]
    return [*applied, *validation_issues], used_waivers, validation_issues

def live_evidence_required(inputs: dict[str, Any], mode: str) -> bool:
    if mode == "production-beta":
        return True
    summary = inputs.get("liveNetworkSummary")
    if not isinstance(summary, dict):
        return False
    return summary.get("enabled") is True or summary.get("required") is True

def collect_issues(
    inputs: dict[str, Any],
    mode: str,
    input_paths: dict[str, Path],
    now: dt.datetime,
    release_id: str,
    require_stable_readiness: bool = False,
) -> tuple[list[Issue], dict[str, dict[str, Any]]]:
    all_evidence = evidence_map(
        inputs.get("releaseCertificationSummary"),
        inputs.get("appPlatformSummary"),
        inputs.get("liveNetworkSummary"),
        inputs.get("securityResponseSummary"),
        inputs.get("stableReadinessSummary"),
    )
    for evidence_id, entry in multi_node_scenario_evidence(
        inputs.get("multiNodeBetaSoakSummary")
    ).items():
        all_evidence.setdefault(evidence_id, entry)
    if "securityDrillsSummary" in inputs:
        security_drills_evidence = security_response_evidence(
            inputs.get("securityDrillsSummary"),
            "security-drills-summary",
            production=mode == "production-beta",
            strict=mode in {"release-candidate", "production-beta"},
            now=now,
            expected_release_id=release_id,
            expected_mode=mode if mode in {"release-candidate", "production-beta"} else None,
            summary_path=input_paths.get("securityDrillsSummary"),
        )
        if security_drills_evidence is not None:
            existing_security_entries = [
                *evidence_entries(
                    inputs.get("releaseCertificationSummary"),
                    "production-security.response-runbook",
                ),
                *evidence_entries(
                    inputs.get("appPlatformSummary"),
                    "production-security.response-runbook",
                ),
                *evidence_entries(
                    inputs.get("securityResponseSummary"),
                    "production-security.response-runbook",
                ),
            ]
            if not existing_security_entries and "production-security.response-runbook" in all_evidence:
                existing_security_entries = [all_evidence["production-security.response-runbook"]]
            all_evidence["production-security.response-runbook"] = combine_security_response_evidence(
                existing_security_entries,
                security_drills_evidence,
            )
        else:
            all_evidence.pop("production-security.response-runbook", None)
    else:
        standalone_security_evidence = security_response_evidence(inputs.get("securityResponseSummary"))
        if standalone_security_evidence is not None:
            all_evidence.setdefault("production-security.response-runbook", standalone_security_evidence)
    issues: list[Issue] = []
    for name in CRITICAL_INPUTS_BY_MODE.get(mode, ()):
        if name not in inputs:
            issues.append(input_missing_issue(name, mode))
    for name, path in input_paths.items():
        if name != "waivers" and name not in inputs and name in {spec_name for spec in DOMAIN_SPECS for spec_name in spec.get("artifactInputs", ())}:
            issues.append(input_missing_issue(name, mode))
    issues.extend(production_summary_issues(inputs.get("productionBetaSummary"), mode))
    issues.extend(release_certification_issues(inputs.get("releaseCertificationSummary"), mode))
    issues.extend(ecosystem_matrix_issues(inputs.get("ecosystemMatrix")))
    issues.extend(network_scale_issues(inputs.get("networkScaleSoakSummary"), mode))
    issues.extend(
        multi_node_issues(
            inputs.get("multiNodeBetaSoakSummary"),
            mode,
            inputs.get("productionBetaSummary") if isinstance(inputs.get("productionBetaSummary"), dict) else None,
        )
    )
    issues.extend(
        stable_readiness_issues(
            inputs.get("stableReadinessSummary"),
            require_stable_readiness,
            release_id,
        )
    )
    for spec in DOMAIN_SPECS:
        domain_id = str(spec["id"])
        if domain_id in {
            "production-beta-release-pipeline",
            "release-certification",
            "ecosystem-rc-certification-matrix",
            "stable-1-0-readiness",
            "network-scale-soak",
            "multi-node-beta-soak",
            "redaction-artifact-hygiene",
        }:
            continue
        if domain_id == "live-network-beta-smoke" and not live_evidence_required(inputs, mode):
            continue
        for evidence_id in spec["evidenceIds"]:
            issue = issue_for_evidence(domain_id, str(evidence_id), all_evidence.get(str(evidence_id)), mode)
            if issue is not None:
                issues.append(issue)
    return dedupe_issues(issues), all_evidence
