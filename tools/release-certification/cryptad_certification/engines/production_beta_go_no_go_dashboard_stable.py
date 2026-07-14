"""Implementation segment for the stable portion of ``production_beta_go_no_go_dashboard.py``."""

from __future__ import annotations

def stable_readiness_issues(
    summary: dict[str, Any] | None,
    required: bool,
    expected_release_id: str | None = None,
) -> list[Issue]:
    domain_id = "stable-1-0-readiness"
    if not isinstance(summary, dict):
        if not required:
            return []
        severity = "blocker" if required else "warning"
        return [
            Issue(
                id="stable-1.0.readiness-summary.missing",
                evidence_id="stable-1.0.readiness-gate",
                domain_id=domain_id,
                severity=severity,
                title="Stable 1.0 readiness summary is missing",
                summary=(
                    "Stable 1.0 readiness is required for this dashboard."
                    if required
                    else "Stable 1.0 readiness was not attached; production beta decision is unchanged."
                ),
                source="stable-readiness-summary",
                waivable=not required,
                category="stable-readiness",
            )
        ]
    issues: list[Issue] = []
    schema_version = summary.get("schemaVersion")
    schema_version_valid = (
        isinstance(schema_version, int)
        and not isinstance(schema_version, bool)
        and schema_version == 1
    )
    if not schema_version_valid:
        issues.append(
            Issue(
                id="stable-1.0.readiness-summary.schema-version",
                evidence_id="stable-1.0.readiness-gate",
                domain_id=domain_id,
                severity="blocker" if required else "warning",
                title="Stable 1.0 readiness summary schema version is invalid",
                summary=(
                    "Stable readiness summary schemaVersion must be integer 1; "
                    f"summary schemaVersion is {schema_version if schema_version is not None else 'missing'}."
                ),
                source="stable-readiness-summary",
                waivable=not required,
                category="stable-readiness",
            )
        )
    kind = str(summary.get("kind", ""))
    if kind != "stable-1.0-readiness":
        issues.append(
            Issue(
                id="stable-1.0.readiness-summary.kind",
                evidence_id="stable-1.0.readiness-gate",
                domain_id=domain_id,
                severity="blocker" if required else "warning",
                title="Stable 1.0 readiness summary kind is invalid",
                summary=f"Stable readiness summary kind is {kind or 'missing'}.",
                source="stable-readiness-summary",
                waivable=not required,
                category="stable-readiness",
            )
        )
    tool = summary.get("tool")
    if not isinstance(tool, str) or tool != "stable-1.0-readiness":
        issues.append(
            Issue(
                id="stable-1.0.readiness-summary.tool",
                evidence_id="stable-1.0.readiness-gate",
                domain_id=domain_id,
                severity="blocker" if required else "warning",
                title="Stable 1.0 readiness summary producer is invalid",
                summary=(
                    "Stable readiness summary tool must be stable-1.0-readiness; "
                    f"summary tool is {tool if isinstance(tool, str) and tool else 'missing'}."
                ),
                source="stable-readiness-summary",
                waivable=not required,
                category="stable-readiness",
            )
        )
    release_id = summary.get("releaseId")
    if expected_release_id and (not isinstance(release_id, str) or release_id != expected_release_id):
        issues.append(
            Issue(
                id="stable-1.0.readiness-summary.release-id",
                evidence_id="stable-1.0.readiness-gate",
                domain_id=domain_id,
                severity="blocker" if required else "warning",
                title="Stable 1.0 readiness summary is not bound to this release",
                summary=(
                    "Stable readiness releaseId must match dashboard candidate "
                    f"{expected_release_id}; summary releaseId is "
                    f"{release_id if isinstance(release_id, str) and release_id else 'missing'}."
                ),
                source="stable-readiness-summary",
                waivable=not required,
                category="stable-readiness",
            )
        )
    redaction = summary.get("redaction") if isinstance(summary.get("redaction"), dict) else {}
    redaction_findings_value = redaction.get("findings")
    redaction_findings_malformed = (
        "findings" in redaction and not isinstance(redaction_findings_value, list)
    )
    redaction_findings = redaction_findings_value if isinstance(redaction_findings_value, list) else []
    redaction_finding_count, malformed_redaction_finding_count = parse_release_blocker_count(
        redaction.get("findingCount", len(redaction_findings))
    )
    (
        redaction_critical_finding_count,
        malformed_redaction_critical_finding_count,
    ) = parse_release_blocker_count(redaction.get("criticalFindingCount", 0))
    redaction_payload_unsafe = recursive_redaction_failure(redaction)
    redaction_payload_unaccounted = redaction_payload_unsafe and not (
        normalize_status(redaction.get("status", "missing")) != "pass"
        or redaction_findings_malformed
        or redaction_findings
        or malformed_redaction_finding_count
        or redaction_finding_count > 0
        or malformed_redaction_critical_finding_count
        or redaction_critical_finding_count > 0
    )
    if (
        normalize_status(redaction.get("status", "missing")) != "pass"
        or redaction_findings_malformed
        or redaction_findings
        or malformed_redaction_finding_count
        or redaction_finding_count > 0
        or malformed_redaction_critical_finding_count
        or redaction_critical_finding_count > 0
        or redaction_payload_unsafe
    ):
        details: list[str] = []
        if redaction_findings_malformed:
            details.append("findings is not a list")
        if malformed_redaction_finding_count:
            details.append("findingCount is not a non-negative integer")
        elif redaction_finding_count > 0:
            details.append(f"findingCount is {redaction_finding_count}")
        if malformed_redaction_critical_finding_count:
            details.append("criticalFindingCount is not a non-negative integer")
        elif redaction_critical_finding_count > 0:
            details.append(f"criticalFindingCount is {redaction_critical_finding_count}")
        if redaction_payload_unaccounted:
            details.append("redaction payload contains unsafe raw or unwaivable findings")
        issues.append(
            Issue(
                id="stable-1.0.readiness-summary.redaction",
                evidence_id="stable-1.0.redaction",
                domain_id=domain_id,
                severity="critical",
                title="Stable 1.0 readiness redaction failed",
                summary=(
                    "Stable readiness summary redaction findings are non-waivable"
                    + (": " + "; ".join(details) if details else "")
                    + "."
                ),
                source="stable-readiness-summary",
                waivable=False,
                category="redaction",
            )
        )
    stable_evidence_rows: dict[str, list[dict[str, Any]]] = {
        evidence_id: []
        for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
    }
    evidence_entries = summary.get("evidence") if isinstance(summary.get("evidence"), list) else []
    for entry in evidence_entries:
        if not isinstance(entry, dict):
            continue
        evidence_id = str(entry.get("id", ""))
        if evidence_id in stable_evidence_rows:
            stable_evidence_rows[evidence_id].append(entry)
    duplicate_evidence = [
        evidence_id
        for evidence_id, rows in stable_evidence_rows.items()
        if len(rows) > 1
    ]
    evidence_redaction_findings = [
        str(entry.get("id") or entry.get("evidenceId") or f"evidence[{index}]")
        for index, entry in enumerate(evidence_entries, start=1)
        if isinstance(entry, dict) and entry_has_redaction_findings(entry)
    ]
    missing_evidence = [
        evidence_id
        for evidence_id, rows in stable_evidence_rows.items()
        if not rows
    ]
    failed_evidence = [
        evidence_id
        for evidence_id, rows in stable_evidence_rows.items()
        if rows
        and any(normalize_status(row.get("status", "missing")) in {"fail", "missing", "skip"} for row in rows)
    ]
    redaction_evidence_rows = stable_evidence_rows.get("stable-1.0.redaction", [])
    non_pass_redaction_evidence = (
        ["stable-1.0.redaction"]
        if redaction_evidence_rows
        and any(
            normalize_status(row.get("status", "missing")) != "pass"
            for row in redaction_evidence_rows
        )
        else []
    )
    failed_redaction_evidence = [
        evidence_id for evidence_id in failed_evidence if evidence_id == "stable-1.0.redaction"
    ]
    failed_redaction_evidence = sorted(
        dict.fromkeys([*failed_redaction_evidence, *non_pass_redaction_evidence])
    )
    failed_evidence = [
        evidence_id for evidence_id in failed_evidence if evidence_id not in failed_redaction_evidence
    ]
    warning_evidence = [
        evidence_id
        for evidence_id, rows in stable_evidence_rows.items()
        if evidence_id != "stable-1.0.redaction"
        if rows
        and any(normalize_status(row.get("status", "missing")) == "warn" for row in rows)
    ]
    if duplicate_evidence:
        issues.append(
            Issue(
                id="stable-1.0.readiness-summary.evidence-duplicate",
                evidence_id="stable-1.0.readiness-gate",
                domain_id=domain_id,
                severity="blocker" if required else "warning",
                title="Stable 1.0 readiness summary contains duplicate evidence",
                summary="Stable readiness summary has duplicate evidence IDs: " + ", ".join(duplicate_evidence) + ".",
                source="stable-readiness-summary",
                waivable=not required,
                category="stable-readiness",
            )
        )
    if missing_evidence:
        issues.append(
            Issue(
                id="stable-1.0.readiness-summary.evidence-missing",
                evidence_id="stable-1.0.readiness-gate",
                domain_id=domain_id,
                severity="blocker" if required else "warning",
                title="Stable 1.0 readiness summary omits required evidence",
                summary="Stable readiness summary is missing evidence IDs: " + ", ".join(missing_evidence) + ".",
                source="stable-readiness-summary",
                waivable=not required,
                category="stable-readiness",
            )
        )
    if evidence_redaction_findings:
        issues.append(
            Issue(
                id="stable-1.0.readiness-summary.evidence-redaction",
                evidence_id="stable-1.0.redaction",
                domain_id=domain_id,
                severity="critical",
                title="Stable 1.0 readiness evidence has redaction findings",
                summary=(
                    "Stable readiness evidence rows contain non-waivable redaction findings: "
                    + ", ".join(evidence_redaction_findings)
                    + "."
                ),
                source="stable-readiness-summary",
                waivable=False,
                category="redaction",
            )
        )
    domain_errors = stable_summary_domain_errors(summary)
    redaction_domain_errors = stable_summary_redaction_domain_errors(summary)
    domain_errors = [error for error in domain_errors if error not in redaction_domain_errors]
    if redaction_domain_errors:
        issues.append(
            Issue(
                id="stable-1.0.readiness-summary.redaction-domain-failed",
                evidence_id="stable-1.0.redaction",
                domain_id=domain_id,
                severity="critical",
                title="Stable 1.0 readiness redaction domain is not passing",
                summary=(
                    "Stable readiness redaction domain contains non-waivable blockers: "
                    + "; ".join(redaction_domain_errors)
                    + "."
                ),
                source="stable-readiness-summary",
                waivable=False,
                category="redaction",
            )
        )
    if domain_errors:
        issues.append(
            Issue(
                id="stable-1.0.readiness-summary.domain-failed",
                evidence_id="stable-1.0.readiness-gate",
                domain_id=domain_id,
                severity="blocker" if required else "warning",
                title="Stable 1.0 readiness summary domains are not passing",
                summary=(
                    "Stable readiness domain rows are inconsistent with a ready decision: "
                    + "; ".join(domain_errors)
                    + "."
                ),
                source="stable-readiness-summary",
                waivable=not required,
                category="stable-readiness",
            )
        )
    if failed_redaction_evidence:
        issues.append(
            Issue(
                id="stable-1.0.readiness-summary.redaction-evidence-failed",
                evidence_id="stable-1.0.redaction",
                domain_id=domain_id,
                severity="critical",
                title="Stable 1.0 readiness redaction evidence is not passing",
                summary=(
                    "Stable readiness redaction evidence is non-waivable and not passing: "
                    + ", ".join(failed_redaction_evidence)
                    + "."
                ),
                source="stable-readiness-summary",
                waivable=False,
                category="redaction",
            )
        )
    if failed_evidence:
        issues.append(
            Issue(
                id="stable-1.0.readiness-summary.evidence-failed",
                evidence_id="stable-1.0.readiness-gate",
                domain_id=domain_id,
                severity="blocker" if required else "warning",
                title="Stable 1.0 readiness summary contains failed evidence",
                summary="Stable readiness evidence is not passing: " + ", ".join(failed_evidence) + ".",
                source="stable-readiness-summary",
                waivable=not required,
                category="stable-readiness",
            )
        )
    warning_count, malformed_warning_count = parse_release_blocker_count(
        summary.get("warningCount", 0)
    )
    if malformed_warning_count:
        issues.append(
            Issue(
                id="stable-1.0.readiness-summary.warning-count-invalid",
                evidence_id="stable-1.0.readiness-gate",
                domain_id=domain_id,
                severity="blocker" if required else "warning",
                title="Stable 1.0 readiness warning count is invalid",
                summary="Stable readiness warningCount is not a non-negative integer.",
                source="stable-readiness-summary",
                waivable=not required,
                category="stable-readiness",
            )
        )
    warning_record_errors = stable_summary_warning_record_errors(
        summary,
        warning_count,
        malformed_warning_count,
    )
    if warning_record_errors:
        issues.append(
            Issue(
                id="stable-1.0.readiness-summary.warning-records-invalid",
                evidence_id="stable-1.0.readiness-gate",
                domain_id=domain_id,
                severity="blocker" if required else "warning",
                title="Stable 1.0 readiness warning records are invalid",
                summary=(
                    "Stable readiness warning records are inconsistent: "
                    + "; ".join(warning_record_errors)
                    + "."
                ),
                source="stable-readiness-summary",
                waivable=not required,
                category="stable-readiness",
            )
        )
    summary_warning_labels = stable_summary_warning_labels(summary)
    summary_reports_warnings = (
        not malformed_warning_count and warning_count > 0
    ) or bool(summary_warning_labels)
    if warning_evidence or summary_reports_warnings:
        warning_details: list[str] = []
        if warning_evidence:
            warning_details.append("warning evidence: " + ", ".join(warning_evidence))
        if summary_warning_labels:
            warning_details.append("warnings: " + ", ".join(summary_warning_labels))
        elif not malformed_warning_count and warning_count > 0:
            warning_details.append(f"warningCount is {warning_count}")
        issues.append(
            Issue(
                id="stable-1.0.readiness-summary.evidence-warnings",
                evidence_id="stable-1.0.readiness-gate",
                domain_id=domain_id,
                severity="warning",
                title="Stable 1.0 readiness summary contains warnings",
                summary="Stable readiness summary has " + "; ".join(warning_details) + ".",
                source="stable-readiness-summary",
                waivable=True,
                category="stable-readiness",
            )
        )
    blocker_count, malformed_blocker_count = parse_release_blocker_count(summary.get("blockerCount", 0))
    allowed_count, malformed_allowed_count = parse_release_blocker_count(
        summary.get("allowedLimitationCount", 0)
    )
    disallowed_count, malformed_disallowed_count = parse_release_blocker_count(
        summary.get("disallowedLimitationCount", 0)
    )
    allowed_limitations = summary.get("allowedLimitations")
    allowed_limitation_count = len(allowed_limitations) if isinstance(allowed_limitations, list) else 0
    allowed_record_errors: list[str] = []
    if not isinstance(allowed_limitations, list):
        allowed_record_errors.append("allowedLimitations must be a list")
    else:
        for index, limitation in enumerate(allowed_limitations):
            allowed_record_errors.extend(
                stable_summary_allowed_limitation_metadata_errors(
                    limitation,
                    f"allowedLimitations[{index}]",
                )
            )
        if not malformed_allowed_count and allowed_count != allowed_limitation_count:
            allowed_record_errors.append(
                f"allowedLimitationCount is {allowed_count} "
                f"but allowedLimitations contains {allowed_limitation_count}"
            )
    record_errors = [
        *stable_summary_record_errors(
            summary,
            "blockers",
            "blockerCount",
            blocker_count,
            malformed_blocker_count,
        ),
        *stable_summary_record_errors(
            summary,
            "disallowedLimitations",
            "disallowedLimitationCount",
            disallowed_count,
            malformed_disallowed_count,
        ),
    ]
    if malformed_allowed_count or allowed_record_errors:
        details: list[str] = []
        if malformed_allowed_count:
            details.append("allowedLimitationCount is not a non-negative integer")
        details.extend(allowed_record_errors)
        issues.append(
            Issue(
                id="stable-1.0.readiness-summary.allowed-limitations-invalid",
                evidence_id="stable-1.0.known-limitations",
                domain_id=domain_id,
                severity="blocker" if required else "warning",
                title="Stable 1.0 readiness allowed limitations are invalid",
                summary="Stable readiness allowed limitations are inconsistent: " + "; ".join(details) + ".",
                source="stable-readiness-summary",
                waivable=not required,
                category="stable-readiness",
            )
        )
    if (
        malformed_blocker_count
        or malformed_disallowed_count
        or blocker_count > 0
        or disallowed_count > 0
        or record_errors
    ):
        details: list[str] = []
        if malformed_blocker_count:
            details.append("blockerCount is not a non-negative integer")
        elif blocker_count > 0:
            details.append(f"blockerCount is {blocker_count}")
        if malformed_disallowed_count:
            details.append("disallowedLimitationCount is not a non-negative integer")
        elif disallowed_count > 0:
            details.append(f"disallowedLimitationCount is {disallowed_count}")
        details.extend(record_errors)
        issues.append(
            Issue(
                id="stable-1.0.readiness-summary.remaining-blockers",
                evidence_id="stable-1.0.readiness-gate",
                domain_id=domain_id,
                severity="blocker" if required else "warning",
                title="Stable 1.0 readiness summary reports remaining blockers",
                summary="Stable readiness summary is inconsistent: " + "; ".join(details) + ".",
                source="stable-readiness-summary",
                waivable=not required,
                category="stable-readiness",
            )
        )
    allowed_limitations_remain = allowed_limitation_count > 0 or (
        not malformed_allowed_count and allowed_count > 0
    )
    status = normalize_status(summary.get("status", "missing"))
    decision = str(summary.get("decision", "not-ready"))
    stable_ready = summary.get("stableReady") is True
    valid_statuses = {"pass", "warn", "fail"}
    valid_decisions = {"ready", "ready-with-allowed-limitations", "not-ready"}
    if status not in valid_statuses or decision not in valid_decisions:
        issues.append(
            Issue(
                id="stable-1.0.readiness-summary.invalid",
                evidence_id="stable-1.0.readiness-gate",
                domain_id=domain_id,
                severity="blocker" if required else "warning",
                title="Stable 1.0 readiness summary status is invalid",
                summary=(
                    f"Stable readiness status is {status}; decision is {decision}. "
                    "Expected status pass|warn|fail and decision ready|ready-with-allowed-limitations|not-ready."
                ),
                source="stable-readiness-summary",
                waivable=not required,
                category="stable-readiness",
            )
        )
    elif status == "warn" and not summary_reports_warnings and not allowed_limitations_remain:
        issues.append(
            Issue(
                id="stable-1.0.readiness-summary.warning-status-invalid",
                evidence_id="stable-1.0.readiness-gate",
                domain_id=domain_id,
                severity="blocker" if required else "warning",
                title="Stable 1.0 readiness warning status is inconsistent",
                summary=(
                    "Stable readiness status is warn, but the summary reports no warnings or "
                    "allowed limitations."
                ),
                source="stable-readiness-summary",
                waivable=not required,
                category="stable-readiness",
            )
        )
    elif not stable_ready or decision == "not-ready" or status == "fail":
        issues.append(
            Issue(
                id="stable-1.0.readiness-summary.not-ready",
                evidence_id="stable-1.0.readiness-gate",
                domain_id=domain_id,
                severity="blocker" if required else "warning",
                title="Stable 1.0 readiness is not passing",
                summary=f"Stable readiness decision is {decision}.",
                source="stable-readiness-summary",
                waivable=not required,
                category="stable-readiness",
            )
        )
    if decision == "ready-with-allowed-limitations" or allowed_limitations_remain:
        issues.append(
            Issue(
                id="stable-1.0.readiness-summary.allowed-limitations",
                evidence_id="stable-1.0.known-limitations",
                domain_id=domain_id,
                severity="warning",
                title="Stable 1.0 readiness has allowed limitations",
                summary=(
                    f"Stable readiness allows {max(allowed_count, allowed_limitation_count)} "
                    "bounded limitation(s)."
                ),
                source="stable-readiness-summary",
                waivable=True,
                category="stable-readiness",
            )
        )
    return issues

def dedupe_issues(issues: list[Issue]) -> list[Issue]:
    result: list[Issue] = []
    seen: set[str] = set()
    for issue in sorted(issues, key=lambda item: (item.id, item.evidence_id, item.summary)):
        if issue.id in seen:
            continue
        seen.add(issue.id)
        result.append(issue)
    return result

def known_ids(all_evidence: dict[str, dict[str, Any]], issues: list[Issue]) -> set[str]:
    ids = set(all_evidence)
    for spec in DOMAIN_SPECS:
        ids.add(str(spec["id"]))
        ids.update(str(evidence_id) for evidence_id in spec["evidenceIds"])
    ids.update(DASHBOARD_EVIDENCE_IDS)
    for issue in issues:
        ids.update({issue.id, issue.evidence_id, issue.domain_id, f"evidence.{issue.evidence_id}"})
    ids.update(NON_WAIVABLE_EVIDENCE_IDS)
    ids.update(PRODUCTION_BETA_NON_WAIVABLE_EVIDENCE_IDS)
    ids.update(PRODUCTION_ARTIFACT_GATE_IDS)
    return expand_waiver_target_aliases(*ids)

def decision_from_issues(issues: list[Issue]) -> str:
    unwaived = [issue for issue in issues if issue.severity in {"critical", "blocker"} and not issue.waived_by]
    if unwaived:
        return "no-go"
    if any(issue.waived_by for issue in issues if issue.severity in {"critical", "blocker"}):
        return "go-with-waivers"
    return "go"

def recommendation_for(decision: str, blockers: list[Issue], warnings: list[Issue]) -> str:
    if decision == "go":
        return "Launch candidate is ready for production beta promotion."
    if decision == "go-with-waivers":
        return "Launch candidate is promotable only with the listed approved waivers preserved in the release record."
    if blockers:
        return f"Do not launch. Resolve or replace the top blocker: {blockers[0].title}."
    if warnings:
        return "Do not launch until dashboard warnings are reviewed and the decision is regenerated."
    return "Do not launch until the dashboard can be regenerated from complete evidence."

def build_dashboard(
    inputs: dict[str, Any],
    input_paths: dict[str, Path],
    scan_targets: list[Path],
    waiver_value: dict[str, Any] | None,
    workspace_root: Path,
    out_dir: Path,
    mode: str,
    release_id: str,
    generated_at: str,
    now: dt.datetime,
    require_stable_readiness: bool = False,
) -> dict[str, Any]:
    if mode not in MODES:
        raise SystemExit(f"--mode must be one of {', '.join(MODES)}")
    issues, all_evidence = collect_issues(
        inputs,
        mode,
        input_paths,
        now,
        release_id,
        require_stable_readiness,
    )
    imported_waivers = release_certification_waiver_records(
        inputs.get("releaseCertificationSummary") if isinstance(inputs.get("releaseCertificationSummary"), dict) else None,
        mode,
        now,
        workspace_root,
        out_dir,
    )
    waivers, waiver_issues = load_waivers(
        waiver_value,
        display_path(input_paths.get("waivers", Path("waivers.json")), workspace_root) if input_paths.get("waivers") else "fixture-waivers",
        mode,
        now,
        known_ids(all_evidence, issues),
        workspace_root,
        out_dir,
    )
    waivers = [*imported_waivers, *waivers]
    issues = dedupe_issues([*issues, *waiver_issues])
    issues, waivers, _validation_issues = apply_waivers(issues, waivers, mode)
    domains = build_domain_rows(inputs, input_paths, workspace_root, out_dir, issues, all_evidence)
    redaction = redaction_report(scan_paths(scan_targets, workspace_root, out_dir))
    if redaction["status"] != "pass":
        redaction_issue = Issue(
            id="dashboard.redaction.scan",
            evidence_id="production-beta.dashboard-redaction",
            domain_id="redaction-artifact-hygiene",
            severity="critical",
            title="Dashboard input redaction scan failed",
            summary=f"Dashboard redaction scanner found {redaction['findingCount']} finding(s).",
            source="dashboard-redaction",
            waivable=False,
            category="redaction",
        )
        issues = dedupe_issues([*issues, redaction_issue])
        domains = build_domain_rows(inputs, input_paths, workspace_root, out_dir, issues, all_evidence)
    blockers = [issue for issue in issues if issue.severity in {"critical", "blocker"} and not issue.waived_by]
    warnings = [issue for issue in issues if issue.severity == "warning" or issue.waived_by]
    decision = decision_from_issues(issues)
    production_summary = inputs.get("productionBetaSummary") if isinstance(inputs.get("productionBetaSummary"), dict) else {}
    multi_node_summary = (
        inputs.get("multiNodeBetaSoakSummary")
        if isinstance(inputs.get("multiNodeBetaSoakSummary"), dict)
        else {}
    )
    previous_upgrade = (
        multi_node_summary.get("previousCandidateUpgrade")
        if isinstance(multi_node_summary.get("previousCandidateUpgrade"), dict)
        else {"status": "missing"}
    )
    security_response_item = all_evidence.get("production-security.response-runbook")
    security_response_details = evidence_details(security_response_item)
    security_drills_component = security_response_details.get("securityDrills")
    security_drills_details = (
        evidence_details(security_drills_component)
        if isinstance(security_drills_component, dict)
        else {}
    )
    artifact_validation = security_drills_details.get("artifactValidation")
    security_drills = compact_security_drills(
        inputs.get("securityDrillsSummary") if isinstance(inputs.get("securityDrillsSummary"), dict) else None,
        production=mode == "production-beta",
        strict=mode in {"release-candidate", "production-beta"},
        now=now,
        expected_release_id=release_id,
        expected_mode=mode if mode in {"release-candidate", "production-beta"} else None,
        artifact_validation=(
            artifact_validation
            if isinstance(artifact_validation, dict) and "status" in artifact_validation
            else None
        ),
    )
    artifact_refs = {
        "dashboardJson": OUTPUT_JSON,
        "dashboardMarkdown": OUTPUT_MARKDOWN,
        "dashboardRedactionReport": OUTPUT_REDACTION,
    }
    stable_readiness = compact_stable_readiness(
        inputs.get("stableReadinessSummary"),
        require_stable_readiness,
        release_id,
    )
    artifacts = production_summary.get("artifacts") if isinstance(production_summary.get("artifacts"), dict) else {}
    for key in ("redactionReport", "distArchive", "checksums", "ecosystemCertification", "multiNodeBetaSoak"):
        if key in artifacts:
            artifact_refs[key] = str(artifacts[key])
    dashboard = {
        "schemaVersion": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "generatedAt": generated_at,
        "mode": mode,
        "releaseId": scrub_text(release_id, workspace_root, out_dir),
        "decision": decision,
        "promotionReady": decision in {"go", "go-with-waivers"},
        "summary": {
            "blockers": len(blockers),
            "warnings": len(warnings),
            "waiversUsed": sum(1 for waiver in waivers if waiver.used_by),
            "criticalRedactionFindings": int(redaction.get("criticalFindingCount", 0)),
            "criticalFindings": sum(1 for issue in issues if issue.severity == "critical" and not issue.waived_by),
        },
        "domains": domains,
        "blockers": [issue.to_json() for issue in blockers],
        "warnings": [issue.to_json() for issue in warnings],
        "waivers": [waiver.to_json() for waiver in waivers],
        "previousCandidateUpgrade": previous_upgrade,
        "securityDrills": security_drills,
        "stableReadiness": stable_readiness,
        "redaction": redaction,
        "recommendation": recommendation_for(decision, blockers, warnings),
        "artifactRefs": artifact_refs,
    }
    return sanitize_value(dashboard, workspace_root, out_dir)

def render_markdown(dashboard: dict[str, Any]) -> str:
    decision_label = {
        "go": "GO",
        "no-go": "NO-GO",
        "go-with-waivers": "GO WITH WAIVERS",
    }.get(str(dashboard.get("decision")), "NO-GO")
    lines = [
        "# Production Beta Go/No-Go Dashboard",
        "",
        f"- Release ID: `{dashboard.get('releaseId', '')}`",
        f"- Mode: `{dashboard.get('mode', '')}`",
        f"- Decision: **{decision_label}**",
        f"- Promotion ready: `{str(dashboard.get('promotionReady', False)).lower()}`",
        f"- Generated: `{dashboard.get('generatedAt', '')}`",
        f"- Recommendation: {dashboard.get('recommendation', '')}",
        "",
        "## Stable 1.0 Readiness",
        "",
    ]
    stable_readiness = (
        dashboard.get("stableReadiness")
        if isinstance(dashboard.get("stableReadiness"), dict)
        else {}
    )
    lines.extend(
        [
            f"- Status: `{stable_readiness.get('status', 'missing')}`",
            f"- Decision: `{stable_readiness.get('decision', 'not-attached')}`",
            f"- Stable ready: `{str(stable_readiness.get('stableReady', False)).lower()}`",
            f"- Required: `{str(stable_readiness.get('required', False)).lower()}`",
            f"- Release ID: `{stable_readiness.get('releaseId', 'missing')}`",
            f"- Expected release ID: `{stable_readiness.get('expectedReleaseId', 'not-required')}`",
            f"- Release ID match: `{str(stable_readiness.get('releaseIdMatchesDashboard', False)).lower()}`",
            f"- Blockers: `{stable_readiness.get('blockerCount', 0)}`",
            f"- Warnings: `{stable_readiness.get('warningCount', 0)}`",
            f"- Allowed limitations: `{stable_readiness.get('allowedLimitationCount', 0)}`",
            f"- Disallowed limitations: `{stable_readiness.get('disallowedLimitationCount', 0)}`",
            f"- Redaction: `{stable_readiness.get('redactionStatus', 'missing')}`",
            "",
        ]
    )
    lines.extend(
        [
        "## Security Drills",
        "",
        ]
    )
    security_drills = dashboard.get("securityDrills") if isinstance(dashboard.get("securityDrills"), dict) else {}
    lines.extend(
        [
            f"- Status: `{security_drills.get('status', 'missing')}`",
            f"- Promotion ready: `{str(security_drills.get('promotionReady', False)).lower()}`",
            f"- Required scenarios: `{security_drills.get('requiredScenarioCount', 0)}`",
            f"- Passed scenarios: `{security_drills.get('passedScenarioCount', 0)}`",
            f"- Failed scenarios: `{security_drills.get('failedScenarioCount', 0)}`",
            f"- Missing scenarios: `{security_drills.get('missingScenarioCount', 0)}`",
            f"- Stale scenarios: `{security_drills.get('staleScenarioCount', 0)}`",
            f"- Redaction: `{security_drills.get('redactionStatus', 'missing')}`",
            f"- Release notes template: `{security_drills.get('releaseNotesTemplateStatus', 'missing')}`",
            f"- Advisory template: `{security_drills.get('advisoryTemplateStatus', 'missing')}`",
            f"- Support-bundle intake redaction: `{security_drills.get('supportBundleIntakeRedactionStatus', 'missing')}`",
            "",
        ]
    )
    if security_drills.get("failedScenarios"):
        lines.append(f"- Failed: {markdown_code_list(security_drills.get('failedScenarios', []))}")
    if security_drills.get("missingScenarios"):
        lines.append(f"- Missing: {markdown_code_list(security_drills.get('missingScenarios', []))}")
    if security_drills.get("staleScenarios"):
        lines.append(f"- Stale: {markdown_code_list(security_drills.get('staleScenarios', []))}")
    lines.extend(
        [
            "",
            "## Top Blockers",
            "",
        ]
    )
    blockers = dashboard.get("blockers", [])
    if not blockers:
        lines.append("No unwaived blockers.")
    else:
        for issue in blockers[:10]:
            if isinstance(issue, dict):
                lines.append(f"- `{issue.get('evidenceId', '')}`: {issue.get('summary', '')}")
    lines.extend(["", "## Top Warnings", ""])
    warnings = dashboard.get("warnings", [])
    if not warnings:
        lines.append("No warnings.")
    else:
        for issue in warnings[:10]:
            if isinstance(issue, dict):
                waived = f" Waiver: `{issue.get('waivedBy')}`." if issue.get("waivedBy") else ""
                lines.append(f"- `{issue.get('evidenceId', '')}`: {issue.get('summary', '')}{waived}")
    upgrade = dashboard.get("previousCandidateUpgrade")
    if isinstance(upgrade, dict) and upgrade:
        lines.extend(
            [
                "",
                "## Previous Candidate Upgrade",
                "",
                f"- Previous release: `{upgrade.get('previousReleaseId', 'missing')}`",
                f"- Previous version: `{upgrade.get('previousVersion', 'missing')}`",
                f"- Current version: `{upgrade.get('currentVersion', 'missing')}`",
                f"- Previous summary: `{upgrade.get('previousSummaryStatus', 'missing')}`",
                f"- Upgrade drill: `{upgrade.get('status', 'missing')}`",
                f"- App migrations: `{upgrade.get('firstPartyAppMigrationStatus', 'missing')}`",
                f"- Backup before update: `{upgrade.get('backupBeforeUpdateStatus', 'missing')}`",
                f"- Restore into clean node: `{upgrade.get('restoreIntoCleanNodeStatus', 'missing')}`",
                f"- Social Inbox migration: `{upgrade.get('socialInboxMigrationStatus', 'missing')}`",
                f"- Trust Graph migration: `{upgrade.get('trustGraphMigrationStatus', 'missing')}`",
                f"- Support bundle redaction: `{upgrade.get('supportBundleRedactionStatus', 'missing')}`",
            ]
        )
    lines.extend(["", "## Waivers Used", ""])
    waivers = [waiver for waiver in dashboard.get("waivers", []) if isinstance(waiver, dict) and waiver.get("usedBy")]
    if not waivers:
        lines.append("No waivers were used.")
    else:
        lines.extend(["| Waiver | Evidence | Scope | Expires | Used by |", "| --- | --- | --- | --- | --- |"])
        for waiver in waivers:
            lines.append(
                "| `{}` | `{}` | `{}` | `{}` | {} |".format(
                    waiver.get("id", ""),
                    waiver.get("evidenceId", ""),
                    waiver.get("scope", ""),
                    waiver.get("expiresAt", ""),
                    markdown_code_list(waiver.get("usedBy", [])),
                )
            )
    lines.extend(["", "## Domain Table", ""])
    lines.extend(["| Domain | Status | Required | Evidence | Artifacts |", "| --- | --- | --- | --- | --- |"])
    for domain in dashboard.get("domains", []):
        if not isinstance(domain, dict):
            continue
        lines.append(
            "| {} | `{}` | `{}` | {} | {} |".format(
                markdown_cell(domain.get("title", domain.get("id", ""))),
                domain.get("status", ""),
                domain.get("severity", "required"),
                markdown_code_list(domain.get("evidenceIds", [])),
                markdown_code_list(domain.get("artifactRefs", [])),
            )
        )
    redaction = dashboard.get("redaction") if isinstance(dashboard.get("redaction"), dict) else {}
    lines.extend(
        [
            "",
            "## Redaction Status",
            "",
            f"- Status: `{redaction.get('status', 'missing')}`",
            f"- Findings: `{redaction.get('findingCount', 0)}`",
            f"- Critical findings: `{redaction.get('criticalFindingCount', 0)}`",
        ]
    )
    for finding in redaction.get("findings", [])[:10] if isinstance(redaction.get("findings"), list) else []:
        if isinstance(finding, dict):
            detail = f": {finding.get('detail')}" if finding.get("detail") else ""
            lines.append(f"- `{finding.get('kind', '')}` at `{finding.get('path', '')}`{detail}")
    lines.extend(["", "## Required Follow-Ups", ""])
    if blockers:
        lines.append("- Resolve all unwaived blockers and regenerate the dashboard.")
    if redaction.get("status") != "pass":
        lines.append("- Remove unsafe input/output content and regenerate the redaction report.")
    invalid_waivers = [
        waiver
        for waiver in dashboard.get("waivers", [])
        if isinstance(waiver, dict) and waiver.get("validationErrors")
    ]
    if invalid_waivers:
        lines.append("- Fix invalid or expired waiver records before promotion.")
    if not blockers and redaction.get("status") == "pass" and not invalid_waivers:
        lines.append("- Preserve this dashboard and the listed redacted artifacts with the release candidate.")
    lines.extend(["", "## Redacted Artifacts", ""])
    artifact_refs = dashboard.get("artifactRefs", {}) if isinstance(dashboard.get("artifactRefs"), dict) else {}
    for name in sorted(artifact_refs):
        lines.append(f"- `{name}`: `{artifact_refs[name]}`")
    lines.append("")
    return "\n".join(lines)

def markdown_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")

def markdown_code_list(values: Any) -> str:
    if not isinstance(values, list):
        return ""
    return ", ".join(f"`{markdown_cell(value)}`" for value in values)

def write_dashboard_artifacts(dashboard: dict[str, Any], out_dir: Path, workspace_root: Path) -> dict[str, Any]:
    write_json(out_dir / OUTPUT_JSON, dashboard)
    write_text(out_dir / OUTPUT_MARKDOWN, render_markdown(dashboard))
    output_findings = scan_paths([out_dir / OUTPUT_JSON, out_dir / OUTPUT_MARKDOWN], workspace_root, out_dir)
    combined_findings = [
        *dashboard.get("redaction", {}).get("findings", []),
        *output_findings,
    ]
    final_redaction = redaction_report([finding for finding in combined_findings if isinstance(finding, dict)])
    dashboard["redaction"] = final_redaction
    if final_redaction["status"] != "pass" and dashboard.get("decision") != "no-go":
        issue = {
            "id": "dashboard.output-redaction.scan",
            "evidenceId": "production-beta.dashboard-redaction",
            "domainId": "redaction-artifact-hygiene",
            "severity": "critical",
            "title": "Dashboard output redaction scan failed",
            "summary": f"Dashboard output redaction scanner found {final_redaction['findingCount']} finding(s).",
            "source": "dashboard-redaction",
            "waivable": False,
            "category": "redaction",
        }
        dashboard["decision"] = "no-go"
        dashboard["promotionReady"] = False
        dashboard.setdefault("blockers", []).append(issue)
        summary = dashboard.setdefault("summary", {})
        summary["blockers"] = int(summary.get("blockers", 0)) + 1
        summary["criticalRedactionFindings"] = int(final_redaction.get("criticalFindingCount", 0))
        dashboard["recommendation"] = "Do not launch. Resolve dashboard output redaction findings and regenerate."
    write_json(out_dir / OUTPUT_JSON, dashboard)
    write_text(out_dir / OUTPUT_MARKDOWN, render_markdown(dashboard))
    write_json(out_dir / OUTPUT_REDACTION, final_redaction)
    return dashboard

def build_command(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    workspace_root = args.workspace_root.resolve()
    out_dir = args.out_dir if args.out_dir.is_absolute() else workspace_root / args.out_dir
    out_dir = out_dir.resolve()
    if args.fixtures is not None:
        inputs, paths, scan_targets, waiver_value, release_id, fixture_mode, fixture_generated_at = load_inputs_from_fixture(args, workspace_root)
        mode = args.mode or fixture_mode
        generated_at, now = parse_generated_at(args.generated_at or fixture_generated_at)
    else:
        inputs, paths, scan_targets, waiver_value, release_id = load_inputs_from_paths(args, workspace_root)
        mode = args.mode or "developer-dry-run"
        generated_at, now = parse_generated_at(args.generated_at)
    dashboard = build_dashboard(
        inputs,
        paths,
        scan_targets,
        waiver_value,
        workspace_root,
        out_dir,
        mode,
        release_id,
        generated_at,
        now,
        args.require_stable_readiness,
    )
    dashboard = write_dashboard_artifacts(dashboard, out_dir, workspace_root)
    return dashboard, 0 if dashboard["decision"] in {"go", "go-with-waivers"} else 1
