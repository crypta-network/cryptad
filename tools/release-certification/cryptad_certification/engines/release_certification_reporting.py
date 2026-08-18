"""Implementation segment for the reporting portion of ``release_certification.py``."""

from __future__ import annotations

def build_summary(
    settings: Settings,
    evidence: list[EvidenceItem],
    copied_artifacts: list[str],
    generated_at: str,
    metadata: dict[str, Any],
    history_comparison: dict[str, Any],
    ecosystem_gates: list[GateResult],
    waiver_context: WaiverContext,
    ecosystem_matrix: dict[str, Any] | None = None,
) -> dict[str, Any]:
    status, release_candidate_passed = determine_certification_status(
        settings.mode, evidence, history_comparison, ecosystem_gates, waiver_context
    )
    ecosystem_status = aggregate_gate_status(ecosystem_gates)
    cli_waivers = sanitized_cli_waivers(settings)
    compact_matrix = matrix_compact_summary(ecosystem_matrix)
    compact_stable_readiness = stable_readiness_compact_summary(
        evidence,
        settings.stable_readiness_required,
    )
    matrix_rows = (
        ecosystem_matrix.get("rows")
        if isinstance(ecosystem_matrix, dict)
        else None
    )
    if required_stable_readiness_blocking(settings, matrix_rows):
        status = "fail"
        release_candidate_passed = False
    compact_rc_gate = ecosystem_rc_gate_summary(ecosystem_gates)
    compact_rc_gate_decision = ecosystem_rc_decision(compact_rc_gate)
    compact_rc_decision = compact_rc_gate_decision if release_candidate_passed else "FAIL"
    ecosystem_rc_passed = (
        compact_rc_decision != "FAIL"
        and bool(compact_rc_gate.get("promotionReady", False))
    )
    return {
        "schemaVersion": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "mode": settings.mode,
        "status": status,
        "promotionDecision": promotion_decision(status, release_candidate_passed),
        "releaseCandidatePassed": release_candidate_passed,
        "generatedAt": generated_at,
        "workspaceRoot": "<repo>",
        "summaryPath": display_path(settings.out_dir / SUMMARY_FILE_NAME, settings.workspace_root, settings.out_dir),
        "reportPath": display_path(settings.out_dir / REPORT_FILE_NAME, settings.workspace_root, settings.out_dir),
        "ecosystemMatrixStatus": compact_matrix.get("status", "missing"),
        "ecosystemMatrixPath": display_path(
            settings.out_dir / ECOSYSTEM_MATRIX_FILE_NAME, settings.workspace_root, settings.out_dir
        ),
        "ecosystemMatrixReportPath": display_path(
            settings.out_dir / ECOSYSTEM_MATRIX_REPORT_FILE_NAME, settings.workspace_root, settings.out_dir
        ),
        "historyComparisonPath": display_path(
            settings.out_dir / HISTORY_COMPARISON_FILE_NAME, settings.workspace_root, settings.out_dir
        ),
        "historyComparisonReportPath": display_path(
            settings.out_dir / HISTORY_COMPARISON_REPORT_FILE_NAME, settings.workspace_root, settings.out_dir
        ),
        "artifactsDir": display_path(settings.out_dir / "artifacts", settings.workspace_root, settings.out_dir),
        "metadata": metadata,
        "waivers": cli_waivers,
        "cliWaivers": cli_waivers,
        "waiverRecords": [record.to_json() for record in waiver_context.records],
        "counts": evidence_counts(evidence),
        "evidence": [item.to_json() for item in evidence],
        "historyComparison": history_comparison,
        "ecosystemGateStatus": ecosystem_status,
        "ecosystemGates": [gate.to_json() for gate in ecosystem_gates],
        "ecosystemRcGate": compact_rc_gate,
        "ecosystemRcPassed": ecosystem_rc_passed,
        "ecosystemRcDecision": compact_rc_decision,
        "ecosystemMatrix": compact_matrix,
        "stableReadiness": compact_stable_readiness,
        "copiedArtifacts": copied_artifacts,
        "redaction": {
            "privateArtifactsExcluded": list(PRIVATE_ARTIFACT_NAMES),
            "secretMaterialRedacted": True,
            "formPasswordsRedacted": True,
            "rawFeedBodiesExcluded": True,
            "rawRequestBodiesExcluded": True,
            "privateInsertUrisExcluded": True,
            "appProcessTokensRedacted": True,
            "browserSessionTokensRedacted": True,
            "signatureValuesRedacted": True,
            "rawUpdateRollbackOutputsExcluded": True,
            "absolutePathsSanitized": True,
        },
    }

def render_report(summary: dict[str, Any]) -> str:
    history = summary.get("historyComparison", {})
    history_status = history.get("status", "missing") if isinstance(history, dict) else "missing"
    decision = summary.get("promotionDecision")
    if not isinstance(decision, str) or not decision:
        decision = promotion_decision(
            str(summary["status"]),
            bool(summary.get("releaseCandidatePassed", True)),
        )
    lines = [
        "# Release Certification Report",
        "",
        f"- Promotion decision: `{decision}`",
        f"- History comparison: `{report_status_label(history_status)}`",
        f"- Ecosystem gates: `{report_status_label(summary.get('ecosystemGateStatus', 'missing'))}`",
        f"- Mode: `{summary['mode']}`",
        f"- Status: `{summary['status']}`",
        f"- Release-candidate gate: `{'passed' if summary['releaseCandidatePassed'] else 'failed'}`",
        f"- Generated: `{summary['generatedAt']}`",
        f"- Summary: `{summary['summaryPath']}`",
        f"- Artifacts: `{summary['artifactsDir']}`",
        "",
    ]
    append_history_comparison(lines, summary)
    append_ecosystem_rc_gate(lines, summary)
    append_ecosystem_gates(lines, summary)
    append_ecosystem_matrix_summary(lines, summary)
    append_stable_readiness_summary(lines, summary)
    append_waivers(lines, summary)
    append_regressions(lines, summary)
    lines.extend(["## Evidence Summary", "", "| Evidence | Status | Required for RC | Source | Summary |", "| --- | --- | --- | --- | --- |"])
    for item in summary["evidence"]:
        required = "yes" if item["requiredForReleaseCandidate"] else "no"
        lines.append(
            "| `{id}` | `{status}` | {required} | `{source}` | {summary_text} |".format(
                id=item["id"],
                status=item["status"],
                required=required,
                source=item["source"],
                summary_text=str(item["summary"]).replace("|", "\\|"),
            )
        )
    lines.extend(["", "## Release Operations", ""])
    append_detail(lines, summary, "release-certification.ecosystem-matrix")
    append_detail(lines, summary, ECOSYSTEM_RC_EVIDENCE_ID)
    append_detail(lines, summary, STABLE_VULNERABILITY_EVIDENCE_ID)
    for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS:
        append_detail(lines, summary, evidence_id)
    lines.extend(["", "## Hyphanet Interop", ""])
    append_detail(lines, summary, "interop.smoke")
    append_detail(lines, summary, "interop.extended")
    lines.extend(["", "## Performance Regression", ""])
    append_detail(lines, summary, "performance.smoke")
    lines.extend(["", "## Live Network Beta", ""])
    for evidence_id in LIVE_NETWORK_BETA_EVIDENCE_IDS:
        append_detail(lines, summary, evidence_id)
    lines.extend(["", "## App Platform", ""])
    for evidence_id in (
        "app-platform.first-party",
        FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID,
        "app-platform.devtools-cli",
        "app-platform.developer-beta-toolkit",
        "app-platform.docs-portal",
        "app-platform.beta-program",
        "app-platform.beta-tutorials",
        "app-platform.docs-redaction",
        *PUBLIC_BETA_DOCS_EVIDENCE_IDS,
        *THIRD_PARTY_DEVELOPER_BETA_EVIDENCE_IDS,
        "platform-api.contract",
        "app-vault.capabilities",
        "app-platform.identity-profile-publish",
        "app-platform.generated-document-insert",
        "app-platform.content-fetch",
        "app-platform.content-subscriptions",
        "network-content.subscription-scheduler",
        "app-platform.durable-app-data-store",
        "app-data.backup-restore-portability",
        "app-platform.trust-graph-preview",
        "app-platform.trust-graph-rc-scope-and-safety",
        "app-platform.trust-graph-durable-store",
        "app-platform.trust-graph-exchange",
        "app-platform.trust-social-beta-hardening",
        "app-platform.trust-social-content-format-profiles",
        "app-platform.trust-statement-signing",
        "app-platform.social-message-signing",
        "app-platform.signed-bundles",
        "catalog.smoke",
        "catalog.live-usk-publication",
        "catalog.live-usk-source-verification",
        "app-catalog.first-party-beta",
        "catalog.production-channels",
        "catalog.operations-and-mirrors",
        "app-catalog.first-party-maintenance-policy",
        "app-review.trusted-receipts",
        "app-review.policy",
        "app-review.governance",
        "app-review.reviewer-key-lifecycle",
        "app-review.transparency-log",
        "app-review.review-history-api",
        "app-review.first-party-catalog",
        "app-review.first-party-review-chain",
        "app-ui.design-system",
        "app-ui.lint",
        "app-ui.first-party-adoption",
        "app-ui.smoke",
        "reference-apps.content",
        "reference-app.profile-publisher",
        "reference-app.profile-publisher-app-data",
        "reference-app.feed-reader",
        "reference-app.feed-reader-subscriptions",
        "reference-app.feed-reader-app-data",
        "reference-app.trust-graph",
        "reference-app.trust-graph-durable-exchange",
        "reference-app.trust-graph-app-data-preview",
        "reference-app.social-inbox",
        "reference-app.social-inbox-signed-message",
        "reference-app.social-inbox-subscriptions",
        "reference-app.social-inbox-app-data",
        "reference-app.social-inbox-trust-annotations",
        "reference-app.social-inbox-rc-threading",
        "app-platform.trust-social-beta-hardening",
        "app-platform.trust-social-content-format-profiles",
        "migration.social-mail-preview",
        *APP_SERVICE_DISCOVERY_AND_GRANT_EVIDENCE_IDS,
        "legacy-plugin.migration-guide",
        "legacy-plugin.social-inbox-spike",
        "legacy-plugin.migration-finalization",
        "apphost.sandbox-provider",
        *PUBLIC_BETA_SECURITY_EVIDENCE_IDS,
        "app-update.lifecycle",
        "app-update.scheduler",
        "app-update.live-catalog-refresh",
        "app-update.rollback",
        "app-update.data-migration-contract",
        *OPERATOR_BETA_EVIDENCE_IDS,
        *OPERATOR_RC_EVIDENCE_IDS,
        "apphost.live",
    ):
        append_detail(lines, summary, evidence_id)
    lines.extend(["", "## Legacy Admin Retirement", ""])
    append_detail(lines, summary, "legacy.retirement")
    append_detail(lines, summary, "legacy-admin.removal-wave-1")
    append_detail(lines, summary, "legacy-admin.removal-wave-2")
    append_detail(lines, summary, "legacy-admin.removal-wave-3")
    append_detail(lines, summary, "legacy-admin.removal-wave-4")
    append_detail(lines, summary, "legacy-admin.removal-wave-5")
    append_detail(lines, summary, "legacy-admin.final-admin-surface")
    append_detail(lines, summary, "legacy-admin.browse-retained")
    append_detail(lines, summary, "legacy-admin.emergency-fallback-retained")
    lines.extend(
        [
            "",
            "## Redaction Rules",
            "",
            "- Private signing keys, form passwords, app process tokens, browser-session tokens, raw request bodies, raw feed bodies, raw update or rollback command output, raw app-data backup payloads, private insert URIs, and raw signatures are not included.",
            "- Local absolute paths, including absolute staging paths, are sanitized as `<repo>`, `<workdir>`, `<home>`, or `<path>` placeholders.",
            "- Catalog scratch paths, staged bundle paths, installed bundle paths, data/cache/run paths, and rollback backup paths are sanitized.",
            "- `artifacts/private-insert-uris.json` is excluded even if an interop summary references it.",
            "",
        ]
    )
    return "\n".join(lines)

def markdown_cell(value: Any) -> str:
    text = str(value)
    return text.replace("\n", " ").replace("|", "\\|")

def markdown_code_list(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return "none"
    return ", ".join(f"`{markdown_cell(value)}`" for value in values)

def coverage_result(value: Any) -> str:
    return "pass" if value is True else "fail"

def coverage_notes(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return "No gaps."
    return markdown_code_list(values)

def render_ecosystem_matrix_report(matrix: dict[str, Any]) -> str:
    counts = matrix.get("counts", {}) if isinstance(matrix.get("counts"), dict) else {}
    coverage = matrix.get("coverage", {}) if isinstance(matrix.get("coverage"), dict) else {}
    rows = matrix.get("rows", []) if isinstance(matrix.get("rows"), list) else []
    lines = [
        "# Ecosystem Certification Matrix",
        "",
        f"- Promotion decision: `{matrix.get('promotionDecision', 'block')}`",
        f"- Matrix status: `{matrix.get('status', 'missing')}`",
        f"- Mode: `{matrix.get('mode', 'missing')}`",
        f"- Generated: `{matrix.get('generatedAt', '')}`",
        f"- Previous summary: `{'present' if matrix.get('previousSummaryPresent') else 'missing'}`",
        f"- Previous matrix: `{'present' if matrix.get('previousMatrixPresent') else 'missing'}`",
        f"- Release blockers: `{counts.get('releaseBlockers', 0)}`",
        "",
        "## Coverage",
        "",
        "| Check | Result | Notes |",
        "| --- | --- | --- |",
        "| Required evidence covered | `{}` | {} |".format(
            coverage_result(coverage.get("requiredEvidenceCovered")),
            coverage_notes(
                (coverage.get("missingRequiredEvidenceIds") or [])
                + (coverage.get("unmappedRequiredEvidenceIds") or [])
            ),
        ),
        "| Ecosystem gates covered | `{}` | {} |".format(
            coverage_result(coverage.get("ecosystemGatesCovered")),
            coverage_notes(coverage.get("unmappedGateIds")),
        ),
        "| First-party apps covered | `{}` | {} |".format(
            coverage_result(coverage.get("firstPartyAppsCovered")),
            coverage_notes(coverage.get("missingFirstPartyApps")),
        ),
        "| Docs covered | `{}` | {} |".format(
            coverage_result(coverage.get("docsCovered")),
            coverage_notes((coverage.get("rowsWithoutDocs") or []) + (coverage.get("missingDocPaths") or [])),
        ),
        "| Redaction | `{}` | {} |".format(
            coverage_result(coverage.get("redactionPassed")),
            "Private material excluded." if coverage.get("redactionPassed") else "Review matrix redaction flags.",
        ),
        "",
        "## Matrix",
        "",
        "| Category | Row | Status | Previous | Regression | Blocker | Evidence | Gates | Waivers | Recommendation |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        if not isinstance(row, dict):
            continue
        lines.append(
            "| {category} | {row_title} | `{status}` | `{previous}` | `{regression}` | {blocker} | {evidence} | {gates} | {waivers} | {recommendation} |".format(
                category=markdown_cell(row.get("category", "")),
                row_title=markdown_cell(row.get("title", row.get("id", ""))),
                status=markdown_cell(row.get("status", "missing")),
                previous=markdown_cell(row.get("previousStatus", "missing")),
                regression=markdown_cell(row.get("regressionStatus", "not-comparable")),
                blocker="yes" if row.get("releaseBlocker") else "no",
                evidence=markdown_code_list(row.get("evidenceIds")),
                gates=markdown_code_list(row.get("gateIds")),
                waivers=markdown_code_list(row.get("waiverIds")),
                recommendation=markdown_cell(row.get("recommendation", "")),
            )
        )
    non_passing = [
        row for row in rows if isinstance(row, dict) and row.get("status") != "pass"
    ]
    if non_passing:
        lines.extend(["", "## Non-Passing Rows", ""])
        for row in non_passing:
            issue_ids = row.get("issueIds", [])
            details = row.get("details", {}) if isinstance(row.get("details"), dict) else {}
            waiver_reasons = details.get("waiverReasons", {}) if isinstance(details.get("waiverReasons"), dict) else {}
            lines.extend(
                [
                    f"### `{row.get('id', '')}`",
                    "",
                    f"- Status: `{row.get('status', 'missing')}`",
                    f"- Release blocker: `{'yes' if row.get('releaseBlocker') else 'no'}`",
                    f"- Regression: `{row.get('regressionStatus', 'not-comparable')}`",
                    f"- Issues: {markdown_code_list(issue_ids)}",
                    f"- Waivers: {markdown_code_list(row.get('waiverIds'))}",
                ]
            )
            if waiver_reasons:
                for waiver_id in sorted(waiver_reasons):
                    lines.append(f"- Waiver `{markdown_cell(waiver_id)}`: {markdown_cell(waiver_reasons[waiver_id])}")
            lines.extend([f"- Recommendation: {markdown_cell(row.get('recommendation', ''))}", ""])
    lines.extend(
        [
            "## Redaction",
            "",
            "The matrix is derived from sanitized summary fields. It does not include raw request bodies, raw feed bodies, raw trust documents, raw signatures, tokens, private insert URIs, or absolute local filesystem paths.",
            "",
        ]
    )
    return "\n".join(lines)

def append_ecosystem_matrix_summary(lines: list[str], summary: dict[str, Any]) -> None:
    matrix = summary.get("ecosystemMatrix", {})
    if not isinstance(matrix, dict):
        return
    coverage = matrix.get("coverage", {}) if isinstance(matrix.get("coverage"), dict) else {}
    lines.extend(
        [
            "## Ecosystem Certification Matrix",
            "",
            f"- Matrix status: `{summary.get('ecosystemMatrixStatus', 'missing')}`",
            f"- Matrix report: `{summary.get('ecosystemMatrixReportPath', '')}`",
            f"- Rows: `{matrix.get('rowCount', 0)}`",
            f"- Release blockers: `{matrix.get('releaseBlockerCount', 0)}`",
            f"- Required evidence covered: `{'yes' if coverage.get('requiredEvidenceCovered') else 'no'}`",
            f"- Ecosystem gates covered: `{'yes' if coverage.get('ecosystemGatesCovered') else 'no'}`",
            "",
        ]
    )

def append_stable_readiness_summary(lines: list[str], summary: dict[str, Any]) -> None:
    stable = summary.get("stableReadiness", {})
    if not isinstance(stable, dict):
        return
    lines.extend(
        [
            "## Stable 1.0 Readiness",
            "",
            f"- Status: `{stable.get('status', 'missing')}`",
            f"- Decision: `{stable.get('decision', 'not-attached')}`",
            f"- Stable ready: `{str(stable.get('stableReady', False)).lower()}`",
            f"- Required: `{str(stable.get('required', False)).lower()}`",
            f"- Blockers: `{stable.get('blockerCount', 0)}`",
            f"- Warnings: `{stable.get('warningCount', 0)}`",
            f"- Allowed limitations: `{stable.get('allowedLimitationCount', 0)}`",
            f"- Disallowed limitations: `{stable.get('disallowedLimitationCount', 0)}`",
            f"- Redaction: `{stable.get('redactionStatus', 'missing')}`",
            f"- Summary: {stable.get('summary', '')}",
            "",
        ]
    )

def append_ecosystem_rc_gate(lines: list[str], summary: dict[str, Any]) -> None:
    compact = summary.get("ecosystemRcGate", {})
    gates = summary.get("ecosystemGates", [])
    gate = None
    if isinstance(gates, list):
        gate = next(
            (
                candidate
                for candidate in gates
                if isinstance(candidate, dict) and candidate.get("id") == ECOSYSTEM_RC_GATE_ID
            ),
            None,
        )
    details = (
        gate.get("details", {})
        if isinstance(gate, dict) and isinstance(gate.get("details"), dict)
        else {}
    )
    waiver_ids = detail_waiver_ids(details)
    lines.extend(
        [
            "## Ecosystem RC Certification Gate",
            "",
            f"- Gate: `{ECOSYSTEM_RC_GATE_ID}`",
            f"- Status: `{compact.get('status', 'missing')}`",
            f"- Promotion decision: `{summary.get('ecosystemRcDecision', 'FAIL')}`",
            f"- Release blocker: `{'yes' if compact.get('releaseBlocker') else 'no'}`",
            f"- Blocking gates: {markdown_code_list(details.get('blockingGateIds'))}",
            f"- Failed evidence: `{compact.get('failedEvidenceCount', 0)}`",
            f"- Missing evidence: `{compact.get('missingEvidenceCount', 0)}`",
            f"- Warning evidence: `{compact.get('warningEvidenceCount', 0)}`",
            f"- Live-network required: `{'yes' if details.get('liveNetworkRequired') else 'no'}`",
            f"- Network-scale soak satisfied: `{'yes' if details.get('networkScaleSoakSatisfied') else 'no'}`",
            f"- Redaction passed: `{'yes' if details.get('redactionPassed') else 'no'}`",
            f"- Waivers: `{compact.get('waiverCount', 0)}` {markdown_code_list(waiver_ids)}",
            "",
        ]
    )

def append_history_comparison(lines: list[str], summary: dict[str, Any]) -> None:
    history = summary.get("historyComparison", {})
    if not isinstance(history, dict):
        return
    previous = history.get("previous", {}) if isinstance(history.get("previous"), dict) else {}
    current = history.get("current", {}) if isinstance(history.get("current"), dict) else {}
    lines.extend(
        [
            "## Historical Comparison",
            "",
            f"- Status: `{history.get('status', 'missing')}`",
            f"- Summary: {history.get('summary', 'No historical comparison was produced.')}",
            f"- Previous generated: `{previous.get('generatedAt', '')}`",
            f"- Previous git SHA: `{previous.get('gitSha', '')}`",
            f"- Previous release version: `{previous.get('releaseVersion', '')}`",
            f"- Current generated: `{current.get('generatedAt', '')}`",
            f"- Current git SHA: `{current.get('gitSha', '')}`",
            f"- Current release version: `{current.get('releaseVersion', '')}`",
            "",
        ]
    )

def append_ecosystem_gates(lines: list[str], summary: dict[str, Any]) -> None:
    gates = summary.get("ecosystemGates", [])
    if not isinstance(gates, list):
        return
    lines.extend(["## Ecosystem Gates", "", "| Gate | Status | Blocker | Summary |", "| --- | --- | --- | --- |"])
    ordered = sorted(
        [gate for gate in gates if isinstance(gate, dict)],
        key=lambda gate: (gate.get("status") != "fail", gate.get("status") != "warn", str(gate.get("id", ""))),
    )
    for gate in ordered:
        lines.append(
            "| `{id}` | `{status}` | {blocker} | {summary_text} |".format(
                id=gate.get("id", ""),
                status=gate.get("status", "missing"),
                blocker="yes" if gate.get("releaseBlocker") else "no",
                summary_text=str(gate.get("summary", "")).replace("|", "\\|"),
            )
        )
    lines.append("")

def append_waivers(lines: list[str], summary: dict[str, Any]) -> None:
    waivers = summary.get("waiverRecords")
    if not isinstance(waivers, list):
        legacy_waivers = summary.get("waivers", [])
        waivers = legacy_waivers if isinstance(legacy_waivers, list) else []
    if not isinstance(waivers, list):
        return
    lines.extend(["## Waivers", ""])
    if not waivers:
        lines.extend(["No waivers were recorded.", ""])
        return
    lines.extend(["| Waiver | Evidence/Gate | Active | Expires | Reason |", "| --- | --- | --- | --- | --- |"])
    for waiver in waivers:
        if not isinstance(waiver, dict):
            continue
        lines.append(
            "| `{id}` | `{evidence}` | `{active}` | `{expires}` | {reason} |".format(
                id=waiver.get("id", ""),
                evidence=waiver.get("evidenceId", ""),
                active=waiver.get("active", False),
                expires=waiver.get("expiresAt", ""),
                reason=str(waiver.get("reason", "")).replace("|", "\\|"),
            )
        )
    lines.append("")

def append_regressions(lines: list[str], summary: dict[str, Any]) -> None:
    history = summary.get("historyComparison", {})
    if not isinstance(history, dict):
        return
    diffs = history.get("evidenceDiffs", [])
    if not isinstance(diffs, list):
        return
    important = [
        diff
        for diff in diffs
        if isinstance(diff, dict) and diff.get("classification") in {"regression", "removed"}
    ]
    lines.extend(["## Regressions Since Previous Certified Release", ""])
    if not important:
        lines.extend(["No evidence regressions were detected.", ""])
        return
    lines.extend(
        [
            "| Evidence | Previous | Current | Classification | Blocker | Reason |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for diff in important:
        lines.append(
            "| `{id}` | `{previous}` | `{current}` | `{classification}` | {blocker} | {reason} |".format(
                id=diff.get("id", ""),
                previous=diff.get("previousStatus", ""),
                current=diff.get("currentStatus", ""),
                classification=diff.get("classification", ""),
                blocker="yes" if diff.get("releaseBlocker") else "no",
                reason=str(diff.get("reason", "")).replace("|", "\\|"),
            )
        )
    lines.append("")

def append_detail(lines: list[str], summary: dict[str, Any], evidence_id: str) -> None:
    item = next((entry for entry in summary["evidence"] if entry["id"] == evidence_id), None)
    if item is None:
        return
    lines.append(f"### `{evidence_id}`")
    lines.append("")
    lines.append(f"- Status: `{item['status']}`")
    lines.append(f"- Source: `{item['source']}`")
    lines.append(f"- Summary: {item['summary']}")
    details = item.get("details", {})
    if details:
        compact = json.dumps(details, indent=2, sort_keys=True)
        lines.extend(["", "```json", compact, "```"])
    lines.append("")

def gather_evidence(settings: Settings, waiver_context: WaiverContext) -> list[EvidenceItem]:
    evidence = [
        interop_evidence(
            "interop.smoke",
            settings.interop_smoke_summary,
            True,
            "smoke",
            settings.workspace_root,
            settings.out_dir,
        ),
        interop_evidence(
            "interop.extended",
            settings.interop_extended_summary,
            False,
            "extended",
            settings.workspace_root,
            settings.out_dir,
        ),
        perf_evidence(settings.perf_smoke_summary, True, settings.workspace_root, settings.out_dir),
    ]
    evidence.extend(
        app_platform_evidence(
            settings.app_platform_summary,
            settings.workspace_root,
            settings.out_dir,
            settings.mode,
        )
    )
    security_item = security_drills_evidence(
        settings.security_drills_summary,
        settings.workspace_root,
        settings.out_dir,
        settings.mode,
    )
    app_platform_security_items = [
        item for item in evidence if item.id == security_item.id
    ]
    evidence = [item for item in evidence if item.id != security_item.id]
    evidence.append(combine_security_response_evidence(app_platform_security_items, security_item))
    evidence.extend(
        live_network_beta_evidence(
            settings.live_network_summary,
            settings.workspace_root,
            settings.out_dir,
            settings.mode,
            settings.live_network_beta_enabled,
            settings.live_network_beta_required,
        )
    )
    evidence.append(
        network_scale_soak_evidence(
            settings.network_scale_soak_summary,
            settings.workspace_root,
            settings.out_dir,
            settings.mode,
        )
    )
    evidence.extend(
        multi_node_beta_soak_evidence(
            settings.multi_node_soak_summary,
            settings.workspace_root,
            settings.out_dir,
            settings.mode,
            settings.multi_node_soak_required,
        )
    )
    app_platform_docs_items = app_platform_docs_evidence(settings.workspace_root, settings.out_dir)
    app_platform_docs_item_ids = {item.id for item in app_platform_docs_items}
    evidence = [item for item in evidence if item.id not in app_platform_docs_item_ids]
    evidence.extend(app_platform_docs_items)
    evidence.extend(production_beta_go_no_go_evidence(settings.workspace_root, settings.out_dir))
    expected_stable_release_id = stable_readiness_expected_release_id(settings, evidence)
    evidence.extend(
        stable_readiness_evidence(
            settings.stable_readiness_summary,
            settings.stable_readiness_required,
            settings.workspace_root,
            settings.out_dir,
            expected_stable_release_id,
        )
    )
    stable_vulnerability_item = stable_vulnerability_evidence(
        settings.stable_vulnerability_summary,
        settings.workspace_root,
        settings.out_dir,
        settings.stable_vulnerability_candidate_release_id,
        settings.stable_vulnerability_candidate_build_version,
        required=settings.stable_vulnerability_required,
    )
    if stable_vulnerability_item is not None:
        evidence.append(stable_vulnerability_item)
    validated_vulnerability_summary_digest: str | None = None
    if (
        stable_vulnerability_item is not None
        and stable_vulnerability_item.status == "pass"
        and settings.stable_vulnerability_summary is not None
    ):
        authenticated_path, _, _, _ = _stable_vulnerability_handoff_paths(
            settings.stable_vulnerability_summary,
            settings.workspace_root,
            settings.out_dir,
        )
        authenticated_summary = (
            read_json(authenticated_path) if authenticated_path is not None else None
        )
        if isinstance(authenticated_summary, dict):
            candidate_digest = authenticated_summary.get("summaryDigest")
            if isinstance(candidate_digest, str):
                validated_vulnerability_summary_digest = candidate_digest
    observed_supply_chain_source_commit = ""
    if (
        settings.stable_supply_chain_required
        or settings.stable_supply_chain_summary is not None
    ):
        observed_supply_chain_source_commit = command_output(
            ["git", "rev-parse", "HEAD"], settings.workspace_root
        )
    stable_supply_chain_item = stable_supply_chain_evidence(
        settings.stable_supply_chain_summary,
        settings.workspace_root,
        settings.out_dir,
        settings.stable_supply_chain_candidate_release_id,
        settings.stable_supply_chain_candidate_build_version,
        settings.stable_supply_chain_candidate_source_commit,
        settings.stable_supply_chain_candidate_source_ref,
        observed_supply_chain_source_commit,
        required=settings.stable_supply_chain_required,
    )
    if stable_supply_chain_item is not None:
        evidence.append(stable_supply_chain_item)
    observed_dependency_vulnerability_source_commit = ""
    if (
        settings.stable_dependency_vulnerability_required
        or settings.stable_dependency_vulnerability_summary is not None
    ):
        observed_dependency_vulnerability_source_commit = command_output(
            ["git", "rev-parse", "HEAD"], settings.workspace_root
        )
    stable_dependency_vulnerability_item = stable_dependency_vulnerability_evidence(
        settings.stable_dependency_vulnerability_summary,
        settings.workspace_root,
        settings.out_dir,
        settings.stable_dependency_vulnerability_candidate_release_id,
        settings.stable_dependency_vulnerability_candidate_build_version,
        settings.stable_dependency_vulnerability_candidate_source_commit,
        settings.stable_dependency_vulnerability_candidate_source_ref,
        observed_dependency_vulnerability_source_commit,
        stable_supply_chain_item,
        stable_vulnerability_item,
        validated_vulnerability_summary_digest,
        required=settings.stable_dependency_vulnerability_required,
        # Observe runner UTC here, after every preceding evidence collector has
        # completed, instead of trusting a time frozen before this command.
        certification_clock=utc_now(),
        evidence_phase=(
            settings.stable_dependency_vulnerability_evidence_phase
        ),
    )
    if stable_dependency_vulnerability_item is not None:
        evidence.append(stable_dependency_vulnerability_item)
    return [
        sanitize_evidence_item(
            with_waiver_record(
                item,
                active_waiver_for_evidence_item(waiver_context, item, settings.mode),
            ),
            settings.workspace_root,
            settings.out_dir,
        )
        for item in evidence
    ]

def render_history_comparison(history: dict[str, Any]) -> str:
    lines = [
        "# Release Certification History Comparison",
        "",
        f"- Status: `{history.get('status', 'missing')}`",
        f"- Summary: {history.get('summary', '')}",
        "",
        "## Evidence Diffs",
        "",
        "| Evidence | Previous | Current | Classification | Blocker | Reason |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    diffs = history.get("evidenceDiffs", [])
    if isinstance(diffs, list):
        for diff in diffs:
            if not isinstance(diff, dict):
                continue
            lines.append(
                "| `{id}` | `{previous}` | `{current}` | `{classification}` | {blocker} | {reason} |".format(
                    id=diff.get("id", ""),
                    previous=diff.get("previousStatus", ""),
                    current=diff.get("currentStatus", ""),
                    classification=diff.get("classification", ""),
                    blocker="yes" if diff.get("releaseBlocker") else "no",
                    reason=str(diff.get("reason", "")).replace("|", "\\|"),
                )
            )
    gates = history.get("ecosystemGates", [])
    if isinstance(gates, list):
        lines.extend(["", "## Ecosystem Gates", "", "| Gate | Status | Blocker | Summary |", "| --- | --- | --- | --- |"])
        for gate in gates:
            if not isinstance(gate, dict):
                continue
            lines.append(
                "| `{id}` | `{status}` | {blocker} | {summary_text} |".format(
                    id=gate.get("id", ""),
                    status=gate.get("status", "missing"),
                    blocker="yes" if gate.get("releaseBlocker") else "no",
                    summary_text=str(gate.get("summary", "")).replace("|", "\\|"),
                )
            )
    lines.append("")
    return "\n".join(lines)

def safe_history_label(summary: dict[str, Any]) -> str:
    metadata = summary.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
    for value in (
        metadata.get("releaseVersion"),
        summary.get("historyLabel"),
        metadata.get("gitCommit"),
        metadata.get("githubSha"),
    ):
        if isinstance(value, str) and value.strip():
            label = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-")
            if label:
                return label[:80]
    return "current"

def write_history_artifacts(settings: Settings, summary: dict[str, Any]) -> None:
    if not settings.write_history:
        return
    history_dir = resolve_path(settings.workspace_root, settings.history_dir)
    comparison = summary.get("historyComparison", {})
    label = settings.history_label.strip() or safe_history_label(summary)
    safe_label = re.sub(r"[^A-Za-z0-9._-]+", "-", label).strip("-") if label else "current"
    if not safe_label:
        safe_label = "current"
    if summary.get("status") == "fail" or summary.get("releaseCandidatePassed") is False:
        failed_dir = history_dir / "failed" / safe_label
        write_json(failed_dir / SUMMARY_FILE_NAME, summary)
        if isinstance(comparison, dict):
            write_json(failed_dir / HISTORY_COMPARISON_FILE_NAME, comparison)
        return
    write_json(history_dir / "latest-summary.json", summary)
    if isinstance(comparison, dict):
        write_json(history_dir / "latest-history-comparison.json", comparison)
    release_dir = history_dir / "releases" / safe_label
    write_json(release_dir / SUMMARY_FILE_NAME, summary)
    if isinstance(comparison, dict):
        write_json(release_dir / HISTORY_COMPARISON_FILE_NAME, comparison)

def run(settings: Settings) -> tuple[dict[str, Any], int]:
    settings.out_dir.mkdir(parents=True, exist_ok=True)
    generated_at = utc_now()
    waiver_context = load_waiver_context(settings, dt.datetime.now(dt.timezone.utc))
    previous_summary, previous_source, previous_error = load_previous_summary(settings)
    copied = collect_source_artifacts(settings, settings.out_dir)
    metadata = collect_metadata(settings)
    base_evidence = gather_evidence(settings, waiver_context)

    def evaluate_history_and_gates(current_evidence: list[EvidenceItem]) -> tuple[dict[str, Any], list[GateResult]]:
        comparison = compare_history(
            settings,
            previous_summary,
            previous_source,
            previous_error,
            current_evidence,
            generated_at,
            metadata,
            waiver_context,
        )
        gates = evaluate_ecosystem_gates(
            settings, current_evidence, previous_summary, comparison, metadata, waiver_context
        )
        comparison["ecosystemGates"] = [gate.to_json() for gate in gates]
        comparison = dict(sanitize_value(comparison, settings.workspace_root, settings.out_dir))
        sanitized_gates = [
            GateResult(
                id=str(gate["id"]),
                status=normalize_evidence_status(str(gate["status"])),
                release_blocker=bool(gate.get("releaseBlocker")),
                summary=str(gate.get("summary", "")),
                details=gate.get("details", {}) if isinstance(gate.get("details"), dict) else {},
            )
            for gate in comparison.get("ecosystemGates", [])
            if isinstance(gate, dict)
        ]
        return comparison, sanitized_gates

    matrix_evidence = placeholder_ecosystem_matrix_evidence(settings.workspace_root, settings.out_dir)
    rc_gate_evidence = placeholder_ecosystem_rc_gate_evidence(settings.workspace_root, settings.out_dir)
    evidence = [*base_evidence, matrix_evidence, rc_gate_evidence]
    history_comparison: dict[str, Any] = {}
    ecosystem_gates: list[GateResult] = []
    ecosystem_matrix: dict[str, Any] = {}
    for _ in range(5):
        history_comparison, ecosystem_gates = evaluate_history_and_gates(evidence)
        final_gate = next((gate for gate in ecosystem_gates if gate.id == ECOSYSTEM_RC_GATE_ID), None)
        next_rc_gate_evidence = ecosystem_rc_gate_evidence(
            final_gate, settings.workspace_root, settings.out_dir
        )
        evidence_for_matrix = [*base_evidence, matrix_evidence, next_rc_gate_evidence]
        ecosystem_matrix = build_ecosystem_matrix(
            settings,
            evidence_for_matrix,
            previous_summary,
            history_comparison,
            ecosystem_gates,
            waiver_context,
            generated_at,
        )
        next_matrix_evidence = ecosystem_matrix_evidence(
            ecosystem_matrix, settings.workspace_root, settings.out_dir
        )
        if next_matrix_evidence == matrix_evidence:
            if next_rc_gate_evidence == rc_gate_evidence:
                evidence = evidence_for_matrix
                break
        matrix_evidence = next_matrix_evidence
        rc_gate_evidence = next_rc_gate_evidence
        evidence = [*base_evidence, matrix_evidence, rc_gate_evidence]
    else:
        history_comparison, ecosystem_gates = evaluate_history_and_gates(evidence)
        final_gate = next((gate for gate in ecosystem_gates if gate.id == ECOSYSTEM_RC_GATE_ID), None)
        rc_gate_evidence = ecosystem_rc_gate_evidence(
            final_gate, settings.workspace_root, settings.out_dir
        )
        evidence = [*base_evidence, matrix_evidence, rc_gate_evidence]
        ecosystem_matrix = build_ecosystem_matrix(
            settings,
            evidence,
            previous_summary,
            history_comparison,
            ecosystem_gates,
            waiver_context,
            generated_at,
        )
    summary = build_summary(
        settings,
        evidence,
        copied,
        generated_at,
        metadata,
        history_comparison,
        ecosystem_gates,
        waiver_context,
        ecosystem_matrix,
    )
    write_json(settings.out_dir / SUMMARY_FILE_NAME, summary)
    write_json(settings.out_dir / HISTORY_COMPARISON_FILE_NAME, history_comparison)
    write_text(settings.out_dir / HISTORY_COMPARISON_REPORT_FILE_NAME, render_history_comparison(history_comparison))
    write_json(settings.out_dir / ECOSYSTEM_MATRIX_FILE_NAME, ecosystem_matrix)
    write_text(
        settings.out_dir / ECOSYSTEM_MATRIX_REPORT_FILE_NAME,
        render_ecosystem_matrix_report(ecosystem_matrix),
    )
    report = render_report(summary)
    write_text(settings.out_dir / REPORT_FILE_NAME, report)
    write_history_artifacts(settings, summary)
    exit_code = 1 if summary["status"] == "fail" else 0
    return summary, exit_code

def parse_key_value(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise argparse.ArgumentTypeError(f"Expected key=value, got {value}")
        key, text = value.split("=", 1)
        if not key:
            raise argparse.ArgumentTypeError(f"Expected non-empty key in {value}")
        result[key] = text
    return result

def env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}

def settings_from_args(args: argparse.Namespace) -> Settings:
    workspace_root = args.workspace_root.resolve()
    out_dir = (workspace_root / args.out_dir).resolve() if not args.out_dir.is_absolute() else args.out_dir.resolve()
    previous_summary = resolve_path(workspace_root, args.previous_summary) if args.previous_summary else None
    history_dir = resolve_path(workspace_root, args.history_dir)
    waiver_files = tuple(resolve_path(workspace_root, path) for path in args.waiver_file)
    mode = args.mode or os.environ.get("CRYPTAD_CERT_MODE", "pr")
    if mode not in MODES:
        raise SystemExit(f"--mode must be one of {', '.join(MODES)}")
    live_network_beta_enabled = args.live_network_beta or env_flag("CRYPTAD_CERT_LIVE_NETWORK_BETA")
    live_network_beta_required = args.require_live_network_beta or env_flag("CRYPTAD_CERT_REQUIRE_LIVE_NETWORK_BETA")
    if live_network_beta_required:
        live_network_beta_enabled = True
    security_drills_summary_arg = (
        args.security_drills_summary
        or args.security_response_summary
        or os.environ.get("CRYPTAD_CERT_SECURITY_DRILLS_SUMMARY")
    )
    stable_readiness_summary_arg = (
        args.stable_readiness_summary
        or args.stable_1_0_readiness_summary
        or os.environ.get("CRYPTAD_CERT_STABLE_READINESS_SUMMARY")
    )
    stable_vulnerability_summary_arg = (
        args.stable_vulnerability_summary
        or os.environ.get("CRYPTAD_CERT_STABLE_VULNERABILITY_SUMMARY")
    )
    stable_supply_chain_summary_arg = (
        args.stable_supply_chain_summary
        or os.environ.get("CRYPTAD_CERT_STABLE_SUPPLY_CHAIN_SUMMARY")
    )
    stable_dependency_vulnerability_summary_arg = (
        args.stable_dependency_vulnerability_summary
        or os.environ.get(
            "CRYPTAD_CERT_STABLE_DEPENDENCY_VULNERABILITY_SUMMARY"
        )
    )
    return Settings(
        workspace_root=workspace_root,
        out_dir=out_dir,
        mode=mode,
        interop_smoke_summary=resolve_path(workspace_root, args.interop_smoke_summary),
        interop_extended_summary=resolve_path(workspace_root, args.interop_extended_summary),
        perf_smoke_summary=resolve_path(workspace_root, args.perf_smoke_summary),
        app_platform_summary=resolve_path(workspace_root, args.app_platform_summary),
        live_network_summary=resolve_path(workspace_root, args.live_network_summary),
        network_scale_soak_summary=resolve_path(workspace_root, args.network_scale_soak_summary),
        live_network_beta_enabled=live_network_beta_enabled,
        live_network_beta_required=live_network_beta_required,
        waivers=parse_key_value(args.waive),
        metadata=parse_key_value(args.metadata),
        skip_git_metadata=args.skip_git_metadata,
        previous_summary=previous_summary,
        require_history=args.require_history,
        history_dir=history_dir,
        write_history=args.write_history,
        history_label=args.history_label,
        waiver_files=waiver_files,
        multi_node_soak_summary=resolve_path(workspace_root, args.multi_node_soak_summary),
        multi_node_soak_required=args.require_multi_node_soak,
        security_drills_summary=(
            resolve_path(workspace_root, Path(security_drills_summary_arg))
            if security_drills_summary_arg
            else None
        ),
        stable_readiness_summary=(
            resolve_path(workspace_root, Path(stable_readiness_summary_arg))
            if stable_readiness_summary_arg
            else None
        ),
        stable_readiness_required=(
            args.require_stable_readiness
            or env_flag("CRYPTAD_CERT_REQUIRE_STABLE_READINESS")
        ),
        stable_vulnerability_summary=(
            resolve_path(workspace_root, Path(stable_vulnerability_summary_arg))
            if stable_vulnerability_summary_arg
            else None
        ),
        stable_vulnerability_required=(
            args.require_stable_vulnerability
            or env_flag("CRYPTAD_CERT_REQUIRE_STABLE_VULNERABILITY")
        ),
        stable_vulnerability_candidate_release_id=(
            args.stable_vulnerability_candidate_release_id
        ),
        stable_vulnerability_candidate_build_version=(
            args.stable_vulnerability_candidate_build_version
        ),
        stable_supply_chain_summary=(
            resolve_path(workspace_root, Path(stable_supply_chain_summary_arg))
            if stable_supply_chain_summary_arg
            else None
        ),
        stable_supply_chain_required=(
            args.require_stable_supply_chain
            or env_flag("CRYPTAD_CERT_REQUIRE_STABLE_SUPPLY_CHAIN")
        ),
        stable_supply_chain_candidate_release_id=(
            args.stable_supply_chain_candidate_release_id
        ),
        stable_supply_chain_candidate_build_version=(
            args.stable_supply_chain_candidate_build_version
        ),
        stable_supply_chain_candidate_source_commit=(
            args.stable_supply_chain_candidate_source_commit
        ),
        stable_supply_chain_candidate_source_ref=(
            args.stable_supply_chain_candidate_source_ref
        ),
        stable_dependency_vulnerability_summary=(
            resolve_path(
                workspace_root,
                Path(stable_dependency_vulnerability_summary_arg),
            )
            if stable_dependency_vulnerability_summary_arg
            else None
        ),
        stable_dependency_vulnerability_required=(
            args.require_stable_dependency_vulnerability
            or env_flag(
                "CRYPTAD_CERT_REQUIRE_STABLE_DEPENDENCY_VULNERABILITY"
            )
        ),
        stable_dependency_vulnerability_candidate_release_id=(
            args.stable_dependency_vulnerability_candidate_release_id
        ),
        stable_dependency_vulnerability_candidate_build_version=(
            args.stable_dependency_vulnerability_candidate_build_version
        ),
        stable_dependency_vulnerability_candidate_source_commit=(
            args.stable_dependency_vulnerability_candidate_source_commit
        ),
        stable_dependency_vulnerability_candidate_source_ref=(
            args.stable_dependency_vulnerability_candidate_source_ref
        ),
        stable_dependency_vulnerability_evidence_phase=(
            args.stable_dependency_vulnerability_evidence_phase
        ),
    )

def resolve_path(workspace_root: Path, path: Path) -> Path:
    return (workspace_root / path).resolve() if not path.is_absolute() else path.resolve()

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run Python-only self-tests.")
    parser.add_argument("--workspace-root", type=Path, default=Path.cwd())
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--mode", choices=MODES, default=None)
    parser.add_argument("--interop-smoke-summary", type=Path, default=Path("build/interop-smoke/summary.json"))
    parser.add_argument("--interop-extended-summary", type=Path, default=Path("build/interop-extended/summary.json"))
    parser.add_argument("--perf-smoke-summary", type=Path, default=Path("build/perf-smoke/summary.json"))
    parser.add_argument(
        "--app-platform-summary",
        type=Path,
        default=DEFAULT_OUT_DIR / "app-platform-smoke" / "summary.json",
    )
    parser.add_argument(
        "--live-network-summary",
        type=Path,
        default=DEFAULT_OUT_DIR / "live-network-beta-smoke" / "summary.json",
    )
    parser.add_argument(
        "--network-scale-soak-summary",
        type=Path,
        default=DEFAULT_OUT_DIR / "network-scale-soak" / "summary.json",
    )
    parser.add_argument(
        "--multi-node-soak-summary",
        type=Path,
        default=DEFAULT_OUT_DIR / "multi-node-beta-soak" / "summary.json",
    )
    parser.add_argument(
        "--security-drills-summary",
        type=Path,
        default=None,
        help="Redacted security response drill summary produced by certify.py security-response.",
    )
    parser.add_argument(
        "--security-response-summary",
        type=Path,
        default=None,
        help="Deprecated alias for --security-drills-summary.",
    )
    parser.add_argument(
        "--stable-readiness-summary",
        type=Path,
        default=None,
        help="Stable 1.0 readiness summary produced by certify.py stable-readiness.",
    )
    parser.add_argument(
        "--stable-1-0-readiness-summary",
        dest="stable_1_0_readiness_summary",
        type=Path,
        default=None,
        help="Alias for --stable-readiness-summary.",
    )
    parser.add_argument(
        "--stable-vulnerability-summary",
        type=Path,
        default=None,
        help=(
            "Bounded public Stable vulnerability governance summary. When supplied, "
            "its authenticated promotion decision is non-waivable."
        ),
    )
    parser.add_argument(
        "--require-stable-vulnerability",
        action="store_true",
        help=(
            "Treat missing or failing Stable vulnerability governance evidence "
            "as a non-waivable release blocker."
        ),
    )
    parser.add_argument(
        "--stable-vulnerability-candidate-release-id",
        default="",
        help=(
            "Exact release identity that an authenticated Stable vulnerability "
            "summary must govern."
        ),
    )
    parser.add_argument(
        "--stable-vulnerability-candidate-build-version",
        default="",
        help=(
            "Exact positive integer build identity that an authenticated Stable "
            "vulnerability summary must govern."
        ),
    )
    parser.add_argument(
        "--stable-supply-chain-summary",
        type=Path,
        default=None,
        help=(
            "Canonical public-safe Stable supply-chain promotion summary. When supplied, "
            "its authenticated promotion decision is non-waivable."
        ),
    )
    parser.add_argument(
        "--require-stable-supply-chain",
        action="store_true",
        help=(
            "Treat missing or failing Stable supply-chain promotion evidence as a "
            "non-waivable release blocker."
        ),
    )
    parser.add_argument(
        "--stable-supply-chain-candidate-release-id",
        default="",
        help="Exact Stable release identity governed by the supply-chain summary.",
    )
    parser.add_argument(
        "--stable-supply-chain-candidate-build-version",
        default="",
        help="Exact positive integer build governed by the supply-chain summary.",
    )
    parser.add_argument(
        "--stable-supply-chain-candidate-source-commit",
        default="",
        help=(
            "Exact lowercase 40-character checkout commit governed by the "
            "supply-chain summary."
        ),
    )
    parser.add_argument(
        "--stable-supply-chain-candidate-source-ref",
        default="",
        help=(
            "Exact immutable commit:<sha> source identity governed by the "
            "supply-chain summary."
        ),
    )
    parser.add_argument(
        "--stable-dependency-vulnerability-summary",
        type=Path,
        default=None,
        help=(
            "Canonical public-safe Stable dependency-vulnerability companion "
            "promotion summary. Its authenticated decision is non-waivable."
        ),
    )
    parser.add_argument(
        "--require-stable-dependency-vulnerability",
        action="store_true",
        help=(
            "Treat missing or failing dependency-vulnerability monitoring "
            "evidence as a non-waivable release blocker."
        ),
    )
    parser.add_argument(
        "--stable-dependency-vulnerability-candidate-release-id",
        default="",
        help="Exact Stable release identity governed by the PR-290 summary.",
    )
    parser.add_argument(
        "--stable-dependency-vulnerability-candidate-build-version",
        default="",
        help="Exact positive integer build governed by the PR-290 summary.",
    )
    parser.add_argument(
        "--stable-dependency-vulnerability-candidate-source-commit",
        default="",
        help="Exact lowercase 40-character candidate commit governed by PR-290.",
    )
    parser.add_argument(
        "--stable-dependency-vulnerability-candidate-source-ref",
        default="",
        help="Exact immutable commit:<sha> source identity governed by PR-290.",
    )
    parser.add_argument(
        "--stable-dependency-vulnerability-evidence-phase",
        choices=("prepublication-evaluation", "final-publication"),
        default="final-publication",
        help=(
            "Require either the authenticated prepublication evaluation used by "
            "Stable RC or final publication-verified PR-290 evidence."
        ),
    )
    parser.add_argument("--live-network-beta", action="store_true", help="Expect optional live-network beta evidence.")
    parser.add_argument(
        "--require-live-network-beta",
        action="store_true",
        help="Treat missing or failing live-network beta evidence as release-blocking.",
    )
    parser.add_argument(
        "--require-multi-node-soak",
        action="store_true",
        help="Treat missing or failing multi-node beta soak evidence as release-blocking.",
    )
    parser.add_argument(
        "--require-stable-readiness",
        action="store_true",
        help="Treat missing or failing Stable 1.0 readiness evidence as release-blocking.",
    )
    parser.add_argument("--waive", action="append", default=[], metavar="ID=REASON")
    parser.add_argument("--waiver-file", action="append", default=[], type=Path)
    parser.add_argument("--previous-summary", type=Path, default=None)
    parser.add_argument("--require-history", action="store_true")
    parser.add_argument("--history-dir", type=Path, default=DEFAULT_HISTORY_DIR)
    parser.add_argument("--write-history", action="store_true")
    parser.add_argument("--history-label", default="")
    parser.add_argument("--metadata", action="append", default=[], metavar="KEY=VALUE")
    parser.add_argument("--skip-git-metadata", action="store_true")
    return parser
