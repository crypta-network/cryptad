"""Implementation segment for the reporting portion of ``stable_1_0_readiness.py``."""

from __future__ import annotations

def build_summary(
    settings: Settings,
    domains: list[dict[str, Any]],
    redaction: dict[str, Any],
    input_paths: dict[str, Path],
    allowed_limitations: list[dict[str, Any]],
    disallowed_limitations: list[dict[str, Any]],
    resolved_limitations: list[dict[str, Any]],
    waivers: list[StableWaiver],
) -> dict[str, Any]:
    blockers = [blocker for domain in domains for blocker in domain.get("blockers", [])]
    warnings = [warning for domain in domains for warning in domain.get("warnings", [])]
    redaction_blockers = [
        blocker
        for blocker in blockers
        if isinstance(blocker, dict) and blocker.get("evidenceId") == "stable-1.0.redaction"
    ]
    if redaction.get("status") != "pass":
        redaction_blocker = blocker_issue(
            "redaction",
            "stable-1.0.redaction",
            "Stable 1.0 readiness redaction scan failed",
            f"Stable 1.0 readiness scanner found {redaction.get('findingCount', 0)} finding(s).",
            "stable-readiness-redaction",
        )
        blockers.append(redaction_blocker)
        redaction_blockers.append(redaction_blocker)
    if redaction_blockers:
        for domain in domains:
            if domain.get("id") == "redaction":
                existing = domain.setdefault("blockers", [])
                existing_keys = {
                    (
                        blocker.get("id"),
                        blocker.get("evidenceId"),
                        blocker.get("source"),
                    )
                    for blocker in existing
                    if isinstance(blocker, dict)
                }
                for redaction_blocker in redaction_blockers:
                    redaction_key = (
                        redaction_blocker.get("id"),
                        redaction_blocker.get("evidenceId"),
                        redaction_blocker.get("source"),
                    )
                    if redaction_key not in existing_keys:
                        existing.append(redaction_blocker)
                        existing_keys.add(redaction_key)
                domain["status"] = "fail"
                domain["summary"] = "Stable 1.0 readiness redaction blockers are present."
                break
    blocker_count = len(blockers)
    warning_count = len(warnings)
    allowed_count = len(allowed_limitations)
    disallowed_count = len(disallowed_limitations)
    if blocker_count or disallowed_count or redaction.get("status") != "pass":
        status = "fail"
        decision = "not-ready"
        stable_ready = False
    elif allowed_count:
        status = "warn"
        decision = "ready-with-allowed-limitations"
        stable_ready = True
    elif warning_count:
        status = "warn"
        decision = "ready"
        stable_ready = True
    else:
        status = "pass"
        decision = "ready"
        stable_ready = True
    release_id = "stable-1.0-candidate"
    production = read_json(settings.production_beta_summary)
    if isinstance(production, dict) and isinstance(production.get("releaseId"), str):
        release_id = production["releaseId"]
    input_refs = {
        key: input_reference(input_paths.get(key), settings.workspace_root)
        for key in (
            "productionBetaSummary",
            "goNoGoSummary",
            "releaseCertificationSummary",
            "ecosystemMatrix",
            "appPlatformSummary",
            "multiNodeSoakSummary",
            "networkScaleSoakSummary",
            "securityDrillsSummary",
            "publicBetaKnownIssues",
            "policy",
            "stableKnownLimitations",
        )
    }
    evidence = [
        evidence_item(
            "stable-1.0.readiness-gate",
            status,
            f"Stable 1.0 readiness decision is {decision}.",
            {"decision": decision, "stableReady": stable_ready},
        )
    ]
    for domain in domains:
        evidence_id = {
            "production-beta-state": "stable-1.0.production-beta-state",
            "release-certification-summary": "stable-1.0.release-certification",
            "platform-api-1.0": "stable-1.0.platform-api-compatibility",
            "app-ecosystem-maturity": "stable-1.0.app-ecosystem-maturity",
            "third-party-intake": "stable-1.0.third-party-intake",
            "security-drills": "stable-1.0.security-drills",
            "live-multi-node-soak": "stable-1.0.live-multi-node-soak",
            "legacy-plugin-migration": "stable-1.0.legacy-plugin-migration",
            "support-feedback-readiness": "stable-1.0.support-feedback-readiness",
            "known-limitations": "stable-1.0.known-limitations",
            "redaction": "stable-1.0.redaction",
        }.get(str(domain.get("id")), f"stable-1.0.{domain.get('id', 'domain')}")
        evidence.append(
            evidence_item(
                evidence_id,
                str(domain.get("status", "missing")),
                str(domain.get("summary", "")),
                {
                    "blockerCount": len(domain.get("blockers", [])),
                    "warningCount": len(domain.get("warnings", [])),
                    "allowedLimitationCount": len(domain.get("allowedLimitations", [])),
                },
            )
        )
    summary = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "stable-1.0-readiness",
        "tool": TOOL_NAME,
        "generatedAt": settings.generated_at,
        "releaseId": release_id,
        "status": status,
        "decision": decision,
        "stableReady": stable_ready,
        "blockerCount": blocker_count,
        "warningCount": warning_count,
        "allowedLimitationCount": allowed_count,
        "disallowedLimitationCount": disallowed_count,
        "domains": domains,
        "blockers": blockers,
        "warnings": warnings,
        "allowedLimitations": allowed_limitations,
        "disallowedLimitations": disallowed_limitations,
        "resolvedLimitations": resolved_limitations,
        "redaction": redaction,
        "waivers": [waiver.to_json() for waiver in waivers],
        "inputs": input_refs,
        "evidence": evidence,
        "artifactRefs": {
            "summary": SUMMARY_FILE,
            "report": REPORT_FILE,
            "knownLimitations": KNOWN_LIMITATIONS_FILE,
            "blockers": BLOCKERS_FILE,
        },
    }
    return dashboard.sanitize_value(summary, settings.workspace_root, settings.out_dir)

def render_report(summary: dict[str, Any]) -> str:
    lines = [
        "# Stable 1.0 Readiness Report",
        "",
        f"- Release ID: `{summary.get('releaseId', '')}`",
        f"- Decision: `{summary.get('decision', '')}`",
        f"- Stable ready: `{str(summary.get('stableReady', False)).lower()}`",
        f"- Status: `{summary.get('status', '')}`",
        f"- Generated: `{summary.get('generatedAt', '')}`",
        f"- Blockers: `{summary.get('blockerCount', 0)}`",
        f"- Warnings: `{summary.get('warningCount', 0)}`",
        f"- Allowed limitations: `{summary.get('allowedLimitationCount', 0)}`",
        f"- Disallowed limitations: `{summary.get('disallowedLimitationCount', 0)}`",
        "",
        "## Domains",
        "",
        "| Domain | Status | Summary |",
        "| --- | --- | --- |",
    ]
    for domain in summary.get("domains", []):
        if isinstance(domain, dict):
            lines.append(
                "| {} | `{}` | {} |".format(
                    dashboard.markdown_cell(domain.get("title", domain.get("id", ""))),
                    domain.get("status", ""),
                    dashboard.markdown_cell(domain.get("summary", "")),
                )
            )
    lines.extend(["", "## Blockers", ""])
    blockers = summary.get("blockers") if isinstance(summary.get("blockers"), list) else []
    if not blockers:
        lines.append("No Stable 1.0 blockers.")
    else:
        for blocker in blockers:
            if isinstance(blocker, dict):
                lines.append(f"- `{blocker.get('evidenceId', '')}`: {blocker.get('summary', '')}")
    lines.extend(["", "## Warnings", ""])
    warnings = summary.get("warnings") if isinstance(summary.get("warnings"), list) else []
    if not warnings:
        lines.append("No Stable 1.0 warnings.")
    else:
        for warning in warnings:
            if isinstance(warning, dict):
                lines.append(f"- `{warning.get('evidenceId', '')}`: {warning.get('summary', '')}")
    lines.extend(["", "## Allowed Limitations", ""])
    allowed = summary.get("allowedLimitations") if isinstance(summary.get("allowedLimitations"), list) else []
    if not allowed:
        lines.append("No allowed limitations remain open.")
    else:
        for limitation in allowed:
            if isinstance(limitation, dict):
                lines.append(f"- `{limitation.get('id', '')}`: {limitation.get('summary', '')}")
    lines.extend(["", "## Disallowed Limitations", ""])
    disallowed = summary.get("disallowedLimitations") if isinstance(summary.get("disallowedLimitations"), list) else []
    if not disallowed:
        lines.append("No disallowed limitations remain open.")
    else:
        for limitation in disallowed:
            if isinstance(limitation, dict):
                lines.append(f"- `{limitation.get('id', '')}`: {limitation.get('summary', '')}")
    redaction = summary.get("redaction") if isinstance(summary.get("redaction"), dict) else {}
    lines.extend(
        [
            "",
            "## Redaction",
            "",
            f"- Status: `{redaction.get('status', 'missing')}`",
            f"- Findings: `{redaction.get('findingCount', 0)}`",
            f"- Critical findings: `{redaction.get('criticalFindingCount', 0)}`",
            "",
            "## Inputs",
            "",
        ]
    )
    inputs = summary.get("inputs") if isinstance(summary.get("inputs"), dict) else {}
    for name in sorted(inputs):
        value = inputs[name]
        if isinstance(value, dict):
            lines.append(f"- `{name}`: `{value.get('path', value.get('status', 'missing'))}`")
    lines.append("")
    return "\n".join(lines)

def write_artifacts(summary: dict[str, Any], settings: Settings) -> None:
    write_json(settings.out_dir / SUMMARY_FILE, summary)
    write_text(settings.out_dir / REPORT_FILE, render_report(summary))
    write_json(
        settings.out_dir / KNOWN_LIMITATIONS_FILE,
        {
            "schemaVersion": SCHEMA_VERSION,
            "kind": "stable-1.0-known-limitations-report",
            "generatedAt": summary.get("generatedAt", ""),
            "releaseId": summary.get("releaseId", ""),
            "allowedLimitations": summary.get("allowedLimitations", []),
            "disallowedLimitations": summary.get("disallowedLimitations", []),
            "resolvedLimitations": summary.get("resolvedLimitations", []),
        },
    )
    write_json(
        settings.out_dir / BLOCKERS_FILE,
        {
            "schemaVersion": SCHEMA_VERSION,
            "kind": "stable-1.0-blockers",
            "generatedAt": summary.get("generatedAt", ""),
            "releaseId": summary.get("releaseId", ""),
            "blockerCount": summary.get("blockerCount", 0),
            "blockers": summary.get("blockers", []),
        },
    )

def run(
    settings: Settings,
    *,
    _validation_time: dt.datetime | None = None,
) -> tuple[dict[str, Any], int]:
    settings.out_dir.mkdir(parents=True, exist_ok=True)
    generated_at = parse_generated_at(settings.generated_at)
    now = _validation_time or dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    settings = dataclasses.replace(settings, generated_at=generated_at)
    inputs, input_paths, scan_targets = build_inputs(settings)
    policy_value = inputs.get("policy")
    policy = policy_value if isinstance(policy_value, dict) else {}
    limitations = (
        inputs.get("stableKnownLimitations")
        if isinstance(inputs.get("stableKnownLimitations"), dict)
        else {}
    )
    waivers = load_waivers(settings.waivers, now, settings.workspace_root)
    redaction = dashboard.redaction_report(dashboard.scan_paths(scan_targets, settings.workspace_root, settings.out_dir))
    evidence = stable_evidence_map_from_summaries(
        inputs.get("releaseCertificationSummary"),
        inputs.get("appPlatformSummary"),
    )
    attached_redaction_blockers = attached_evidence_redaction_blockers(
        ("release-certification-summary", inputs.get("releaseCertificationSummary")),
        ("app-platform-summary", inputs.get("appPlatformSummary")),
    )
    production_summary = inputs.get("productionBetaSummary")
    candidate_release_id = (
        str(production_summary.get("releaseId", "")).strip()
        if isinstance(production_summary, dict)
        else ""
    )
    known_limitations_domain, allowed, disallowed, resolved = evaluate_known_limitations(
        limitations,
        waivers,
        policy,
    )
    domains = [
        evaluate_policy(
            policy_value if isinstance(policy_value, dict) else None,
            input_paths.get("policy", settings.policy),
            settings.workspace_root,
        ),
        evaluate_production_beta_state(
            inputs.get("productionBetaSummary"),
            inputs.get("goNoGoSummary"),
            policy,
        ),
        evaluate_release_certification_summary(inputs.get("releaseCertificationSummary")),
        evaluate_ecosystem_matrix(inputs.get("ecosystemMatrix")),
        evaluate_platform_api(evidence, policy),
        evaluate_app_ecosystem(evidence, inputs.get("appPlatformSummary")),
        evaluate_third_party(evidence),
        evaluate_security(
            evidence,
            inputs.get("securityDrillsSummary"),
            policy,
            now,
            candidate_release_id,
        ),
        evaluate_live_multi_node_soak(
            evidence,
            inputs.get("multiNodeSoakSummary"),
            inputs.get("networkScaleSoakSummary"),
            policy,
            now,
            candidate_release_id,
        ),
        evaluate_legacy(evidence),
        evaluate_support_feedback(
            evidence,
            inputs.get("publicBetaKnownIssues"),
            settings.workspace_root,
            candidate_release_id,
        ),
        known_limitations_domain,
        domain_result(
            "redaction",
            "Redaction safety",
            ("stable-1.0.redaction",),
            attached_redaction_blockers,
            [],
        ),
    ]
    validation_blockers = validate_waivers_against_blockers(
        waivers,
        [blocker for domain in domains for blocker in domain.get("blockers", [])],
        policy,
    )
    if validation_blockers:
        for domain in domains:
            if domain.get("id") == "known-limitations":
                domain.setdefault("blockers", []).extend(validation_blockers)
                domain["status"] = "fail"
                domain["summary"] = validation_blockers[0]["summary"]
                break
    summary = build_summary(settings, domains, redaction, input_paths, allowed, disallowed, resolved, waivers)
    write_artifacts(summary, settings)
    output_findings = dashboard.scan_paths(
        [
            settings.out_dir / SUMMARY_FILE,
            settings.out_dir / REPORT_FILE,
            settings.out_dir / KNOWN_LIMITATIONS_FILE,
            settings.out_dir / BLOCKERS_FILE,
        ],
        settings.workspace_root,
        settings.out_dir,
    )
    if output_findings:
        combined = [
            *redaction.get("findings", []),
            *output_findings,
        ]
        final_redaction = dashboard.redaction_report([finding for finding in combined if isinstance(finding, dict)])
        summary = build_summary(
            settings,
            domains,
            final_redaction,
            input_paths,
            allowed,
            disallowed,
            resolved,
            waivers,
        )
        write_artifacts(summary, settings)
    return summary, 0 if summary.get("stableReady") is True else 1

def write_case_files(root: Path, inputs: dict[str, Any], limitations: dict[str, Any]) -> dict[str, Path]:
    case_dir = root / "inputs"
    case_dir.mkdir(parents=True, exist_ok=True)
    mapping = {
        "productionBetaSummary": "production-beta-summary.json",
        "goNoGoSummary": "go-no-go-summary.json",
        "releaseCertificationSummary": "release-certification-summary.json",
        "ecosystemMatrix": "ecosystem-certification-matrix.json",
        "appPlatformSummary": "app-platform-summary.json",
        "multiNodeSoakSummary": "multi-node-beta-soak-summary.json",
        "networkScaleSoakSummary": "network-scale-soak-summary.json",
        "securityDrillsSummary": "security-drills-summary.json",
        "publicBetaKnownIssues": "public-beta-known-issues.json",
    }
    paths: dict[str, Path] = {}
    for key, file_name in mapping.items():
        if key in inputs:
            path = case_dir / file_name
            write_json(path, inputs[key])
            paths[key] = path
    limitations_path = case_dir / "stable-known-limitations.json"
    write_json(limitations_path, limitations)
    paths["stableKnownLimitations"] = limitations_path
    return paths

def base_self_test_inputs() -> tuple[dict[str, Any], dict[str, Any]]:
    go_fixture = dashboard.load_fixture(FIXTURE_DIR / "go-no-go-pass.json")
    go_inputs = copy.deepcopy(go_fixture["inputs"])
    app_platform = read_json(FIXTURE_DIR / "self-test-app-platform-smoke.json") or {}
    network = copy.deepcopy(read_json(FIXTURE_DIR / "self-test-network-scale-soak.json") or {})
    network["mode"] = "live-rc-soak"
    network["status"] = "pass"
    network["releaseId"] = "cryptad-beta-270"
    production = copy.deepcopy(go_inputs["productionBetaSummary"])
    production["generatedAt"] = DEFAULT_GENERATED_AT
    production["releaseId"] = "cryptad-beta-270"
    production["version"] = "270"
    production["workspaceStatusKnown"] = True
    production["dirtyWorkspace"] = False
    production["signingProfile"] = {
        "kind": "production",
        "generatedTestKeys": False,
        "appKeyId": "production-app-key",
        "reviewerKeyId": "production-reviewer-key",
        "privateKeyMaterialIncluded": False,
    }
    production["pipelineStages"] = {
        "crypta-app-launcher-install": {"status": "pass"},
        "gradle-full-build": {"status": "pass"},
        "first-party-app-staging": {"status": "pass"},
        "first-party-app-signing": {"status": "pass"},
        "first-party-app-verification": {"status": "pass"},
    }
    production["promotion"] = {
        "status": "pass",
        "promotionReady": True,
        "nonRelease": False,
        "failedGateCount": 0,
        "gates": [
            {"id": "build.crypta-app-launcher-install", "status": "pass"},
            {"id": "build.gradle-full-build", "status": "pass"},
            {"id": "build.first-party-app-staging", "status": "pass"},
            {"id": "build.first-party-app-signing", "status": "pass"},
            {"id": "build.first-party-app-verification", "status": "pass"},
            {"id": "build.production-beta-complete", "status": "pass"},
            {"id": "workspace.clean-production-beta", "status": "pass"},
            {"id": "signing.production-keys", "status": "pass"},
        ],
    }
    go_no_go = {
        "schemaVersion": 1,
        "tool": "production-beta-go-no-go-dashboard",
        "mode": "production-beta",
        "releaseId": "cryptad-beta-270",
        "decision": "go",
        "promotionReady": True,
        "summary": {
            "blockers": 0,
            "warnings": 0,
            "waiversUsed": 0,
            "criticalRedactionFindings": 0,
            "criticalFindings": 0,
        },
        "domains": [
            {
                "id": domain_id,
                "status": "pass",
                "summary": f"Synthetic dashboard domain {domain_id} passed.",
            }
            for domain_id in GO_NO_GO_DOMAIN_IDS
        ],
        "blockers": [],
        "warnings": [],
        "waivers": [],
        "redaction": {"schemaVersion": 1, "status": "pass", "findingCount": 0, "findings": []},
    }
    release_cert = {
        "schemaVersion": 1,
        "tool": "release-certification",
        "mode": "release-candidate",
        "status": "pass",
        "releaseCandidatePassed": True,
        "ecosystemRcPassed": True,
        "evidence": copy.deepcopy(app_platform.get("evidence", [])),
        "redaction": {
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
    release_cert["evidence"].extend(
        {
            "id": evidence_id,
            "status": "pass",
            "summary": f"{evidence_id} passed.",
            "details": {"redaction": {"status": "pass", "findings": []}}
            if evidence_id == "live-network-beta.redaction"
            else {},
        }
        for evidence_id in LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS
    )
    security = copy.deepcopy(go_inputs["securityDrillsSummary"])
    security["releaseId"] = "cryptad-beta-270"
    security["generatedAt"] = DEFAULT_GENERATED_AT
    multi_node_config_path = FIXTURE_DIR / "self-test-multi-node-beta-soak.json"
    multi_node_config = multi_node_beta_soak.validate_config(
        copy.deepcopy(read_json(multi_node_config_path) or {}),
        override_mode="hybrid",
    )
    multi_node_config["currentCandidate"]["version"] = "270"
    multi_node = multi_node_beta_soak.build_summary(
        multi_node_config,
        base_dir=multi_node_config_path.parent,
        strict=True,
    )
    multi_node["generatedAt"] = DEFAULT_GENERATED_AT
    multi_node["previousCandidateUpgrade"] = multi_node_beta_soak.compact_previous_candidate_upgrade(
        multi_node
    )
    scenario_statuses = (
        multi_node.get("scenarioStatuses")
        if isinstance(multi_node.get("scenarioStatuses"), dict)
        else {}
    )
    multi_node["scenarioStatuses"] = {
        **{scenario_id: "pass" for scenario_id in multi_node_beta_soak.SCENARIO_EVIDENCE_IDS},
        **scenario_statuses,
    }
    network["generatedAt"] = DEFAULT_GENERATED_AT
    limitations = copy.deepcopy(read_json(DEFAULT_LIMITATIONS) or {})
    ecosystem_matrix = copy.deepcopy(go_inputs["ecosystemMatrix"])
    ecosystem_matrix.update(
        {
            "schemaVersion": certification.ECOSYSTEM_MATRIX_SCHEMA_VERSION,
            "tool": certification.TOOL_NAME,
            "kind": "ecosystem-certification-matrix",
            "mode": "release-candidate",
            "status": "pass",
            "releaseBlockerCount": 0,
        }
    )
    ecosystem_matrix["rows"] = [
        {
            "id": row_id,
            "status": "pass",
            "releaseBlocker": False,
        }
        for row_id in ECOSYSTEM_MATRIX_REQUIRED_ROW_IDS
    ]
    ecosystem_matrix["counts"] = {
        **(
            ecosystem_matrix.get("counts")
            if isinstance(ecosystem_matrix.get("counts"), dict)
            else {}
        ),
        "rows": len(ECOSYSTEM_MATRIX_REQUIRED_ROW_IDS),
        "releaseBlockers": 0,
    }
    inputs = {
        "productionBetaSummary": production,
        "goNoGoSummary": go_no_go,
        "releaseCertificationSummary": release_cert,
        "ecosystemMatrix": ecosystem_matrix,
        "appPlatformSummary": app_platform,
        "multiNodeSoakSummary": multi_node,
        "networkScaleSoakSummary": network,
        "securityDrillsSummary": security,
        "publicBetaKnownIssues": copy.deepcopy(read_json(DEFAULT_PUBLIC_BETA_KNOWN_ISSUES) or {}),
    }
    return inputs, limitations

def resolved_limitations(limitations: dict[str, Any]) -> dict[str, Any]:
    copy_value = copy.deepcopy(limitations)
    for limitation in copy_value.get("limitations", []):
        if isinstance(limitation, dict):
            limitation["status"] = "resolved"
    return copy_value

def mutate_evidence(inputs: dict[str, Any], evidence_id: str, mutator: Callable[[dict[str, Any]], None] | None = None, remove: bool = False) -> None:
    evidence = inputs["appPlatformSummary"]["evidence"]
    cert_evidence = inputs["releaseCertificationSummary"]["evidence"]
    for collection in (evidence, cert_evidence):
        if remove:
            collection[:] = [entry for entry in collection if not isinstance(entry, dict) or entry.get("id") != evidence_id]
            continue
        for entry in collection:
            if isinstance(entry, dict) and entry.get("id") == evidence_id and mutator is not None:
                mutator(entry)

def self_test_settings(workspace: Path, out_dir: Path, paths: dict[str, Path], waiver_path: Path | None = None) -> Settings:
    return Settings(
        workspace_root=workspace,
        out_dir=out_dir,
        generated_at=DEFAULT_GENERATED_AT,
        production_beta_summary=paths.get("productionBetaSummary"),
        go_no_go_summary=paths.get("goNoGoSummary"),
        release_certification_summary=paths.get("releaseCertificationSummary"),
        ecosystem_matrix=paths.get("ecosystemMatrix"),
        app_platform_summary=paths.get("appPlatformSummary"),
        multi_node_soak_summary=paths.get("multiNodeSoakSummary"),
        network_scale_soak_summary=paths.get("networkScaleSoakSummary"),
        security_drills_summary=paths.get("securityDrillsSummary"),
        public_beta_known_issues=paths.get("publicBetaKnownIssues"),
        policy=paths.get("policy", DEFAULT_POLICY),
        stable_known_limitations=paths["stableKnownLimitations"],
        waivers=waiver_path,
    )

def run_case(
    root: Path,
    name: str,
    mutator: Callable[[dict[str, Any], dict[str, Any], dict[str, Path]], Path | None] | None,
    expected_decision: str,
    *,
    expect_blocker: str | None = None,
    expect_allowed: str | None = None,
    post_check: Callable[[dict[str, Any]], None] | None = None,
    use_real_validation_time: bool = False,
) -> None:
    inputs, limitations = base_self_test_inputs()
    if expected_decision == "ready":
        limitations = resolved_limitations(limitations)
    paths = write_case_files(root / name, inputs, limitations)
    path_keys_before_mutation = set(paths)
    waiver_path = mutator(inputs, limitations, paths) if mutator is not None else None
    if mutator is not None:
        path_overrides = {
            key: value
            for key, value in paths.items()
            if key not in path_keys_before_mutation or key == "policy"
        }
        paths = write_case_files(root / name, inputs, limitations)
        paths.update(path_overrides)
        if waiver_path is not None:
            paths["waivers"] = waiver_path
    settings = self_test_settings(root, root / "out" / name, paths, waiver_path)
    summary, _exit_code = run(
        settings,
        _validation_time=None if use_real_validation_time else SELF_TEST_VALIDATION_TIME,
    )
    if summary["decision"] != expected_decision:
        raise AssertionError(f"{name} expected {expected_decision}, got {summary['decision']}: {summary}")
    if expect_blocker:
        blocker_ids = {str(blocker.get("evidenceId")) for blocker in summary.get("blockers", [])}
        if expect_blocker not in blocker_ids:
            raise AssertionError(f"{name} missing blocker {expect_blocker}: {summary.get('blockers')}")
    if expect_allowed:
        allowed_ids = {str(limitation.get("id")) for limitation in summary.get("allowedLimitations", [])}
        if expect_allowed not in allowed_ids:
            raise AssertionError(f"{name} missing allowed limitation {expect_allowed}: {summary.get('allowedLimitations')}")
    if post_check is not None:
        post_check(summary)
