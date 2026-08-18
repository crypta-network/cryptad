"""Implementation segment for the evidence portion of ``production_beta_release.py``."""

from __future__ import annotations

def certification_mode(settings: Settings) -> str:
    return "pr" if settings.mode == "developer-dry-run" else "release-candidate"

def security_drills_dir(settings: Settings) -> Path:
    return settings.out_dir / "security-drills"

def security_drills_summary_path(settings: Settings) -> Path:
    return security_drills_dir(settings) / "security-drills-summary.json"

def security_release_notes_draft_path(settings: Settings) -> Path:
    return settings.out_dir / "security/security-release-notes-draft.md"

def stable_readiness_out_dir(settings: Settings) -> Path:
    return settings.out_dir / STABLE_READINESS_DIR

def stable_readiness_summary_path(settings: Settings) -> Path:
    return settings.out_dir / STABLE_READINESS_SUMMARY_JSON

def stable_readiness_multi_node_soak_path(settings: Settings) -> Path:
    return settings.out_dir / STABLE_READINESS_MULTI_NODE_SOAK_JSON

def stable_readiness_network_scale_soak_path(settings: Settings) -> Path:
    return settings.out_dir / STABLE_READINESS_NETWORK_SCALE_SOAK_JSON

def security_drills_release_id(state: PipelineState) -> str:
    return state.settings.release_id or f"cryptad-beta-{state.version}"

def attached_security_drill_artifact_errors(
    state: PipelineState,
    summary: dict[str, Any],
    attached_summary: Path,
    target_dir: Path,
) -> list[str]:
    artifacts = summary.get("artifacts")
    if not isinstance(artifacts, list):
        return ["attached security drills summary artifacts must be an array"]
    source_dir = attached_summary.parent
    target_dir.mkdir(parents=True, exist_ok=True)
    model_path = (
        state.settings.workspace_root
        / "tools/release-certification/production-security-response-runbook.json"
    )
    errors: list[str] = []
    seen: set[str] = set()
    for index, entry in enumerate(artifacts):
        if not isinstance(entry, dict):
            errors.append(f"attached security drill artifact entry {index} must be an object")
            continue
        scenario = entry.get("scenario")
        if scenario not in security_response_runbook.REQUIRED_DRILLS:
            errors.append(f"attached security drill artifact entry {index} has an unknown scenario")
            continue
        scenario_text = str(scenario)
        if scenario_text in seen:
            errors.append(f"attached security drill artifact for {scenario_text} is duplicated")
            continue
        seen.add(scenario_text)
        artifact_name = entry.get("artifact")
        expected_name = security_response_runbook.DRILL_OUTPUT_FILENAMES[scenario_text]
        if artifact_name != expected_name:
            errors.append(f"attached security drill artifact for {scenario_text} must be named {expected_name}")
            continue
        if Path(str(artifact_name)).name != artifact_name or bad_artifact_name(str(artifact_name)):
            errors.append(f"attached security drill artifact for {scenario_text} has an unsafe file name")
            continue
        source_path = source_dir / str(artifact_name)
        if not source_path.is_file() or source_path.is_symlink():
            errors.append(f"attached security drill artifact for {scenario_text} is missing")
            continue
        try:
            digest = security_response_runbook.sha256_path(source_path)
            verification = security_response_runbook.drill_verify(source_path, model_path)
        except (OSError, ValueError, json.JSONDecodeError):
            errors.append(f"attached security drill artifact for {scenario_text} could not be verified")
            continue
        if entry.get("digest") != digest:
            errors.append(f"attached security drill artifact digest mismatch for {scenario_text}")
            continue
        if verification.get("status") != "pass":
            errors.append(f"attached security drill artifact for {scenario_text} failed offline verification")
            continue
        target_path = target_dir / str(artifact_name)
        if source_path.resolve() != target_path.resolve():
            shutil.copy2(source_path, target_path)
    missing = sorted(set(security_response_runbook.REQUIRED_DRILLS) - seen)
    for scenario in missing:
        errors.append(f"attached security drill artifact for {scenario} is missing")
    return errors

def mark_attached_security_drills_summary_failed(summary: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    failed = json.loads(json.dumps(summary, sort_keys=True))
    failed["status"] = "fail"
    failed["promotionReady"] = False
    failed["attachmentErrors"] = list(errors)
    return failed

def attached_security_drills_failure_summary(
    state: PipelineState,
    expected_release_id: str,
    validation: dict[str, Any],
    release_id_matches: bool,
    errors: list[Any],
) -> dict[str, Any]:
    safe_errors = security_response_runbook.safe_redaction_findings([str(error) for error in errors])
    validation_findings = validation.get("redactionFindings")
    safe_findings = security_response_runbook.safe_redaction_findings(
        validation_findings if isinstance(validation_findings, list) else []
    )
    attached_digest = "missing"
    attached_path = state.settings.security_drills_summary
    if attached_path is not None and attached_path.is_file() and not attached_path.is_symlink():
        try:
            attached_digest = security_response_runbook.sha256_path(attached_path)
        except OSError:
            attached_digest = "unavailable"
    required = list(security_response_runbook.REQUIRED_DRILLS)
    return {
        "kind": "cryptad-security-response-drills-summary",
        "schemaVersion": security_response_runbook.DRILL_SUMMARY_SCHEMA_VERSION,
        "status": "fail",
        "promotionReady": False,
        "nonRelease": True,
        "fixtureOnly": False,
        "releaseId": expected_release_id,
        "mode": state.settings.mode,
        "generatedAt": state.started_at,
        "maxAgeDays": security_response_runbook.DEFAULT_MAX_AGE_DAYS,
        "requiredScenarios": required,
        "passedScenarios": [],
        "failedScenarios": [],
        "missingScenarios": required,
        "staleScenarios": [],
        "malformedScenarios": [],
        "counts": {
            "required": len(required),
            "passed": 0,
            "failed": 0,
            "missing": len(required),
            "stale": 0,
            "malformed": 0,
        },
        "redaction": {
            "status": "fail",
            "rawSensitiveMaterialExcluded": False,
            "findings": safe_findings or ["attached security drills summary was rejected before ingestion"],
        },
        "releaseNotes": {
            "templateStatus": "fail",
            "redactedSnippet": "Attached security drill summary was rejected before release evidence ingestion.",
        },
        "advisoryTemplate": {
            "templateStatus": "fail",
            "redactedSnippet": "Attached security drill summary was rejected before advisory evidence ingestion.",
        },
        "artifacts": [],
        "attachment": {
            "status": "fail",
            "releaseIdMatchesCandidate": release_id_matches,
            "validationStatus": validation.get("status", "fail"),
            "attachedSummaryDigest": attached_digest,
            "sanitized": True,
        },
        "attachmentErrors": safe_errors,
    }

def run_security_response_drills(state: PipelineState) -> Path:
    summary_path = security_drills_summary_path(state.settings)
    if state.settings.security_drills_summary is not None:
        value = read_json(state.settings.security_drills_summary)
        expected_release_id = security_drills_release_id(state)
        validation = security_response_runbook.validate_drills_summary(
            value if isinstance(value, dict) else {},
            production=state.settings.mode == "production-beta",
            strict=state.settings.mode in {"release-candidate", "production-beta"},
            now=security_response_runbook.parse_timestamp(state.started_at),
            expected_mode=state.settings.mode if state.settings.mode in {"release-candidate", "production-beta"} else None,
        )
        release_id_matches = isinstance(value, dict) and value.get("releaseId") == expected_release_id
        rejection_errors: list[Any] = []
        if not release_id_matches:
            rejection_errors.append("attached security response drill summary releaseId does not match this candidate")
            state.failures.append(
                "attached security response drill summary releaseId does not match this candidate."
            )
        if validation.get("status") != "pass":
            validation_errors = (
                validation.get("errors") if isinstance(validation.get("errors"), list) else []
            )
            rejection_errors.extend(validation_errors)
            safe_validation_errors = security_response_runbook.safe_redaction_findings(
                [str(error) for error in validation_errors[:5]]
            )
            state.failures.append(
                "attached security response drill summary is not promotion-ready: "
                + ("; ".join(safe_validation_errors) or "validation failed")
            )
        if isinstance(value, dict):
            artifact_errors: list[str] = []
            final_validation = validation
            if validation.get("status") == "pass" and release_id_matches:
                write_json(summary_path, value)
                artifact_errors = attached_security_drill_artifact_errors(
                    state,
                    value,
                    state.settings.security_drills_summary,
                    security_drills_dir(state.settings),
                )
                if artifact_errors:
                    write_json(summary_path, mark_attached_security_drills_summary_failed(value, artifact_errors))
                    state.failures.append(
                        "attached security response drill artifacts are incomplete or unverified: "
                        + "; ".join(artifact_errors[:5])
                    )
                else:
                    verified_summary = security_response_runbook.drill_verify_all(
                        security_drills_dir(state.settings),
                        summary_path,
                        state.settings.workspace_root
                        / "tools/release-certification/production-security-response-runbook.json",
                        release_id=expected_release_id,
                        mode=(
                            state.settings.mode
                            if state.settings.mode in {"release-candidate", "production-beta"}
                            else None
                        ),
                        now_text=state.started_at,
                    )
                    final_validation = security_response_runbook.validate_drills_summary(
                        verified_summary,
                        production=state.settings.mode == "production-beta",
                        strict=state.settings.mode in {"release-candidate", "production-beta"},
                        now=security_response_runbook.parse_timestamp(state.started_at),
                        expected_mode=(
                            state.settings.mode
                            if state.settings.mode in {"release-candidate", "production-beta"}
                            else None
                        ),
                    )
                    if final_validation.get("status") != "pass":
                        state.failures.append(
                            "attached security response drill artifacts did not verify as a complete summary: "
                            + "; ".join(str(error) for error in final_validation.get("errors", [])[:5])
                        )
            else:
                write_json(
                    summary_path,
                    attached_security_drills_failure_summary(
                        state,
                        expected_release_id,
                        validation,
                        release_id_matches,
                        rejection_errors,
                    ),
                )
        else:
            artifact_errors = ["attached summary is missing or malformed"]
            final_validation = validation
            write_json(
                summary_path,
                attached_security_drills_failure_summary(
                    state,
                    expected_release_id,
                    validation,
                    False,
                    artifact_errors,
                ),
            )
        stage_ok = (
            validation.get("status") == "pass"
            and final_validation.get("status") == "pass"
            and release_id_matches
            and not artifact_errors
        )
        record_pipeline_stage(
            state,
            "security-response-drills",
            "pass" if stage_ok else "fail",
            "Consumed attached security response drill summary and verified per-scenario artifacts.",
        )
        return summary_path

    verify_result = run_command(
        state,
        "security-response-runbook-verify",
        [
            sys.executable,
            str(state.settings.workspace_root / "tools/release-certification/cryptad_certification/engine_entry.py"),
            "security-response",
            "verify",
        ],
        timeout_seconds=120,
        allow_failure=True,
    )
    run_all_result = run_command(
        state,
        "security-response-drill-run-all",
        [
            sys.executable,
            str(state.settings.workspace_root / "tools/release-certification/cryptad_certification/engine_entry.py"),
            "security-response",
            "drill",
            "run-all",
            "--out-dir",
            str(security_drills_dir(state.settings)),
            "--summary-out",
            str(summary_path),
            "--release-id",
            security_drills_release_id(state),
            "--generated-at",
            state.started_at,
            "--mode",
            state.settings.mode,
            "--release-notes-out",
            str(security_release_notes_draft_path(state.settings)),
        ],
        timeout_seconds=120,
        allow_failure=True,
    )
    verify_all_result = run_command(
        state,
        "security-response-drill-verify-all",
        [
            sys.executable,
            str(state.settings.workspace_root / "tools/release-certification/cryptad_certification/engine_entry.py"),
            "security-response",
            "drill",
            "verify-all",
            "--input-dir",
            str(security_drills_dir(state.settings)),
            "--summary-out",
            str(summary_path),
            "--release-id",
            security_drills_release_id(state),
            "--generated-at",
            state.started_at,
            "--mode",
            state.settings.mode,
            "--now",
            state.started_at,
        ],
        timeout_seconds=120,
        allow_failure=True,
    )
    generated_summary = read_json(summary_path)
    validation = security_response_runbook.validate_drills_summary(
        generated_summary if isinstance(generated_summary, dict) else {},
        production=state.settings.mode == "production-beta",
        strict=state.settings.mode in {"release-candidate", "production-beta"},
        now=security_response_runbook.parse_timestamp(state.started_at),
        expected_mode=state.settings.mode if state.settings.mode in {"release-candidate", "production-beta"} else None,
    )
    stage_ok = (
        verify_result.ok()
        and run_all_result.ok()
        and verify_all_result.ok()
        and validation.get("status") == "pass"
    )
    if not stage_ok:
        state.failures.append("security response drills did not produce a promotion-ready summary.")
    record_pipeline_stage(
        state,
        "security-response-drills",
        "pass" if stage_ok else "fail",
        "Generated and verified all required security response drills.",
        verify_all_result,
    )
    return summary_path

def run_fixture_certification(state: PipelineState, cert_out: Path) -> None:
    fixtures = state.settings.workspace_root / "tools/release-certification/fixtures"
    cert_out.mkdir(parents=True, exist_ok=True)
    network_summary = cert_out / "network-scale-soak/summary.json"
    app_summary = cert_out / "app-platform-smoke/summary.json"
    multi_node_summary = cert_out / "multi-node-beta-soak/summary.json"
    network_summary.parent.mkdir(parents=True, exist_ok=True)
    app_summary.parent.mkdir(parents=True, exist_ok=True)
    multi_node_summary.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(fixtures / "self-test-network-scale-soak.json", network_summary)
    shutil.copy(fixtures / "self-test-app-platform-smoke.json", app_summary)
    multi_node_config = multi_node_beta_soak.validate_config(
        multi_node_beta_soak.load_config(fixtures / "self-test-multi-node-beta-soak.json")
    )
    multi_node_value = multi_node_beta_soak.build_summary(
        multi_node_config,
        out_dir=multi_node_summary.parent,
        base_dir=fixtures,
    )
    write_json(multi_node_summary, multi_node_value)
    write_text(
        multi_node_summary.parent / multi_node_beta_soak.REPORT_FILE_NAME,
        multi_node_beta_soak.render_report(multi_node_value),
    )
    args = [
        sys.executable,
        str(state.settings.workspace_root / "tools/release-certification/cryptad_certification/engine_entry.py"),
        "release-certification",
        "--workspace-root",
        str(state.settings.workspace_root),
        "--out-dir",
        str(cert_out),
        "--mode",
        certification_mode(state.settings),
        "--interop-smoke-summary",
        str(fixtures / "self-test-interop-smoke.json"),
        "--perf-smoke-summary",
        str(fixtures / "self-test-perf-smoke.json"),
        "--app-platform-summary",
        str(app_summary),
        "--network-scale-soak-summary",
        str(network_summary),
        "--multi-node-soak-summary",
        str(multi_node_summary),
        "--security-drills-summary",
        str(security_drills_summary_path(state.settings)),
        "--skip-git-metadata",
    ]
    result = run_command(state, "release-certification-fixture", args, timeout_seconds=300, allow_failure=True)
    record_certification_result(state, result)

def record_certification_result(state: PipelineState, result: CommandResult) -> None:
    state.certification_exit_code = result.exit_code
    if result.exit_code != 0:
        state.failures.append(f"{result.name} failed with exit code {result.exit_code}")

def generated_multi_node_soak_config(state: PipelineState, cert_out: Path) -> Path | None:
    config_path = state.settings.multi_node_soak_config
    previous_summary = state.settings.previous_summary
    if not state.settings.run_multi_node_soak or config_path is None or previous_summary is None:
        return config_path
    raw_config = read_json(config_path)
    if raw_config is None:
        return config_path
    config = json.loads(json.dumps(raw_config, sort_keys=True))
    previous = config.get("previousCandidate")
    current = config.get("currentCandidate")
    if not isinstance(previous, dict) or not isinstance(current, dict):
        return config_path

    previous["summaryPath"] = str(previous_summary)
    previous_value = read_json(previous_summary)
    if multi_node_beta_soak.validate_previous_beta_candidate_summary(previous_value):
        return config_path
    previous_version = previous_value.get("version") if isinstance(previous_value, dict) else None
    if isinstance(previous_version, str) and previous_version.strip():
        previous["version"] = previous_version.strip()
    current["version"] = state.version

    generated_config = cert_out / "multi-node-beta-soak/production-beta-soak-config.json"
    write_json(generated_config, config)
    return generated_config


def effective_multi_node_mode(config_path: Path | None, override_mode: str | None) -> str | None:
    if override_mode is not None:
        return override_mode
    config = (
        read_json(config_path)
        if config_path is not None
        else multi_node_beta_soak.DEFAULT_CONFIG
    )
    mode = config.get("mode") if isinstance(config, dict) else None
    return mode if isinstance(mode, str) else None


def run_release_certification(state: PipelineState, env: dict[str, str], cert_out: Path) -> None:
    if state.settings.use_fixture_evidence:
        run_fixture_certification(state, cert_out)
        return
    multi_node_soak_config = generated_multi_node_soak_config(state, cert_out)
    app_platform_out = cert_out / "app-platform-smoke"
    app_platform_mode = certification_mode(state.settings)
    app_platform_args = [
        sys.executable,
        str(
            state.settings.workspace_root
            / "tools/release-certification/cryptad_certification/engine_entry.py"
        ),
        "app-platform",
        "--workspace-root",
        str(state.settings.workspace_root),
        "--out-dir",
        str(app_platform_out),
        "--mode",
        app_platform_mode,
    ]
    if app_platform_mode == "pr" or state.settings.skip_gradle:
        app_platform_args.append("--skip-gradle")
    app_platform_result = run_command(
        state,
        "app-platform-smoke",
        app_platform_args,
        env=env,
        timeout_seconds=max(state.settings.timeout_seconds, 1800),
        allow_failure=True,
    )
    live_network_out = cert_out / "live-network-beta-smoke"
    live_network_summary = state.settings.live_network_summary or live_network_out / "summary.json"
    live_network_result: CommandResult | None = None
    if state.settings.require_live_network and state.settings.live_network_summary is None:
        live_network_result = run_command(
            state,
            "live-network-beta-smoke",
            [
                sys.executable,
                str(
                    state.settings.workspace_root
                    / "tools/release-certification/cryptad_certification/engine_entry.py"
                ),
                "live-network-beta",
                "--workspace-root",
                str(state.settings.workspace_root),
                "--out-dir",
                str(live_network_out),
                "--mode",
                certification_mode(state.settings),
                "--require",
            ],
            env=env,
            timeout_seconds=max(state.settings.timeout_seconds, 1800),
            allow_failure=True,
        )
    network_scale_out = cert_out / "network-scale-soak"
    network_scale_summary = (
        state.settings.network_scale_soak_summary or network_scale_out / "summary.json"
    )
    if state.settings.network_scale_soak_summary is None:
        write_json(
            network_scale_summary,
            network_scale_soak.summary_for_release(security_drills_release_id(state)),
        )
    generated_multi_node_summary: Path | None = None
    if state.settings.run_multi_node_soak and state.settings.multi_node_soak_summary is None:
        multi_node_out = cert_out / "multi-node-beta-soak"
        multi_args = [
            sys.executable,
            str(
                state.settings.workspace_root
                / "tools/release-certification/cryptad_certification/engine_entry.py"
            ),
            "multi-node-beta",
            "run",
            "--out-dir",
            str(multi_node_out),
        ]
        if multi_node_soak_config is not None:
            multi_args.extend(["--config", str(multi_node_soak_config)])
        if state.settings.multi_node_mode is not None:
            multi_args.extend(["--mode", state.settings.multi_node_mode])
        if state.settings.require_multi_node_soak:
            multi_args.append("--require-all-scenarios")
            if (
                effective_multi_node_mode(
                    multi_node_soak_config,
                    state.settings.multi_node_mode,
                )
                == "live"
            ):
                multi_args.append("--require-live")
        run_command(
            state,
            "multi-node-beta-soak",
            multi_args,
            timeout_seconds=max(state.settings.timeout_seconds, 1800),
            allow_failure=True,
        )
        generated_multi_node_summary = multi_node_out / "summary.json"
    args = [
        sys.executable,
        str(state.settings.workspace_root / "tools/release-certification/cryptad_certification/engine_entry.py"),
        "release-certification",
        "--mode",
        certification_mode(state.settings),
        "--out-dir",
        str(cert_out),
        "--app-platform-summary",
        str(app_platform_out / "summary.json"),
        "--network-scale-soak-summary",
        str(network_scale_summary),
        "--live-network-summary",
        str(live_network_summary),
    ]
    external_inputs = {
        "--interop-smoke-summary": state.settings.interop_smoke_summary,
        "--interop-extended-summary": state.settings.interop_extended_summary,
        "--perf-smoke-summary": state.settings.performance_smoke_summary,
    }
    missing_inputs = cert_out / "missing-inputs"
    for option, path in external_inputs.items():
        args.extend([option, str(path or missing_inputs / f"{option.removeprefix('--')}.json")])
    if (
        state.settings.require_live_network
        or state.settings.live_network_summary is not None
    ):
        args.append("--live-network-beta")
    if state.settings.require_live_network:
        args.append("--require-live-network-beta")
    if state.settings.multi_node_soak_summary and not state.settings.run_multi_node_soak:
        args.extend(["--multi-node-soak-summary", str(state.settings.multi_node_soak_summary)])
    elif generated_multi_node_summary is not None:
        args.extend(["--multi-node-soak-summary", str(generated_multi_node_summary)])
    if state.settings.require_multi_node_soak:
        args.append("--require-multi-node-soak")
    args.extend(["--security-drills-summary", str(security_drills_summary_path(state.settings))])
    history_summary = previous_release_certification_summary_for_certification(state.settings)
    if state.settings.require_history:
        args.append("--require-history")
    if history_summary is not None:
        args.extend(["--previous-summary", str(history_summary)])
    if state.settings.waiver_file:
        args.extend(["--waiver-file", str(state.settings.waiver_file)])
    if state.settings.stable_vulnerability_summary is not None:
        args.extend(
            [
                "--stable-vulnerability-summary",
                str(state.settings.stable_vulnerability_summary),
            ]
        )
    if state.settings.require_stable_vulnerability:
        args.append("--require-stable-vulnerability")
    if (
        state.settings.stable_vulnerability_summary is not None
        or state.settings.require_stable_vulnerability
    ):
        if not state.settings.release_id:
            state.failures.append(
                "Stable vulnerability governance requires a candidate release identity."
            )
        else:
            args.extend(
                [
                    "--stable-vulnerability-candidate-release-id",
                    state.settings.release_id,
                    "--stable-vulnerability-candidate-build-version",
                    state.version,
                ]
            )
    stable_commit = state.settings.stable_governance_candidate_source_commit
    stable_ref = state.settings.stable_governance_candidate_source_ref
    if state.settings.stable_supply_chain_summary is not None:
        args.extend(
            [
                "--stable-supply-chain-summary",
                str(state.settings.stable_supply_chain_summary),
            ]
        )
    if state.settings.require_stable_supply_chain:
        args.append("--require-stable-supply-chain")
    if (
        state.settings.stable_supply_chain_summary is not None
        or state.settings.require_stable_supply_chain
    ):
        args.extend(
            [
                "--stable-supply-chain-candidate-release-id",
                str(state.settings.release_id or ""),
                "--stable-supply-chain-candidate-build-version",
                state.version,
                "--stable-supply-chain-candidate-source-commit",
                stable_commit,
                "--stable-supply-chain-candidate-source-ref",
                stable_ref,
            ]
        )
    if state.settings.stable_dependency_vulnerability_summary is not None:
        args.extend(
            [
                "--stable-dependency-vulnerability-summary",
                str(state.settings.stable_dependency_vulnerability_summary),
            ]
        )
    if state.settings.require_stable_dependency_vulnerability:
        args.append("--require-stable-dependency-vulnerability")
    if (
        state.settings.stable_dependency_vulnerability_summary is not None
        or state.settings.require_stable_dependency_vulnerability
    ):
        args.extend(
            [
                "--stable-dependency-vulnerability-candidate-release-id",
                str(state.settings.release_id or ""),
                "--stable-dependency-vulnerability-candidate-build-version",
                state.version,
                "--stable-dependency-vulnerability-candidate-source-commit",
                stable_commit,
                "--stable-dependency-vulnerability-candidate-source-ref",
                stable_ref,
                "--stable-dependency-vulnerability-evidence-phase",
                state.settings.stable_dependency_vulnerability_evidence_phase,
            ]
        )
    cert_env = dict(env)
    cert_env["CRYPTAD_CERT_NETWORK_SCALE_SOAK_RELEASE_ID"] = security_drills_release_id(state)
    if state.settings.run_multi_node_soak:
        cert_env["CRYPTAD_CERT_MULTI_NODE_SOAK_SUMMARY"] = ""
    result = run_command(
        state,
        "release-certification",
        args,
        env=cert_env,
        timeout_seconds=max(state.settings.timeout_seconds, 1800),
        allow_failure=True,
    )
    if app_platform_result.exit_code != 0:
        state.failures.append("app-platform-smoke failed before release certification")
    if live_network_result is not None and live_network_result.exit_code != 0:
        state.failures.append("live-network-beta-smoke failed before release certification")
    record_certification_result(state, result)

def read_json(path: Path) -> dict[str, Any] | None:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None

def evidence_by_id(summary: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not summary:
        return {}
    evidence = summary.get("evidence", [])
    if not isinstance(evidence, list):
        return {}
    return {str(item.get("id")): item for item in evidence if isinstance(item, dict)}

def contract_snapshot_payload_from_file(path: Path) -> dict[str, Any] | None:
    payload = read_json(path)
    if not isinstance(payload, dict):
        return None
    contract = contract_snapshot_contract(payload)
    if not is_platform_api_contract_snapshot_shape(contract):
        return None
    return {"contract": contract}

def contract_snapshot_contract(payload: dict[str, Any]) -> dict[str, Any] | None:
    contract = payload.get("contract")
    if isinstance(contract, dict):
        return contract
    return payload if "apiVersion" in payload and "contractVersion" in payload else None

def is_platform_api_contract_snapshot_shape(contract: dict[str, Any] | None) -> bool:
    if not isinstance(contract, dict):
        return False
    return (
        isinstance(contract.get("apiVersion"), str)
        and isinstance(contract.get("contractVersion"), int)
        and isinstance(contract.get("capabilities"), list)
        and isinstance(contract.get("endpoints"), list)
    )

def platform_api_contract_details(summary: dict[str, Any] | None) -> dict[str, Any]:
    item = evidence_by_id(summary).get("platform-api.contract")
    details = item.get("details") if isinstance(item, dict) else None
    return details if isinstance(details, dict) else {}

def platform_api_snapshot_from_evidence_details(details: dict[str, Any]) -> dict[str, Any] | None:
    stable_baseline = details.get("stableBaseline")
    if not isinstance(stable_baseline, dict):
        return None
    baseline_contract_version = parse_int_field(
        stable_baseline.get("contractVersion"),
        0,
        minimum=1,
    )
    contract_version = parse_int_field(
        details.get("contractVersion"),
        baseline_contract_version,
        minimum=1,
    )
    capabilities = sorted_unique_strings(stable_baseline.get("capabilities"))
    endpoints = sorted_unique_strings(stable_baseline.get("endpoints"))
    endpoint_capabilities = details.get("stableEndpointRequiredCapabilities")
    endpoint_access = details.get("stableEndpointAppAccess")
    endpoint_action_labels = stable_endpoint_action_label_map(
        details.get("stableEndpointActionLabels")
    )
    if (
        baseline_contract_version <= 0
        or contract_version <= 0
        or not capabilities
        or not endpoints
        or not isinstance(endpoint_capabilities, dict)
        or not isinstance(endpoint_access, dict)
    ):
        return None

    capability_descriptors = [
        {
            "name": capability,
            "stability": "stable",
            "sinceContractVersion": baseline_contract_version,
            "deprecation": None,
            "description": f"Stable Platform API 1.0 capability {capability}.",
        }
        for capability in capabilities
    ]
    endpoint_descriptors: list[dict[str, Any]] = []
    for identity in endpoints:
        descriptor = stable_endpoint_descriptor_from_evidence(
            identity,
            capabilities,
            endpoint_capabilities,
            endpoint_access,
            endpoint_action_labels,
            baseline_contract_version,
        )
        if descriptor is None:
            return None
        endpoint_descriptors.append(descriptor)

    contract: dict[str, Any] = {
        "apiVersion": str(details.get("apiVersion") or "v1"),
        "contractVersion": contract_version,
        "generatedBy": str(details.get("generatedBy") or "cryptad"),
        "stabilityPolicy": str(
            details.get("stabilityPolicy")
            or "Platform API 1.0 stable compatibility snapshot."
        ),
        "stableBaseline": {
            "name": str(stable_baseline.get("name") or "1.0"),
            "contractVersion": baseline_contract_version,
            "capabilityCount": len(capabilities),
            "endpointCount": len(endpoints),
            "capabilities": capabilities,
            "endpoints": endpoints,
        },
        "capabilities": capability_descriptors,
        "endpoints": endpoint_descriptors,
    }
    compatibility_window = details.get("compatibilityWindow")
    if isinstance(compatibility_window, dict):
        window_contract_version = parse_int_field(
            compatibility_window.get("currentContractVersion"),
            0,
            minimum=1,
        )
        if window_contract_version != contract_version:
            return None
        contract["compatibilityWindow"] = compatibility_window
    return {"contract": contract}

def sorted_unique_strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({str(item).strip() for item in value if str(item).strip()})

def stable_endpoint_descriptor_from_evidence(
    identity: str,
    capabilities: list[str],
    endpoint_capabilities: dict[str, Any],
    endpoint_access: dict[str, Any],
    endpoint_action_labels: dict[str, str],
    baseline_contract_version: int,
) -> dict[str, Any] | None:
    method_route = method_route_from_stable_endpoint_identity(identity)
    if method_route is None:
        return None
    method, route_template = method_route
    required_capabilities = sorted_unique_strings(endpoint_capabilities.get(identity))
    if not required_capabilities or any(
        capability not in capabilities for capability in required_capabilities
    ):
        return None
    access = endpoint_access.get(identity)
    if not isinstance(access, dict):
        return None
    app_process_allowed = access.get("appProcessPrincipalsAllowed")
    app_browser_allowed = access.get("appBrowserPrincipalsAllowed")
    if not isinstance(app_process_allowed, bool) or not isinstance(app_browser_allowed, bool):
        return None
    if not app_process_allowed and not app_browser_allowed:
        return None
    route_family = route_template.strip("/").split("/", 1)[0] or "platform"
    action_label = endpoint_action_labels.get(identity)
    if not action_label:
        return None
    return {
        "routeFamily": route_family,
        "method": method,
        "routeTemplate": route_template,
        "actionLabel": action_label,
        "requiredCapabilities": required_capabilities,
        "hostOperatorBypassAllowed": True,
        "appProcessPrincipalsAllowed": app_process_allowed,
        "appBrowserPrincipalsAllowed": app_browser_allowed,
        "stability": "stable",
        "sinceContractVersion": baseline_contract_version,
        "deprecation": None,
        "description": f"Stable Platform API 1.0 endpoint {identity}.",
    }

def method_route_from_stable_endpoint_identity(identity: str) -> tuple[str, str] | None:
    parts = str(identity).strip().split(" ", 1)
    if len(parts) != 2:
        return None
    method = parts[0].strip().upper()
    route_template = parts[1].strip()
    if not method or not route_template.startswith("/"):
        return None
    return method, route_template

def stable_endpoint_action_label_map(value: Any) -> dict[str, str]:
    labels: dict[str, str] = {}
    if isinstance(value, dict):
        labels.update(
            {
                str(identity): str(label).strip()
                for identity, label in value.items()
                if str(identity).strip() and str(label).strip()
            }
        )
    return labels

def third_party_intake_evidence(
    app_evidence: dict[str, dict[str, Any]],
    cert_evidence: dict[str, dict[str, Any]],
    intake_summary: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    evidence = {
        evidence_id: item
        for evidence_id in THIRD_PARTY_INTAKE_EVIDENCE_IDS
        if (item := app_evidence.get(evidence_id) or cert_evidence.get(evidence_id)) is not None
    }
    evidence.update(evidence_by_id(intake_summary))
    return evidence

def third_party_intake_required_evidence(
    intake_summary: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Return only evidence rows attached to the third-party intake summary.

    Required production promotion evidence must come from the attached intake summary, not from
    source-level smoke evidence with the same ids. Source-level rows are useful diagnostics, but
    they cannot fill omitted public-beta intake rows when --require-third-party-intake is active.
    """

    return evidence_by_id(intake_summary)

def summary_status(summary: dict[str, Any] | None) -> str:
    if not isinstance(summary, dict):
        return "missing"
    return str(summary.get("status", "missing")).strip().lower()

def third_party_intake_redaction_status(
    intake_summary: dict[str, Any] | None,
    evidence: dict[str, dict[str, Any]],
) -> str:
    redaction = intake_summary.get("redaction") if isinstance(intake_summary, dict) else None
    if isinstance(redaction, dict):
        return str(redaction.get("status", "missing")).strip().lower()
    item = evidence.get("third-party-intake.redaction")
    return str(item.get("status", "missing")).strip().lower() if isinstance(item, dict) else "missing"

def third_party_intake_summary_is_non_release(
    intake_summary: dict[str, Any] | None,
    *,
    stable_rc: bool = False,
) -> bool:
    """Classify intake evidence under its applicable production contract.

    Existing release-candidate and production-beta inputs explicitly classify only non-release
    and non-production state. Stable RC adds explicit fixture and simulation classifications,
    but that additive requirement must not reinterpret earlier production input contracts.
    """

    if not isinstance(intake_summary, dict):
        return False
    fields = ["nonRelease", "nonProduction"]
    if stable_rc:
        fields.extend(("fixtureOnly", "simulatedOnly"))
    return any(
        intake_summary.get(field) is not False
        for field in fields
    )

def multi_node_summary_path(settings: Settings, cert_out: Path) -> Path:
    if settings.multi_node_soak_summary is not None and not settings.run_multi_node_soak:
        return settings.multi_node_soak_summary
    return cert_out / "multi-node-beta-soak/summary.json"

def uses_self_test_multi_node_topology(settings: Settings) -> bool:
    config = settings.multi_node_soak_config
    if config is None:
        return False
    try:
        rel = config.resolve().relative_to(settings.workspace_root.resolve()).as_posix()
    except ValueError:
        rel = config.name
    return rel == "tools/release-certification/fixtures/self-test-multi-node-beta-soak.json"

def is_release_certification_history_summary(path: Path) -> bool:
    value = read_json(path)
    return isinstance(value, dict) and release_certification.previous_summary_contract_error(value) == ""

def previous_release_certification_summary_for_certification(settings: Settings) -> Path | None:
    if settings.previous_release_certification_summary is not None:
        return settings.previous_release_certification_summary
    if settings.previous_summary is not None and is_release_certification_history_summary(settings.previous_summary):
        return settings.previous_summary
    if settings.mode != "developer-dry-run":
        return default_release_certification_history_summary(settings)
    return None

def previous_release_certification_summary_for_artifacts(settings: Settings) -> Path | None:
    summary = previous_release_certification_summary_for_certification(settings)
    if summary is not None:
        return summary
    return default_release_certification_history_summary(settings)

def default_release_certification_history_summary(settings: Settings) -> Path | None:
    default_history_summary = settings.workspace_root / release_certification.DEFAULT_HISTORY_DIR / "latest-summary.json"
    return default_history_summary if default_history_summary.is_file() else None

def previous_candidate_summary_validation_errors(settings: Settings) -> list[str]:
    if settings.previous_summary is None:
        return ["previous beta candidate summary path is missing"]
    return multi_node_beta_soak.validate_previous_beta_candidate_summary(
        read_json(settings.previous_summary),
        production=settings.mode == "production-beta",
        max_age_days=90 if settings.mode == "production-beta" else None,
    )

def previous_release_history_binding_errors(previous_summary: Path, history_summary: Path) -> list[str]:
    return multi_node_beta_soak.previous_release_certification_history_binding_errors(
        read_json(previous_summary),
        read_json(history_summary),
        release_certification_digest=multi_node_beta_soak.sha256_path(history_summary),
    )

def previous_candidate_upgrade_binding_errors(
    compact: dict[str, Any],
    previous_summary: dict[str, Any] | None,
    current_version: str | None = None,
    current_catalog_channel: str | None = None,
    current_catalog_edition: int | None = None,
) -> list[str]:
    upgrade = compact.get("previousCandidateUpgrade")
    if not isinstance(upgrade, dict):
        return ["previousCandidateUpgrade is missing"]
    if not isinstance(previous_summary, dict):
        return ["previous beta candidate summary is missing or malformed"]
    errors: list[str] = []
    expected_release_id = previous_summary.get("releaseId")
    expected_version = previous_summary.get("version")
    if upgrade.get("previousReleaseId") != expected_release_id:
        errors.append("upgrade previousReleaseId does not match supplied previous summary releaseId")
    if upgrade.get("previousVersion") != expected_version:
        errors.append("upgrade previousVersion does not match supplied previous summary version")
    expected_drill_digest = multi_node_beta_soak.previous_candidate_drill_digest(previous_summary)
    if upgrade.get("previousSummaryDrillDigest") != expected_drill_digest:
        errors.append(
            "upgrade previousSummaryDrillDigest does not match supplied previous summary drill metadata"
        )
    if isinstance(current_version, str) and current_version.strip():
        if upgrade.get("currentVersion") != current_version.strip():
            errors.append("upgrade currentVersion does not match current release version")
    if isinstance(current_catalog_channel, str) and current_catalog_channel.strip():
        if upgrade.get("currentCatalogChannel") != current_catalog_channel.strip():
            errors.append("upgrade currentCatalogChannel does not match current catalog channel")
    if isinstance(current_catalog_edition, int) and not isinstance(current_catalog_edition, bool):
        upgrade_catalog_edition = upgrade.get("currentCatalogEdition")
        if (
            not isinstance(upgrade_catalog_edition, int)
            or isinstance(upgrade_catalog_edition, bool)
            or upgrade_catalog_edition != current_catalog_edition
        ):
            errors.append("upgrade currentCatalogEdition does not match current catalog edition")
    return errors

def previous_candidate_upgrade_ready(
    compact: dict[str, Any],
    previous_summary: dict[str, Any] | None,
    current_version: str | None = None,
    current_catalog_channel: str | None = None,
    current_catalog_edition: int | None = None,
) -> bool:
    upgrade = compact.get("previousCandidateUpgrade")
    if not isinstance(upgrade, dict):
        return False
    if upgrade.get("status") != "pass":
        return False
    if previous_candidate_upgrade_binding_errors(
        compact,
        previous_summary,
        current_version,
        current_catalog_channel,
        current_catalog_edition,
    ):
        return False
    expected = {
        "previousSummaryConfigured": True,
        "previousSummaryProvided": True,
        "previousSummaryValid": True,
        "currentUpgradePathRepresented": True,
        "rawDataIncluded": False,
        "firstPartyAppMigrationStatus": "pass",
        "backupBeforeUpdateStatus": "pass",
        "restoreIntoCleanNodeStatus": "pass",
        "socialInboxMigrationStatus": "pass",
        "trustGraphMigrationStatus": "pass",
        "supportBundleRedactionStatus": "pass",
        "rollbackStatus": "pass",
    }
    return all(upgrade.get(field) == expected_value for field, expected_value in expected.items())

def compact_multi_node_summary_for_release(summary: dict[str, Any] | None, *, strict: bool = False) -> dict[str, Any]:
    if not isinstance(summary, dict):
        return {"status": "missing"}
    compact = multi_node_beta_soak.compact_for_release(summary)
    validation_errors = multi_node_beta_soak.validate_summary(summary, strict=strict)
    if not validation_errors:
        return compact

    compact["status"] = "fail"
    compact["promotionReady"] = False
    compact["validationErrors"] = validation_errors
    blockers = compact.get("blockers", [])
    if not isinstance(blockers, list):
        blockers = []
    compact["blockers"] = sorted(set([*blockers, "multi-node beta soak summary validation failed"]))

    redaction = compact.get("redaction", {})
    if not isinstance(redaction, dict):
        redaction = {}
    redaction_findings = redaction.get("findings", [])
    if not isinstance(redaction_findings, list):
        redaction_findings = []
    validation_findings = release_certification.multi_node_validation_redaction_findings(validation_errors)
    if validation_findings:
        redaction["status"] = "fail"
        redaction["findings"] = [*redaction_findings, *validation_findings]
    compact["redaction"] = redaction
    return compact

def generated_at_from_summary(summary: dict[str, Any] | None) -> str:
    if not isinstance(summary, dict):
        return ""
    generated_at = summary.get("generatedAt")
    return generated_at.strip() if isinstance(generated_at, str) else ""

def stable_readiness_soak_summary(
    summary: dict[str, Any] | None,
    *,
    fallback_generated_at: str = "",
    release_id: str = "",
) -> dict[str, Any]:
    if not isinstance(summary, dict):
        return {"status": "missing"}
    stable_summary = dict(summary)
    if release_id:
        stable_summary["releaseId"] = release_id
    if fallback_generated_at and not generated_at_from_summary(stable_summary):
        stable_summary["generatedAt"] = fallback_generated_at
    return stable_summary

def third_party_intake_sample_summary() -> dict[str, Any]:
    """Return non-release deterministic evidence for exercising the intake release gates."""
    return {
        "schemaVersion": 1,
        "kind": "cryptad-third-party-intake-summary",
        "status": "pass",
        "required": True,
        "nonRelease": True,
        "nonProduction": True,
        "summary": "Deterministic third-party intake sample flow passed; not production promotion evidence.",
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
        "evidence": [
            {
                "id": evidence_id,
                "status": "pass",
                "summary": f"{evidence_id} passed in the non-production intake sample flow.",
                "details": {"nonRelease": True},
            }
            for evidence_id in THIRD_PARTY_INTAKE_EVIDENCE_IDS
        ],
    }

def read_third_party_intake_summary(settings: Settings) -> dict[str, Any] | None:
    if settings.third_party_intake_summary is not None:
        value = read_json(settings.third_party_intake_summary)
        return value if isinstance(value, dict) else {"status": "fail", "error": "summary is not a JSON object"}
    if settings.run_third_party_intake_sample_flow:
        return third_party_intake_sample_summary()
    return None

def write_platform_api_contract_snapshot_artifacts(
    settings: Settings,
    cert_out: Path,
    app_summary: dict[str, Any] | None,
    evidence_dir: Path,
) -> None:
    current_snapshot = contract_snapshot_payload_from_file(
        cert_out / "app-platform-smoke/artifacts/platform-api-contract.json"
    )
    if current_snapshot is None:
        current_snapshot = platform_api_snapshot_from_evidence_details(
            platform_api_contract_details(app_summary)
        )
    if current_snapshot is None:
        current_snapshot = missing_platform_api_snapshot(
            "current",
            "Current Platform API contract snapshot was not generated by app-platform smoke.",
        )
    write_json(evidence_dir / "platform-api-contract-current.json", current_snapshot)

    previous_summary_path = previous_release_certification_summary_for_artifacts(settings)
    previous_summary = read_json(previous_summary_path) if previous_summary_path is not None else None
    previous_snapshot = platform_api_snapshot_from_evidence_details(
        platform_api_contract_details(previous_summary),
    )
    if previous_snapshot is None:
        previous_snapshot = missing_platform_api_snapshot(
            "previous",
            "Previous Platform API contract snapshot requires release-certification history "
            "with platform-api.contract details.",
        )
    write_json(evidence_dir / "platform-api-contract-previous.json", previous_snapshot)

def missing_platform_api_snapshot(which: str, summary: str) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "redacted": True,
        "status": "missing",
        "snapshot": which,
        "summary": summary,
    }

def write_evidence_extracts(settings: Settings, cert_out: Path) -> dict[str, Any]:
    app_summary_path = cert_out / "app-platform-smoke/summary.json"
    live_summary_path = (
        settings.live_network_summary
        or cert_out / "live-network-beta-smoke/summary.json"
    )
    network_summary_path = (
        settings.network_scale_soak_summary
        or cert_out / "network-scale-soak/summary.json"
    )
    resolved_multi_node_summary_path = multi_node_summary_path(settings, cert_out)
    cert_summary_path = cert_out / release_certification.SUMMARY_FILE_NAME
    matrix_path = cert_out / release_certification.ECOSYSTEM_MATRIX_FILE_NAME
    security_drills_path = security_drills_summary_path(settings)
    app_summary = read_json(app_summary_path)
    live_summary = read_json(live_summary_path)
    network_summary = read_json(network_summary_path)
    multi_node_summary = read_json(resolved_multi_node_summary_path)
    cert_summary = read_json(cert_summary_path)
    matrix_summary = read_json(matrix_path)
    security_drills_summary = read_json(security_drills_path)
    third_party_intake_summary = read_third_party_intake_summary(settings)

    evidence_dir = settings.out_dir / "evidence"
    write_json(evidence_dir / "app-platform-smoke.json", app_summary or {"status": "missing"})
    write_json(evidence_dir / "live-network-beta-smoke.json", live_summary or {"status": "missing", "enabled": False})
    write_json(evidence_dir / "network-scale-soak.json", network_summary or {"status": "missing"})
    write_json(
        evidence_dir / "multi-node-beta-soak.json",
        compact_multi_node_summary_for_release(
            multi_node_summary,
            strict=settings.mode == "production-beta" and settings.require_multi_node_soak,
        ),
    )
    write_json(
        stable_readiness_multi_node_soak_path(settings),
        stable_readiness_soak_summary(
            multi_node_summary,
            release_id=(settings.release_id or "") if settings.run_multi_node_soak else "",
        ),
    )
    write_json(
        stable_readiness_network_scale_soak_path(settings),
        stable_readiness_soak_summary(
            network_summary,
            fallback_generated_at=generated_at_from_summary(cert_summary),
        ),
    )
    write_json(evidence_dir / "ecosystem-rc-certification.json", cert_summary or {"status": "missing"})
    write_json(evidence_dir / "ecosystem-certification-matrix.json", matrix_summary or {"status": "missing"})
    write_json(evidence_dir / "security-drills-summary.json", security_drills_summary or {"status": "missing"})
    write_json(
        evidence_dir / "third-party-intake-summary.json",
        third_party_intake_summary or {"status": "missing", "required": settings.require_third_party_intake},
    )

    app_evidence = evidence_by_id(app_summary)
    platform_api_evidence_ids = (
        "platform-api.contract",
        "platform-api.stable-baseline",
        "platform-api.stable-breaking-change-check",
        "platform-api.compatibility-window",
        "platform-api.previous-contract-snapshot",
        "platform-api.deprecation-window-policy",
        "platform-api.experimental-graduation-policy",
        "platform-api.manifest-target-stability",
        "platform-api.first-party-stability-declarations",
        "platform-api.stable-reference-docs",
        "third-party-developer.compatibility-window",
    )
    platform_api_evidence = [
        app_evidence.get(evidence_id, {"id": evidence_id, "status": "missing"})
        for evidence_id in platform_api_evidence_ids
    ]
    write_json(
        evidence_dir / "api-compatibility.json",
        {
            "schemaVersion": 1,
            "redacted": True,
            "evidence": platform_api_evidence,
        },
    )
    write_platform_api_contract_snapshot_artifacts(
        settings,
        cert_out,
        app_summary,
        evidence_dir,
    )
    history_comparison = (
        cert_summary.get("historyComparison", {})
        if isinstance(cert_summary, dict) and isinstance(cert_summary.get("historyComparison"), dict)
        else {}
    )
    ecosystem_gates = (
        cert_summary.get("ecosystemGates", []) if isinstance(cert_summary, dict) else []
    )
    if not isinstance(ecosystem_gates, list):
        ecosystem_gates = []
    platform_api_gate = next(
        (
            gate
            for gate in ecosystem_gates
            if isinstance(gate, dict)
            and gate.get("id") == "ecosystem.platform-api-compatibility"
        ),
        {"status": "missing"},
    )
    write_json(
        evidence_dir / "platform-api-stable-diff.json",
        {
            "schemaVersion": 1,
            "redacted": True,
            "gate": platform_api_gate,
            "historyComparisonStatus": history_comparison.get("status", "missing"),
        },
    )
    write_json(evidence_dir / "app-ui-lint.json", app_evidence.get("app-ui.lint", {"status": "missing"}))
    write_json(evidence_dir / "sandbox-provider-tests.json", app_evidence.get("apphost.sandbox-provider", {"status": "missing"}))
    return {
        "appPlatform": app_summary,
        "liveNetwork": live_summary,
        "networkScale": network_summary,
        "multiNodeBetaSoak": multi_node_summary,
        "certification": cert_summary,
        "matrix": matrix_summary,
        "securityDrills": security_drills_summary,
        "thirdPartyIntake": third_party_intake_summary,
    }

def status_ok(status: str) -> bool:
    return status == "pass"

def evidence_details(item: dict[str, Any]) -> dict[str, Any]:
    details = item.get("details")
    return details if isinstance(details, dict) else {}

def nested_evidence_details(parent_details: dict[str, Any], key: str) -> dict[str, Any]:
    nested_item = parent_details.get(key)
    if isinstance(nested_item, dict):
        nested_details = nested_item.get("details")
        if isinstance(nested_details, dict):
            return nested_details
    return parent_details

def evidence_has_unwaivable_redaction_findings(item: dict[str, Any]) -> bool:
    redaction_findings = evidence_details(item).get("redactionFindings")
    return isinstance(redaction_findings, list) and bool(redaction_findings)

def evidence_status_ok(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    status = str(item.get("status", ""))
    if evidence_has_unwaivable_redaction_findings(item):
        return False
    if status_ok(status):
        return True
    return status == "warn" and evidence_details(item).get("waived") is True

def legacy_admin_final_surface_summary(all_evidence: dict[str, Any]) -> dict[str, Any]:
    wave_five = all_evidence.get("legacy-admin.removal-wave-5")
    final_surface = all_evidence.get("legacy-admin.final-admin-surface")
    browse = all_evidence.get("legacy-admin.browse-retained")
    emergency = all_evidence.get("legacy-admin.emergency-fallback-retained")
    wave_five_details = evidence_details(wave_five) if isinstance(wave_five, dict) else {}
    final_details = evidence_details(final_surface) if isinstance(final_surface, dict) else {}
    return {
        "removalWave5Status": wave_five.get("status") if isinstance(wave_five, dict) else "missing",
        "finalAdminSurfaceStatus": final_surface.get("status")
        if isinstance(final_surface, dict)
        else "missing",
        "browseRetainedStatus": browse.get("status") if isinstance(browse, dict) else "missing",
        "emergencyFallbackStatus": emergency.get("status")
        if isinstance(emergency, dict)
        else "missing",
        "waveFivePromotedRouteIds": wave_five_details.get("waveFivePromotedRouteIds", []),
        "finalSurfaceCategories": sorted(final_details.get("categories", {}).keys())
        if isinstance(final_details.get("categories"), dict)
        else [],
    }

def production_security_response_summary(all_evidence: dict[str, Any]) -> dict[str, Any]:
    item = all_evidence.get("production-security.response-runbook")
    if not isinstance(item, dict):
        return {
            "status": "missing",
            "runbookStatus": "missing",
            "advisoryLifecycleStatus": "missing",
            "reviewerCompromiseDrillStatus": "missing",
            "catalogKeyRotationDrillStatus": "missing",
            "appSigningKeyCompromiseDrillStatus": "missing",
            "emergencyCatalogUpdateDrillStatus": "missing",
            "supportRedactionStatus": "missing",
            "securityReleaseNotesTemplateStatus": "missing",
            "blockers": ["production-security.response-runbook evidence is missing."],
            "warnings": [],
        }
    details = evidence_details(item)
    app_runbook_item = (
        details.get("appPlatformRunbook")
        if isinstance(details.get("appPlatformRunbook"), dict)
        else item
    )
    app_runbook_details = nested_evidence_details(details, "appPlatformRunbook")
    drill_details = nested_evidence_details(details, "securityDrills")
    checks = (
        app_runbook_details.get("checks")
        if isinstance(app_runbook_details.get("checks"), dict)
        else {}
    )
    drill_ids = set(
        app_runbook_details.get("drillIds")
        if isinstance(app_runbook_details.get("drillIds"), list)
        else []
    )
    passed_scenarios = set(
        str(value) for value in drill_details.get("passedScenarios", []) if isinstance(value, str)
    ) if isinstance(drill_details.get("passedScenarios"), list) else set()
    failed_scenarios = [
        str(value) for value in drill_details.get("failedScenarios", []) if isinstance(value, str)
    ] if isinstance(drill_details.get("failedScenarios"), list) else []
    missing_scenarios = [
        str(value) for value in drill_details.get("missingScenarios", []) if isinstance(value, str)
    ] if isinstance(drill_details.get("missingScenarios"), list) else []
    stale_scenarios = [
        str(value) for value in drill_details.get("staleScenarios", []) if isinstance(value, str)
    ] if isinstance(drill_details.get("staleScenarios"), list) else []
    malformed_scenarios = [
        str(value) for value in drill_details.get("malformedScenarios", []) if isinstance(value, str)
    ] if isinstance(drill_details.get("malformedScenarios"), list) else []
    counts = drill_details.get("counts") if isinstance(drill_details.get("counts"), dict) else {}
    redaction = (
        drill_details.get("redaction")
        if isinstance(drill_details.get("redaction"), dict)
        else {}
    )
    release_notes = (
        drill_details.get("releaseNotes")
        if isinstance(drill_details.get("releaseNotes"), dict)
        else {}
    )
    item_ok = evidence_status_ok(item)
    app_runbook_ok = evidence_status_ok(app_runbook_item)
    app_runbook_status = str(app_runbook_item.get("status", item.get("status", "missing")))

    def check_status(key: str) -> str:
        if not checks:
            return "pass" if app_runbook_ok else app_runbook_status
        if checks.get(key) is True:
            return "pass"
        return "fail" if app_runbook_status == "fail" else "missing"

    def drill_status(drill_id: str) -> str:
        if drill_id in failed_scenarios or drill_id in malformed_scenarios:
            return "fail"
        if drill_id in stale_scenarios:
            return "stale"
        if drill_id in missing_scenarios:
            return "missing"
        if drill_id in passed_scenarios:
            return "pass"
        if not drill_ids:
            return "pass" if item_ok else "missing"
        return "pass" if drill_id in drill_ids else "missing"

    blockers: list[str] = []
    if not item_ok:
        blockers.append(str(item.get("summary", "Security response runbook evidence is not passing.")))
    blockers.extend(f"Security response drill failed: {scenario}" for scenario in failed_scenarios)
    blockers.extend(f"Security response drill missing: {scenario}" for scenario in missing_scenarios)
    blockers.extend(f"Security response drill stale: {scenario}" for scenario in stale_scenarios)
    blockers.extend(f"Security response drill malformed: {scenario}" for scenario in malformed_scenarios)
    errors = details.get("errors")
    warnings = [str(error) for error in errors] if isinstance(errors, list) else []
    app_errors = app_runbook_details.get("errors")
    if isinstance(app_errors, list):
        warnings.extend(str(error) for error in app_errors)
    validation_errors = drill_details.get("validationErrors")
    if isinstance(validation_errors, list):
        warnings.extend(str(error) for error in validation_errors)
    return {
        "status": str(item.get("status", "missing")),
        "runbookStatus": check_status("runbookDocExists"),
        "advisoryLifecycleStatus": check_status("advisoryLifecycleTestable"),
        "reviewerCompromiseDrillStatus": drill_status("reviewer-key-compromise"),
        "catalogKeyRotationDrillStatus": drill_status("catalog-signing-key-rotation"),
        "appSigningKeyCompromiseDrillStatus": drill_status("app-signing-key-compromise"),
        "vulnerableAppVersionDrillStatus": drill_status("vulnerable-app-version"),
        "maliciousCatalogEntryDrillStatus": drill_status("malicious-catalog-entry"),
        "emergencyCatalogUpdateDrillStatus": drill_status("emergency-replacement-app"),
        "supportRedactionStatus": (
            drill_status("support-bundle-intake-redaction")
            if counts
            else check_status("supportRedactionDrill")
        ),
        "securityReleaseNotesTemplateStatus": (
            str(release_notes.get("templateStatus", "missing")) if release_notes else check_status("releaseNotesTemplate")
        ),
        "redactionStatus": str(redaction.get("status", "missing")) if redaction else "missing",
        "promotionReady": bool(drill_details.get("promotionReady", details.get("promotionReady", item_ok))),
        "nonRelease": bool(drill_details.get("nonRelease", details.get("nonRelease", False))),
        "fixtureOnly": bool(drill_details.get("fixtureOnly", details.get("fixtureOnly", False))),
        "counts": counts,
        "requiredScenarios": drill_details.get("requiredScenarios", []),
        "passedScenarios": sorted(passed_scenarios),
        "failedScenarios": failed_scenarios,
        "missingScenarios": missing_scenarios,
        "staleScenarios": stale_scenarios,
        "malformedScenarios": malformed_scenarios,
        "blockers": blockers,
        "warnings": warnings,
    }

def developer_beta_program_summary(all_evidence: dict[str, Any]) -> dict[str, Any]:
    status_by_id = {
        evidence_id: str(all_evidence.get(evidence_id, {}).get("status", "missing"))
        if isinstance(all_evidence.get(evidence_id), dict)
        else "missing"
        for evidence_id in THIRD_PARTY_DEVELOPER_BETA_EVIDENCE_IDS
    }

    def status_for(*evidence_ids: str) -> str:
        values = [status_by_id[evidence_id] for evidence_id in evidence_ids]
        if any(value in {"fail", "missing"} for value in values):
            return "fail" if "fail" in values else "missing"
        if any(value in {"warn", "skip"} for value in values):
            return "warn"
        return "pass"

    blockers = [
        str(item.get("summary", f"{evidence_id} is not passing."))
        for evidence_id in THIRD_PARTY_DEVELOPER_BETA_EVIDENCE_IDS
        if isinstance((item := all_evidence.get(evidence_id)), dict)
        and not evidence_status_ok(item)
    ]
    missing = [
        evidence_id
        for evidence_id in THIRD_PARTY_DEVELOPER_BETA_EVIDENCE_IDS
        if not isinstance(all_evidence.get(evidence_id), dict)
    ]
    warnings: list[str] = []
    for evidence_id in THIRD_PARTY_DEVELOPER_BETA_EVIDENCE_IDS:
        item = all_evidence.get(evidence_id)
        if not isinstance(item, dict):
            continue
        details = evidence_details(item)
        errors = details.get("errors")
        if isinstance(errors, list):
            warnings.extend(str(error) for error in errors)
    if missing:
        blockers.extend(f"{evidence_id} evidence is missing." for evidence_id in missing)
    return {
        "status": status_for(*THIRD_PARTY_DEVELOPER_BETA_EVIDENCE_IDS),
        "sampleAppFlow": status_for("third-party-developer.sample-app-flow"),
        "docs": status_for(
            "third-party-developer.beta-program",
            "third-party-developer.docs",
        ),
        "submissionChecklist": status_for("third-party-developer.submission-checklist"),
        "compatibilityWindow": status_for("third-party-developer.compatibility-window"),
        "feedbackWorkflow": status_for("third-party-developer.feedback-workflow"),
        "template": status_for("third-party-developer.template"),
        "pluginAuthorMigration": status_for("third-party-developer.plugin-author-migration"),
        "redaction": status_for("third-party-developer.redaction"),
        "blockers": blockers,
        "warnings": warnings,
    }

def public_beta_docs_summary(all_evidence: dict[str, Any]) -> dict[str, Any]:
    status_by_id = {
        evidence_id: str(all_evidence.get(evidence_id, {}).get("status", "missing"))
        if isinstance(all_evidence.get(evidence_id), dict)
        else "missing"
        for evidence_id in PUBLIC_BETA_ONBOARDING_EVIDENCE_IDS
    }

    def status_for(*evidence_ids: str) -> str:
        values = [status_by_id[evidence_id] for evidence_id in evidence_ids]
        if any(value in {"fail", "missing"} for value in values):
            return "fail" if "fail" in values else "missing"
        if any(value in {"warn", "skip"} for value in values):
            return "warn"
        return "pass"

    blockers = [
        str(item.get("summary", f"{evidence_id} is not passing."))
        for evidence_id in PUBLIC_BETA_ONBOARDING_EVIDENCE_IDS
        if isinstance((item := all_evidence.get(evidence_id)), dict)
        and not evidence_status_ok(item)
    ]
    missing = [
        evidence_id
        for evidence_id in PUBLIC_BETA_ONBOARDING_EVIDENCE_IDS
        if not isinstance(all_evidence.get(evidence_id), dict)
    ]
    warnings: list[str] = []
    for evidence_id in PUBLIC_BETA_ONBOARDING_EVIDENCE_IDS:
        item = all_evidence.get(evidence_id)
        if not isinstance(item, dict):
            continue
        details = evidence_details(item)
        errors = details.get("errors")
        if isinstance(errors, list):
            warnings.extend(str(error) for error in errors)
    if missing:
        blockers.extend(f"{evidence_id} evidence is missing." for evidence_id in missing)
    return {
        "status": status_for(*PUBLIC_BETA_ONBOARDING_EVIDENCE_IDS),
        "docsOnboarding": status_for("public-beta.docs-onboarding"),
        "userGuide": status_for("public-beta.user-guide"),
        "developerQuickstart": status_for("public-beta.developer-quickstart"),
        "troubleshooting": status_for("public-beta.troubleshooting"),
        "securityReporting": status_for("public-beta.security-reporting"),
        "limitations": status_for("public-beta.limitations"),
        "linksRedaction": status_for("public-beta.links-redaction"),
        "blockers": blockers,
        "warnings": warnings,
    }

def public_beta_support_feedback_summary(all_evidence: dict[str, Any]) -> dict[str, Any]:
    def effective_status(evidence_id: str) -> str:
        item = all_evidence.get(evidence_id)
        if not isinstance(item, dict):
            return "missing"
        if evidence_has_unwaivable_redaction_findings(item):
            return "fail"
        return str(item.get("status", "missing"))

    status_by_id = {
        evidence_id: effective_status(evidence_id)
        for evidence_id in PUBLIC_BETA_SUPPORT_FEEDBACK_EVIDENCE_IDS
    }

    def status_for(*evidence_ids: str) -> str:
        values = [status_by_id[evidence_id] for evidence_id in evidence_ids]
        if any(value in {"fail", "missing"} for value in values):
            return "fail" if "fail" in values else "missing"
        if any(value in {"warn", "skip"} for value in values):
            return "warn"
        return "pass"

    blockers: list[str] = []
    for evidence_id in PUBLIC_BETA_SUPPORT_FEEDBACK_EVIDENCE_IDS:
        item = all_evidence.get(evidence_id)
        if not isinstance(item, dict) or evidence_status_ok(item):
            continue
        if evidence_has_unwaivable_redaction_findings(item):
            blockers.append(f"{evidence_id} evidence has redaction findings.")
        else:
            blockers.append(str(item.get("summary", f"{evidence_id} is not passing.")))
    missing = [
        evidence_id
        for evidence_id in PUBLIC_BETA_SUPPORT_FEEDBACK_EVIDENCE_IDS
        if not isinstance(all_evidence.get(evidence_id), dict)
    ]
    warnings: list[str] = []
    for evidence_id in PUBLIC_BETA_SUPPORT_FEEDBACK_EVIDENCE_IDS:
        item = all_evidence.get(evidence_id)
        if not isinstance(item, dict):
            continue
        details = evidence_details(item)
        errors = details.get("errors")
        if isinstance(errors, list):
            warnings.extend(str(error) for error in errors)
    if missing:
        blockers.extend(f"{evidence_id} evidence is missing." for evidence_id in missing)
    return {
        "status": status_for(*PUBLIC_BETA_SUPPORT_FEEDBACK_EVIDENCE_IDS),
        "docs": status_for("public-beta.support-feedback-docs"),
        "issueTemplates": status_for("public-beta.issue-templates"),
        "triageTaxonomy": status_for("public-beta.triage-taxonomy"),
        "knownIssuesTracker": status_for("public-beta.known-issues-tracker"),
        "feedbackToBacklog": status_for("public-beta.feedback-to-backlog"),
        "releaseNotesTemplate": status_for("public-beta.release-notes-template"),
        "supportBundleGuidance": status_for("public-beta.support-bundle-guidance"),
        "securityHandoff": status_for("public-beta.security-reporting-handoff"),
        "appSpecificFeedback": status_for("public-beta.app-specific-feedback"),
        "catalogIncidentFeedback": status_for("public-beta.catalog-incident-feedback"),
        "redactionFixtures": status_for("public-beta.redaction-fixtures"),
        "blockers": blockers,
        "warnings": warnings,
    }
