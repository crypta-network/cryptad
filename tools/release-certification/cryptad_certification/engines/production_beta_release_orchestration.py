"""Implementation segment for the orchestration portion of ``production_beta_release.py``."""

from __future__ import annotations

def release_exit_code(settings: Settings, summary: dict[str, Any]) -> int:
    go_no_go = summary.get("goNoGo") if isinstance(summary.get("goNoGo"), dict) else {}
    decision = go_no_go.get("decision")
    if settings.mode == "production-beta" and decision in {"go", "go-with-waivers", "no-go"}:
        if decision == "no-go":
            return 1
        return 0 if summary.get("status") == "pass" and summary.get("promotionReady") is True and summary.get("nonRelease") is False else 1
    if settings.mode == "developer-dry-run":
        return 0 if summary.get("status") == "pass" else 1
    return 0 if summary.get("status") == "pass" and (settings.mode != "production-beta" or summary.get("promotionReady") is True) else 1

def dashboard_args(
    settings: Settings,
    stable_readiness_summary: Path | None = None,
    require_stable_readiness: bool = False,
) -> list[str]:
    args = [
        sys.executable,
        str(TOOL_DIR / "cryptad_certification/engine_entry.py"),
        "go-no-go",
        "build",
        "--workspace-root",
        str(settings.workspace_root),
        "--out-dir",
        str(settings.out_dir / "reports"),
        "--mode",
        settings.mode,
        "--production-beta-summary",
        str(settings.out_dir / "reports/production-beta-summary.json"),
        "--release-certification-summary",
        str(settings.out_dir / "evidence/ecosystem-rc-certification.json"),
        "--ecosystem-matrix",
        str(settings.out_dir / "evidence/ecosystem-certification-matrix.json"),
        "--app-platform-summary",
        str(settings.out_dir / "evidence/app-platform-smoke.json"),
        "--live-network-summary",
        str(settings.out_dir / "evidence/live-network-beta-smoke.json"),
        "--network-scale-soak-summary",
        str(settings.out_dir / "evidence/network-scale-soak.json"),
        "--multi-node-beta-soak-summary",
        str(settings.out_dir / "evidence/multi-node-beta-soak.json"),
        "--security-drills-summary",
        str(security_drills_summary_path(settings)),
    ]
    if settings.waiver_file:
        args.extend(["--waivers", str(settings.waiver_file)])
    if stable_readiness_summary is not None:
        args.extend(["--stable-readiness-summary", str(stable_readiness_summary)])
    if require_stable_readiness:
        args.append("--require-stable-readiness")
    return args

def assert_dashboard_args_use_security_drill_artifact_directory() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-dashboard-drills-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, out_dir),
            mode="production-beta",
        )
        args = dashboard_args(settings)
        summary_index = args.index("--security-drills-summary") + 1
        summary_path = Path(args[summary_index])
        assert summary_path == security_drills_summary_path(settings), args
        assert summary_path.parent == security_drills_dir(settings), args
        assert summary_path != settings.out_dir / "evidence/security-drills-summary.json", args

def clear_stale_go_no_go_dashboard_artifacts(out_dir: Path) -> list[str]:
    failures: list[str] = []
    for artifact in (
        GO_NO_GO_DASHBOARD_JSON,
        GO_NO_GO_DASHBOARD_MARKDOWN,
        GO_NO_GO_REDACTION_REPORT,
    ):
        path = out_dir / artifact
        try:
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink()
        except FileNotFoundError:
            continue
        except OSError as exc:
            failures.append(f"Could not remove stale go/no-go dashboard artifact {artifact}: {exc}")
    return failures

def go_no_go_dashboard_artifact_failure(
    settings: Settings,
    dashboard: dict[str, Any] | None,
    result: CommandResult,
    stale_clear_failures: list[str],
) -> str | None:
    if stale_clear_failures:
        return "Go/no-go dashboard could not safely clear stale artifacts before regeneration."
    if dashboard is None:
        if result.exit_code != 0:
            return f"Go/no-go dashboard failed with exit code {result.exit_code} before producing a readable JSON artifact."
        return "Go/no-go dashboard did not generate a readable JSON artifact."

    missing_artifacts: list[str] = []
    if not (settings.out_dir / GO_NO_GO_DASHBOARD_MARKDOWN).is_file():
        missing_artifacts.append(GO_NO_GO_DASHBOARD_MARKDOWN)
    redaction_report = read_json(settings.out_dir / GO_NO_GO_REDACTION_REPORT)
    if redaction_report is None:
        missing_artifacts.append(GO_NO_GO_REDACTION_REPORT)
    if missing_artifacts:
        return "Go/no-go dashboard did not generate a complete artifact set: " + ", ".join(missing_artifacts)

    redaction_status = str(redaction_report.get("status", "missing"))
    if redaction_status != "pass":
        return f"Go/no-go dashboard redaction report status is {redaction_status}; dashboard artifacts require pass."
    dashboard_redaction = dashboard.get("redaction")
    dashboard_redaction_status = (
        str(dashboard_redaction.get("status", "missing")) if isinstance(dashboard_redaction, dict) else "missing"
    )
    if dashboard_redaction_status != "pass":
        return f"Go/no-go dashboard redaction status is {dashboard_redaction_status}; dashboard artifacts require pass."
    decision = str(dashboard.get("decision", "no-go"))
    if decision not in {"go", "go-with-waivers"}:
        return None
    if result.exit_code != 0:
        return f"Go/no-go dashboard returned launchable decision but exited with code {result.exit_code}."
    return None

def write_rejected_launchable_dashboard_artifacts(
    settings: Settings,
    dashboard: dict[str, Any],
    failure: str,
) -> dict[str, Any]:
    redaction = dashboard.get("redaction") if isinstance(dashboard.get("redaction"), dict) else {}
    overridden = dict(dashboard)
    blocker = {
        "id": "production-beta.wrapper.rejected-launchable-dashboard",
        "evidenceId": "production-beta.go-no-go-decision",
        "domainId": "production-beta-release-pipeline",
        "severity": "blocker",
        "title": "Release wrapper rejected launchable dashboard decision",
        "summary": failure,
        "source": "production-beta-release",
        "waivable": False,
        "category": "pipeline",
    }
    blockers = [item for item in overridden.get("blockers", []) if isinstance(item, dict)]
    if not any(item.get("id") == blocker["id"] for item in blockers):
        blockers.append(blocker)
    dashboard_summary = overridden.get("summary") if isinstance(overridden.get("summary"), dict) else {}
    dashboard_summary = dict(dashboard_summary)
    dashboard_summary["blockers"] = max(int(dashboard_summary.get("blockers", 0)), len(blockers))
    dashboard_summary.setdefault("warnings", 0)
    dashboard_summary.setdefault("waiversUsed", 0)
    dashboard_summary.setdefault("criticalRedactionFindings", 0)
    overridden.update(
        {
            "decision": "no-go",
            "promotionReady": False,
            "summary": dashboard_summary,
            "blockers": blockers,
            "redaction": redaction,
            "recommendation": "Do not launch. Regenerate the dashboard after the production summary is promotion-ready.",
        }
    )
    write_json(settings.out_dir / GO_NO_GO_DASHBOARD_JSON, overridden)
    write_text(
        settings.out_dir / GO_NO_GO_DASHBOARD_MARKDOWN,
        "\n".join(
            [
                "# Production Beta Go/No-Go Dashboard",
                "",
                "Decision: `NO-GO`",
                "",
                "The production beta release wrapper rejected a launchable dashboard decision.",
                "",
                f"- Failure: {failure}",
                f"- Mode: `{settings.mode}`",
                "",
            ]
        ),
    )
    return overridden

def attach_go_no_go_dashboard(
    state: PipelineState,
    summary: dict[str, Any],
    stable_readiness_summary: Path | None = None,
    require_stable_readiness: bool = False,
) -> dict[str, Any]:
    stale_clear_failures = clear_stale_go_no_go_dashboard_artifacts(state.settings.out_dir)
    for failure in stale_clear_failures:
        if failure not in state.failures:
            state.failures.append(failure)
    result = run_command(
        state,
        "production-beta-go-no-go-dashboard",
        dashboard_args(
            state.settings,
            stable_readiness_summary,
            require_stable_readiness,
        ),
        timeout_seconds=120,
        allow_failure=True,
    )
    dashboard_path = state.settings.out_dir / GO_NO_GO_DASHBOARD_JSON
    dashboard = None if stale_clear_failures else read_json(dashboard_path)
    dashboard_failure = go_no_go_dashboard_artifact_failure(state.settings, dashboard, result, stale_clear_failures)
    dashboard_missing = dashboard_failure is not None
    if dashboard_missing:
        if dashboard_failure not in state.failures:
            state.failures.append(dashboard_failure)
        redaction_path = state.settings.out_dir / GO_NO_GO_REDACTION_REPORT
        existing_redaction = read_json(redaction_path)
        fallback_redaction = (
            existing_redaction
            if existing_redaction is not None
            else {
                "schemaVersion": SCHEMA_VERSION,
                "status": "missing",
                "findingCount": 0,
                "criticalFindingCount": 0,
                "findings": [],
            }
        )
        dashboard = {
            "decision": "no-go",
            "promotionReady": False,
            "summary": {"blockers": 1, "warnings": 0, "waiversUsed": 0, "criticalRedactionFindings": 0},
            "blockers": [
                {
                    "id": "production-beta.go-no-go-dashboard.missing",
                    "evidenceId": "production-beta.go-no-go-dashboard",
                    "severity": "blocker",
                    "summary": dashboard_failure,
                }
            ],
            "redaction": fallback_redaction,
        }
        write_json(dashboard_path, dashboard)
        write_text(
            state.settings.out_dir / GO_NO_GO_DASHBOARD_MARKDOWN,
            "\n".join(
                [
                    "# Production Beta Go/No-Go Dashboard",
                    "",
                    "Decision: `NO-GO`",
                    "",
                    "The go/no-go dashboard generator did not produce a complete, readable artifact set.",
                    "",
                    f"- Failure: {dashboard_failure}",
                    f"- Mode: `{state.settings.mode}`",
                    "",
                ]
            ),
        )
        if existing_redaction is None:
            write_json(redaction_path, fallback_redaction)
    failed_gate_ids = [
        str(gate.get("id", ""))
        for gate in summary.get("promotion", {}).get("gates", [])
        if isinstance(gate, dict) and gate.get("status") != "pass"
    ]
    previous_go_no_go = summary.get("goNoGo") if isinstance(summary.get("goNoGo"), dict) else {}
    summary_redaction = summary.get("redaction") if isinstance(summary.get("redaction"), dict) else {}
    go_no_go = {
        "decision": str(dashboard.get("decision", "no-go")),
        "basis": "production-beta-go-no-go-dashboard",
        "dashboardJson": GO_NO_GO_DASHBOARD_JSON,
        "dashboardMarkdown": GO_NO_GO_DASHBOARD_MARKDOWN,
        "redactionReport": GO_NO_GO_REDACTION_REPORT,
        "blockingGateIds": failed_gate_ids,
        "failedGateCount": int(summary.get("promotion", {}).get("failedGateCount", len(failed_gate_ids))),
        "redactionStatus": str(dashboard.get("redaction", {}).get("status", "missing"))
        if isinstance(dashboard.get("redaction"), dict)
        else "missing",
        "releaseArtifactRedactionStatus": str(
            previous_go_no_go.get(
                "releaseArtifactRedactionStatus",
                summary_redaction.get("status", "missing"),
            )
        ),
        "nonRelease": bool(summary.get("nonRelease", True)),
        "waiversUsed": int(dashboard.get("summary", {}).get("waiversUsed", 0))
        if isinstance(dashboard.get("summary"), dict)
        else 0,
    }
    summary["goNoGo"] = go_no_go
    summary["commands"] = [dataclasses.asdict(command) for command in state.commands]
    if dashboard_missing:
        summary["status"] = "fail"
        summary["promotionReady"] = False
        if isinstance(summary.get("promotion"), dict):
            summary["promotion"]["promotionReady"] = False
        failures = summary.get("failures") if isinstance(summary.get("failures"), list) else []
        if dashboard_failure and dashboard_failure not in failures:
            failures.append(dashboard_failure)
        summary["failures"] = failures
    elif go_no_go["decision"] == "no-go":
        summary["promotionReady"] = False
        if isinstance(summary.get("promotion"), dict):
            summary["promotion"]["promotionReady"] = False
        if state.settings.mode == "production-beta":
            summary["status"] = "fail"
    elif state.settings.mode == "production-beta":
        promotion = summary.get("promotion") if isinstance(summary.get("promotion"), dict) else {}
        try:
            failed_gate_count = int(promotion.get("failedGateCount", go_no_go["failedGateCount"]))
        except (TypeError, ValueError):
            failed_gate_count = go_no_go["failedGateCount"]
        dashboard_confirms_ready = (
            dashboard.get("promotionReady") is True
            and summary.get("promotionReady") is True
            and promotion.get("promotionReady") is True
            and summary.get("nonRelease") is False
            and failed_gate_count == 0
            and go_no_go["redactionStatus"] == "pass"
            and not state.failures
        )
        if dashboard_confirms_ready:
            summary["promotionReady"] = True
            promotion["promotionReady"] = True
            summary["promotion"] = promotion
            summary["status"] = "pass"
        else:
            summary["promotionReady"] = False
            promotion["promotionReady"] = False
            summary["promotion"] = promotion
            summary["status"] = "fail"
            failure = (
                "Go/no-go dashboard returned a launchable decision, but the pre-dashboard production "
                "summary was not promotion-ready."
            )
            failures = summary.get("failures") if isinstance(summary.get("failures"), list) else []
            if failure not in failures:
                failures.append(failure)
            if failure not in state.failures:
                state.failures.append(failure)
            summary["failures"] = failures
            dashboard = write_rejected_launchable_dashboard_artifacts(state.settings, dashboard, failure)
            go_no_go["decision"] = "no-go"
            dashboard_summary = dashboard.get("summary") if isinstance(dashboard.get("summary"), dict) else {}
            go_no_go["waiversUsed"] = int(dashboard_summary.get("waiversUsed", 0))
            blocking_gate_ids = list(go_no_go.get("blockingGateIds", []))
            if "production-beta.go-no-go-decision" not in blocking_gate_ids:
                blocking_gate_ids.append("production-beta.go-no-go-decision")
            go_no_go["blockingGateIds"] = blocking_gate_ids
            go_no_go["failedGateCount"] = max(int(go_no_go.get("failedGateCount", 0)), len(blocking_gate_ids))
            summary["goNoGo"] = go_no_go
    write_json(state.settings.out_dir / "reports/production-beta-summary.json", summary)
    write_text(state.settings.out_dir / "reports/production-beta-summary.md", render_markdown_summary(summary))
    return summary

def stable_readiness_args(settings: Settings) -> list[str]:
    args = [
        sys.executable,
        str(TOOL_DIR / "cryptad_certification/engine_entry.py"),
        "stable-readiness",
        "--workspace-root",
        str(settings.workspace_root),
        "--out-dir",
        str(stable_readiness_out_dir(settings)),
        "--production-beta-summary",
        str(settings.out_dir / "reports/production-beta-summary.json"),
        "--go-no-go-summary",
        str(settings.out_dir / GO_NO_GO_DASHBOARD_JSON),
        "--release-certification-summary",
        str(settings.out_dir / "evidence/ecosystem-rc-certification.json"),
        "--ecosystem-matrix",
        str(settings.out_dir / "evidence/ecosystem-certification-matrix.json"),
        "--app-platform-summary",
        str(settings.out_dir / "evidence/app-platform-smoke.json"),
        "--multi-node-beta-soak-summary",
        str(stable_readiness_multi_node_soak_path(settings)),
        "--network-scale-soak-summary",
        str(stable_readiness_network_scale_soak_path(settings)),
        "--security-drills-summary",
        str(security_drills_summary_path(settings)),
        "--public-beta-known-issues",
        str(settings.workspace_root / "tools/release-certification/public-beta-known-issues.json"),
    ]
    if settings.stable_readiness_policy is not None:
        args.extend(["--policy", str(settings.stable_readiness_policy)])
    if settings.stable_known_limitations is not None:
        args.extend(["--stable-known-limitations", str(settings.stable_known_limitations)])
    if settings.stable_readiness_waivers is not None:
        args.extend(["--waivers", str(settings.stable_readiness_waivers)])
    return args

def stable_readiness_summary_redaction_status(stable_summary: dict[str, Any] | None) -> str:
    if not isinstance(stable_summary, dict):
        return "missing"
    redaction = stable_summary.get("redaction") if isinstance(stable_summary.get("redaction"), dict) else {}
    redaction_status = release_certification.normalize_evidence_status(
        str(redaction.get("status", "missing"))
    )
    if redaction_status != "pass":
        return redaction_status
    findings = redaction.get("findings")
    if isinstance(findings, list) and findings:
        return "fail"
    if parse_int_field(redaction.get("findingCount", 0), 0, minimum=0) > 0:
        return "fail"

    evidence = stable_summary.get("evidence") if isinstance(stable_summary.get("evidence"), list) else []
    redaction_rows = [
        entry
        for entry in evidence
        if isinstance(entry, dict) and entry.get("id") == "stable-1.0.redaction"
    ]
    if not redaction_rows:
        return "missing"
    for row in redaction_rows:
        row_status = release_certification.normalize_evidence_status(str(row.get("status", "missing")))
        if row_status != "pass" or release_certification.evidence_entry_has_unwaivable_redaction_findings(row):
            return "fail"

    domains = stable_summary.get("domains") if isinstance(stable_summary.get("domains"), list) else []
    for domain in domains:
        if not isinstance(domain, dict):
            continue
        evidence_ids = domain.get("evidenceIds") if isinstance(domain.get("evidenceIds"), list) else []
        if domain.get("id") != "redaction" and "stable-1.0.redaction" not in evidence_ids:
            continue
        domain_status = release_certification.normalize_evidence_status(
            str(domain.get("status", "missing"))
        )
        if domain_status != "pass":
            return "fail"
        blockers = domain.get("blockers") if isinstance(domain.get("blockers"), list) else []
        if blockers:
            return "fail"

    blockers = stable_summary.get("blockers") if isinstance(stable_summary.get("blockers"), list) else []
    for blocker in blockers:
        if isinstance(blocker, dict) and blocker.get("evidenceId") == "stable-1.0.redaction":
            return "fail"
    return "pass"

def stable_readiness_redaction_findings(summary: dict[str, Any]) -> list[dict[str, str]]:
    stable_readiness = (
        summary.get("stableReadiness") if isinstance(summary.get("stableReadiness"), dict) else {}
    )
    if not stable_readiness:
        return []
    redaction_status = str(stable_readiness.get("redactionStatus", "missing")).strip().lower()
    if redaction_status == "pass":
        return []
    return [
        {
            "path": STABLE_READINESS_SUMMARY_JSON,
            "kind": "stable-readiness-redaction-status",
            "detail": f"Stable 1.0 readiness redaction status was {redaction_status}.",
        }
    ]

def stable_readiness_release_redaction_report(
    settings: Settings,
    summary: dict[str, Any],
) -> dict[str, Any]:
    findings = scan_tree(settings.out_dir, settings, include_dist=True)
    findings.extend(stable_readiness_redaction_findings(summary))
    return release_redaction_report(findings)

def record_artifact_redaction_failure(state: PipelineState, summary: dict[str, Any]) -> None:
    if ARTIFACT_REDACTION_FAILURE not in state.failures:
        state.failures.append(ARTIFACT_REDACTION_FAILURE)
    failures = summary.get("failures") if isinstance(summary.get("failures"), list) else []
    if ARTIFACT_REDACTION_FAILURE not in failures:
        failures.append(ARTIFACT_REDACTION_FAILURE)
    summary["failures"] = failures
    summary["status"] = "fail"
    summary["promotionReady"] = False
    promotion = summary.get("promotion") if isinstance(summary.get("promotion"), dict) else {}
    promotion["promotionReady"] = False
    summary["promotion"] = promotion

def apply_release_redaction_report(
    state: PipelineState,
    summary: dict[str, Any],
    redaction_report: dict[str, Any],
) -> dict[str, Any]:
    summary["redaction"] = redaction_report
    go_no_go = summary.get("goNoGo") if isinstance(summary.get("goNoGo"), dict) else {}
    go_no_go["releaseArtifactRedactionStatus"] = redaction_report.get("status", "missing")
    summary["goNoGo"] = go_no_go
    if redaction_report.get("status") != "pass":
        record_artifact_redaction_failure(state, summary)
    write_json(state.settings.out_dir / "reports/redaction-report.json", redaction_report)
    write_json(state.settings.out_dir / "reports/production-beta-summary.json", summary)
    write_text(state.settings.out_dir / "reports/production-beta-summary.md", render_markdown_summary(summary))
    return summary

def release_redaction_allows_dist(summary: dict[str, Any], redaction_report: dict[str, Any]) -> bool:
    go_no_go = summary.get("goNoGo") if isinstance(summary.get("goNoGo"), dict) else {}
    summary_redaction = summary.get("redaction") if isinstance(summary.get("redaction"), dict) else {}
    return (
        str(redaction_report.get("status", "missing")) == "pass"
        and str(summary_redaction.get("status", "missing")) == "pass"
        and str(go_no_go.get("redactionStatus", "missing")) == "pass"
    )

def assert_stable_readiness_args_use_stable_waiver_file_only() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-stable-waiver-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        waiver_file = workspace / "release-waivers.json"
        stable_waivers = workspace / "stable-waivers.json"
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "build/production-beta",
            mode="developer-dry-run",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=True,
            allow_dirty_workspace=True,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=waiver_file,
            timeout_seconds=120,
            clean_out_dir=True,
            generate_stable_readiness=True,
            stable_readiness_policy=workspace / "tools/release-certification/stable-1.0-readiness-policy.json",
            stable_known_limitations=workspace / "tools/release-certification/stable-1.0-known-limitations.json",
            stable_readiness_waivers=stable_waivers,
        )
        args = stable_readiness_args(settings)
        assert str(waiver_file) not in args, args
        assert "--waivers" in args, args
        assert str(stable_waivers) in args, args

def assert_required_stable_readiness_removes_dist_refs_from_dashboard() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-stable-dist-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        out_dir = workspace / "build/production-beta"
        settings = Settings(
            workspace_root=workspace,
            out_dir=out_dir,
            mode="developer-dry-run",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=True,
            allow_dirty_workspace=True,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=120,
            clean_out_dir=True,
            generate_stable_readiness=True,
            require_stable_readiness=True,
            stable_readiness_policy=workspace / "tools/release-certification/stable-1.0-readiness-policy.json",
            stable_known_limitations=workspace / "tools/release-certification/stable-1.0-known-limitations.json",
        )

        summary, exit_code = run_pipeline(settings)

        assert exit_code == 1, summary
        stable_readiness = summary.get("stableReadiness")
        assert isinstance(stable_readiness, dict), summary
        assert stable_readiness["required"] is True, stable_readiness
        assert stable_readiness["stableReady"] is False, stable_readiness
        stable_summary = read_json(stable_readiness_summary_path(settings))
        assert isinstance(stable_summary, dict), stable_readiness
        stable_blockers = json.dumps(stable_summary.get("blockers", []), sort_keys=True)
        assert "distArchive" not in stable_blockers, stable_summary
        assert "checksums" not in stable_blockers, stable_summary
        artifacts = summary.get("artifacts") if isinstance(summary.get("artifacts"), dict) else {}
        assert "distArchive" not in artifacts, artifacts
        assert "checksums" not in artifacts, artifacts
        persisted_summary = read_json(out_dir / "reports/production-beta-summary.json")
        assert persisted_summary is not None, summary
        persisted_artifacts = (
            persisted_summary.get("artifacts") if isinstance(persisted_summary.get("artifacts"), dict) else {}
        )
        assert "distArchive" not in persisted_artifacts, persisted_artifacts
        assert "checksums" not in persisted_artifacts, persisted_artifacts
        dashboard = read_json(out_dir / GO_NO_GO_DASHBOARD_JSON)
        assert dashboard is not None, summary
        assert dashboard["decision"] == "no-go", dashboard
        dashboard_stable = dashboard.get("stableReadiness")
        assert isinstance(dashboard_stable, dict), dashboard
        assert dashboard_stable["required"] is True, dashboard_stable
        assert dashboard_stable["stableReady"] is False, dashboard_stable
        artifact_refs = dashboard.get("artifactRefs") if isinstance(dashboard.get("artifactRefs"), dict) else {}
        assert "distArchive" not in artifact_refs, artifact_refs
        assert "checksums" not in artifact_refs, artifact_refs
        encoded_dashboard = json.dumps(dashboard, sort_keys=True)
        assert f"crypta-production-beta-{summary['version']}.tar.gz" not in encoded_dashboard, dashboard
        assert "dist/checksums.txt" not in encoded_dashboard, dashboard

def compact_stable_readiness_for_summary(
    settings: Settings,
    stable_summary: dict[str, Any] | None,
    result: CommandResult,
) -> dict[str, Any]:
    if not isinstance(stable_summary, dict):
        return {
            "status": "missing",
            "decision": "not-ready",
            "stableReady": False,
            "required": settings.require_stable_readiness,
            "summaryPath": STABLE_READINESS_SUMMARY_JSON,
            "reportPath": STABLE_READINESS_REPORT_MARKDOWN,
            "blockerCount": 1 if settings.require_stable_readiness else 0,
            "warningCount": 0,
            "allowedLimitationCount": 0,
            "disallowedLimitationCount": 0,
            "redactionStatus": "missing",
            "toolExitCode": result.exit_code,
        }
    return {
        "status": str(stable_summary.get("status", "missing")),
        "decision": str(stable_summary.get("decision", "not-ready")),
        "stableReady": stable_summary.get("stableReady") is True,
        "required": settings.require_stable_readiness,
        "summaryPath": STABLE_READINESS_SUMMARY_JSON,
        "reportPath": STABLE_READINESS_REPORT_MARKDOWN,
        "blockersPath": STABLE_READINESS_BLOCKERS_JSON,
        "knownLimitationsPath": STABLE_READINESS_LIMITATIONS_JSON,
        "blockerCount": int(stable_summary.get("blockerCount", 0)),
        "warningCount": int(stable_summary.get("warningCount", 0)),
        "allowedLimitationCount": int(stable_summary.get("allowedLimitationCount", 0)),
        "disallowedLimitationCount": int(stable_summary.get("disallowedLimitationCount", 0)),
        "redactionStatus": stable_readiness_summary_redaction_status(stable_summary),
        "toolExitCode": result.exit_code,
    }

def generate_stable_readiness(state: PipelineState, summary: dict[str, Any]) -> dict[str, Any]:
    output_dir = stable_readiness_out_dir(state.settings)
    if output_dir.exists():
        shutil.rmtree(output_dir)
    result = run_command(
        state,
        "stable-1.0-readiness",
        stable_readiness_args(state.settings),
        timeout_seconds=max(state.settings.timeout_seconds, 300),
        allow_failure=True,
    )
    stable_summary = read_json(stable_readiness_summary_path(state.settings))
    compact = compact_stable_readiness_for_summary(state.settings, stable_summary, result)
    artifacts = summary.get("artifacts") if isinstance(summary.get("artifacts"), dict) else {}
    artifacts.update(
        {
            "stableReadinessSummary": STABLE_READINESS_SUMMARY_JSON,
            "stableReadinessReport": STABLE_READINESS_REPORT_MARKDOWN,
            "stableKnownLimitations": STABLE_READINESS_LIMITATIONS_JSON,
            "stableBlockers": STABLE_READINESS_BLOCKERS_JSON,
        }
    )
    summary["artifacts"] = artifacts
    summary["stableReadiness"] = compact
    if state.settings.require_stable_readiness and compact.get("stableReady") is not True:
        failure = "Stable 1.0 readiness is required and the candidate is not ready."
        if failure not in state.failures:
            state.failures.append(failure)
        failures = summary.get("failures") if isinstance(summary.get("failures"), list) else []
        if failure not in failures:
            failures.append(failure)
        summary["failures"] = failures
        summary["status"] = "fail"
        summary["promotionReady"] = False
        promotion = summary.get("promotion") if isinstance(summary.get("promotion"), dict) else {}
        promotion["promotionReady"] = False
        summary["promotion"] = promotion
    summary["commands"] = [dataclasses.asdict(command) for command in state.commands]
    write_json(state.settings.out_dir / "reports/production-beta-summary.json", summary)
    write_text(state.settings.out_dir / "reports/production-beta-summary.md", render_markdown_summary(summary))
    return summary

def run_pipeline(settings: Settings) -> tuple[dict[str, Any], int]:
    version = read_project_version(settings.workspace_root)
    state = PipelineState(settings, version, utc_now(), [], [], [])
    check_workspace_clean(state)
    ensure_safe_out_dir(settings)
    reset_release_output_roots(settings)
    reset_dist_dir(settings)
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-") as temp_name:
        temp_dir = Path(temp_name)
        key_dir = temp_dir / "keys"
        work_dir = temp_dir / "work"
        cert_out = temp_dir / "release-certification"
        validate_toolchain(state)
        if settings.use_fixture_evidence and settings.mode != "developer-dry-run":
            state.failures.append("fixture evidence is only allowed for developer-dry-run/self-test and cannot certify strict release modes.")

        if settings.use_fixture_evidence:
            state.signing_profile = prepare_signing_profile(state, key_dir)
            copy_first_party_maintenance_policy_input(state)
            copy_first_party_beta_readiness_input(state)
            create_fixture_artifacts(state)
        else:
            clear_workspace_generated_release_outputs(state)
            install_result = run_gradle(state, "gradle-install-crypta-app", [":platform-devtools:installDist"])
            record_gradle_stage(
                state,
                "crypta-app-launcher-install",
                install_result,
                "Installed the crypta-app launcher distribution in this pipeline execution.",
            )
            state.signing_profile = prepare_signing_profile(state, key_dir)
            copy_first_party_maintenance_policy_input(state)
            copy_first_party_beta_readiness_input(state)
            write_json(settings.out_dir / "inputs/release-config.json", release_config(state))
            if not settings.skip_full_build:
                build_tasks = ["build"] if settings.mode == "production-beta" else ["buildJar", "assembleCryptadDist"]
                build_result = run_gradle(
                    state,
                    "gradle-release-build",
                    build_tasks,
                    env=state.signing_profile.env if state.signing_profile else None,
                )
                record_gradle_stage(
                    state,
                    "gradle-full-build",
                    build_result,
                    "Ran the full Gradle build in this pipeline execution.",
                )
            elif settings.mode in {"release-candidate", "production-beta"} and not settings.emergency_skip_build:
                state.failures.append("release-candidate and production-beta modes require the build stage unless --emergency-skip-build is used.")
                record_pipeline_stage(
                    state,
                    "gradle-full-build",
                    "skipped",
                    "Skipped the Gradle build stage without an emergency build skip.",
                )
            else:
                record_pipeline_stage(
                    state,
                    "gradle-full-build",
                    "skipped",
                    "Skipped the Gradle build stage by explicit emergency or non-production request.",
                )
            stage_result = run_gradle(
                state,
                "gradle-stage-sign-verify-first-party-apps",
                ["stageFirstPartyApps", "signFirstPartyApps", "verifyFirstPartyApps"],
                env=state.signing_profile.env if state.signing_profile else None,
            )
            for stage_id, summary in (
                ("first-party-app-staging", "Staged first-party app bundles in this pipeline execution."),
                ("first-party-app-signing", "Signed first-party app bundles in this pipeline execution."),
                ("first-party-app-verification", "Verified first-party app bundle signatures in this pipeline execution."),
            ):
                record_gradle_stage(state, stage_id, stage_result, summary)
            if settings.mode == "production-beta" and not all_required_production_pipeline_stages_completed(state):
                state.failures.append(
                    "production-beta mode did not complete all required Gradle build/stage/sign/verify stages; "
                    "stale workspace artifacts will not be packaged."
                )
            else:
                copy_launcher_distribution(state)
                copied_apps = copy_staged_apps(state)
                package_catalog_and_reviews(state, state.signing_profile, copied_apps, work_dir)

        check_workspace_clean(state, "post-artifact-build")
        write_json(settings.out_dir / "inputs/release-config.json", release_config(state))
        profile_env = state.signing_profile.env if state.signing_profile else os.environ.copy()
        run_security_response_drills(state)
        run_release_certification(state, profile_env, cert_out)
        check_workspace_clean(state, "post-certification")
        summaries = write_evidence_extracts(settings, cert_out)
        promotion = evaluate_promotion(state, summaries)
        pre_dist_findings = scan_tree(settings.out_dir, settings, include_dist=True)
        redaction_report = release_redaction_report(pre_dist_findings)
        write_json(settings.out_dir / "reports/redaction-report.json", redaction_report)
        archive: Path | None = None
        summary: dict[str, Any] | None = None
        if redaction_report["status"] == "pass":
            summary = build_final_summary(state, promotion, redaction_report, None)
            write_json(settings.out_dir / "reports/production-beta-summary.json", summary)
            write_text(settings.out_dir / "reports/production-beta-summary.md", render_markdown_summary(summary))
            summary = attach_go_no_go_dashboard(state, summary)
            if settings.generate_stable_readiness:
                summary = generate_stable_readiness(state, summary)
                summary = attach_go_no_go_dashboard(
                    state,
                    summary,
                    stable_readiness_summary_path(settings),
                    settings.require_stable_readiness,
                )
                redaction_report = stable_readiness_release_redaction_report(settings, summary)
                summary = apply_release_redaction_report(state, summary, redaction_report)
            stable_allows_dist = (
                not settings.require_stable_readiness
                or (
                    isinstance(summary.get("stableReadiness"), dict)
                    and summary["stableReadiness"].get("stableReady") is True
                )
            )
            if release_redaction_allows_dist(summary, redaction_report) and stable_allows_dist:
                planned_archive = dist_bundle_path(settings, version)
                summary.setdefault("artifacts", {})["distArchive"] = f"dist/{planned_archive.name}"
                summary.setdefault("artifacts", {})["checksums"] = "dist/checksums.txt"
                write_json(settings.out_dir / "reports/production-beta-summary.json", summary)
                write_text(settings.out_dir / "reports/production-beta-summary.md", render_markdown_summary(summary))
                summary = attach_go_no_go_dashboard(
                    state,
                    summary,
                    stable_readiness_summary_path(settings) if settings.generate_stable_readiness else None,
                    settings.require_stable_readiness,
                )
                try:
                    archive = create_dist_bundle(settings, version)
                except ReleaseArtifactError as exc:
                    tar_findings = [{"kind": "forbidden-tar-entry", "path": "dist", "detail": str(exc)}]
                    partial_archive = dist_bundle_path(settings, version)
                    remove_dist_bundle(settings, partial_archive)
                    archive = None
                else:
                    tar_findings = scan_tarball(archive, settings)
            else:
                tar_findings = []
                archive = None
                artifacts = summary.get("artifacts") if isinstance(summary.get("artifacts"), dict) else {}
                artifacts.pop("distArchive", None)
                artifacts.pop("checksums", None)
                summary["artifacts"] = artifacts
                write_json(settings.out_dir / "reports/production-beta-summary.json", summary)
                write_text(settings.out_dir / "reports/production-beta-summary.md", render_markdown_summary(summary))
                summary = attach_go_no_go_dashboard(
                    state,
                    summary,
                    stable_readiness_summary_path(settings) if settings.generate_stable_readiness else None,
                    settings.require_stable_readiness,
                )
            if archive is not None and not tar_findings:
                summary.setdefault("artifacts", {})["distArchive"] = f"dist/{archive.name}"
                summary.setdefault("artifacts", {})["checksums"] = "dist/checksums.txt"
                write_json(settings.out_dir / "reports/production-beta-summary.json", summary)
                write_text(settings.out_dir / "reports/production-beta-summary.md", render_markdown_summary(summary))
            elif tar_findings:
                redaction_report = release_redaction_report(tar_findings)
                write_json(settings.out_dir / "reports/redaction-report.json", redaction_report)
                if archive is not None:
                    remove_dist_bundle(settings, archive)
                archive = None
                summary = None
        if redaction_report["status"] != "pass":
            if summary is not None:
                record_artifact_redaction_failure(state, summary)
                write_json(settings.out_dir / "reports/production-beta-summary.json", summary)
                write_text(settings.out_dir / "reports/production-beta-summary.md", render_markdown_summary(summary))
            elif ARTIFACT_REDACTION_FAILURE not in state.failures:
                state.failures.append(ARTIFACT_REDACTION_FAILURE)
        if summary is None:
            summary = build_final_summary(state, promotion, redaction_report, archive)
            write_json(settings.out_dir / "reports/production-beta-summary.json", summary)
            write_text(settings.out_dir / "reports/production-beta-summary.md", render_markdown_summary(summary))
            summary = attach_go_no_go_dashboard(state, summary)
            if settings.generate_stable_readiness:
                summary = generate_stable_readiness(state, summary)
                summary = attach_go_no_go_dashboard(
                    state,
                    summary,
                    stable_readiness_summary_path(settings),
                    settings.require_stable_readiness,
                )
        return summary, release_exit_code(settings, summary)

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run Python-only production beta pipeline tests.")
    parser.add_argument("--workspace-root", type=Path, default=Path.cwd())
    parser.add_argument("--out-dir", type=Path, default=Path("build/production-beta-release"))
    parser.add_argument("--mode", choices=MODES, default="developer-dry-run")
    parser.add_argument("--release-id", default="", help="Candidate release identity for bound evidence.")
    parser.add_argument("--catalog-channel", choices=CATALOG_CHANNELS, default="stable")
    parser.add_argument(
        "--artifact-base-uri",
        default="",
        help=(
            "Public base URI for app bundle artifacts. Required for release-candidate and "
            "production-beta unless CRYPTAD_PRODUCTION_BETA_ARTIFACT_BASE_URI is set."
        ),
    )
    parser.add_argument("--require-live-network", action="store_true", help="Require live-network beta evidence.")
    parser.add_argument(
        "--require-history",
        action="store_true",
        help="Require a previous release-certification summary for strict history comparison.",
    )
    parser.add_argument("--interop-smoke-summary", type=Path)
    parser.add_argument("--interop-extended-summary", type=Path)
    parser.add_argument("--perf-smoke-summary", type=Path)
    parser.add_argument("--live-network-summary", type=Path)
    parser.add_argument("--network-scale-soak-summary", type=Path)
    parser.add_argument(
        "--multi-node-soak-summary",
        type=Path,
        help="Attach an existing multi-node beta soak summary instead of generating one in certification.",
    )
    parser.add_argument(
        "--run-multi-node-soak",
        action="store_true",
        help="Generate deterministic multi-node beta soak evidence during certification.",
    )
    parser.add_argument(
        "--multi-node-soak-config",
        type=Path,
        help="Topology config for generated multi-node beta soak evidence.",
    )
    parser.add_argument(
        "--require-multi-node-soak",
        action="store_true",
        help="Require passing multi-node beta soak evidence for promotion gates.",
    )
    parser.add_argument(
        "--multi-node-mode",
        choices=multi_node_beta_soak.MODES,
        default=None,
        help="Override the topology config mode for generated multi-node beta soak evidence.",
    )
    parser.add_argument(
        "--third-party-intake-summary",
        type=Path,
        help="Attach a redacted third-party app intake summary for optional or required production-beta evidence.",
    )
    parser.add_argument(
        "--security-drills-summary",
        type=Path,
        help="Attach a redacted security response drill summary instead of generating drills in this run.",
    )
    parser.add_argument(
        "--require-third-party-intake",
        action="store_true",
        help="Require third-party intake evidence for promotion gates.",
    )
    parser.add_argument(
        "--run-third-party-intake-sample-flow",
        action="store_true",
        help="Generate deterministic non-release third-party intake sample evidence.",
    )
    parser.add_argument(
        "--generate-stable-readiness",
        action="store_true",
        help="Generate advisory Stable 1.0 readiness artifacts after production beta go/no-go evidence.",
    )
    parser.add_argument(
        "--require-stable-readiness",
        action="store_true",
        help="Require passing Stable 1.0 readiness before packaging a stable-promotion artifact.",
    )
    parser.add_argument(
        "--stable-readiness-policy",
        type=Path,
        help="Stable 1.0 readiness policy JSON. Defaults to tools/release-certification/stable-1.0-readiness-policy.json.",
    )
    parser.add_argument(
        "--stable-known-limitations",
        type=Path,
        help="Stable 1.0 known limitations JSON. Defaults to tools/release-certification/stable-1.0-known-limitations.json.",
    )
    parser.add_argument(
        "--stable-readiness-waivers",
        type=Path,
        help="Stable 1.0 waiver JSON forwarded only to the Stable readiness gate.",
    )
    parser.add_argument("--require-sandbox-provider-tests", action="store_true", help="Require sandbox evidence.")
    parser.add_argument("--skip-gradle", action="store_true", help="Skip Gradle stages. Use only for fixture/self-test dry-runs.")
    parser.add_argument("--skip-full-build", action="store_true", help="Skip buildJar and assembleCryptadDist.")
    parser.add_argument(
        "--use-fixture-evidence",
        action="store_true",
        help="Use deterministic checked-in evidence fixtures. Allowed only for developer-dry-run and internal self-tests.",
    )
    parser.add_argument("--allow-dirty-workspace", action="store_true", help="Allow dirty workspace in strict modes.")
    parser.add_argument("--emergency-skip-live-network", action="store_true", help="Production-beta emergency/test escape hatch for live evidence.")
    parser.add_argument("--emergency-skip-build", action="store_true", help="Production-beta emergency/test escape hatch for skipped Gradle stages.")
    parser.add_argument("--allow-test-signing-in-production", action="store_true", help="Explicit test escape hatch; artifacts remain non-release.")
    parser.add_argument(
        "--previous-summary",
        type=Path,
        help="Previous beta candidate summary for production upgrade gating.",
    )
    parser.add_argument(
        "--previous-release-certification-summary",
        type=Path,
        help="Previous release-certification summary for strict history comparison.",
    )
    parser.add_argument("--waiver-file", type=Path, help="Structured release or go/no-go dashboard waiver JSON file.")
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--no-clean-out-dir", action="store_true", help="Do not remove an existing output directory before running.")
    return parser

def settings_from_args(args: argparse.Namespace) -> Settings:
    workspace = args.workspace_root.resolve()
    out_dir = (workspace / args.out_dir).resolve() if not args.out_dir.is_absolute() else args.out_dir.resolve()
    if args.run_multi_node_soak and args.multi_node_soak_summary is not None:
        raise SystemExit("--run-multi-node-soak cannot be combined with --multi-node-soak-summary.")
    previous_summary = resolve_workspace_path_arg(args.previous_summary, workspace)
    previous_release_certification_summary = resolve_workspace_path_arg(
        args.previous_release_certification_summary,
        workspace,
    )
    if previous_release_certification_summary is not None and not is_release_certification_history_summary(
        previous_release_certification_summary
    ):
        raise SystemExit(
            "previous release-certification history summary is invalid: "
            + release_certification.previous_summary_contract_error(
                read_json(previous_release_certification_summary) or {}
            )
        )
    multi_node_soak_summary = None
    if not args.run_multi_node_soak:
        multi_node_soak_summary = (
            resolve_workspace_path_arg(args.multi_node_soak_summary, workspace)
            if args.multi_node_soak_summary is not None
            else resolve_workspace_path_text(os.environ.get("CRYPTAD_CERT_MULTI_NODE_SOAK_SUMMARY"), workspace)
        )
    multi_node_soak_config = resolve_workspace_path_arg(args.multi_node_soak_config, workspace)
    third_party_intake_summary = resolve_workspace_path_arg(args.third_party_intake_summary, workspace)
    security_drills_summary = (
        resolve_workspace_path_arg(args.security_drills_summary, workspace)
        if args.security_drills_summary is not None
        else resolve_workspace_path_text(os.environ.get("CRYPTAD_SECURITY_DRILLS_SUMMARY"), workspace)
    )
    generate_stable_readiness = args.generate_stable_readiness or args.require_stable_readiness
    stable_readiness_policy = resolve_workspace_path_arg(
        args.stable_readiness_policy
        or Path("tools/release-certification/stable-1.0-readiness-policy.json"),
        workspace,
    )
    stable_known_limitations = resolve_workspace_path_arg(
        args.stable_known_limitations
        or Path("tools/release-certification/stable-1.0-known-limitations.json"),
        workspace,
    )
    stable_readiness_waivers = resolve_workspace_path_arg(args.stable_readiness_waivers, workspace)
    if args.third_party_intake_summary is not None and args.run_third_party_intake_sample_flow:
        raise SystemExit("--run-third-party-intake-sample-flow cannot be combined with --third-party-intake-summary.")
    artifact_base_uri = args.artifact_base_uri.strip() or os.environ.get(
        "CRYPTAD_PRODUCTION_BETA_ARTIFACT_BASE_URI", ""
    ).strip()
    if not artifact_base_uri:
        if args.mode != "developer-dry-run":
            raise SystemExit(
                "--artifact-base-uri or CRYPTAD_PRODUCTION_BETA_ARTIFACT_BASE_URI is required for "
                f"{args.mode} mode."
            )
        artifact_base_uri = f"https://downloads.crypta.invalid/production-beta/{read_project_version(workspace)}"
    validate_artifact_base_uri(args.mode, artifact_base_uri)
    if args.use_fixture_evidence and args.mode != "developer-dry-run":
        raise SystemExit("--use-fixture-evidence is only allowed with --mode developer-dry-run or internal self-tests.")
    require_live = args.require_live_network or (
        args.mode == "production-beta" and not args.emergency_skip_live_network
    )
    require_multi_node_soak = args.require_multi_node_soak or args.mode == "production-beta"
    run_multi_node_soak = args.run_multi_node_soak or multi_node_soak_summary is None
    require_sandbox = args.require_sandbox_provider_tests or args.mode == "production-beta"
    if args.mode == "production-beta":
        if previous_summary is None:
            raise SystemExit(
                "production-beta mode requires --previous-summary with a validated previous beta candidate summary."
            )
        previous_summary_errors = multi_node_beta_soak.validate_previous_beta_candidate_summary(
            read_json(previous_summary),
            production=True,
            max_age_days=90,
        )
        if previous_summary_errors:
            raise SystemExit(
                "production-beta previous beta candidate summary is invalid: "
                + "; ".join(previous_summary_errors[:5])
            )
        default_history_summary = workspace / release_certification.DEFAULT_HISTORY_DIR / "latest-summary.json"
        if (
            previous_release_certification_summary is None
            and not default_history_summary.is_file()
            and not is_release_certification_history_summary(previous_summary)
        ):
            raise SystemExit(
                "production-beta mode requires --previous-release-certification-summary or "
                f"{release_certification.DEFAULT_HISTORY_DIR.as_posix()}/latest-summary.json for release history."
            )
        previous_history_for_binding = previous_release_certification_summary
        if previous_history_for_binding is None and default_history_summary.is_file():
            previous_history_for_binding = default_history_summary
        if previous_history_for_binding is not None:
            binding_errors = previous_release_history_binding_errors(previous_summary, previous_history_for_binding)
            if binding_errors:
                raise SystemExit(
                    "production-beta previous release-certification history does not match "
                    "previous beta candidate summary: "
                    + "; ".join(binding_errors[:5])
                )
        if (args.skip_gradle or args.skip_full_build) and not args.emergency_skip_build:
            raise SystemExit(
                "production-beta mode cannot use --skip-gradle or --skip-full-build without --emergency-skip-build; "
                "emergency build skips are always non-release and cannot be promoted."
            )
        if require_multi_node_soak and multi_node_soak_summary is None:
            if not args.run_multi_node_soak:
                raise SystemExit(
                    "production-beta mode requires --multi-node-soak-summary or explicit --run-multi-node-soak "
                    "with a production --multi-node-soak-config."
                )
            if multi_node_soak_config is None:
                raise SystemExit(
                    "production-beta --run-multi-node-soak requires an explicit production --multi-node-soak-config."
                )
            if args.multi_node_mode == "simulated":
                raise SystemExit("production-beta cannot use --multi-node-mode simulated as required promotion evidence.")
            try:
                rel_config = multi_node_soak_config.resolve().relative_to(workspace).as_posix()
            except ValueError:
                rel_config = multi_node_soak_config.name
            if rel_config == "tools/release-certification/fixtures/self-test-multi-node-beta-soak.json":
                raise SystemExit(
                    "production-beta cannot use the self-test multi-node soak topology as required promotion evidence."
                )
    return Settings(
        workspace_root=workspace,
        out_dir=out_dir,
        mode=args.mode,
        catalog_channel=args.catalog_channel,
        artifact_base_uri=artifact_base_uri,
        require_live_network=require_live,
        require_sandbox_provider_tests=require_sandbox,
        skip_gradle=args.skip_gradle,
        skip_full_build=args.skip_full_build,
        use_fixture_evidence=args.use_fixture_evidence,
        allow_dirty_workspace=args.allow_dirty_workspace,
        emergency_skip_live_network=args.emergency_skip_live_network,
        emergency_skip_build=args.emergency_skip_build,
        allow_test_signing_in_production=args.allow_test_signing_in_production,
        previous_summary=previous_summary,
        waiver_file=resolve_workspace_path_arg(args.waiver_file, workspace),
        timeout_seconds=args.timeout_seconds,
        clean_out_dir=not args.no_clean_out_dir,
        multi_node_soak_summary=multi_node_soak_summary,
        run_multi_node_soak=run_multi_node_soak,
        multi_node_soak_config=multi_node_soak_config,
        require_multi_node_soak=require_multi_node_soak,
        multi_node_mode=args.multi_node_mode,
        previous_release_certification_summary=previous_release_certification_summary,
        third_party_intake_summary=third_party_intake_summary,
        require_third_party_intake=(
            args.require_third_party_intake or args.mode == "production-beta"
        ),
        run_third_party_intake_sample_flow=args.run_third_party_intake_sample_flow,
        security_drills_summary=security_drills_summary,
        generate_stable_readiness=generate_stable_readiness,
        require_stable_readiness=args.require_stable_readiness,
        stable_readiness_policy=stable_readiness_policy,
        stable_known_limitations=stable_known_limitations,
        stable_readiness_waivers=stable_readiness_waivers,
        release_id=args.release_id.strip() or None,
        interop_smoke_summary=resolve_workspace_path_arg(args.interop_smoke_summary, workspace),
        interop_extended_summary=resolve_workspace_path_arg(args.interop_extended_summary, workspace),
        performance_smoke_summary=resolve_workspace_path_arg(args.perf_smoke_summary, workspace),
        live_network_summary=resolve_workspace_path_arg(args.live_network_summary, workspace),
        network_scale_soak_summary=resolve_workspace_path_arg(
            args.network_scale_soak_summary,
            workspace,
        ),
        require_history=args.require_history or args.mode == "production-beta",
    )

def normalized_artifact_hostname(hostname: str) -> str:
    return hostname.rstrip(".").lower()

def artifact_hostname_is_well_formed(hostname: str) -> bool:
    normalized_host = normalized_artifact_hostname(hostname)
    if not normalized_host or any(char.isspace() for char in normalized_host):
        return False
    try:
        ipaddress.ip_address(normalized_host)
        return True
    except ValueError:
        labels = normalized_host.split(".")
        return all(DNS_ARTIFACT_LABEL_RE.fullmatch(label) for label in labels)

def artifact_uri_authority_is_well_formed(parsed: urllib.parse.ParseResult) -> bool:
    try:
        port = parsed.port
    except ValueError:
        return False
    if port == 0:
        return False
    if any(char.isspace() for char in parsed.netloc):
        return False
    host_port = parsed.netloc.rsplit("@", 1)[-1]
    if not host_port or host_port.endswith(":"):
        return False
    return artifact_hostname_is_well_formed(parsed.hostname or "")

def is_numeric_dotted_host(hostname: str) -> bool:
    labels = hostname.split(".")
    return len(labels) > 1 and all(label.isdigit() for label in labels)

def artifact_hostname_is_public(hostname: str) -> bool:
    normalized_host = normalized_artifact_hostname(hostname)
    if not artifact_hostname_is_well_formed(normalized_host) or "%" in normalized_host:
        return False
    if normalized_host in LOCAL_ARTIFACT_HOSTS or normalized_host in PLACEHOLDER_ARTIFACT_HOSTS:
        return False
    if any(normalized_host.endswith(suffix) for suffix in PRIVATE_ARTIFACT_HOST_SUFFIXES):
        return False
    try:
        address = ipaddress.ip_address(normalized_host)
    except ValueError:
        if is_numeric_dotted_host(normalized_host):
            return False
        return "." in normalized_host
    return address.is_global and not address.is_multicast

def validate_artifact_base_uri(mode: str, artifact_base_uri: str) -> None:
    if mode == "developer-dry-run":
        return
    try:
        parsed = urllib.parse.urlparse(artifact_base_uri)
    except ValueError as exc:
        raise SystemExit("release-candidate and production-beta artifact base URIs must use a valid https URI.") from exc
    hostname = parsed.hostname or ""
    if parsed.scheme != "https" or not hostname:
        raise SystemExit("release-candidate and production-beta artifact base URIs must use https.")
    if not artifact_uri_authority_is_well_formed(parsed):
        raise SystemExit("artifact base URI must include a valid host and optional port.")
    if parsed.username or parsed.password:
        raise SystemExit("artifact base URI must not contain credentials.")
    if parsed.query or parsed.fragment:
        raise SystemExit("artifact base URI must not contain query strings or fragments.")
    normalized_host = normalized_artifact_hostname(hostname)
    if normalized_host in PLACEHOLDER_ARTIFACT_HOSTS or normalized_host.endswith(".invalid"):
        raise SystemExit("artifact base URI must not use the placeholder .invalid host.")
    if not artifact_hostname_is_public(hostname):
        raise SystemExit("artifact base URI must be a public HTTPS release artifact host.")
