"""Implementation segment for the selftest policy portion of ``production_beta_release.py``."""

from __future__ import annotations

def assert_go_with_waivers_cannot_promote_failed_production_summary() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-waived-dashboard-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, out_dir),
            mode="production-beta",
            artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
            skip_gradle=False,
            skip_full_build=False,
            allow_dirty_workspace=False,
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        summary = build_final_summary(
            state,
            {
                "status": "fail",
                "promotionReady": False,
                "nonRelease": False,
                "failedGateCount": 1,
                "gates": [
                    {
                        "id": "live.live-network-beta.content-fetch",
                        "status": "fail",
                        "summary": "Live content fetch evidence is missing.",
                    }
                ],
                "knownLimitations": [],
            },
            {
                "schemaVersion": 1,
                "status": "pass",
                "scannedRoot": "<release-out>",
                "findingCount": 0,
                "findings": [],
            },
            None,
        )

        def fake_run_command(
            state: PipelineState,
            name: str,
            args: list[str],
            env: dict[str, str] | None = None,
            timeout_seconds: int = 0,
            allow_failure: bool = False,
        ) -> CommandResult:
            del name, args, env, timeout_seconds, allow_failure
            write_json(
                state.settings.out_dir / GO_NO_GO_DASHBOARD_JSON,
                {
                    "decision": "go-with-waivers",
                    "promotionReady": True,
                    "summary": {"blockers": 0, "warnings": 1, "waiversUsed": 1, "criticalRedactionFindings": 0},
                    "warnings": [
                        {
                            "id": "promotion.live.live-network-beta.content-fetch",
                            "evidenceId": "live-network-beta.content-fetch",
                            "severity": "blocker",
                            "summary": "Waived live content fetch evidence.",
                            "waivedBy": "waiver-live-content",
                        }
                    ],
                    "redaction": {"status": "pass", "findings": []},
                },
            )
            write_text(state.settings.out_dir / GO_NO_GO_DASHBOARD_MARKDOWN, "Decision: `GO WITH WAIVERS`\n")
            write_json(
                state.settings.out_dir / GO_NO_GO_REDACTION_REPORT,
                {
                    "schemaVersion": SCHEMA_VERSION,
                    "status": "pass",
                    "findingCount": 0,
                    "criticalFindingCount": 0,
                    "findings": [],
                },
            )
            return CommandResult("production-beta-go-no-go-dashboard", [], 0, 1, "", "")

        original_run_command = globals()["run_command"]
        try:
            globals()["run_command"] = fake_run_command
            attached = attach_go_no_go_dashboard(state, summary)
        finally:
            globals()["run_command"] = original_run_command

        assert attached["goNoGo"]["decision"] == "no-go", attached
        assert attached["status"] == "fail", attached
        assert attached["promotionReady"] is False, attached
        assert attached["promotion"]["promotionReady"] is False, attached
        assert "production-beta.go-no-go-decision" in attached["goNoGo"]["blockingGateIds"], attached
        assert release_exit_code(settings, attached) == 1, attached
        regenerated_dashboard = read_json(out_dir / GO_NO_GO_DASHBOARD_JSON)
        assert regenerated_dashboard["decision"] == "no-go", regenerated_dashboard
        assert regenerated_dashboard["promotionReady"] is False, regenerated_dashboard
        assert any(
            blocker.get("id") == "production-beta.wrapper.rejected-launchable-dashboard"
            for blocker in regenerated_dashboard.get("blockers", [])
            if isinstance(blocker, dict)
        ), regenerated_dashboard
        regenerated_markdown = (out_dir / GO_NO_GO_DASHBOARD_MARKDOWN).read_text(encoding="utf-8")
        assert "Decision: `NO-GO`" in regenerated_markdown, regenerated_markdown
        assert "GO WITH WAIVERS" not in regenerated_markdown, regenerated_markdown

def assert_missing_go_no_go_dashboard_fails_summary_and_exit() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-missing-dashboard-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, out_dir),
            mode="release-candidate",
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        summary = build_final_summary(
            state,
            {
                "status": "pass",
                "promotionReady": False,
                "nonRelease": True,
                "failedGateCount": 0,
                "gates": [],
                "knownLimitations": [],
            },
            {
                "schemaVersion": 1,
                "status": "pass",
                "scannedRoot": "<release-out>",
                "findingCount": 0,
                "findings": [],
            },
            None,
        )

        def fake_run_command(
            state: PipelineState,
            name: str,
            args: list[str],
            env: dict[str, str] | None = None,
            timeout_seconds: int = 0,
            allow_failure: bool = False,
        ) -> CommandResult:
            del state, name, args, env, timeout_seconds, allow_failure
            return CommandResult(
                "production-beta-go-no-go-dashboard",
                [],
                23,
                1,
                "",
                "failed before artifact write",
            )

        original_run_command = globals()["run_command"]
        try:
            globals()["run_command"] = fake_run_command
            attached = attach_go_no_go_dashboard(state, summary)
        finally:
            globals()["run_command"] = original_run_command

        assert attached["goNoGo"]["decision"] == "no-go", attached
        assert attached["status"] == "fail", attached
        assert attached["promotionReady"] is False, attached
        assert release_exit_code(settings, attached) == 1, attached
        assert any(
            "before producing a readable JSON artifact" in failure for failure in attached["failures"]
        ), attached
        assert (out_dir / GO_NO_GO_DASHBOARD_JSON).is_file(), attached
        assert (out_dir / GO_NO_GO_DASHBOARD_MARKDOWN).is_file(), attached
        assert (out_dir / GO_NO_GO_REDACTION_REPORT).is_file(), attached

def assert_stale_go_no_go_dashboard_is_not_reused() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-stale-dashboard-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, out_dir),
            mode="production-beta",
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        write_json(
            out_dir / GO_NO_GO_DASHBOARD_JSON,
            {
                "decision": "go",
                "promotionReady": True,
                "summary": {"blockers": 0, "warnings": 0, "waiversUsed": 0, "criticalRedactionFindings": 0},
                "blockers": [],
                "redaction": {"status": "pass", "findings": []},
            },
        )
        write_text(out_dir / GO_NO_GO_DASHBOARD_MARKDOWN, "Decision: `GO`\n")
        write_json(
            out_dir / GO_NO_GO_REDACTION_REPORT,
            {
                "schemaVersion": SCHEMA_VERSION,
                "status": "pass",
                "findingCount": 0,
                "criticalFindingCount": 0,
                "findings": [],
            },
        )
        summary = build_final_summary(
            state,
            {
                "status": "fail",
                "promotionReady": False,
                "nonRelease": False,
                "failedGateCount": 1,
                "gates": [
                    {
                        "id": "artifact-redaction",
                        "status": "fail",
                        "required": True,
                        "summary": "Artifact redaction scan failed.",
                    }
                ],
                "knownLimitations": [],
            },
            {
                "schemaVersion": 1,
                "status": "fail",
                "scannedRoot": "<release-out>",
                "findingCount": 1,
                "findings": [{"kind": "raw-app-data", "path": "reports/production-beta-summary.json"}],
            },
            None,
        )

        def fake_run_command(
            state: PipelineState,
            name: str,
            args: list[str],
            env: dict[str, str] | None = None,
            timeout_seconds: int = 0,
            allow_failure: bool = False,
        ) -> CommandResult:
            del state, name, args, env, timeout_seconds, allow_failure
            return CommandResult(
                "production-beta-go-no-go-dashboard",
                [],
                23,
                1,
                "",
                "failed before artifact write",
            )

        original_run_command = globals()["run_command"]
        try:
            globals()["run_command"] = fake_run_command
            attached = attach_go_no_go_dashboard(state, summary)
        finally:
            globals()["run_command"] = original_run_command

        assert attached["goNoGo"]["decision"] == "no-go", attached
        assert attached["status"] == "fail", attached
        assert attached["promotionReady"] is False, attached
        assert release_exit_code(settings, attached) == 1, attached
        regenerated_dashboard = read_json(out_dir / GO_NO_GO_DASHBOARD_JSON)
        assert regenerated_dashboard is not None, attached
        assert regenerated_dashboard["decision"] == "no-go", regenerated_dashboard
        regenerated_markdown = (out_dir / GO_NO_GO_DASHBOARD_MARKDOWN).read_text(encoding="utf-8")
        assert regenerated_markdown != "Decision: `GO`\n", regenerated_markdown
        assert "before producing a readable JSON artifact" in regenerated_markdown, regenerated_markdown

def assert_incomplete_go_no_go_dashboard_outputs_fail_summary_and_exit() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-incomplete-dashboard-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, out_dir),
            mode="production-beta",
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        summary = build_final_summary(
            state,
            {
                "status": "pass",
                "promotionReady": True,
                "nonRelease": False,
                "failedGateCount": 0,
                "gates": [],
                "knownLimitations": [],
            },
            {
                "schemaVersion": 1,
                "status": "pass",
                "scannedRoot": "<release-out>",
                "findingCount": 0,
                "findings": [],
            },
            None,
        )

        def fake_run_command(
            state: PipelineState,
            name: str,
            args: list[str],
            env: dict[str, str] | None = None,
            timeout_seconds: int = 0,
            allow_failure: bool = False,
        ) -> CommandResult:
            del name, args, env, timeout_seconds, allow_failure
            write_json(
                state.settings.out_dir / GO_NO_GO_DASHBOARD_JSON,
                {
                    "decision": "go",
                    "promotionReady": True,
                    "summary": {"blockers": 0, "warnings": 0, "waiversUsed": 0, "criticalRedactionFindings": 0},
                    "blockers": [],
                    "redaction": {"status": "pass", "findings": []},
                },
            )
            return CommandResult("production-beta-go-no-go-dashboard", [], 0, 1, "", "")

        original_run_command = globals()["run_command"]
        try:
            globals()["run_command"] = fake_run_command
            attached = attach_go_no_go_dashboard(state, summary)
        finally:
            globals()["run_command"] = original_run_command

        assert attached["goNoGo"]["decision"] == "no-go", attached
        assert attached["status"] == "fail", attached
        assert attached["promotionReady"] is False, attached
        assert release_exit_code(settings, attached) == 1, attached
        assert any("complete artifact set" in failure for failure in attached["failures"]), attached
        assert (out_dir / GO_NO_GO_DASHBOARD_JSON).is_file(), attached
        assert (out_dir / GO_NO_GO_DASHBOARD_MARKDOWN).is_file(), attached
        assert (out_dir / GO_NO_GO_REDACTION_REPORT).is_file(), attached
        regenerated_dashboard = read_json(out_dir / GO_NO_GO_DASHBOARD_JSON)
        assert regenerated_dashboard is not None, attached
        assert regenerated_dashboard["decision"] == "no-go", regenerated_dashboard

def assert_failed_go_no_go_redaction_fails_summary_and_exit() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-dashboard-redaction-fail-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, out_dir),
            mode="release-candidate",
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        summary = build_final_summary(
            state,
            {
                "status": "pass",
                "promotionReady": False,
                "nonRelease": True,
                "failedGateCount": 0,
                "gates": [],
                "knownLimitations": [],
            },
            {
                "schemaVersion": 1,
                "status": "pass",
                "scannedRoot": "<release-out>",
                "findingCount": 0,
                "findings": [],
            },
            None,
        )

        def fake_run_command(
            state: PipelineState,
            name: str,
            args: list[str],
            env: dict[str, str] | None = None,
            timeout_seconds: int = 0,
            allow_failure: bool = False,
        ) -> CommandResult:
            del name, args, env, timeout_seconds, allow_failure
            redaction = {
                "schemaVersion": SCHEMA_VERSION,
                "status": "fail",
                "findingCount": 1,
                "criticalFindingCount": 1,
                "findings": [
                    {
                        "kind": "protected-secret-value",
                        "path": GO_NO_GO_DASHBOARD_JSON,
                        "severity": "critical",
                    }
                ],
            }
            write_json(
                state.settings.out_dir / GO_NO_GO_DASHBOARD_JSON,
                {
                    "decision": "no-go",
                    "promotionReady": False,
                    "summary": {"blockers": 1, "warnings": 0, "waiversUsed": 0, "criticalRedactionFindings": 1},
                    "blockers": [
                        {
                            "id": "dashboard.redaction.scan",
                            "evidenceId": "production-beta.dashboard-redaction",
                            "severity": "critical",
                            "summary": "Dashboard redaction scanner found 1 finding.",
                        }
                    ],
                    "redaction": redaction,
                },
            )
            write_text(state.settings.out_dir / GO_NO_GO_DASHBOARD_MARKDOWN, "Decision: `NO-GO`\n")
            write_json(state.settings.out_dir / GO_NO_GO_REDACTION_REPORT, redaction)
            return CommandResult("production-beta-go-no-go-dashboard", [], 1, 1, "", "")

        original_run_command = globals()["run_command"]
        try:
            globals()["run_command"] = fake_run_command
            attached = attach_go_no_go_dashboard(state, summary)
        finally:
            globals()["run_command"] = original_run_command

        assert attached["goNoGo"]["decision"] == "no-go", attached
        assert attached["status"] == "fail", attached
        assert attached["promotionReady"] is False, attached
        assert release_exit_code(settings, attached) == 1, attached
        assert any("redaction report status is fail" in failure for failure in attached["failures"]), attached

def cleanup_test_settings(workspace: Path, out_dir: Path) -> Settings:
    return Settings(
        workspace_root=workspace,
        out_dir=out_dir,
        mode="developer-dry-run",
        catalog_channel="stable",
        artifact_base_uri="https://downloads.crypta.invalid/self-test",
        require_live_network=False,
        require_sandbox_provider_tests=False,
        skip_gradle=True,
        skip_full_build=True,
        use_fixture_evidence=False,
        allow_dirty_workspace=True,
        emergency_skip_live_network=False,
        emergency_skip_build=False,
        allow_test_signing_in_production=False,
        previous_summary=None,
        waiver_file=None,
        timeout_seconds=60,
        clean_out_dir=True,
    )

def assert_attached_multi_node_summary_is_extracted() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-attached-multi-node-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        cert_out = workspace / "external-certification"
        attached_summary = workspace / "attached/multi-node-summary.json"
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, out_dir),
            multi_node_soak_summary=attached_summary,
        )
        write_json(attached_summary, passing_promotion_summaries()["multiNodeBetaSoak"])

        summaries = write_evidence_extracts(settings, cert_out)
        extracted = read_json(out_dir / "evidence/multi-node-beta-soak.json")
        assert summaries["multiNodeBetaSoak"]["status"] == "pass", summaries
        assert isinstance(extracted, dict), extracted
        assert extracted["status"] == "pass", extracted
        assert extracted["promotionReady"] is True, extracted

def assert_stable_readiness_soak_inputs_are_timestamped() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-stable-soak-inputs-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        cert_out = workspace / "external-certification"
        custom_release_id = "cryptad-candidate-stable-self-test"
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, out_dir),
            release_id=custom_release_id,
            run_multi_node_soak=True,
        )
        cert_generated_at = "2026-06-24T00:00:00Z"
        multi_node_summary = passing_promotion_summaries()["multiNodeBetaSoak"]
        network_summary = read_json(
            REPO_ROOT / "tools/release-certification/fixtures/self-test-network-scale-soak.json"
        )
        assert isinstance(network_summary, dict), network_summary
        assert generated_at_from_summary(multi_node_summary), multi_node_summary
        assert not generated_at_from_summary(network_summary), network_summary

        write_json(cert_out / "app-platform-smoke/summary.json", {"status": "pass", "evidence": []})
        write_json(cert_out / "live-network-beta-smoke/summary.json", {"status": "pass", "evidence": []})
        write_json(cert_out / "network-scale-soak/summary.json", network_summary)
        write_json(cert_out / "multi-node-beta-soak/summary.json", multi_node_summary)
        write_json(
            cert_out / release_certification.SUMMARY_FILE_NAME,
            {
                "status": "pass",
                "generatedAt": cert_generated_at,
                "historyComparison": {"status": "pass"},
                "ecosystemGates": [],
                "evidence": [],
            },
        )
        write_json(
            cert_out / release_certification.ECOSYSTEM_MATRIX_FILE_NAME,
            {"status": "pass"},
        )

        write_evidence_extracts(settings, cert_out)

        compact_multi_node = read_json(out_dir / "evidence/multi-node-beta-soak.json")
        stable_multi_node = read_json(stable_readiness_multi_node_soak_path(settings))
        stable_network = read_json(stable_readiness_network_scale_soak_path(settings))
        assert isinstance(compact_multi_node, dict), compact_multi_node
        assert isinstance(stable_multi_node, dict), stable_multi_node
        assert isinstance(stable_network, dict), stable_network
        assert "generatedAt" not in compact_multi_node, compact_multi_node
        assert stable_multi_node["generatedAt"] == multi_node_summary["generatedAt"], stable_multi_node
        assert stable_multi_node["releaseId"] == custom_release_id, stable_multi_node
        assert stable_1_0_readiness.multi_node_candidate_release_ids(stable_multi_node) == [
            ("releaseId", custom_release_id)
        ], stable_multi_node
        assert stable_network["generatedAt"] == cert_generated_at, stable_network

        args = stable_readiness_args(settings)
        multi_node_arg = args[args.index("--multi-node-beta-soak-summary") + 1]
        network_arg = args[args.index("--network-scale-soak-summary") + 1]
        assert multi_node_arg == str(stable_readiness_multi_node_soak_path(settings)), args
        assert network_arg == str(stable_readiness_network_scale_soak_path(settings)), args

def assert_stable_readiness_redaction_failure_updates_release_report() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-stable-redaction-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        settings = cleanup_test_settings(workspace, workspace / "build/production-beta")
        state = PipelineState(settings, "270", utc_now(), [], [], [])
        promotion = {
            "status": "pass",
            "promotionReady": True,
            "nonRelease": True,
            "failedGateCount": 0,
            "gates": [],
        }
        summary = build_final_summary(
            state,
            promotion,
            release_redaction_report([]),
            archive=None,
        )
        semantic_redaction_failure_summary = {
            "schemaVersion": 1,
            "kind": "stable-1.0-readiness",
            "status": "fail",
            "decision": "not-ready",
            "stableReady": False,
            "blockerCount": 1,
            "warningCount": 0,
            "allowedLimitationCount": 0,
            "disallowedLimitationCount": 0,
            "redaction": {"status": "pass", "findingCount": 0, "findings": []},
            "domains": [
                {
                    "id": "redaction",
                    "status": "fail",
                    "summary": "Stable 1.0 readiness redaction blockers are present.",
                    "evidenceIds": ["stable-1.0.redaction"],
                    "blockers": [
                        {
                            "id": "stable-1.0.redaction.semantic-self-test",
                            "evidenceId": "stable-1.0.redaction",
                            "summary": "Semantic Stable redaction evidence failed.",
                        }
                    ],
                    "warnings": [],
                    "allowedLimitations": [],
                }
            ],
            "blockers": [
                {
                    "id": "stable-1.0.redaction.semantic-self-test",
                    "evidenceId": "stable-1.0.redaction",
                    "summary": "Semantic Stable redaction evidence failed.",
                }
            ],
            "warnings": [],
            "allowedLimitations": [],
            "disallowedLimitations": [],
            "evidence": [
                {
                    "id": "stable-1.0.readiness-gate",
                    "status": "fail",
                    "summary": "Stable 1.0 readiness decision is not-ready.",
                    "details": {"decision": "not-ready", "stableReady": False},
                },
                {
                    "id": "stable-1.0.redaction",
                    "status": "fail",
                    "summary": "Stable 1.0 readiness redaction checks failed.",
                    "details": {"blockerCount": 1},
                },
            ],
        }
        compact = compact_stable_readiness_for_summary(
            settings,
            semantic_redaction_failure_summary,
            CommandResult("stable-1.0-readiness", [], 1, 0, "", ""),
        )
        assert compact["required"] is False, compact
        assert compact["redactionStatus"] == "fail", compact
        summary["stableReadiness"] = compact
        write_json(
            stable_readiness_summary_path(settings),
            semantic_redaction_failure_summary,
        )

        redaction_report = stable_readiness_release_redaction_report(settings, summary)
        summary = apply_release_redaction_report(state, summary, redaction_report)

        persisted_report = read_json(settings.out_dir / "reports/redaction-report.json")
        persisted_summary = read_json(settings.out_dir / "reports/production-beta-summary.json")
        assert persisted_report is not None, redaction_report
        assert persisted_summary is not None, summary
        assert persisted_report["status"] == "fail", persisted_report
        assert any(
            finding.get("kind") == "stable-readiness-redaction-status"
            for finding in persisted_report["findings"]
        ), persisted_report
        assert persisted_summary["redaction"]["status"] == "fail", persisted_summary
        assert persisted_summary["goNoGo"]["redactionStatus"] == "pass", persisted_summary
        assert persisted_summary["goNoGo"]["releaseArtifactRedactionStatus"] == "fail", persisted_summary
        assert persisted_summary["promotionReady"] is False, persisted_summary
        assert ARTIFACT_REDACTION_FAILURE in persisted_summary["failures"], persisted_summary

def assert_release_redaction_update_preserves_dashboard_redaction_status() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-dashboard-redaction-preserve-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        settings = cleanup_test_settings(workspace, workspace / "build/production-beta")
        state = PipelineState(settings, "270", utc_now(), [], [], [])
        summary = build_final_summary(
            state,
            {
                "status": "pass",
                "promotionReady": True,
                "nonRelease": True,
                "failedGateCount": 0,
                "gates": [],
            },
            release_redaction_report([]),
            archive=None,
        )
        summary["goNoGo"]["redactionStatus"] = "fail"

        clean_release_redaction = release_redaction_report([])
        updated = apply_release_redaction_report(state, summary, clean_release_redaction)

        assert updated["redaction"]["status"] == "pass", updated
        assert updated["goNoGo"]["redactionStatus"] == "fail", updated
        assert updated["goNoGo"]["releaseArtifactRedactionStatus"] == "pass", updated
        assert release_redaction_allows_dist(updated, clean_release_redaction) is False, updated

def assert_platform_api_contract_snapshots_are_written_as_envelopes() -> None:
    with tempfile.TemporaryDirectory(
        prefix="cryptad-production-beta-api-contract-snapshots-"
    ) as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        cert_out = workspace / "external-certification"
        previous_history = workspace / release_certification.DEFAULT_HISTORY_DIR / "latest-summary.json"
        settings = cleanup_test_settings(workspace, out_dir)
        write_valid_release_certification_history_summary(previous_history)
        details = previous_platform_api_contract_details()
        current_snapshot = platform_api_snapshot_from_evidence_details(details)
        assert current_snapshot is not None, details
        write_json(
            cert_out / "app-platform-smoke/artifacts/platform-api-contract.json",
            current_snapshot,
        )
        write_json(
            cert_out / "app-platform-smoke/summary.json",
            {
                "status": "pass",
                "evidence": [
                    {
                        "id": "platform-api.contract",
                        "status": "pass",
                        "summary": "Current Platform API contract snapshot was generated.",
                        "details": details,
                    }
                ],
            },
        )
        write_json(
            cert_out / "live-network-beta-smoke/summary.json",
            {"status": "pass", "evidence": []},
        )
        write_json(
            cert_out / "network-scale-soak/summary.json",
            {"status": "pass", "evidence": []},
        )
        write_json(
            cert_out / "multi-node-beta-soak/summary.json",
            passing_promotion_summaries()["multiNodeBetaSoak"],
        )
        write_json(
            cert_out / release_certification.SUMMARY_FILE_NAME,
            {
                "status": "pass",
                "historyComparison": {"status": "pass"},
                "ecosystemGates": [
                    {"id": "ecosystem.platform-api-compatibility", "status": "pass"}
                ],
                "evidence": [],
            },
        )
        write_json(
            cert_out / release_certification.ECOSYSTEM_MATRIX_FILE_NAME,
            {"status": "pass"},
        )

        write_evidence_extracts(settings, cert_out)

        current = read_json(out_dir / "evidence/platform-api-contract-current.json")
        previous = read_json(out_dir / "evidence/platform-api-contract-previous.json")
        assert isinstance(current, dict) and isinstance(current.get("contract"), dict), current
        assert isinstance(previous, dict) and isinstance(previous.get("contract"), dict), previous
        assert current["contract"]["apiVersion"] == "v1", current
        assert previous["contract"]["stableBaseline"]["endpoints"] == ["GET /queue"], previous

        previous_history_without_labels = read_json(previous_history)
        assert isinstance(previous_history_without_labels, dict), previous_history
        for item in previous_history_without_labels.get("evidence", []):
            if isinstance(item, dict) and item.get("id") == "platform-api.contract":
                details_without_labels = item.get("details")
                assert isinstance(details_without_labels, dict), item
                details_without_labels.pop("stableEndpointActionLabels", None)
        write_json(previous_history, previous_history_without_labels)

        write_evidence_extracts(settings, cert_out)

        previous_without_labels = read_json(
            out_dir / "evidence/platform-api-contract-previous.json"
        )
        assert isinstance(previous_without_labels, dict), previous_without_labels
        assert previous_without_labels["status"] == "missing", previous_without_labels
        assert "contract" not in previous_without_labels, previous_without_labels

def assert_env_attached_multi_node_summary_is_extracted() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-env-multi-node-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        cert_out = workspace / "external-certification"
        attached_summary = workspace / "attached/multi-node-summary.json"
        write_json(attached_summary, passing_promotion_summaries()["multiNodeBetaSoak"])
        parser = build_parser()
        env_name = "CRYPTAD_CERT_MULTI_NODE_SOAK_SUMMARY"
        old_env = os.environ.get(env_name)
        os.environ[env_name] = "attached/multi-node-summary.json"
        try:
            settings = settings_from_args(
                parser.parse_args(
                    [
                        "--workspace-root",
                        str(workspace),
                        "--out-dir",
                        str(out_dir.relative_to(workspace)),
                        "--artifact-base-uri",
                        "https://downloads.crypta.invalid/self-test",
                    ]
                )
            )
        finally:
            if old_env is None:
                os.environ.pop(env_name, None)
            else:
                os.environ[env_name] = old_env

        assert settings.multi_node_soak_summary == attached_summary.resolve(), settings.multi_node_soak_summary
        summaries = write_evidence_extracts(settings, cert_out)
        extracted = read_json(out_dir / "evidence/multi-node-beta-soak.json")
        assert summaries["multiNodeBetaSoak"]["status"] == "pass", summaries
        assert isinstance(extracted, dict), extracted
        assert extracted["status"] == "pass", extracted
        assert extracted["promotionReady"] is True, extracted

def assert_attached_multi_node_summary_is_not_marked_generated() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-attached-multi-node-config-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        attached_summary = workspace / "attached/multi-node-summary.json"
        previous_summary = workspace / "attached/previous-beta-candidate-summary.json"
        history_summary = workspace / "attached/previous-release-certification-summary.json"
        write_json(attached_summary, passing_promotion_summaries()["multiNodeBetaSoak"])
        write_valid_previous_candidate_history_pair(previous_summary, history_summary)
        parser = build_parser()
        settings = settings_from_args(
            parser.parse_args(
                [
                    "--workspace-root",
                    str(workspace),
                    "--out-dir",
                    str(out_dir.relative_to(workspace)),
                    "--mode",
                    "production-beta",
                    "--artifact-base-uri",
                    "https://downloads.crypta.org/self-test",
                    "--multi-node-soak-summary",
                    str(attached_summary.relative_to(workspace)),
                    "--previous-summary",
                    str(previous_summary.relative_to(workspace)),
                    "--previous-release-certification-summary",
                    str(history_summary.relative_to(workspace)),
                ]
            )
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        config = release_config(state)

        assert settings.require_multi_node_soak is True, settings
        assert settings.run_multi_node_soak is False, settings
        assert config["requireMultiNodeSoak"] is True, config
        assert config["runMultiNodeSoak"] is False, config

def assert_run_multi_node_soak_overrides_attached_env_summary() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-run-multi-node-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        cert_out = workspace / "build/certification"
        attached_summary = workspace / "attached/multi-node-summary.json"
        captured_args: list[list[str]] = []
        captured_envs: list[dict[str, str]] = []

        parser = build_parser()
        env_name = "CRYPTAD_CERT_MULTI_NODE_SOAK_SUMMARY"
        old_env = os.environ.get(env_name)
        os.environ[env_name] = str(attached_summary.relative_to(workspace))
        try:
            settings = settings_from_args(
                parser.parse_args(
                    [
                        "--workspace-root",
                        str(workspace),
                        "--out-dir",
                        str(out_dir.relative_to(workspace)),
                        "--artifact-base-uri",
                        "https://downloads.crypta.invalid/self-test",
                        "--run-multi-node-soak",
                    ]
                )
            )
        finally:
            if old_env is None:
                os.environ.pop(env_name, None)
            else:
                os.environ[env_name] = old_env

        def fake_run_command(
            state: PipelineState,
            name: str,
            args: list[str],
            env: dict[str, str] | None = None,
            timeout_seconds: int = 0,
            allow_failure: bool = False,
        ) -> CommandResult:
            del state, timeout_seconds, allow_failure
            captured_args.append(list(args))
            captured_envs.append(dict(env or {}))
            return CommandResult(name, list(args), 0, 1, "", "")

        original_run_command = globals()["run_command"]
        try:
            globals()["run_command"] = fake_run_command
            run_release_certification(
                PipelineState(settings, "self-test", utc_now(), [], [], []),
                {env_name: str(attached_summary)},
                cert_out,
            )
        finally:
            globals()["run_command"] = original_run_command

        assert settings.multi_node_soak_summary is None, settings
        assert settings.run_multi_node_soak is True, settings
        multi_node_args = next(
            args for args in captured_args if "multi-node-beta" in args and "run" in args
        )
        assert "--config" not in multi_node_args, multi_node_args
        assert "--multi-node-soak-summary" in captured_args[-1], captured_args[-1]
        summary_index = captured_args[-1].index("--multi-node-soak-summary")
        assert Path(captured_args[-1][summary_index + 1]) == (
            cert_out / "multi-node-beta-soak/summary.json"
        ), captured_args[-1]
        assert captured_envs[-1].get(env_name) == "", captured_envs[-1]
        assert captured_envs[-1].get("CRYPTAD_CERT_NETWORK_SCALE_SOAK_RELEASE_ID") == (
            "cryptad-beta-self-test"
        ), captured_envs[-1]
        assert multi_node_summary_path(settings, cert_out) == cert_out / "multi-node-beta-soak/summary.json"

def assert_generated_multi_node_soak_uses_previous_candidate_summary() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-generated-multi-node-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        cert_out = workspace / "build/certification"
        previous_summary = workspace / "previous-beta-candidate-summary.json"
        config_path = workspace / "topology.json"
        write_valid_previous_candidate_summary(previous_summary)
        config = multi_node_beta_soak.load_config(multi_node_beta_soak.fixture_path())
        config["previousCandidate"]["summaryPath"] = "stale-previous-summary.json"
        config["previousCandidate"]["version"] = "stale-previous"
        config["currentCandidate"]["version"] = "stale-current"
        write_json(config_path, config)
        captured_args: list[list[str]] = []

        def fake_run_command(
            state: PipelineState,
            name: str,
            args: list[str],
            env: dict[str, str] | None = None,
            timeout_seconds: int = 0,
            allow_failure: bool = False,
        ) -> CommandResult:
            del state, env, timeout_seconds, allow_failure
            captured_args.append(list(args))
            return CommandResult(name, list(args), 0, 1, "", "")

        original_run_command = globals()["run_command"]
        try:
            globals()["run_command"] = fake_run_command
            settings = dataclasses.replace(
                cleanup_test_settings(workspace, out_dir),
                mode="production-beta",
                run_multi_node_soak=True,
                multi_node_soak_config=config_path,
                require_multi_node_soak=True,
                previous_summary=previous_summary,
            )
            run_release_certification(PipelineState(settings, "self-test", utc_now(), [], [], []), {}, cert_out)
        finally:
            globals()["run_command"] = original_run_command

        multi_node_args = next(
            args
            for args in captured_args
            if "multi-node-beta" in args and "run" in args
        )
        assert "--config" in multi_node_args, multi_node_args
        config_index = multi_node_args.index("--config")
        generated_config_path = Path(multi_node_args[config_index + 1])
        assert generated_config_path != config_path, multi_node_args
        generated_config = read_json(generated_config_path)
        assert isinstance(generated_config, dict), generated_config_path
        assert generated_config["previousCandidate"]["summaryPath"] == str(previous_summary), generated_config
        assert generated_config["previousCandidate"]["version"] == "previous-beta", generated_config
        assert generated_config["currentCandidate"]["version"] == "self-test", generated_config
        original_config = read_json(config_path)
        assert original_config["previousCandidate"]["summaryPath"] == "stale-previous-summary.json", original_config
        assert original_config["currentCandidate"]["version"] == "stale-current", original_config

def assert_run_multi_node_soak_rejects_cli_summary() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-run-multi-node-conflict-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        parser = build_parser()
        try:
            settings_from_args(
                parser.parse_args(
                    [
                        "--workspace-root",
                        str(workspace),
                        "--out-dir",
                        str(out_dir.relative_to(workspace)),
                        "--artifact-base-uri",
                        "https://downloads.crypta.invalid/self-test",
                        "--run-multi-node-soak",
                        "--multi-node-soak-summary",
                        "attached/multi-node-summary.json",
                    ]
                )
            )
        except SystemExit as exc:
            assert "--run-multi-node-soak cannot be combined" in str(exc), exc
        else:
            raise AssertionError("--run-multi-node-soak accepted --multi-node-soak-summary")

def assert_attached_multi_node_safety_flags_block_promotion() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-attached-multi-node-safety-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, out_dir),
            require_multi_node_soak=True,
        )
        summaries = passing_promotion_summaries()
        unsafe_summary = json.loads(json.dumps(summaries["multiNodeBetaSoak"], sort_keys=True))
        support_bundle = next(
            scenario for scenario in unsafe_summary["scenarios"] if scenario.get("id") == "support-bundle-drill"
        )
        evidence = support_bundle.setdefault("evidence", {})
        evidence["privateInsertUrisIncluded"] = True
        evidence["tokensIncluded"] = True
        evidence["redactionScanStatus"] = "fail"
        unsafe_summary["redaction"]["checks"]["failOnTokens"] = False
        summaries["multiNodeBetaSoak"] = unsafe_summary

        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        promotion = evaluate_promotion(state, summaries)
        failed_ids = {gate["id"] for gate in promotion["gates"] if gate["status"] == "fail"}
        multi_node = promotion["multiNodeBetaSoak"]

        assert "multi-node-beta.soak" in failed_ids, promotion
        assert "multi-node-beta.redaction" in failed_ids, promotion
        assert promotion["promotionReady"] is False, promotion
        assert multi_node["status"] == "fail", multi_node
        assert multi_node["promotionReady"] is False, multi_node
        assert multi_node["redaction"]["status"] == "fail", multi_node
        assert any(
            finding.get("kind") == "forbidden-included-flag"
            for finding in multi_node["redaction"].get("findings", [])
            if isinstance(finding, dict)
        ), multi_node
        assert any(
            finding.get("kind") == "disabled-redaction-check"
            for finding in multi_node["redaction"].get("findings", [])
            if isinstance(finding, dict)
        ), multi_node

def assert_attached_multi_node_non_promotable_summary_blocks_promotion() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-attached-multi-node-ready-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, out_dir),
            require_multi_node_soak=True,
        )
        summaries = passing_promotion_summaries()
        non_promotable_summary = json.loads(json.dumps(summaries["multiNodeBetaSoak"], sort_keys=True))
        non_promotable_summary["promotionReady"] = False
        summaries["multiNodeBetaSoak"] = non_promotable_summary

        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        promotion = evaluate_promotion(state, summaries)
        failed_ids = {gate["id"] for gate in promotion["gates"] if gate["status"] == "fail"}
        multi_node = promotion["multiNodeBetaSoak"]

        assert "multi-node-beta.soak" in failed_ids, promotion
        assert promotion["promotionReady"] is False, promotion
        assert multi_node["status"] == "fail", multi_node
        assert multi_node["promotionReady"] is False, multi_node
        assert "promotionReady must be true when summary status is pass" in multi_node["validationErrors"], multi_node

def assert_attached_multi_node_blockers_and_warnings_block_promotion() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-attached-multi-node-blockers-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, out_dir),
            require_multi_node_soak=True,
        )

        for field, message, expected_error in (
            ("blockers", "fixture blocker", "summary status must be fail when blockers are present"),
            ("warnings", "fixture warning", "summary status must not be pass when warnings are present"),
        ):
            summaries = passing_promotion_summaries()
            malformed_summary = json.loads(json.dumps(summaries["multiNodeBetaSoak"], sort_keys=True))
            malformed_summary["status"] = "pass"
            malformed_summary["promotionReady"] = True
            malformed_summary[field] = [message]
            summaries["multiNodeBetaSoak"] = malformed_summary

            state = PipelineState(settings, "self-test", utc_now(), [], [], [])
            promotion = evaluate_promotion(state, summaries)
            failed_ids = {gate["id"] for gate in promotion["gates"] if gate["status"] == "fail"}
            multi_node = promotion["multiNodeBetaSoak"]

            assert "multi-node-beta.soak" in failed_ids, promotion
            assert promotion["promotionReady"] is False, promotion
            assert multi_node["status"] == "fail", multi_node
            assert multi_node["promotionReady"] is False, multi_node
            assert expected_error in multi_node["validationErrors"], multi_node

def assert_missing_previous_summary_blocks_production_multi_node_promotion() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-missing-previous-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, out_dir),
            mode="production-beta",
            artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
            require_live_network=True,
            require_sandbox_provider_tests=True,
            skip_gradle=False,
            skip_full_build=False,
            allow_dirty_workspace=False,
            require_multi_node_soak=True,
        )
        write_minimal_promotion_artifacts(out_dir)
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        state.signing_profile = production_signing_profile()
        mark_required_pipeline_stages_passed(state)

        promotion = evaluate_promotion(state, passing_promotion_summaries())
        failed_ids = {gate["id"] for gate in promotion["gates"] if gate["status"] == "fail"}

        assert "multi-node-beta.previous-candidate-summary" in failed_ids, promotion
        assert promotion["promotionReady"] is False, promotion

def assert_mismatched_previous_summary_blocks_production_multi_node_promotion() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-mismatched-previous-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        previous_summary = workspace / "previous-beta-candidate-summary.json"
        write_valid_previous_candidate_summary(previous_summary)
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, out_dir),
            mode="production-beta",
            artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
            require_live_network=True,
            require_sandbox_provider_tests=True,
            skip_gradle=False,
            skip_full_build=False,
            allow_dirty_workspace=False,
            require_multi_node_soak=True,
            previous_summary=previous_summary,
        )
        write_minimal_promotion_artifacts(out_dir)
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        state.signing_profile = production_signing_profile()
        mark_required_pipeline_stages_passed(state)
        summaries = passing_promotion_summaries()
        for scenario in summaries["multiNodeBetaSoak"]["scenarios"]:
            if scenario.get("id") == "upgrade-from-previous-candidate":
                scenario["evidence"]["previousVersion"] = "different-beta"
                break

        promotion = evaluate_promotion(state, summaries)
        failed_ids = {gate["id"] for gate in promotion["gates"] if gate["status"] == "fail"}

        assert "multi-node-beta.previous-candidate-summary" in failed_ids, promotion
        assert "multi-node-beta.previous-candidate-upgrade-binding" in failed_ids, promotion
        assert promotion["promotionReady"] is False, promotion

        write_valid_previous_candidate_summary(previous_summary)
        supplied_previous_summary = read_json(previous_summary) or {}
        catalog = supplied_previous_summary.get("catalog")
        if isinstance(catalog, dict):
            catalog["stableChannelEdition"] = int(catalog.get("stableChannelEdition", 0)) + 10
        write_json(previous_summary, supplied_previous_summary)

        promotion = evaluate_promotion(state, passing_promotion_summaries())
        failed_ids = {gate["id"] for gate in promotion["gates"] if gate["status"] == "fail"}

        assert "multi-node-beta.previous-candidate-upgrade-binding" in failed_ids, promotion
        assert promotion["promotionReady"] is False, promotion

def assert_mismatched_current_version_blocks_production_multi_node_promotion() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-mismatched-current-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        previous_summary = workspace / "previous-beta-candidate-summary.json"
        write_valid_previous_candidate_summary(previous_summary)
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, out_dir),
            mode="production-beta",
            artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
            require_live_network=True,
            require_sandbox_provider_tests=True,
            skip_gradle=False,
            skip_full_build=False,
            allow_dirty_workspace=False,
            require_multi_node_soak=True,
            previous_summary=previous_summary,
        )
        write_minimal_promotion_artifacts(out_dir)
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        state.signing_profile = production_signing_profile()
        mark_required_pipeline_stages_passed(state)
        summaries = passing_promotion_summaries()
        for scenario in summaries["multiNodeBetaSoak"]["scenarios"]:
            if scenario.get("id") == "upgrade-from-previous-candidate":
                scenario["evidence"]["currentVersion"] = "different-current"
                break

        promotion = evaluate_promotion(state, summaries)
        failed_ids = {gate["id"] for gate in promotion["gates"] if gate["status"] == "fail"}

        assert "multi-node-beta.previous-candidate-summary" in failed_ids, promotion
        assert "multi-node-beta.previous-candidate-upgrade-binding" in failed_ids, promotion
        assert promotion["promotionReady"] is False, promotion

def assert_mismatched_current_catalog_blocks_production_multi_node_promotion() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-mismatched-current-catalog-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        previous_summary = workspace / "previous-beta-candidate-summary.json"
        write_valid_previous_candidate_summary(previous_summary)
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, out_dir),
            mode="production-beta",
            artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
            require_live_network=True,
            require_sandbox_provider_tests=True,
            skip_gradle=False,
            skip_full_build=False,
            allow_dirty_workspace=False,
            require_multi_node_soak=True,
            previous_summary=previous_summary,
        )
        write_minimal_promotion_artifacts(out_dir)
        write_json(
            out_dir / "catalog/channel-metadata.json",
            {
                "schemaVersion": 1,
                "channel": "stable",
                "stableChannelEdition": 501,
                "betaChannelEdition": 777,
            },
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        state.signing_profile = production_signing_profile()
        mark_required_pipeline_stages_passed(state)

        def promotion_summaries_with_upgrade_evidence(**updates: Any) -> dict[str, Any]:
            summaries = passing_promotion_summaries()
            for scenario in summaries["multiNodeBetaSoak"]["scenarios"]:
                if scenario.get("id") == "upgrade-from-previous-candidate":
                    evidence = scenario["evidence"]
                    evidence["currentCatalogChannel"] = "stable"
                    evidence["currentCatalogEdition"] = 501
                    evidence.update(updates)
                    return summaries
            raise AssertionError("previous-candidate upgrade scenario is missing")

        promotion = evaluate_promotion(state, promotion_summaries_with_upgrade_evidence())
        failed_ids = {gate["id"] for gate in promotion["gates"] if gate["status"] == "fail"}
        assert "multi-node-beta.previous-candidate-upgrade-binding" not in failed_ids, promotion

        for updates in (
            {"currentCatalogChannel": "beta", "currentCatalogEdition": 777},
            {"currentCatalogEdition": 500},
        ):
            promotion = evaluate_promotion(state, promotion_summaries_with_upgrade_evidence(**updates))
            failed_ids = {gate["id"] for gate in promotion["gates"] if gate["status"] == "fail"}

            assert "multi-node-beta.previous-candidate-summary" in failed_ids, promotion
            assert "multi-node-beta.previous-candidate-upgrade-binding" in failed_ids, promotion
            assert promotion["promotionReady"] is False, promotion

def assert_multi_node_mode_is_only_forwarded_when_overridden() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-multi-node-mode-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        cert_out = workspace / "build/certification"
        config_path = workspace / "topology.json"
        captured_args: list[list[str]] = []

        def fake_run_command(
            state: PipelineState,
            name: str,
            args: list[str],
            env: dict[str, str] | None = None,
            timeout_seconds: int = 0,
            allow_failure: bool = False,
        ) -> CommandResult:
            del state, env, timeout_seconds, allow_failure
            captured_args.append(list(args))
            return CommandResult(name, list(args), 0, 1, "", "")

        original_run_command = globals()["run_command"]
        try:
            globals()["run_command"] = fake_run_command
            settings = dataclasses.replace(
                cleanup_test_settings(workspace, out_dir),
                run_multi_node_soak=True,
                multi_node_soak_config=config_path,
                multi_node_mode=None,
            )
            run_release_certification(PipelineState(settings, "self-test", utc_now(), [], [], []), {}, cert_out)
            default_multi_node_args = next(
                args for args in captured_args if "multi-node-beta" in args and "run" in args
            )
            assert "--mode" not in default_multi_node_args, default_multi_node_args

            override_settings = dataclasses.replace(settings, multi_node_mode="hybrid")
            override_start = len(captured_args)
            run_release_certification(
                PipelineState(override_settings, "self-test", utc_now(), [], [], []),
                {},
                cert_out,
            )
            override_multi_node_args = next(
                args
                for args in captured_args[override_start:]
                if "multi-node-beta" in args and "run" in args
            )
            assert "--mode" in override_multi_node_args, override_multi_node_args
            mode_index = override_multi_node_args.index("--mode")
            assert override_multi_node_args[mode_index + 1] == "hybrid", override_multi_node_args
        finally:
            globals()["run_command"] = original_run_command

def assert_previous_candidate_summary_is_not_forwarded_as_cert_history() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-previous-history-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        cert_out = workspace / "build/certification"
        previous_candidate = workspace / "previous-beta-candidate-summary.json"
        release_history = workspace / "previous-release-certification-summary.json"
        write_valid_previous_candidate_summary(previous_candidate)
        write_json(
            release_history,
            {
                "schemaVersion": 1,
                "tool": release_certification.TOOL_NAME,
                "status": "pass",
                "evidence": [{"id": "interop.smoke", "status": "pass"}],
            },
        )
        captured_args: list[list[str]] = []

        def fake_run_command(
            state: PipelineState,
            name: str,
            args: list[str],
            env: dict[str, str] | None = None,
            timeout_seconds: int = 0,
            allow_failure: bool = False,
        ) -> CommandResult:
            del state, env, timeout_seconds, allow_failure
            captured_args.append(list(args))
            return CommandResult(name, list(args), 0, 1, "", "")

        original_run_command = globals()["run_command"]
        try:
            globals()["run_command"] = fake_run_command
            candidate_settings = dataclasses.replace(
                cleanup_test_settings(workspace, out_dir),
                mode="release-candidate",
                previous_summary=previous_candidate,
            )
            run_release_certification(
                PipelineState(candidate_settings, "self-test", utc_now(), [], [], []),
                {},
                cert_out,
            )
            assert "--require-history" not in captured_args[-1], captured_args[-1]
            assert "--previous-summary" not in captured_args[-1], captured_args[-1]

            required_candidate_settings = dataclasses.replace(
                candidate_settings,
                require_history=True,
            )
            run_release_certification(
                PipelineState(
                    required_candidate_settings,
                    "self-test",
                    utc_now(),
                    [],
                    [],
                    [],
                ),
                {},
                cert_out,
            )
            assert "--require-history" in captured_args[-1], captured_args[-1]
            assert "--previous-summary" not in captured_args[-1], captured_args[-1]

            history_settings = dataclasses.replace(
                cleanup_test_settings(workspace, out_dir),
                mode="release-candidate",
                previous_summary=release_history,
                require_history=True,
            )
            run_release_certification(
                PipelineState(history_settings, "self-test", utc_now(), [], [], []),
                {},
                cert_out,
            )
            assert "--previous-summary" in captured_args[-1], captured_args[-1]
            previous_index = captured_args[-1].index("--previous-summary")
            assert captured_args[-1][previous_index + 1] == str(release_history), captured_args[-1]
        finally:
            globals()["run_command"] = original_run_command

def assert_multi_node_paths_resolve_from_workspace() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-multi-node-paths-") as temp_name:
        workspace = Path(temp_name) / "repo"
        outside = Path(temp_name) / "outside"
        make_self_test_workspace(workspace)
        outside.mkdir(parents=True)
        summary_path = workspace / "build/multi-node/summary.json"
        config_path = workspace / "tools/release-certification/fixtures/self-test-multi-node-beta-soak.json"
        write_text(summary_path, "{}\n")
        write_text(config_path, "{}\n")
        parser = build_parser()
        original_cwd = Path.cwd()
        try:
            os.chdir(outside)
            settings = settings_from_args(
                parser.parse_args(
                    [
                        "--workspace-root",
                        str(workspace),
                        "--out-dir",
                        "build/production-beta",
                        "--mode",
                        "developer-dry-run",
                        "--artifact-base-uri",
                        "https://downloads.crypta.invalid/self-test",
                        "--multi-node-soak-summary",
                        "build/multi-node/summary.json",
                        "--multi-node-soak-config",
                        "tools/release-certification/fixtures/self-test-multi-node-beta-soak.json",
                    ]
                )
            )
        finally:
            os.chdir(original_cwd)
        assert settings.multi_node_soak_summary == summary_path.resolve(), settings.multi_node_soak_summary
        assert settings.multi_node_soak_config == config_path.resolve(), settings.multi_node_soak_config
        assert settings.multi_node_mode is None, settings.multi_node_mode

def assert_production_beta_cli_rejects_unsafe_strict_inputs() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-cli-strict-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        parser = build_parser()
        summary_path = workspace / "multi-node-summary.json"
        previous_summary_path = workspace / "previous-beta-candidate-summary.json"
        history_summary_path = workspace / "previous-release-certification-summary.json"
        write_json(summary_path, passing_promotion_summaries()["multiNodeBetaSoak"])
        write_valid_previous_candidate_history_pair(previous_summary_path, history_summary_path)
        base_args = [
            "--workspace-root",
            str(workspace),
            "--out-dir",
            "build/production-beta",
            "--mode",
            "production-beta",
            "--artifact-base-uri",
            "https://downloads.crypta.network/production-beta/self-test",
            "--previous-summary",
            str(previous_summary_path.relative_to(workspace)),
            "--previous-release-certification-summary",
            str(history_summary_path.relative_to(workspace)),
        ]
        stale_history_summary_path = workspace / "stale-previous-release-certification-summary.json"
        write_valid_release_certification_history_summary(stale_history_summary_path)
        stale_history_summary = read_json(stale_history_summary_path) or {}
        stale_history_summary["version"] = "stale-previous-beta"
        write_json(stale_history_summary_path, stale_history_summary)
        try:
            settings_from_args(
                parser.parse_args(
                    [
                        "--workspace-root",
                        str(workspace),
                        "--out-dir",
                        "build/production-beta",
                        "--mode",
                        "production-beta",
                        "--artifact-base-uri",
                        "https://downloads.crypta.network/production-beta/self-test",
                        "--multi-node-soak-summary",
                        str(summary_path.relative_to(workspace)),
                        "--previous-summary",
                        str(previous_summary_path.relative_to(workspace)),
                        "--previous-release-certification-summary",
                        str(stale_history_summary_path.relative_to(workspace)),
                    ]
                )
            )
        except SystemExit as exc:
            assert "source.releaseCertificationSummaryDigest" in str(exc), exc
        else:
            raise AssertionError("production-beta accepted stale previous release-certification history")
        default_history_summary_path = workspace / release_certification.DEFAULT_HISTORY_DIR / "latest-summary.json"
        write_valid_release_certification_history_summary(default_history_summary_path)
        default_history_summary = read_json(default_history_summary_path) or {}
        default_history_summary["version"] = "stale-default-previous-beta"
        write_json(default_history_summary_path, default_history_summary)
        try:
            settings_from_args(
                parser.parse_args(
                    [
                        "--workspace-root",
                        str(workspace),
                        "--out-dir",
                        "build/production-beta",
                        "--mode",
                        "production-beta",
                        "--artifact-base-uri",
                        "https://downloads.crypta.network/production-beta/self-test",
                        "--multi-node-soak-summary",
                        str(summary_path.relative_to(workspace)),
                        "--previous-summary",
                        str(previous_summary_path.relative_to(workspace)),
                    ]
                )
            )
        except SystemExit as exc:
            assert "source.releaseCertificationSummaryDigest" in str(exc), exc
        else:
            raise AssertionError("production-beta accepted stale default previous release-certification history")
        try:
            settings_from_args(
                parser.parse_args(
                    [
                        "--workspace-root",
                        str(workspace),
                        "--out-dir",
                        "build/production-beta",
                        "--mode",
                        "production-beta",
                        "--artifact-base-uri",
                        "https://downloads.crypta.network/production-beta/self-test",
                        "--multi-node-soak-summary",
                        str(summary_path.relative_to(workspace)),
                        "--previous-release-certification-summary",
                        str(history_summary_path.relative_to(workspace)),
                    ]
                )
            )
        except SystemExit as exc:
            assert "requires --previous-summary" in str(exc), exc
        else:
            raise AssertionError("production-beta accepted missing previous beta candidate summary")

        for extra_args, expected in (
            (
                ["--skip-gradle", "--multi-node-soak-summary", str(summary_path.relative_to(workspace))],
                "cannot use --skip-gradle or --skip-full-build",
            ),
            ([], "requires --multi-node-soak-summary or explicit --run-multi-node-soak"),
            (
                [
                    "--run-multi-node-soak",
                    "--multi-node-soak-config",
                    "topology.json",
                    "--multi-node-mode",
                    "simulated",
                ],
                "cannot use --multi-node-mode simulated",
            ),
            (
                [
                    "--run-multi-node-soak",
                    "--multi-node-soak-config",
                    "tools/release-certification/fixtures/self-test-multi-node-beta-soak.json",
                ],
                "cannot use the self-test multi-node soak topology",
            ),
        ):
            try:
                settings_from_args(parser.parse_args([*base_args, *extra_args]))
            except SystemExit as exc:
                assert expected in str(exc), exc
            else:
                raise AssertionError(f"production-beta accepted unsafe input combination: {extra_args}")

def create_git_tracked_output_target(workspace: Path) -> Path | None:
    tracked_dir = workspace / "platform-appcatalog"
    write_text(tracked_dir / "source.txt", "tracked source data\n")
    if not run_git(workspace, "init"):
        return None
    if not run_git(workspace, "add", "."):
        return None
    if not run_git(
        workspace,
        "-c",
        "user.name=Crypta Self Test",
        "-c",
        "user.email=self-test@crypta.invalid",
        "commit",
        "-m",
        "self-test workspace",
    ):
        return None
    return tracked_dir

def assert_cleanup_refuses_protected_workspace_paths() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-clean-protected-") as temp_name:
        workspace = Path(temp_name) / "repo"
        docs_dir = workspace / "docs"
        docs_dir.mkdir(parents=True)
        write_text(docs_dir / "important.md", "do not delete\n")
        settings = cleanup_test_settings(workspace, docs_dir)
        try:
            ensure_safe_out_dir(settings)
        except SystemExit as exc:
            assert "protected workspace path" in str(exc), exc
        else:
            raise AssertionError("cleanup accepted a protected workspace path")
        assert (docs_dir / "important.md").is_file(), "protected workspace path was deleted"

def assert_cleanup_refuses_arbitrary_existing_directory_without_sentinel() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-clean-arbitrary-") as temp_name:
        workspace = Path(temp_name) / "repo"
        out_dir = workspace / "release-artifacts"
        out_dir.mkdir(parents=True)
        write_text(out_dir / "important.txt", "do not delete\n")
        settings = cleanup_test_settings(workspace, out_dir)
        try:
            ensure_safe_out_dir(settings)
        except SystemExit as exc:
            assert "without a production beta sentinel" in str(exc), exc
        else:
            raise AssertionError("cleanup accepted an arbitrary existing directory without a sentinel")
        assert (out_dir / "important.txt").is_file(), "arbitrary workspace directory was deleted"

def assert_no_clean_refuses_arbitrary_existing_directory_without_sentinel() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-no-clean-arbitrary-") as temp_name:
        workspace = Path(temp_name) / "repo"
        out_dir = workspace / "release-artifacts"
        write_text(out_dir / "build/important-build-output.txt", "do not delete\n")
        write_text(out_dir / "reports/important-report.txt", "do not delete\n")
        write_text(out_dir / "dist/important-dist.txt", "do not delete\n")
        settings = dataclasses.replace(cleanup_test_settings(workspace, out_dir), clean_out_dir=False)
        try:
            ensure_safe_out_dir(settings)
        except SystemExit as exc:
            assert "without a production beta sentinel" in str(exc), exc
        else:
            raise AssertionError("no-clean output validation accepted an arbitrary existing directory without a sentinel")
        assert (out_dir / "build/important-build-output.txt").is_file(), "no-clean build subtree was deleted"
        assert (out_dir / "reports/important-report.txt").is_file(), "no-clean reports subtree was deleted"
        assert (out_dir / "dist/important-dist.txt").is_file(), "no-clean dist subtree was deleted"
        assert not cleanup_sentinel(out_dir).exists(), "sentinel was written into an untrusted no-clean output directory"

def assert_no_clean_refuses_tracked_directory_before_sentinel() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-clean-tracked-no-clean-") as temp_name:
        workspace = Path(temp_name) / "repo"
        tracked_dir = create_git_tracked_output_target(workspace)
        if tracked_dir is None:
            return
        settings = dataclasses.replace(cleanup_test_settings(workspace, tracked_dir), clean_out_dir=False)
        try:
            ensure_safe_out_dir(settings)
        except SystemExit as exc:
            assert "without a production beta sentinel" in str(exc), exc
        else:
            raise AssertionError("no-clean output validation accepted a git-tracked source directory")
        assert (tracked_dir / "source.txt").is_file(), "tracked source directory was modified"
        assert not cleanup_sentinel(tracked_dir).exists(), "sentinel was written into a tracked source directory"

def assert_cleanup_refuses_tracked_directory_even_with_sentinel() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-clean-tracked-sentinel-") as temp_name:
        workspace = Path(temp_name) / "repo"
        tracked_dir = create_git_tracked_output_target(workspace)
        if tracked_dir is None:
            return
        write_text(cleanup_sentinel(tracked_dir), "Crypta production beta release output directory.\n")
        settings = cleanup_test_settings(workspace, tracked_dir)
        try:
            ensure_safe_out_dir(settings)
        except SystemExit as exc:
            assert "contains git-tracked files" in str(exc), exc
        else:
            raise AssertionError("sentinel authorized cleanup of a git-tracked source directory")
        assert (tracked_dir / "source.txt").is_file(), "tracked source directory was deleted"
        assert cleanup_sentinel(tracked_dir).is_file(), "test sentinel unexpectedly disappeared"

def assert_cleanup_refuses_unknown_tracked_file_status() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-clean-unknown-tracked-") as temp_name:
        workspace = Path(temp_name) / "repo"
        out_dir = workspace / "build/production-beta-unknown-tracked"
        out_dir.mkdir(parents=True)
        write_text(cleanup_sentinel(out_dir), "Crypta production beta release output directory.\n")
        write_text(out_dir / "important.txt", "do not delete\n")
        settings = cleanup_test_settings(workspace, out_dir)
        original_git_tracked_files_under = globals()["git_tracked_files_under"]
        try:
            globals()["git_tracked_files_under"] = lambda _workspace, _out_dir: None
            try:
                ensure_safe_out_dir(settings)
            except SystemExit as exc:
                assert "git-tracked file status could not be verified" in str(exc), exc
            else:
                raise AssertionError("cleanup accepted an output directory with unknown git-tracked file status")
        finally:
            globals()["git_tracked_files_under"] = original_git_tracked_files_under
        assert (out_dir / "important.txt").is_file(), "output directory was deleted despite unknown tracked-file status"
        assert cleanup_sentinel(out_dir).is_file(), "test sentinel unexpectedly disappeared"

def assert_cleanup_allows_default_release_output_prefix() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-clean-default-") as temp_name:
        workspace = Path(temp_name) / "repo"
        out_dir = workspace / "build/production-beta-self-test"
        out_dir.mkdir(parents=True)
        if not run_git(workspace, "init"):
            return
        write_text(out_dir / "stale.txt", "delete me\n")
        settings = cleanup_test_settings(workspace, out_dir)
        ensure_safe_out_dir(settings)
        assert not (out_dir / "stale.txt").exists(), "default release output prefix was not cleaned"
        assert cleanup_sentinel(out_dir).is_file(), "release output sentinel was not written"

def assert_cleanup_allows_sentinel_directory() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-clean-sentinel-") as temp_name:
        workspace = Path(temp_name) / "repo"
        out_dir = workspace / "custom-output"
        out_dir.mkdir(parents=True)
        if not run_git(workspace, "init"):
            return
        write_text(cleanup_sentinel(out_dir), "Crypta production beta release output directory.\n")
        write_text(out_dir / "stale.txt", "delete me\n")
        settings = cleanup_test_settings(workspace, out_dir)
        ensure_safe_out_dir(settings)
        assert not (out_dir / "stale.txt").exists(), "sentinel output directory was not cleaned"
        assert cleanup_sentinel(out_dir).is_file(), "release output sentinel was not restored"

def assert_strict_skip_gradle_requires_emergency_build_flag() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-skip-gradle-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "build/production-beta",
            mode="release-candidate",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=False,
            allow_dirty_workspace=False,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=60,
            clean_out_dir=True,
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        run_gradle(state, "gradle-self-test", ["help"])
        assert any("release-candidate mode cannot skip Gradle stage" in failure for failure in state.failures), state.failures

        emergency_settings = dataclasses.replace(settings, emergency_skip_build=True)
        emergency_state = PipelineState(emergency_settings, "self-test", utc_now(), [], [], [])
        run_gradle(emergency_state, "gradle-self-test", ["help"])
        assert not emergency_state.failures, emergency_state.failures

def assert_unknown_workspace_status_fails_strict_modes() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-unknown-workspace-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        for mode in ("release-candidate", "production-beta"):
            settings = Settings(
                workspace_root=workspace,
                out_dir=workspace / f"build/{mode}",
                mode=mode,
                catalog_channel="stable",
                artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
                require_live_network=False,
                require_sandbox_provider_tests=False,
                skip_gradle=True,
                skip_full_build=True,
                use_fixture_evidence=False,
                allow_dirty_workspace=True,
                emergency_skip_live_network=True,
                emergency_skip_build=True,
                allow_test_signing_in_production=False,
                previous_summary=None,
                waiver_file=None,
                timeout_seconds=60,
                clean_out_dir=True,
            )
            state = PipelineState(settings, "self-test", utc_now(), [], [], [])
            check_workspace_clean(state)
            assert state.workspace_status_known is False, state
            assert any("requires a readable git workspace status" in failure for failure in state.failures), state.failures

def assert_catalog_signature_and_timestamps_are_canonical() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-catalog-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        write_fake_crypta_app_cli(workspace)
        policy_file = workspace / FIRST_PARTY_MAINTENANCE_POLICY_FILE
        policy = json.loads(policy_file.read_text(encoding="utf-8"))
        policy["apps"]["queue-manager"]["minimumCryptaVersion"] = "41"
        policy["apps"]["queue-manager"]["maximumCryptaVersion"] = "43"
        write_json(policy_file, policy)
        out_dir = workspace / "build/production-beta"
        app_dir = out_dir / "build/staged-apps/queue-manager"
        write_text(
            app_dir / "cryptad-app.properties",
            "\n".join(
                [
                    "app.id=queue-manager",
                    "app.name=Queue Manager",
                    "app.version=1.2.3",
                    "app.permissions=queue.read",
                    "",
                ]
            ),
        )
        started_at = "2026-06-15T12:34:56Z"
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
            use_fixture_evidence=False,
            allow_dirty_workspace=True,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=60,
            clean_out_dir=True,
        )
        state = PipelineState(settings, "self-test", started_at, [], [], [])
        profile = SigningProfile(
            kind="test",
            generated_test_keys=True,
            env={
                "CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64": "AQID",
                "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64": "BAUG",
            },
            private_paths=[],
            app_key_id="app-key",
            reviewer_key_id="reviewer-key",
            review_policy_id="crypta-app-review-v1",
            review_policy_version="1",
        )
        package_catalog_and_reviews(state, profile, {"queue-manager": app_dir}, workspace / "work")
        assert not state.failures, state.failures
        canonical = out_dir / "catalog" / CANONICAL_CATALOG_SIGNATURE
        alias = out_dir / "catalog" / RELEASE_CATALOG_SIGNATURE_ALIAS
        assert canonical.is_file(), canonical
        assert alias.is_file(), alias
        assert (
            canonical.read_bytes() == alias.read_bytes()
        ), "catalog signature alias diverged from canonical sidecar"
        catalog_text = (out_dir / "catalog/first-party-catalog.properties").read_text(encoding="utf-8")
        assert f"generatedAt={started_at}" in catalog_text
        assert (
            "bundle.uri=https://downloads.crypta.invalid/self-test/build/app-bundles/queue-manager-1.2.3.zip"
            in catalog_text
        ), catalog_text
        assert "minimumCryptaVersion=41" in catalog_text, catalog_text
        assert "maximumCryptaVersion=43" in catalog_text, catalog_text
        assert "maintenance.owner=crypta-core" in catalog_text, catalog_text
        assert "maintenance.supportLevel=core" in catalog_text, catalog_text
        assert "/apps/queue-manager-1.2.3.zip" not in catalog_text, catalog_text
        channel_metadata = json.loads(
            (out_dir / "catalog/channel-metadata.json").read_text(encoding="utf-8")
        )
        assert channel_metadata["maintenancePolicyComplete"] is True, channel_metadata
        assert channel_metadata["apps"][0]["maintenance"]["owner"] == "crypta-core", (
            channel_metadata
        )
        assert f"reviewedAt={started_at}" in (
            out_dir / "reviews/review-receipts/queue-manager-review-receipt.properties"
        ).read_text(encoding="utf-8")

def assert_reviewer_public_key_file_resolves_from_workspace() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-reviewer-key-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        write_bytes(workspace / "protected/reviewer-public.der", b"\x01\x02\x03")
        profile = SigningProfile(
            kind="production",
            generated_test_keys=False,
            env={"CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE": "protected/reviewer-public.der"},
            private_paths=[],
            app_key_id="app-key",
            reviewer_key_id="reviewer-key",
            review_policy_id="crypta-app-review-v1",
            review_policy_version="1",
        )
        output = workspace / "work/trusted-reviewers.properties"
        outside = Path(temp_name) / "outside"
        outside.mkdir()
        original_cwd = Path.cwd()
        try:
            os.chdir(outside)
            write_trusted_reviewer_keys(output, profile, workspace)
        finally:
            os.chdir(original_cwd)
        trusted_text = output.read_text(encoding="utf-8")
        assert "reviewer.1.public.key.base64=AQID" in trusted_text, trusted_text

def assert_protected_secret_file_redaction_resolves_from_workspace() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-redaction-secret-file-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        secret_bytes = b"\x30\x82\x01\x00workspace-relative-private-key-material-9f4b6a"
        write_redaction_fixture_bytes(workspace / "protected/app-signing-private.der", secret_bytes)
        out_dir = workspace / "build/redaction"
        write_redaction_fixture_bytes(out_dir / "neutral.bin", b"prefix-" + secret_bytes + b"-suffix")
        write_redaction_fixture_text(
            out_dir / "neutral-base64.txt", base64.b64encode(secret_bytes).decode("ascii") + "\n"
        )
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
            timeout_seconds=60,
            clean_out_dir=False,
        )
        outside = Path(temp_name) / "outside"
        outside.mkdir()
        saved_secret_file = os.environ.get("CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE")
        original_cwd = Path.cwd()
        try:
            os.environ["CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE"] = "protected/app-signing-private.der"
            os.chdir(outside)
            findings = scan_tree(out_dir, settings, include_dist=True)
        finally:
            os.chdir(original_cwd)
            if saved_secret_file is None:
                os.environ.pop("CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE", None)
            else:
                os.environ["CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE"] = saved_secret_file
        protected_paths = {
            finding["path"]
            for finding in findings
            if finding.get("kind") == "protected-secret-value"
        }
        assert {"neutral.bin", "neutral-base64.txt"}.issubset(protected_paths), findings

def assert_no_clean_rerun_drops_stale_dist_files() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-stale-dist-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        if not run_git(workspace, "init"):
            return
        out_dir = workspace / "build/production-beta"
        write_text(cleanup_sentinel(out_dir), "Crypta production beta release output directory.\n")
        write_redaction_fixture_text(out_dir / "dist/leak.txt", "CRYPTAD_APP_TOKEN=abc1234567890abcdef\n")
        write_text(out_dir / "build/app-bundles/stale-old-version.zip", "stale bundle from an earlier run\n")
        write_text(out_dir / "reports/stale-report.txt", "stale report from an earlier run\n")
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
            clean_out_dir=False,
        )
        summary, exit_code = run_pipeline(settings)
        assert exit_code == 0, summary
        assert summary["redaction"]["status"] == "pass", summary
        assert not (out_dir / "dist/leak.txt").exists(), "stale dist leak survived the rerun"
        assert not (out_dir / "build/app-bundles/stale-old-version.zip").exists(), "stale bundle survived the rerun"
        assert not (out_dir / "reports/stale-report.txt").exists(), "stale report survived the rerun"
        checksum_text = dist_checksums_path(settings).read_text(encoding="utf-8")
        assert "leak.txt" not in checksum_text, checksum_text
        archive_path = out_dir / summary["artifacts"]["distArchive"]
        with tarfile.open(archive_path, "r:gz") as archive:
            names = set(archive.getnames())
        assert "build/app-bundles/stale-old-version.zip" not in names, names
        assert "reports/stale-report.txt" not in names, names

def run_git(workspace: Path, *args: str) -> bool:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=str(workspace),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0

def assert_custom_out_dir_does_not_dirty_workspace_before_check() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-custom-out-dir-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        if not run_git(workspace, "init"):
            return
        if not run_git(workspace, "add", "."):
            return
        if not run_git(
            workspace,
            "-c",
            "user.name=Crypta Self Test",
            "-c",
            "user.email=self-test@crypta.invalid",
            "commit",
            "-m",
            "self-test workspace",
        ):
            return
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "release-artifacts",
            mode="developer-dry-run",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=True,
            allow_dirty_workspace=False,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=120,
            clean_out_dir=True,
        )
        summary, exit_code = run_pipeline(settings)
        assert exit_code == 0, summary
        assert summary["workspaceStatusKnown"] is True, summary
        assert summary["dirtyWorkspace"] is False, summary
        assert cleanup_sentinel(settings.out_dir).is_file(), "custom output sentinel was not written"

def assert_post_artifact_workspace_recheck_detects_mutation() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-post-build-dirty-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        if not run_git(workspace, "init"):
            return
        if not run_git(workspace, "add", "."):
            return
        if not run_git(
            workspace,
            "-c",
            "user.name=Crypta Self Test",
            "-c",
            "user.email=self-test@crypta.invalid",
            "commit",
            "-m",
            "self-test workspace",
        ):
            return
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "release-artifacts",
            mode="production-beta",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=True,
            require_sandbox_provider_tests=True,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=True,
            allow_dirty_workspace=False,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=120,
            clean_out_dir=True,
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        check_workspace_clean(state)
        assert state.workspace_status_known is True, state
        assert state.dirty_workspace is False, state
        assert not state.failures, state.failures

        ensure_safe_out_dir(settings)
        write_text(settings.out_dir / "reports/generated.txt", "generated release output\n")
        check_workspace_clean(state, "post-artifact-build")
        assert state.dirty_workspace is False, state
        assert not state.failures, state.failures

        build_file = workspace / "build.gradle.kts"
        write_text(build_file, build_file.read_text(encoding="utf-8") + "\n// post-build mutation\n")
        check_workspace_clean(state, "post-artifact-build")
        assert state.dirty_workspace is True, state
        assert any("after build/staging" in failure for failure in state.failures), state.failures

def assert_dirty_workspace_state_is_sticky_across_checks() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-sticky-dirty-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        if not run_git(workspace, "init"):
            return
        if not run_git(workspace, "add", "."):
            return
        if not run_git(
            workspace,
            "-c",
            "user.name=Crypta Self Test",
            "-c",
            "user.email=self-test@crypta.invalid",
            "commit",
            "-m",
            "self-test workspace",
        ):
            return
        build_file = workspace / "build.gradle.kts"
        original_build_text = build_file.read_text(encoding="utf-8")
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "release-artifacts",
            mode="production-beta",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=False,
            allow_dirty_workspace=True,
            emergency_skip_live_network=True,
            emergency_skip_build=True,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=120,
            clean_out_dir=True,
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])

        write_text(build_file, original_build_text + "\n// temporary dirty state\n")
        check_workspace_clean(state)
        assert state.dirty_workspace is True, state
        assert not state.failures, state.failures

        write_text(build_file, original_build_text)
        check_workspace_clean(state, "post-artifact-build")
        assert state.dirty_workspace is True, state
        promotion = evaluate_promotion(state, {})
        assert promotion_gate_by_id(promotion, "workspace.clean-production-beta")["status"] == "fail", promotion
        assert promotion["nonRelease"] is True, promotion
        assert promotion["promotionReady"] is False, promotion

def assert_project_version_parser_accepts_release_build_numbers() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-version-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        build_file = workspace / "build.gradle.kts"

        write_text(build_file, 'version = "41"\n')
        assert read_project_version(workspace) == "41"

        write_text(build_file, "version = 42\n")
        assert read_project_version(workspace) == "42"

        write_text(build_file, "version = 43 // release build\n")
        assert read_project_version(workspace) == "43"

        write_text(build_file, "version = releaseBuild\n")
        try:
            read_project_version(workspace)
        except SystemExit as exc:
            assert "Unable to parse project version" in str(exc), exc
        else:
            raise AssertionError("read_project_version accepted an unsupported version assignment")

def assert_maintenance_policy_resolves_from_workspace() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-maintenance-workspace-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        settings = cleanup_test_settings(workspace, workspace / "build/policy-copy")
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        policy_file = first_party_maintenance_policy_file(state)
        policy = json.loads(policy_file.read_text(encoding="utf-8"))
        for app_id in APP_IDS:
            policy["apps"][app_id]["maximumCryptaVersion"] = "43"
        write_json(policy_file, policy)

        loaded = load_first_party_maintenance_policy(state)
        copy_first_party_maintenance_policy_input(state)
        copy_first_party_beta_readiness_input(state)
        copied_policy = json.loads(
            (settings.out_dir / "inputs/first-party-app-maintenance-policy.json").read_text(
                encoding="utf-8"
            )
        )

        assert not state.failures, state.failures
        assert loaded["queue-manager"]["maximumCryptaVersion"] == "43", loaded
        assert copied_policy["apps"]["queue-manager"]["maximumCryptaVersion"] == "43", (
            copied_policy
        )

def assert_missing_maintenance_policy_warns_in_dry_run_and_fails_strict_modes() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-maintenance-policy-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        original_policy = globals()["FIRST_PARTY_MAINTENANCE_POLICY_FILE"]
        try:
            globals()["FIRST_PARTY_MAINTENANCE_POLICY_FILE"] = (
                workspace / "tools/release-certification/missing-policy.json"
            )
            dry_run_settings = cleanup_test_settings(workspace, workspace / "build/dry-run")
            dry_run_state = PipelineState(dry_run_settings, "self-test", utc_now(), [], [], [])
            assert load_first_party_maintenance_policy(dry_run_state) == {}
            assert dry_run_state.warnings, dry_run_state
            assert str(workspace) not in json.dumps(dry_run_state.warnings), dry_run_state.warnings
            assert "<repo>/tools/release-certification/missing-policy.json" in dry_run_state.warnings[0], (
                dry_run_state.warnings
            )
            assert not dry_run_state.failures, dry_run_state

            strict_settings = dataclasses.replace(
                dry_run_settings,
                mode="release-candidate",
                allow_dirty_workspace=False,
                emergency_skip_build=True,
            )
            strict_state = PipelineState(strict_settings, "self-test", utc_now(), [], [], [])
            assert load_first_party_maintenance_policy(strict_state) == {}
            assert strict_state.failures, strict_state
            assert str(workspace) not in json.dumps(strict_state.failures), strict_state.failures
            assert "<repo>/tools/release-certification/missing-policy.json" in strict_state.failures[0], (
                strict_state.failures
            )
        finally:
            globals()["FIRST_PARTY_MAINTENANCE_POLICY_FILE"] = original_policy

def assert_incomplete_maintenance_policy_warns_in_dry_run_and_fails_strict_modes() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-incomplete-maintenance-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        policy_file = workspace / FIRST_PARTY_MAINTENANCE_POLICY_FILE
        policy = json.loads(policy_file.read_text(encoding="utf-8"))
        maintenance = policy["apps"]["queue-manager"]["maintenance"]
        maintenance.pop("ownerUri")
        maintenance.pop("supportUri")
        write_json(policy_file, policy)

        dry_run_settings = cleanup_test_settings(workspace, workspace / "build/dry-run")
        dry_run_state = PipelineState(dry_run_settings, "self-test", utc_now(), [], [], [])
        dry_run_policy = load_first_party_maintenance_policy(dry_run_state)
        assert "queue-manager" not in dry_run_policy, dry_run_policy
        assert dry_run_state.warnings, dry_run_state
        assert "ownerUri, supportUri" in dry_run_state.warnings[0], dry_run_state.warnings
        assert not dry_run_state.failures, dry_run_state

        strict_settings = dataclasses.replace(
            dry_run_settings,
            mode="release-candidate",
            allow_dirty_workspace=False,
            emergency_skip_build=True,
        )
        strict_state = PipelineState(strict_settings, "self-test", utc_now(), [], [], [])
        strict_policy = load_first_party_maintenance_policy(strict_state)
        assert "queue-manager" not in strict_policy, strict_policy
        assert strict_state.failures, strict_state
        assert "ownerUri, supportUri" in strict_state.failures[0], strict_state.failures

def assert_maintenance_policy_input_copy_redacts_invalid_values() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-maintenance-redaction-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        policy_file = workspace / FIRST_PARTY_MAINTENANCE_POLICY_FILE
        policy = json.loads(policy_file.read_text(encoding="utf-8"))
        unknown_app_id = str(workspace / "private-extra-app-token-secret")
        policy["apps"][unknown_app_id] = {
            "channel": "stable",
            "supportStatus": "supported",
            "deprecationStatus": "none",
            "maintenance": {},
        }
        app_policy = policy["apps"]["queue-manager"]
        app_policy["channel"] = str(workspace / "private-channel-token.txt")
        app_policy["supportStatus"] = "token=status-secret"
        app_policy["deprecationStatus"] = "USK@PRIVATE-DEPRECATION"
        app_policy["minimumCryptaVersion"] = str(workspace / "private-min-version.txt")
        app_policy["maximumCryptaVersion"] = "version-token=secret"
        maintenance = app_policy["maintenance"]
        maintenance["owner"] = "crypta-core token=owner-secret"
        maintenance["ownerUri"] = (
            "https://example.invalid/crypta/owners/core?token=owner-uri-secret"
        )
        maintenance["supportUri"] = (
            "https://example.invalid/crypta/apps/queue-manager/support?token=support-uri-secret"
        )
        maintenance["securityPolicy"] = "token=security-secret"
        write_json(policy_file, policy)

        settings = cleanup_test_settings(workspace, workspace / "build/redacted-policy-copy")
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        copy_first_party_maintenance_policy_input(state)
        copy_first_party_beta_readiness_input(state)
        copied_text = (
            settings.out_dir / "inputs/first-party-app-maintenance-policy.json"
        ).read_text(encoding="utf-8")
        loaded = load_first_party_maintenance_policy(state)
        warning_text = json.dumps(state.warnings + state.failures, sort_keys=True)

        assert "queue-manager" not in loaded, loaded
        assert state.warnings, state
        assert "invalid or unsafe fields" in warning_text, state.warnings
        assert "contains 1 unknown app id(s)" in warning_text, state.warnings
        assert "<redacted>" in copied_text, copied_text
        for forbidden in (
            "private-extra-app-token-secret",
            "private-channel-token.txt",
            "status-secret",
            "PRIVATE-DEPRECATION",
            "private-min-version.txt",
            "version-token",
            "owner-secret",
            "owner-uri-secret",
            "support-uri-secret",
            "security-secret",
            str(workspace),
        ):
            assert forbidden not in copied_text, f"maintenance input copy leaked {forbidden}"
            assert forbidden not in warning_text, f"maintenance warning leaked {forbidden}"

def assert_beta_readiness_input_copy_redacts_invalid_values() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-readiness-redaction-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        readiness_file = workspace / FIRST_PARTY_BETA_READINESS_FILE
        readiness = json.loads(readiness_file.read_text(encoding="utf-8"))
        readiness["evidenceId"] = "first-party-app.beta-quality-pass token=evidence-secret"
        readiness["apps"][str(workspace / "private-readiness-app-token-secret")] = {
            "betaReadiness": {"status": "ready"}
        }
        beta = readiness["apps"]["queue-manager"]["betaReadiness"]
        beta["status"] = "ready token=readiness-status-secret"
        beta["diagnostics"] = "Bearer readiness-diagnostic-secret"
        beta["schemaVersion"] = str(workspace / "schema-secret")
        beta["exportSupported"] = ["array-secret-supported"]
        beta["supportMetadata"] = {"value": "object-secret-required"}
        beta["accessibility"] = True
        write_json(readiness_file, readiness)

        settings = cleanup_test_settings(workspace, workspace / "build/redacted-readiness-copy")
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        copy_first_party_beta_readiness_input(state)
        copied_text = (
            settings.out_dir / "inputs/first-party-app-beta-readiness.json"
        ).read_text(encoding="utf-8")

        assert "<redacted>" in copied_text, copied_text
        for forbidden in (
            "evidence-secret",
            "private-readiness-app-token-secret",
            "readiness-status-secret",
            "readiness-diagnostic-secret",
            "schema-secret",
            "array-secret-supported",
            "object-secret-required",
            str(workspace),
        ):
            assert forbidden not in copied_text, f"readiness input copy leaked {forbidden}"

def assert_final_summary_emits_previous_candidate_metadata() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-previous-metadata-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, workspace / "build/production-beta"),
            mode="production-beta",
            artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
            require_live_network=True,
            require_sandbox_provider_tests=True,
            allow_dirty_workspace=False,
        )
        state = PipelineState(settings, "270", utc_now(), [], [], [])
        state.signing_profile = production_signing_profile()
        copy_first_party_maintenance_policy_input(state)
        copy_first_party_beta_readiness_input(state)
        create_fixture_artifacts(state)
        fixtures = workspace / "tools/release-certification/fixtures"
        app_platform_summary = read_json(fixtures / "self-test-app-platform-smoke.json")
        assert app_platform_summary is not None
        write_json(settings.out_dir / "evidence/app-platform-smoke.json", app_platform_summary)
        promotion = {
            "status": "pass",
            "promotionReady": True,
            "nonRelease": False,
            "failedGateCount": 0,
            "gates": [],
            "multiNodeBetaSoak": passing_promotion_summaries()["multiNodeBetaSoak"],
        }
        redaction_report = {
            "schemaVersion": 1,
            "status": "pass",
            "scannedRoot": "<release-out>",
            "findingCount": 0,
            "findings": [],
        }

        summary = build_final_summary(state, promotion, redaction_report, archive=None)
        metadata = summary.get("previousCandidateMetadata")
        assert isinstance(metadata, dict), summary
        assert set(multi_node_beta_soak.PREVIOUS_CANDIDATE_SOURCE_METADATA_FIELDS).issubset(
            metadata
        ), metadata
        assert metadata["catalog"]["catalogDigest"].startswith("sha256:"), metadata
        assert metadata["firstPartyApps"], metadata
        assert (
            summary["artifacts"]["firstPartyBetaReadiness"]
            == "inputs/first-party-app-beta-readiness.json"
        ), summary["artifacts"]

        previous_summary = multi_node_beta_soak.build_previous_candidate_summary(
            {
                "schemaVersion": 1,
                "tool": "release-certification",
                "version": state.version,
                "status": "pass",
                "releaseCandidatePassed": True,
                "metadata": {"gitCommit": "self-test-git-commit"},
                "evidence": [{"id": "self-test.previous", "status": "pass"}],
            },
            summary,
            release_certification_digest=multi_node_beta_soak.synthetic_full_digest(
                "self-test-release-certification",
                state.version,
            ),
            production_beta_digest=multi_node_beta_soak.synthetic_full_digest(
                "self-test-production-beta",
                state.version,
            ),
            generated_at=utc_now(),
        )
        errors = multi_node_beta_soak.validate_previous_beta_candidate_summary(
            previous_summary,
            production=True,
        )
        assert errors == [], errors

def run_self_test() -> None:
    assert_safe_copy_tree_rejects_symlink()
    assert_safe_copy_tree_rejects_symlinked_root()
    assert_redaction_rejects_release_output_symlink()
    assert_tarball_redaction_rejects_symlink_member()
    assert_blank_review_policy_env_uses_defaults()
    assert_fixture_signing_profile_ignores_ambient_env()
    assert_dirty_production_beta_is_non_promotable()
    assert_emergency_build_skip_is_non_promotable()
    assert_allow_test_signing_env_profile_is_non_release()
    assert_test_key_ids_without_escape_hatch_are_rejected()
    assert_failed_final_summary_clears_promotion_ready()
    assert_required_third_party_intake_requires_summary()
    assert_required_third_party_intake_uses_attached_summary_rows()
    assert_production_third_party_intake_rejects_non_release_summary()
    assert_production_third_party_intake_rejects_optional_non_release_summary()
    assert_release_candidate_third_party_intake_rejects_non_release_summary()
    assert_public_beta_support_feedback_evidence_is_critical()
    assert_waived_critical_evidence_is_accepted_without_redaction_findings()
    assert_developer_dry_run_exit_code_fails_on_recorded_failures()
    assert_security_release_notes_draft_artifact_requires_file()
    assert_security_response_summary_reads_combined_drill_details()
    assert_attached_security_drills_summary_is_bound_to_release_id()
    assert_invalid_attached_security_drills_summary_is_sanitized()
    assert_attached_security_drills_summary_preserves_artifacts()
    assert_stable_readiness_args_use_stable_waiver_file_only()
    assert_required_stable_readiness_removes_dist_refs_from_dashboard()
    assert_certification_failure_marks_dry_run_failed()
    assert_dashboard_args_use_security_drill_artifact_directory()
    assert_release_candidate_no_go_dashboard_preserves_summary_and_exit()
    assert_go_with_waivers_cannot_promote_failed_production_summary()
    assert_missing_go_no_go_dashboard_fails_summary_and_exit()
    assert_stale_go_no_go_dashboard_is_not_reused()
    assert_incomplete_go_no_go_dashboard_outputs_fail_summary_and_exit()
    assert_failed_go_no_go_redaction_fails_summary_and_exit()
    assert_attached_multi_node_summary_is_extracted()
    assert_stable_readiness_soak_inputs_are_timestamped()
    assert_stable_readiness_redaction_failure_updates_release_report()
    assert_release_redaction_update_preserves_dashboard_redaction_status()
    assert_platform_api_contract_snapshots_are_written_as_envelopes()
    assert_env_attached_multi_node_summary_is_extracted()
    assert_attached_multi_node_summary_is_not_marked_generated()
    assert_run_multi_node_soak_overrides_attached_env_summary()
    assert_generated_multi_node_soak_uses_previous_candidate_summary()
    assert_run_multi_node_soak_rejects_cli_summary()
    assert_attached_multi_node_safety_flags_block_promotion()
    assert_attached_multi_node_non_promotable_summary_blocks_promotion()
    assert_attached_multi_node_blockers_and_warnings_block_promotion()
    assert_missing_previous_summary_blocks_production_multi_node_promotion()
    assert_mismatched_previous_summary_blocks_production_multi_node_promotion()
    assert_mismatched_current_version_blocks_production_multi_node_promotion()
    assert_mismatched_current_catalog_blocks_production_multi_node_promotion()
    assert_multi_node_mode_is_only_forwarded_when_overridden()
    assert_previous_candidate_summary_is_not_forwarded_as_cert_history()
    assert_multi_node_paths_resolve_from_workspace()
    assert_production_beta_cli_rejects_unsafe_strict_inputs()
    assert_cleanup_refuses_protected_workspace_paths()
    assert_cleanup_refuses_arbitrary_existing_directory_without_sentinel()
    assert_no_clean_refuses_arbitrary_existing_directory_without_sentinel()
    assert_no_clean_refuses_tracked_directory_before_sentinel()
    assert_cleanup_refuses_tracked_directory_even_with_sentinel()
    assert_cleanup_refuses_unknown_tracked_file_status()
    assert_cleanup_allows_default_release_output_prefix()
    assert_cleanup_allows_sentinel_directory()
    assert_strict_skip_gradle_requires_emergency_build_flag()
    assert_unknown_workspace_status_fails_strict_modes()
    assert_catalog_signature_and_timestamps_are_canonical()
    assert_reviewer_public_key_file_resolves_from_workspace()
    assert_protected_secret_file_redaction_resolves_from_workspace()
    assert_no_clean_rerun_drops_stale_dist_files()
    assert_custom_out_dir_does_not_dirty_workspace_before_check()
    assert_post_artifact_workspace_recheck_detects_mutation()
    assert_dirty_workspace_state_is_sticky_across_checks()
    assert_project_version_parser_accepts_release_build_numbers()
    assert_maintenance_policy_resolves_from_workspace()
    assert_missing_maintenance_policy_warns_in_dry_run_and_fails_strict_modes()
    assert_incomplete_maintenance_policy_warns_in_dry_run_and_fails_strict_modes()
    assert_maintenance_policy_input_copy_redacts_invalid_values()
    assert_beta_readiness_input_copy_redacts_invalid_values()
    assert_final_summary_emits_previous_candidate_metadata()

    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-self-test-") as temp_name:
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
        )
        summary, exit_code = run_pipeline(settings)
        assert exit_code == 0, summary
        for required in (
            "inputs/release-config.json",
            "build/staged-apps/queue-manager/cryptad-app.properties",
            "build/app-bundles/queue-manager-0.0.0-test.zip",
            "catalog/first-party-catalog.properties",
            f"catalog/{CANONICAL_CATALOG_SIGNATURE}",
            f"catalog/{RELEASE_CATALOG_SIGNATURE_ALIAS}",
            "reviews/review-receipts/queue-manager-review-receipt.properties",
            "evidence/api-compatibility.json",
            "evidence/platform-api-contract-current.json",
            "evidence/platform-api-contract-previous.json",
            "evidence/platform-api-stable-diff.json",
            "evidence/app-ui-lint.json",
            "evidence/sandbox-provider-tests.json",
            "reports/production-beta-summary.json",
            "reports/production-beta-summary.md",
            "reports/redaction-report.json",
            GO_NO_GO_DASHBOARD_JSON,
            GO_NO_GO_DASHBOARD_MARKDOWN,
            GO_NO_GO_REDACTION_REPORT,
        ):
            assert (out_dir / required).exists(), required
        assert summary["nonRelease"] is True, summary
        assert summary["signingProfile"]["kind"] == "test-fixture", summary
        assert summary["promotionReady"] is False, summary
        assert summary["goNoGo"]["decision"] == "no-go", summary
        assert summary["artifacts"]["goNoGoDashboard"] == GO_NO_GO_DASHBOARD_JSON, summary
        archive_rel = summary["artifacts"].get("distArchive")
        assert archive_rel == f"dist/crypta-production-beta-{summary['version']}.tar.gz", summary
        with tarfile.open(out_dir / archive_rel, "r:gz") as archive:
            archived_summary_file = archive.extractfile("reports/production-beta-summary.json")
            assert archived_summary_file is not None, summary
            archived_summary = json.load(archived_summary_file)
        assert archived_summary["artifacts"]["distArchive"] == archive_rel, archived_summary
        assert archived_summary["artifacts"]["checksums"] == "dist/checksums.txt", archived_summary
        assert archived_summary["redaction"]["status"] == "pass", archived_summary
        assert archived_summary["goNoGo"]["dashboardJson"] == GO_NO_GO_DASHBOARD_JSON, archived_summary

    assert_redaction_fails(
        "private-insert-uri",
        lambda out_dir: write_redaction_fixture_text(out_dir / "leak.txt", "insert=USK@PRIVATE-INSERT/test\n"),
    )
    assert_redaction_fails(
        "private-insert-concrete-usk",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "leak.json",
            '{"privateInsertUri":"USK@abcdefghijklmno,qrstuvwxyz0123456789ABCDEFG/name/0"}\n',
        ),
    )
    assert_redaction_fails(
        "private-insert-concrete-ssk",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "leak.txt",
            "Insert URI: crypta:SSK@abcdefghijklmno,qrstuvwxyz0123456789ABCDEFG/name\n",
        ),
    )
    assert_redaction_allows(
        "public-usk-placeholders",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "static/index.html",
            "\n".join(
                [
                    'placeholder="crypta:USK@feed-key/feed/0/"',
                    'placeholder="USK@profile-key/profile/1/profile.json"',
                    'placeholder="USK@publisher/site/0/"',
                    'placeholder="crypta:USK@source-key/social/0/social-outbox.json"',
                    "",
                ]
            ),
        ),
    )
    assert_redaction_allows(
        "public-concrete-catalog-source",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "source.json",
            '{"catalogSource":"crypta:USK@abcdefghijklmno,qrstuvwxyz0123456789ABCDEFG/catalog/0/cryptad-app-catalog.properties"}\n',
        ),
    )
    assert_redaction_allows(
        "sdk-profile-document-code",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "static/crypta-platform.js",
            "const result = { profileDocument: profileDocumentResponse };\n",
        ),
    )
    assert_redaction_allows(
        "api-profile-document-metadata",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "evidence/api.json", '{"capability":"profile-document:experimental"}\n'
        ),
    )
    assert_redaction_fails(
        "private-key",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "key.pem",
            "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n",
        ),
    )
    assert_redaction_fails(
        "binary-private-der",
        lambda out_dir: write_redaction_fixture_bytes(
            out_dir / "build/staged-apps/queue-manager/app-signing-private.der",
            b"\x30\x82\x00\x01private-key-material",
        ),
    )
    assert_redaction_fails(
        "binary-private-der-zip-member",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/crypta-app-launcher/lib/app.jar",
            {"keys/app-signing-private.der": b"\x30\x82\x00\x01private-key-material"},
        ),
    )
    assert_redaction_allows(
        "private-key-code-class-name",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/crypta-app-launcher/lib/crypto.jar",
            {"org/example/PrivateKeyInfo.class": b"\xca\xfe\xba\xbe\x00\x00\x00\x3d"},
        ),
    )
    assert_redaction_allows(
        "compiled-class-token-constant",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/crypta-app-launcher/lib/app.jar",
            {"org/example/AppTokenConstants.class": b"\xca\xfe\xba\xbe\x00CRYPTAD_APP_TOKEN=abcdefghijklmnop"},
        ),
    )
    assert_redaction_allows(
        "native-archive-member-token-bytes",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/crypta-app-launcher/lib/jna.jar",
            {"native/linux-x86-64/libjnidispatch.so": b"\x7fELF\x00Authorization: Bearer abcdefghijklmnopqrstuvwxyz"},
        ),
    )
    assert_redaction_fails(
        "secret-bearing-native-archive-member-name",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/crypta-app-launcher/lib/native.jar",
            {"native/app-token.so": b"\x7fELF\x00"},
        ),
    )
    assert_redaction_fails(
        "compiled-suffix-nested-archive-token",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/crypta-app-launcher/lib/app.jar",
            {
                "fixtures/archive.class": test_zip_archive_bytes(
                    {"fixtures/token.txt": "CRYPTAD_APP_TOKEN=abcdefghijklmnop\n"}
                )
            },
        ),
    )
    assert_redaction_fails(
        "bearer",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "auth.txt", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz\n"
        ),
    )
    assert_redaction_fails(
        "authorization-assignment",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "auth.txt", "Authorization=Basic abcdefghijklmnopqrstuvwxyz\n"
        ),
    )
    assert_redaction_fails(
        "json-authorization-header",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "auth.json", '{"Authorization": "Digest abcdefghijklmnopqrstuvwxyz"}\n'
        ),
    )
    assert_redaction_fails(
        "app-token",
        lambda out_dir: write_redaction_fixture_text(out_dir / "token.txt", "CRYPTAD_APP_TOKEN=abc1234567890abcdef\n"),
    )
    assert_redaction_fails(
        "identifier-app-token",
        lambda out_dir: write_redaction_fixture_text(out_dir / "token.txt", "CRYPTAD_APP_TOKEN=abcdefghijklmnop\n"),
    )
    assert_redaction_allows(
        "app-token-code-expression",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "static/crypta-platform.js",
            "const browserSessionToken = sessionTokenFromBootstrap(data);\n",
        ),
    )
    assert_redaction_fails(
        "nul-bearing-app-token",
        lambda out_dir: write_redaction_fixture_bytes(
            out_dir / "resource.bin",
            "CRYPTAD_APP_TOKEN=abcdefghijklmnop\n".encode("utf-16le"),
        ),
    )
    assert_redaction_fails(
        "nul-bearing-jar-token-entry",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/crypta-app-launcher/lib/app.jar",
            {"fixtures/resource.dat": "CRYPTAD_APP_TOKEN=abcdefghijklmnop\n".encode("utf-16le")},
        ),
    )
    assert_redaction_fails(
        "identifier-ci-secret",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "secret.txt", "CRYPTAD_CERT_FORM_PASSWORD=abcdefghijklmnop\n"
        ),
    )
    assert_redaction_fails(
        "form-password-field",
        lambda out_dir: write_redaction_fixture_text(out_dir / "secret.json", '{"formPassword": "hunter2-password"}\n'),
    )
    assert_redaction_fails(
        "form-password-header",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "secret.http", "X-Crypta-Form-Password: hunter2-password\n"
        ),
    )
    assert_redaction_fails(
        "parenthesized-form-password-field",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "secret.json", '{"formPassword": "(hunter2-password)"}\n'
        ),
    )
    assert_redaction_fails(
        "quoted-function-like-form-password-field",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "secret.json", '{"formPassword": "secret(password)"}\n'
        ),
    )
    assert_redaction_allows(
        "redacted-form-password-field",
        lambda out_dir: write_redaction_fixture_text(out_dir / "secret.json", '{"formPassword": "<redacted>"}\n'),
    )
    assert_redaction_fails(
        "parenthesized-authorization-header",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "auth.txt", "Authorization: Bearer (abcdefghijklmnopqrstuvwxyz)\n"
        ),
    )
    assert_redaction_fails(
        "json-browser-session-token",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "token.json", '{"browserSessionToken": "abc1234567890abcdef"}\n'
        ),
    )
    assert_redaction_fails(
        "json-app-process-token",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "token.json", '{"appProcessToken": "abc1234567890abcdef"}\n'
        ),
    )
    assert_redaction_fails(
        "raw-content",
        lambda out_dir: write_redaction_fixture_text(out_dir / "raw.txt", "raw fetched body: unredacted body value\n"),
    )
    assert_redaction_fails(
        "raw-app-data-value",
        lambda out_dir: write_redaction_fixture_text(out_dir / "raw.txt", "rawAppDataValue=abcdefghijklmnop\n"),
    )
    assert_redaction_fails(
        "queue-html-raw-payload",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "raw.json", '{"queueHtml": "private-queue-html-payload-abcdefghijklmnop"}\n'
        ),
    )
    assert_redaction_fails(
        "payload-base64-raw-payload",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "raw.json", '{"payloadBase64": "cHJpdmF0ZS1wYXlsb2FkLWFiY2RlZmdoaWprbG1ub3A="}\n'
        ),
    )
    assert_redaction_fails(
        "unredacted-payload",
        lambda out_dir: write_redaction_fixture_text(out_dir / "raw.txt", "unredacted payload=abcdefghijklmnop\n"),
    )
    assert_redaction_fails(
        "appledouble",
        lambda out_dir: write_redaction_fixture_text(out_dir / "._bad", "metadata\n"),
    )
    assert_redaction_fails(
        "jar-appledouble-entry",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/crypta-app-launcher/lib/app.jar",
            {"._bad": "metadata\n"},
        ),
    )
    assert_redaction_fails(
        "jar-token-entry",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/crypta-app-launcher/lib/app.jar",
            {"fixtures/token.txt": "CRYPTAD_APP_TOKEN=abcdefghijklmnop\n"},
        ),
    )
    assert_redaction_fails(
        "nested-tar-gz-token-zip-member",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/app-bundles/queue-manager-0.0.0-test.zip",
            {
                "fixtures.tar.gz": test_tar_gz_archive_bytes(
                    {"fixtures/token.txt": "CRYPTAD_APP_TOKEN=abcdefghijklmnop\n"}
                )
            },
        ),
    )
    assert_redaction_fails(
        "nested-zip-token-jar-member",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/crypta-app-launcher/lib/app.jar",
            {"fixtures.zip": test_zip_archive_bytes({"fixtures/token.txt": "CRYPTAD_APP_TOKEN=abcdefghijklmnop\n"})},
        ),
    )
    assert_redaction_fails(
        "direct-tar-gz-token-artifact",
        lambda out_dir: write_test_tar_gz_archive(
            out_dir / "build/app-bundles/fixtures.tar.gz",
            {"fixtures/token.txt": "CRYPTAD_APP_TOKEN=abcdefghijklmnop\n"},
        ),
    )
    assert_redaction_fails(
        "large-jar-token-entry",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/crypta-app-launcher/lib/app.jar",
            {
                "static/app.js.map": (
                    "x" * (2 * 1024 * 1024 + 64) + "\nCRYPTAD_APP_TOKEN=abcdefghijklmnop\n"
                )
            },
        ),
    )
    assert_redaction_allows(
        "large-clean-jar-text-entry",
        lambda out_dir: write_test_zip_archive(
            out_dir / "build/crypta-app-launcher/lib/app.jar",
            {"static/app.js.map": "x" * (2 * 1024 * 1024 + 64)},
        ),
    )
    assert_redaction_fails(
        "absolute-path",
        lambda out_dir: write_redaction_fixture_text(out_dir / "path.txt", "localPath=/home/alice/private/key.pem\n"),
    )
    assert_redaction_fails(
        "file-uri-single-slash-path",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "path.txt", "localPath=file:/home/alice/.cryptad/state\n"
        ),
    )
    assert_redaction_fails(
        "file-uri-triple-slash-path",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "path.txt", "localPath=file:///home/alice/.cryptad/state\n"
        ),
    )
    assert_redaction_fails(
        "file-uri-localhost-path",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "path.txt", "localPath=file://localhost/home/alice/.cryptad/state\n"
        ),
    )
    assert_redaction_allows(
        "file-uri-regex-literal",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "static/app.js",
            'if (/^file:/i.test(sourceUri)) {\n  return "file";\n}\n',
        ),
    )
    assert_redaction_fails(
        "root-gradle-path",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "path.txt", "localPath=/root/.gradle/caches/modules-2/files-2.1\n"
        ),
    )
    assert_redaction_fails(
        "etc-local-path",
        lambda out_dir: write_redaction_fixture_text(out_dir / "path.txt", "config=/etc/cryptad/config.ini\n"),
    )
    assert_redaction_fails(
        "srv-local-path",
        lambda out_dir: write_redaction_fixture_text(out_dir / "path.txt", "artifact=/srv/cryptad/release\n"),
    )
    assert_redaction_fails(
        "hostedtoolcache-path",
        lambda out_dir: write_redaction_fixture_text(
            out_dir / "path.txt", "javaHome=/opt/hostedtoolcache/Java_Temurin-Hotspot_jdk/25\n"
        ),
    )

    saved_env = {
        "CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE": os.environ.get("CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE"),
        "CRYPTAD_CERT_FORM_PASSWORD": os.environ.get("CRYPTAD_CERT_FORM_PASSWORD"),
        "CRYPTAD_CERT_LIVE_TEST_INSERT_URI_ENV": os.environ.get("CRYPTAD_CERT_LIVE_TEST_INSERT_URI_ENV"),
        "CRYPTAD_CERT_LIVE_TEST_INSERT_URI_FILE": os.environ.get("CRYPTAD_CERT_LIVE_TEST_INSERT_URI_FILE"),
        "SELF_TEST_PRIVATE_INSERT_VALUE": os.environ.get("SELF_TEST_PRIVATE_INSERT_VALUE"),
    }
    try:
        os.environ["CRYPTAD_CERT_FORM_PASSWORD"] = "unit-test-live-password-9f4b6a"
        assert_redaction_fails(
            "bare-live-form-password-env-value",
            lambda out_dir: write_redaction_fixture_text(out_dir / "live.txt", "unit-test-live-password-9f4b6a\n"),
        )
        os.environ["CRYPTAD_CERT_LIVE_TEST_INSERT_URI_ENV"] = "SELF_TEST_PRIVATE_INSERT_VALUE"
        os.environ["SELF_TEST_PRIVATE_INSERT_VALUE"] = "unit-test-private-insert-material-9f4b6a"
        assert_redaction_fails(
            "bare-live-private-insert-indirection-value",
            lambda out_dir: write_redaction_fixture_text(
                out_dir / "live.txt", "unit-test-private-insert-material-9f4b6a\n"
            ),
        )
        with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-private-insert-file-") as secret_temp_name:
            secret_file = Path(secret_temp_name) / "private-insert-uri.txt"
            write_redaction_fixture_text(secret_file, "unit-test-private-insert-file-material-9f4b6a\n")
            os.environ["CRYPTAD_CERT_LIVE_TEST_INSERT_URI_FILE"] = str(secret_file)
            assert_redaction_fails(
                "bare-live-private-insert-file-value",
                lambda out_dir: write_redaction_fixture_text(
                    out_dir / "live.txt", "unit-test-private-insert-file-material-9f4b6a\n"
                ),
            )
        with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-private-key-file-") as secret_temp_name:
            secret_file = Path(secret_temp_name) / "app-signing-private.der"
            secret_bytes = b"\x30\x82\x01\x00unit-test-private-key-material-9f4b6a"
            write_redaction_fixture_bytes(secret_file, secret_bytes)
            os.environ["CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE"] = str(secret_file)
            secret_base64 = base64.b64encode(secret_bytes).decode("ascii")
            assert_redaction_fails(
                "private-key-file-base64-value",
                lambda out_dir: write_redaction_fixture_text(out_dir / "neutral.txt", f"{secret_base64}\n"),
            )
            assert_redaction_fails(
                "private-key-file-raw-bytes",
                lambda out_dir: write_redaction_fixture_bytes(out_dir / "neutral.bin", secret_bytes),
            )
    finally:
        for name, value in saved_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-artifact-uri-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        parser = build_parser()
        saved_artifact_base_uri = os.environ.pop("CRYPTAD_PRODUCTION_BETA_ARTIFACT_BASE_URI", None)
        try:
            try:
                settings_from_args(
                    parser.parse_args(
                        [
                            "--workspace-root",
                            str(workspace),
                            "--out-dir",
                            "build/production-beta",
                            "--mode",
                            "release-candidate",
                        ]
                    )
                )
            except SystemExit as exc:
                assert "artifact-base-uri" in str(exc), exc
            else:
                raise AssertionError("release-candidate mode accepted a missing artifact base URI")
        finally:
            if saved_artifact_base_uri is None:
                os.environ.pop("CRYPTAD_PRODUCTION_BETA_ARTIFACT_BASE_URI", None)
            else:
                os.environ["CRYPTAD_PRODUCTION_BETA_ARTIFACT_BASE_URI"] = saved_artifact_base_uri
        try:
            settings_from_args(
                parser.parse_args(
                    [
                        "--workspace-root",
                        str(workspace),
                        "--out-dir",
                        "build/production-beta",
                        "--mode",
                        "production-beta",
                        "--artifact-base-uri",
                        "https://downloads.crypta.invalid/production-beta/self-test",
                    ]
                )
            )
        except SystemExit as exc:
            assert ".invalid" in str(exc), exc
        else:
            raise AssertionError("production-beta mode accepted a placeholder artifact base URI")
        for private_uri in (
            "https://localhost./production-beta/self-test",
            "https://127.1/production-beta/self-test",
            "https://10.1/production-beta/self-test",
            "https://10.0.0.5/production-beta/self-test",
            "https://192.168.1/production-beta/self-test",
            "https://[::ffff:127.0.0.1]/production-beta/self-test",
            "https://artifacts.localdomain/production-beta/self-test",
        ):
            try:
                settings_from_args(
                    parser.parse_args(
                        [
                            "--workspace-root",
                            str(workspace),
                            "--out-dir",
                            "build/production-beta",
                            "--mode",
                            "release-candidate",
                            "--artifact-base-uri",
                            private_uri,
                        ]
                    )
                )
            except SystemExit as exc:
                assert "public HTTPS" in str(exc), exc
            else:
                raise AssertionError(f"release-candidate mode accepted private artifact base URI {private_uri}")
        for malformed_uri in (
            "https://downloads.crypta.network:99999/production-beta/self-test",
            "https://bad host.com/production-beta/self-test",
            "https://bad_host.com/production-beta/self-test",
            "https://downloads.crypta.network:/production-beta/self-test",
            "https://downloads.crypta.network:0/production-beta/self-test",
        ):
            try:
                settings_from_args(
                    parser.parse_args(
                        [
                            "--workspace-root",
                            str(workspace),
                            "--out-dir",
                            "build/production-beta",
                            "--mode",
                            "release-candidate",
                            "--artifact-base-uri",
                            malformed_uri,
                        ]
                    )
                )
            except SystemExit as exc:
                assert "valid host" in str(exc), exc
            else:
                raise AssertionError(f"release-candidate mode accepted malformed artifact base URI {malformed_uri}")
        try:
            settings_from_args(
                parser.parse_args(
                    [
                        "--workspace-root",
                        str(workspace),
                        "--out-dir",
                        "build/production-beta",
                        "--mode",
                        "release-candidate",
                        "--artifact-base-uri",
                        "https://downloads.crypta.network/production-beta/self-test",
                        "--use-fixture-evidence",
                    ]
                )
            )
        except SystemExit as exc:
            assert "use-fixture-evidence" in str(exc), exc
        else:
            raise AssertionError("release-candidate mode accepted fixture evidence")

    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-rc-fixture-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "build/production-beta",
            mode="release-candidate",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
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
        )
        summary, exit_code = run_pipeline(settings)
        assert exit_code == 1, summary
        assert summary["status"] == "fail", summary
        failed_ids = {gate["id"] for gate in summary["promotion"]["gates"] if gate["status"] == "fail"}
        assert "fixture-evidence.strict-mode" in failed_ids, failed_ids
        assert any("fixture evidence" in failure for failure in summary["failures"]), summary["failures"]

    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-prod-missing-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "build/production-beta",
            mode="production-beta",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=True,
            require_sandbox_provider_tests=True,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=True,
            allow_dirty_workspace=True,
            emergency_skip_live_network=False,
            emergency_skip_build=True,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=120,
            clean_out_dir=True,
        )
        summary, exit_code = run_pipeline(settings)
        assert exit_code == 1, summary
        assert summary["promotionReady"] is False, summary
        failed_ids = {gate["id"] for gate in summary["promotion"]["gates"] if gate["status"] == "fail"}
        assert "live.live-network-beta.preflight" in failed_ids, failed_ids
        assert "signing.production-keys" in failed_ids, failed_ids

    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-emergency-live-skip-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "build/production-beta",
            mode="production-beta",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=True,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=True,
            allow_dirty_workspace=True,
            emergency_skip_live_network=True,
            emergency_skip_build=True,
            allow_test_signing_in_production=True,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=120,
            clean_out_dir=True,
        )
        summary, exit_code = run_pipeline(settings)
        assert exit_code == 1, summary
        assert summary["promotionReady"] is False, summary
        failed_ids = {gate["id"] for gate in summary["promotion"]["gates"] if gate["status"] == "fail"}
        assert "live.production-beta-skip" in failed_ids, failed_ids

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        run_self_test()
        print("production beta release self-test passed")
        return 0
    settings = settings_from_args(args)
    _, exit_code = run_pipeline(settings)
    result = "pass" if exit_code == 0 else "fail"
    print(f"Production beta release {result}: <out-dir>/reports/production-beta-summary.json")
    return exit_code
