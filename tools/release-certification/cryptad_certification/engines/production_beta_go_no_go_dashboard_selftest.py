"""Implementation segment for the selftest portion of ``production_beta_go_no_go_dashboard.py``."""

from __future__ import annotations

def run_self_test(quiet: bool = False) -> None:
    content_format_evidence_id = "app-platform.trust-social-content-format-profiles"
    privacy_diagnostics_evidence_id = "app-platform.privacy-preserving-beta-diagnostics"
    plugin_migration_evidence_id = "legacy-plugin.migration-finalization"
    support_feedback_evidence_id = "public-beta.support-feedback-loop"
    if content_format_evidence_id not in CRITICAL_PRODUCTION_BETA_EVIDENCE_IDS:
        raise AssertionError("content-format profile evidence must be production-critical")
    if privacy_diagnostics_evidence_id not in CRITICAL_PRODUCTION_BETA_EVIDENCE_IDS:
        raise AssertionError("privacy-preserving diagnostics evidence must be production-critical")
    if plugin_migration_evidence_id not in CRITICAL_PRODUCTION_BETA_EVIDENCE_IDS:
        raise AssertionError("legacy plugin migration finalization evidence must be production-critical")
    if support_feedback_evidence_id not in CRITICAL_PRODUCTION_BETA_EVIDENCE_IDS:
        raise AssertionError("public beta support feedback loop must be production-critical")
    if not evidence_id_is_non_waivable_in_mode(content_format_evidence_id, "production-beta"):
        raise AssertionError(
            "content-format profile evidence must be non-waivable in production-beta"
        )
    if not evidence_id_is_non_waivable_in_mode(
        f"evidence.{content_format_evidence_id}",
        "production-beta",
    ):
        raise AssertionError(
            "content-format profile promotion gate must be non-waivable in production-beta"
        )
    if not evidence_id_is_non_waivable_in_mode(
        privacy_diagnostics_evidence_id,
        "production-beta",
    ):
        raise AssertionError("privacy-preserving diagnostics evidence must be non-waivable")
    if not evidence_id_is_non_waivable_in_mode(
        f"evidence.{privacy_diagnostics_evidence_id}",
        "production-beta",
    ):
        raise AssertionError(
            "privacy-preserving diagnostics promotion gate must be non-waivable"
        )
    if not evidence_id_is_non_waivable_in_mode(
        plugin_migration_evidence_id,
        "production-beta",
    ):
        raise AssertionError("legacy plugin migration finalization must be non-waivable")
    if not evidence_id_is_non_waivable_in_mode(
        f"evidence.{plugin_migration_evidence_id}",
        "production-beta",
    ):
        raise AssertionError(
            "legacy plugin migration finalization gate must be non-waivable"
        )
    if not evidence_id_is_non_waivable_in_mode(
        support_feedback_evidence_id,
        "production-beta",
    ):
        raise AssertionError("public beta support feedback loop must be non-waivable")
    if not evidence_id_is_non_waivable_in_mode(
        f"evidence.{support_feedback_evidence_id}",
        "production-beta",
    ):
        raise AssertionError(
            "public beta support feedback loop promotion gate must be non-waivable"
        )
    for evidence_id in CRITICAL_PRODUCTION_BETA_EVIDENCE_IDS:
        if not evidence_id_is_non_waivable_in_mode(evidence_id, "production-beta"):
            raise AssertionError(f"production critical evidence is waivable in production-beta: {evidence_id}")
        gate_id = f"evidence.{evidence_id}"
        if not evidence_id_is_non_waivable_in_mode(gate_id, "production-beta"):
            raise AssertionError(f"production critical evidence gate is waivable in production-beta: {gate_id}")
    if evidence_id_is_non_waivable_in_mode("app-store.submission-cli", "release-candidate"):
        raise AssertionError("release-candidate app-store evidence should remain waiverable")
    if not evidence_id_is_non_waivable_in_mode(
        "multi-node-beta.previous-candidate-upgrade-binding",
        "production-beta",
    ):
        raise AssertionError("previous-candidate binding failures must be non-waivable in production-beta")
    optional_stable_matrix = {
        "status": "pass",
        "releaseBlockerCount": 0,
        "rows": [
            {
                "id": "stable-1-0-readiness",
                "status": "skip",
                "releaseBlocker": False,
                "summary": "Stable 1.0 readiness was not requested for this certification run.",
                "details": {"notRequested": True, "required": False},
            }
        ],
    }
    if ecosystem_matrix_issues(optional_stable_matrix):
        raise AssertionError("optional Stable 1.0 not-requested matrix row produced a dashboard warning")
    unrelated_skip_matrix = copy.deepcopy(optional_stable_matrix)
    unrelated_skip_matrix["rows"][0]["id"] = "self-test-unrelated-row"
    unrelated_skip_issues = ecosystem_matrix_issues(unrelated_skip_matrix)
    if not any(issue.id == "ecosystem-matrix.self-test-unrelated-row" for issue in unrelated_skip_issues):
        raise AssertionError("non-Stable skipped matrix rows must still be surfaced by the dashboard")
    for invalid_stable_summary in (
        {
            "kind": "stable-1.0-readiness",
            "status": "skip",
            "decision": "ready",
            "stableReady": True,
            "redaction": {"status": "pass", "findings": []},
        },
        {
            "kind": "stable-1.0-readiness",
            "status": "pass",
            "decision": "ship-it",
            "stableReady": True,
            "redaction": {"status": "pass", "findings": []},
        },
    ):
        invalid_stable_issues = stable_readiness_issues(invalid_stable_summary, True)
        if not any(
            issue.id == "stable-1.0.readiness-summary.invalid"
            and issue.severity == "blocker"
            for issue in invalid_stable_issues
        ):
            raise AssertionError(
                f"required malformed Stable readiness summary did not block: {invalid_stable_issues}"
            )

    passing_network_scale_summary = {
        "status": "success",
        "redaction": {
            "status": "pass",
            "rawFetchedContentExcluded": True,
            "privateInsertUrisExcluded": True,
            "tokensExcluded": True,
            "absolutePathsExcluded": True,
            "queueHtmlExcluded": True,
        },
        "budgets": {
            "globalFetchBudgetEnforced": True,
            "perAppFetchBudgetEnforced": True,
            "concurrencyLeasesReleased": True,
        },
    }
    for case_name, redaction_patch in (
        ("failed status", {"status": "fail"}),
        ("declared findings", {"findings": [{"kind": "network-scale-self-test"}]}),
        ("finding count", {"findingCount": 1}),
    ):
        failed_network_scale_summary = copy.deepcopy(passing_network_scale_summary)
        failed_network_scale_summary["redaction"].update(redaction_patch)
        redaction_issues = [
            issue
            for issue in network_scale_issues(failed_network_scale_summary, "production-beta")
            if issue.id == "network-scale-soak.redaction-or-budget"
            and issue.evidence_id == "network-scale.redaction"
            and issue.severity == "critical"
            and not issue.waivable
        ]
        if not redaction_issues:
            raise AssertionError(
                f"network-scale redaction {case_name} did not create a non-waivable blocker"
            )

    fixture_expectations = {
        "go-no-go-pass.json": "go",
        "go-no-go-no-go.json": "no-go",
        "go-no-go-with-waivers.json": "no-go",
        "go-no-go-expired-waiver.json": "no-go",
        "go-no-go-waiver-valid-at-generated-at.json": "no-go",
        "go-no-go-critical-redaction.json": "no-go",
        "go-no-go-test-signing-production.json": "no-go",
        "go-no-go-summary-failure-with-gates.json": "no-go",
        "go-no-go-production-summary-not-ready.json": "no-go",
        "go-no-go-production-summary-skipped.json": "no-go",
        "go-no-go-missing-ecosystem-matrix-status.json": "no-go",
        "go-no-go-warning-ecosystem-matrix.json": "go",
        "go-no-go-malformed-ecosystem-matrix-count.json": "no-go",
        "go-no-go-release-cert-schema-waiver.json": "go-with-waivers",
        "go-no-go-release-cert-applied-waiver.json": "go-with-waivers",
        "go-no-go-release-cert-applied-waiver-expired.json": "no-go",
        "go-no-go-release-cert-applied-waiver-missing-record.json": "no-go",
        "go-no-go-artifact-gate-waiver.json": "no-go",
        "go-no-go-warning-redaction-findings.json": "no-go",
        "go-no-go-multi-node-upgrade-waiver.json": "go-with-waivers",
        "go-no-go-network-scale-redaction-waiver.json": "no-go",
        "go-no-go-previous-candidate-warning.json": "no-go",
        "go-no-go-previous-candidate-binding-waiver.json": "no-go",
        "go-no-go-secret-value-redaction.json": "no-go",
        "go-no-go-underseverity-waiver.json": "no-go",
        "go-no-go-live-evidence-waiver-alias.json": "no-go",
        "go-no-go-live-network-skip-waiver.json": "no-go",
        "go-no-go-production-critical-evidence-waiver.json": "no-go",
        "go-no-go-release-candidate-live-waiver.json": "go-with-waivers",
        "go-no-go-release-candidate-live-disabled.json": "no-go",
        "go-no-go-malformed-non-release-status.json": "no-go",
        "go-no-go-security-drills-missing-summary.json": "no-go",
        "go-no-go-security-drills-missing-scenario.json": "no-go",
        "go-no-go-security-drills-failed-scenario.json": "no-go",
        "go-no-go-security-drills-stale-scenario.json": "no-go",
        "go-no-go-security-drills-redaction-unsafe.json": "no-go",
        "go-no-go-security-drills-fixture-only.json": "no-go",
        "go-no-go-security-drills-developer-dry-run.json": "no-go",
        "go-no-go-security-drills-malformed-envelope.json": "no-go",
        "go-no-go-security-drills-single-artifact-pass.json": "no-go",
        "go-no-go-security-drills-malformed-count.json": "no-go",
        "go-no-go-security-drills-expired-waiver.json": "no-go",
        "go-no-go-security-drills-underseverity-redaction-waiver.json": "no-go",
    }
    with tempfile.TemporaryDirectory(prefix="cryptad-go-no-go-dashboard-") as temp_name:
        root = Path(temp_name)
        outputs: dict[str, str] = {}
        for fixture_name, expected in fixture_expectations.items():
            out_dir = root / fixture_name.removesuffix(".json")
            fixture = FIXTURE_DIR / fixture_name
            args = build_parser().parse_args(
                [
                    "build",
                    "--workspace-root",
                    str(Path(__file__).resolve().parents[2]),
                    "--out-dir",
                    str(out_dir),
                    "--fixtures",
                    str(fixture),
                ]
            )
            dashboard, _exit_code = build_command(args)
            if dashboard["decision"] != expected:
                raise AssertionError(f"{fixture_name} expected {expected}, got {dashboard['decision']}: {dashboard}")
            blocker_ids = {
                str(blocker.get("evidenceId"))
                for blocker in dashboard.get("blockers", [])
                if isinstance(blocker, dict)
            }
            if fixture_name == "go-no-go-underseverity-waiver.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("under-severity waiver was incorrectly used")
                if "production-beta.waiver-validation" not in blocker_ids:
                    raise AssertionError("under-severity waiver did not produce a waiver-validation blocker")
            if fixture_name == "go-no-go-expired-waiver.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("expired waiver was incorrectly used")
                if "production-beta.waiver-validation" not in blocker_ids:
                    raise AssertionError("expired waiver did not produce a waiver-validation blocker")
                if dashboard.get("generatedAt") != "2026-06-24T00:00:00Z":
                    raise AssertionError("expired waiver fixture did not use its recorded generatedAt")
            if fixture_name.startswith("go-no-go-security-drills-"):
                if "production-security.response-runbook" not in blocker_ids:
                    raise AssertionError(
                        f"{fixture_name} did not block on production security response evidence"
                    )
                security_drills = dashboard.get("securityDrills")
                if not isinstance(security_drills, dict) or security_drills.get("promotionReady") is True:
                    raise AssertionError(f"{fixture_name} left security drills promotion-ready")
            if fixture_name == "go-no-go-security-drills-redaction-unsafe.json":
                critical_security_blockers = [
                    blocker
                    for blocker in dashboard.get("blockers", [])
                    if isinstance(blocker, dict)
                    and blocker.get("evidenceId") == "production-security.response-runbook"
                    and blocker.get("severity") == "critical"
                ]
                if not critical_security_blockers:
                    raise AssertionError("redaction-unsafe drill fixture did not create a critical blocker")
            if fixture_name in {
                "go-no-go-security-drills-expired-waiver.json",
                "go-no-go-security-drills-underseverity-redaction-waiver.json",
            }:
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("security drill waiver fixture was incorrectly used")
                if "production-beta.waiver-validation" not in blocker_ids:
                    raise AssertionError("security drill waiver fixture did not fail waiver validation")
            if fixture_name == "go-no-go-waiver-valid-at-generated-at.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("non-waivable live evidence waiver was incorrectly used")
                if dashboard.get("generatedAt") != "1999-06-24T00:00:00Z":
                    raise AssertionError("historical waiver fixture did not use its recorded generatedAt")
                if "production-beta.waiver-validation" not in blocker_ids:
                    raise AssertionError("historical non-waivable live evidence waiver did not fail validation")
            if fixture_name == "go-no-go-production-summary-not-ready.json":
                if "production-beta.promotion-ready" not in blocker_ids:
                    raise AssertionError("non-ready production summary did not block production beta")
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("promotionReady=false hard blocker was incorrectly waived")
            if fixture_name == "go-no-go-production-summary-skipped.json":
                if "production-beta.summary" not in blocker_ids:
                    raise AssertionError("skipped production summary did not block production beta")
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("non-passing production summary hard blocker was incorrectly waived")
            if fixture_name == "go-no-go-previous-candidate-binding-waiver.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("previous-candidate binding waiver was incorrectly used")
                if "multi-node-beta.previous-candidate-upgrade-binding" not in blocker_ids:
                    raise AssertionError("previous-candidate binding failure did not remain blocked")
                if "production-beta.waiver-validation" not in blocker_ids:
                    raise AssertionError("previous-candidate binding waiver did not fail waiver validation")
            if fixture_name == "go-no-go-live-evidence-waiver-alias.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("live evidence alias waiver was incorrectly used")
                if "live-network-beta.content-fetch" not in blocker_ids:
                    raise AssertionError("live evidence waiver attempt did not leave live-network evidence blocked")
                if "production-beta.waiver-validation" not in blocker_ids:
                    raise AssertionError("live evidence waiver attempt did not fail waiver validation")
            if fixture_name == "go-no-go-release-candidate-live-waiver.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 1:
                    raise AssertionError("release-candidate live evidence waiver was not used")
                waived_evidence_ids = {
                    str(warning.get("evidenceId"))
                    for warning in dashboard.get("warnings", [])
                    if isinstance(warning, dict) and warning.get("waivedBy")
                }
                if "live-network-beta.content-fetch" not in waived_evidence_ids:
                    raise AssertionError("release-candidate live evidence waiver did not waive content-fetch evidence")
            if fixture_name == "go-no-go-production-critical-evidence-waiver.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("production-critical evidence waiver was incorrectly used")
                if "app-store.submission-cli" not in blocker_ids:
                    raise AssertionError("production-critical app-store evidence did not remain blocked")
                if "production-beta.waiver-validation" not in blocker_ids:
                    raise AssertionError("production-critical evidence waiver attempt did not fail validation")
            if fixture_name == "go-no-go-release-cert-schema-waiver.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 1:
                    raise AssertionError("release-certification schema waiver was not used by dashboard")
                waived_evidence_ids = {
                    str(warning.get("evidenceId"))
                    for warning in dashboard.get("warnings", [])
                    if isinstance(warning, dict) and warning.get("waivedBy")
                }
                if "app-store.submission-cli" not in waived_evidence_ids:
                    raise AssertionError("canonical app-store evidence id did not waive evidence-prefixed gate")
                if any(
                    str(warning.get("evidenceId")).startswith("evidence.")
                    for warning in dashboard.get("warnings", [])
                    if isinstance(warning, dict)
                ):
                    raise AssertionError("dashboard exposed evidence-prefixed promotion evidence id")
            if fixture_name == "go-no-go-release-cert-applied-waiver.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 1:
                    raise AssertionError("already-applied release-certification waiver was not preserved")
                waived_evidence_ids = {
                    str(warning.get("evidenceId"))
                    for warning in dashboard.get("warnings", [])
                    if isinstance(warning, dict) and warning.get("waivedBy")
                }
                if "release-certification.ecosystem-rc-gate" not in waived_evidence_ids:
                    raise AssertionError("already-applied release-certification waiver did not remain visible")
            if fixture_name == "go-no-go-release-cert-applied-waiver-expired.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("expired release-certification waiver record was incorrectly counted")
                if "production-beta.waiver-validation" not in blocker_ids:
                    raise AssertionError("expired release-certification waiver record did not block the dashboard")
            if fixture_name == "go-no-go-release-cert-applied-waiver-missing-record.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("missing release-certification waiver record was incorrectly counted")
                if "production-beta.waiver-validation" not in blocker_ids:
                    raise AssertionError("missing release-certification waiver record did not block the dashboard")
            if fixture_name == "go-no-go-artifact-gate-waiver.json":
                if "artifact.signed-first-party-bundles" not in blocker_ids:
                    raise AssertionError("artifact-presence gate waiver incorrectly removed the blocker")
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("artifact-presence gate waiver was incorrectly used")
            if fixture_name == "go-no-go-warning-redaction-findings.json":
                if "release-certification.ecosystem-rc-gate" not in blocker_ids:
                    raise AssertionError("warning evidence with redaction findings did not block launch")
                critical_ids = {
                    str(blocker.get("evidenceId"))
                    for blocker in dashboard.get("blockers", [])
                    if isinstance(blocker, dict) and blocker.get("severity") == "critical"
                }
                if "release-certification.ecosystem-rc-gate" not in critical_ids:
                    raise AssertionError("warning evidence redaction findings were not critical")
            if fixture_name == "go-no-go-multi-node-upgrade-waiver.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 1:
                    raise AssertionError("canonical multi-node upgrade-drill waiver was not used")
                waived_evidence_ids = {
                    str(warning.get("evidenceId"))
                    for warning in dashboard.get("warnings", [])
                    if isinstance(warning, dict) and warning.get("waivedBy")
                }
                if "multi-node-beta.upgrade-drill" not in waived_evidence_ids:
                    raise AssertionError("multi-node upgrade scenario did not use canonical evidence id")
            if fixture_name == "go-no-go-live-network-skip-waiver.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
                    raise AssertionError("live-network production-beta skip hard blocker was incorrectly waived")
                if "live.production-beta-skip" not in blocker_ids:
                    raise AssertionError("live-network production-beta skip did not block launch")
                if "production-beta.waiver-validation" not in blocker_ids:
                    raise AssertionError("live-network production-beta skip waiver did not fail validation")
            if fixture_name == "go-no-go-release-candidate-live-disabled.json":
                if any(blocker_id.startswith("live-network-beta.") for blocker_id in blocker_ids):
                    raise AssertionError("disabled live-network evidence blocked release-candidate mode")
                if "production-beta.non-release" not in blocker_ids:
                    raise AssertionError("release-candidate non-release artifact did not block publication")
            if fixture_name == "go-no-go-malformed-non-release-status.json":
                if "production-beta.non-release" not in blocker_ids:
                    raise AssertionError("malformed nonRelease value did not block launchable decision")
            if fixture_name == "go-no-go-malformed-ecosystem-matrix-count.json":
                if "release-certification.ecosystem-matrix" not in blocker_ids:
                    raise AssertionError("malformed ecosystem matrix releaseBlockerCount did not block launch")
            if fixture_name == "go-no-go-network-scale-redaction-waiver.json":
                if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 1:
                    raise AssertionError("network-scale status waiver was not recorded")
                if "network-scale.redaction" not in blocker_ids:
                    raise AssertionError("network-scale redaction failure was incorrectly waived")
                waived_evidence_ids = {
                    str(warning.get("evidenceId"))
                    for warning in dashboard.get("warnings", [])
                    if isinstance(warning, dict) and warning.get("waivedBy")
                }
                if "network-scale.rc-soak-summary" not in waived_evidence_ids:
                    raise AssertionError("network-scale status waiver did not apply to the generic status issue")
            for artifact_name in (OUTPUT_JSON, OUTPUT_MARKDOWN, OUTPUT_REDACTION):
                if not (out_dir / artifact_name).is_file():
                    raise AssertionError(f"{fixture_name} did not write {artifact_name}")
            markdown = (out_dir / OUTPUT_MARKDOWN).read_text(encoding="utf-8")
            for required in ("Production Beta Go/No-Go Dashboard", "Domain Table", "Redaction Status"):
                if required not in markdown:
                    raise AssertionError(f"{fixture_name} markdown missing {required}")
            encoded = json.dumps(dashboard, sort_keys=True) + markdown
            for forbidden in (
                "Bearer abcdefghijklmnop",
                "-----BEGIN PRIVATE KEY-----",
                "USK@PRIVATE-INSERT",
                "/home/alice",
                "/work/cryptad",
                "hunter2",
                "session=abc1234567890",
                "app-token-123456789",
                "rawpayload123456789",
                "github-token-123456789",
            ):
                if forbidden in encoded:
                    raise AssertionError(f"{fixture_name} leaked {forbidden}")
            outputs[fixture_name] = (out_dir / OUTPUT_JSON).read_text(encoding="utf-8")
        pass_fixture = load_fixture(FIXTURE_DIR / "go-no-go-pass.json")
        missing_support_fixture = copy.deepcopy(pass_fixture)
        for summary_name in ("appPlatformSummary", "releaseCertificationSummary"):
            summary = missing_support_fixture.get("inputs", {}).get(summary_name)
            if isinstance(summary, dict) and isinstance(summary.get("evidence"), list):
                summary["evidence"] = [
                    item
                    for item in summary["evidence"]
                    if not (
                        isinstance(item, dict)
                        and item.get("id") == "public-beta.support-feedback-loop"
                    )
                ]
        missing_fixture_path = root / "go-no-go-missing-support-feedback.json"
        write_json(missing_fixture_path, missing_support_fixture)
        missing_out = root / "missing-support-feedback"
        missing_args = build_parser().parse_args(
            [
                "build",
                "--workspace-root",
                str(Path(__file__).resolve().parents[2]),
                "--out-dir",
                str(missing_out),
                "--fixtures",
                str(missing_fixture_path),
            ]
        )
        missing_dashboard, _ = build_command(missing_args)
        if missing_dashboard["decision"] != "no-go":
            raise AssertionError("missing support-feedback-loop evidence did not block")
        missing_blocker_ids = {
            str(blocker.get("evidenceId"))
            for blocker in missing_dashboard.get("blockers", [])
            if isinstance(blocker, dict)
        }
        if "public-beta.support-feedback-loop" not in missing_blocker_ids:
            raise AssertionError("missing support-feedback-loop blocker was not reported")
        unsafe_support_fixture = copy.deepcopy(pass_fixture)
        unsafe_evidence_found = False
        for summary_name in ("appPlatformSummary", "releaseCertificationSummary"):
            summary = unsafe_support_fixture.get("inputs", {}).get(summary_name)
            if not isinstance(summary, dict) or not isinstance(summary.get("evidence"), list):
                continue
            for item in summary["evidence"]:
                if isinstance(item, dict) and item.get("id") == "public-beta.redaction-fixtures":
                    item["details"] = {
                        "redactionFindings": [
                            {"path": "support-feedback", "issue": "app-token"}
                        ]
                    }
                    unsafe_evidence_found = True
        if not unsafe_evidence_found:
            raise AssertionError("pass fixture is missing public-beta.redaction-fixtures")
        unsafe_fixture_path = root / "go-no-go-unsafe-support-feedback.json"
        write_json(unsafe_fixture_path, unsafe_support_fixture)
        unsafe_out = root / "unsafe-support-feedback"
        unsafe_args = build_parser().parse_args(
            [
                "build",
                "--workspace-root",
                str(Path(__file__).resolve().parents[2]),
                "--out-dir",
                str(unsafe_out),
                "--fixtures",
                str(unsafe_fixture_path),
            ]
        )
        unsafe_dashboard, _ = build_command(unsafe_args)
        if unsafe_dashboard["decision"] != "no-go":
            raise AssertionError("redaction-unsafe support-feedback evidence did not block")
        unsafe_critical_ids = {
            str(blocker.get("evidenceId"))
            for blocker in unsafe_dashboard.get("blockers", [])
            if isinstance(blocker, dict) and blocker.get("severity") == "critical"
        }
        if "public-beta.redaction-fixtures" not in unsafe_critical_ids:
            raise AssertionError("redaction-unsafe support-feedback blocker was not critical")
        repeat_dir = root / "repeat"
        repeat_args = build_parser().parse_args(
            [
                "build",
                "--workspace-root",
                str(Path(__file__).resolve().parents[2]),
                "--out-dir",
                str(repeat_dir),
                "--fixtures",
                str(FIXTURE_DIR / "go-no-go-pass.json"),
                "--generated-at",
                DEFAULT_GENERATED_AT,
            ]
        )
        build_command(repeat_args)
        repeat_text = (repeat_dir / OUTPUT_JSON).read_text(encoding="utf-8")
        if repeat_text != outputs["go-no-go-pass.json"]:
            raise AssertionError("go/no-go dashboard JSON is not deterministic for fixed fixture inputs")
        assert_supplied_waiver_file_errors_block_launch(root)
        assert_protected_secret_values_are_scanned_and_redacted(root)
        assert_redaction_proof_semantics()
        assert_symlink_inputs_are_rejected(root)
        assert_legacy_security_response_summary_fallback_is_honored(root)
        assert_standalone_security_response_summary_is_honored(root)
        assert_security_drills_preserve_failing_runbook_evidence(root)
        assert_security_drills_require_app_platform_runbook_evidence(root)
        assert_security_drill_summary_evidence_is_not_generic_release_evidence(root)
        assert_security_drill_summary_path_requires_sibling_artifacts(root)
        assert_security_drills_release_id_matches_dashboard_candidate(root)
        assert_required_stable_readiness_release_id_matches_dashboard_candidate(root)
        assert_validator_security_drill_redaction_findings_are_non_waivable(root)
        assert_inherited_security_drill_summary_timestamp_rebinds(root)
        assert_previous_candidate_upgrade_current_binding_is_enforced(root)
        assert_multi_node_release_evidence_is_not_overwritten(root)
    if not quiet:
        print("production beta go/no-go dashboard self-test passed")

def assert_redaction_proof_semantics() -> None:
    if not entry_has_redaction_findings({"details": {"redactionClean": False}}):
        raise AssertionError("redactionClean=false was not treated as unsafe")
    if not entry_has_redaction_findings({"details": {"redactionClean": "false"}}):
        raise AssertionError("malformed redactionClean proof was not treated as unsafe")
    if entry_has_redaction_findings({"details": {"redactionClean": True}}):
        raise AssertionError("redactionClean=true was treated as unsafe")
    for unsafe_status in ("fail", "warn", "missing", "success", None, True):
        if not entry_has_redaction_findings(
            {"details": {"redactionStatus": unsafe_status}}
        ):
            raise AssertionError(
                f"redactionStatus={unsafe_status!r} was not treated as unsafe"
            )
    if entry_has_redaction_findings({"details": {"redactionStatus": "pass"}}):
        raise AssertionError("redactionStatus=pass was treated as unsafe")
    for unsafe_status in ("fail", "warn", "missing", "skip", "success", None, True):
        if not entry_has_redaction_findings(
            {"details": {"redaction": {"status": unsafe_status}}}
        ):
            raise AssertionError(
                f"nested redaction status={unsafe_status!r} was not treated as unsafe"
            )
    if entry_has_redaction_findings(
        {"details": {"redaction": {"status": "pass"}}}
    ):
        raise AssertionError("nested redaction status=pass was treated as unsafe")
    boolean_proof_cases = (
        ("privateInsertUrisExcluded", True, (False, "false", None, 1)),
        ("rawSupportBundlesStored", False, (True, "true", None, 0)),
        ("rawFetchedContentIncluded", False, (True, "true", None, 0)),
        ("rawContentPersisted", False, (True, "true", None, 0)),
        ("rawStatementsInEvidence", False, (True, "true", None, 0)),
    )
    for key, safe_value, unsafe_values in boolean_proof_cases:
        if entry_has_redaction_findings({"details": {key: safe_value}}):
            raise AssertionError(f"{key}={safe_value!r} was treated as unsafe")
        for unsafe_value in unsafe_values:
            if not entry_has_redaction_findings({"details": {key: unsafe_value}}):
                raise AssertionError(
                    f"{key}={unsafe_value!r} was not treated as unsafe"
                )

def assert_multi_node_release_evidence_is_not_overwritten(root: Path) -> None:
    pass_fixture = load_fixture(FIXTURE_DIR / "go-no-go-pass.json")
    inputs = json.loads(json.dumps(pass_fixture["inputs"]))
    release_certification = inputs["releaseCertificationSummary"]
    release_certification.setdefault("evidence", []).append(
        {
            "id": "multi-node-beta.support-bundle-drill",
            "status": "fail",
            "summary": "Release certification found support-bundle redaction findings.",
            "source": "release-certification-summary",
            "details": {"redactionFindings": ["support bundle leaked unsafe material"]},
        }
    )
    generated_at, now = parse_generated_at(DEFAULT_GENERATED_AT)
    dashboard = build_dashboard(
        inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "multi-node-release-evidence-preserved",
        "production-beta",
        "crypta-production-beta-270",
        generated_at,
        now,
    )
    if dashboard.get("decision") != "no-go":
        raise AssertionError(
            "failing release-certification multi-node evidence was overwritten: "
            f"{dashboard}"
        )
    blocker_ids = {
        str(blocker.get("evidenceId"))
        for blocker in dashboard.get("blockers", [])
        if isinstance(blocker, dict)
    }
    if "multi-node-beta.support-bundle-drill" not in blocker_ids:
        raise AssertionError(
            "failing release-certification support-bundle drill evidence did not block: "
            f"{dashboard}"
        )

def assert_inherited_security_drill_summary_timestamp_rebinds(root: Path) -> None:
    args = build_parser().parse_args(
        [
            "build",
            "--workspace-root",
            str(Path(__file__).resolve().parents[2]),
            "--out-dir",
            str(root / "inherited-security-drills-timestamp-rebind"),
            "--fixtures",
            str(FIXTURE_DIR / "go-no-go-expired-waiver.json"),
        ]
    )
    inputs, _paths, _scan_targets, _waiver_value, _release_id, mode, generated_at = (
        load_inputs_from_fixture(args, Path(__file__).resolve().parents[2])
    )
    summary = inputs.get("securityDrillsSummary")
    if not isinstance(summary, dict):
        raise AssertionError("expired-waiver fixture did not inherit a security drills summary")
    if summary.get("generatedAt") != generated_at:
        raise AssertionError(
            "inherited security drills summary did not rebind generatedAt: "
            f"{summary.get('generatedAt')} != {generated_at}"
        )
    _timestamp, now = parse_generated_at(generated_at)
    validation = security_response_runbook.validate_drills_summary(
        summary,
        production=mode == "production-beta",
        strict=mode in {"release-candidate", "production-beta"},
        now=now,
        expected_mode=mode if mode in {"release-candidate", "production-beta"} else None,
    )
    if "drills summary is stale" in validation.get("errors", []):
        raise AssertionError(
            "inherited security drills summary kept the parent fixture timestamp: "
            f"{validation}"
        )

def assert_previous_candidate_upgrade_current_binding_is_enforced(root: Path) -> None:
    pass_fixture = load_fixture(FIXTURE_DIR / "go-no-go-pass.json")
    mutations = (
        ("current-version", "currentVersion", "269"),
        ("current-catalog-channel", "currentCatalogChannel", "beta"),
        ("current-catalog-edition", "currentCatalogEdition", 123),
    )
    for label, field, value in mutations:
        inputs = json.loads(json.dumps(pass_fixture["inputs"]))
        upgrade = inputs["multiNodeBetaSoakSummary"]["previousCandidateUpgrade"]
        upgrade[field] = value
        generated_at, now = parse_generated_at(DEFAULT_GENERATED_AT)
        dashboard = build_dashboard(
            inputs,
            {},
            [FIXTURE_DIR / "go-no-go-pass.json"],
            None,
            Path(__file__).resolve().parents[2],
            root / f"previous-candidate-current-binding-{label}",
            "production-beta",
            "crypta-production-beta-270",
            generated_at,
            now,
        )
        if dashboard.get("decision") != "no-go":
            raise AssertionError(f"mismatched previous-candidate upgrade {field} did not block: {dashboard}")
        blocker_ids = {
            str(blocker.get("evidenceId"))
            for blocker in dashboard.get("blockers", [])
            if isinstance(blocker, dict)
        }
        if "multi-node-beta.previous-candidate-upgrade-binding" not in blocker_ids:
            raise AssertionError(f"mismatched previous-candidate upgrade {field} used wrong blocker: {dashboard}")

def assert_security_drills_preserve_failing_runbook_evidence(root: Path) -> None:
    pass_fixture = load_fixture(FIXTURE_DIR / "go-no-go-pass.json")
    inputs = json.loads(json.dumps(pass_fixture["inputs"]))
    inputs["releaseCertificationSummary"].setdefault("evidence", []).append(
        {
            "id": "production-security.response-runbook",
            "status": "pass",
            "summary": "Combined release-certification security response evidence passed.",
            "source": "release-certification-summary",
            "details": {
                "appPlatformRunbook": {
                    "id": "production-security.response-runbook",
                    "status": "pass",
                    "summary": "App-platform runbook evidence passed.",
                    "source": "app-platform-smoke",
                },
                "securityDrills": {
                    "id": "production-security.response-runbook",
                    "status": "pass",
                    "summary": "Security response drills passed.",
                    "source": "security-drills-summary",
                },
                "componentStatuses": {
                    "appPlatformRunbook": "pass",
                    "securityDrills": "pass",
                },
            },
        }
    )
    for entry in inputs["appPlatformSummary"]["evidence"]:
        if isinstance(entry, dict) and entry.get("id") == "production-security.response-runbook":
            entry["status"] = "fail"
            entry["summary"] = "App-platform security response runbook integration failed."
            entry["details"] = {"checks": {"runbookDocExists": False}}
            break
    else:
        raise AssertionError("app-platform production-security.response-runbook evidence is missing")
    generated_at, now = parse_generated_at(DEFAULT_GENERATED_AT)
    dashboard = build_dashboard(
        inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "security-drills-preserve-failing-runbook",
        "production-beta",
        "crypta-production-beta-270",
        generated_at,
        now,
    )
    if dashboard.get("decision") != "no-go":
        raise AssertionError(
            "passing security drills overwrote failing runbook evidence: "
            f"{dashboard}"
        )
    blocker_ids = {
        str(blocker.get("evidenceId"))
        for blocker in dashboard.get("blockers", [])
        if isinstance(blocker, dict)
    }
    if "production-security.response-runbook" not in blocker_ids:
        raise AssertionError(f"failing runbook evidence did not block: {dashboard}")
    security_domain = next(
        (domain for domain in dashboard.get("domains", []) if domain.get("id") == "production-security-response"),
        {},
    )
    if security_domain.get("status") != "fail":
        raise AssertionError(f"security response domain did not fail: {security_domain}")

def assert_security_drills_require_app_platform_runbook_evidence(root: Path) -> None:
    pass_fixture = load_fixture(FIXTURE_DIR / "go-no-go-pass.json")
    inputs = json.loads(json.dumps(pass_fixture["inputs"]))
    for summary_name in ("releaseCertificationSummary", "appPlatformSummary"):
        summary = inputs.get(summary_name)
        if not isinstance(summary, dict) or not isinstance(summary.get("evidence"), list):
            continue
        summary["evidence"] = [
            entry
            for entry in summary["evidence"]
            if not (isinstance(entry, dict) and entry.get("id") == "production-security.response-runbook")
        ]
    generated_at, now = parse_generated_at(DEFAULT_GENERATED_AT)
    dashboard = build_dashboard(
        inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "security-drills-require-app-platform-runbook",
        "production-beta",
        "crypta-production-beta-270",
        generated_at,
        now,
    )
    if dashboard.get("decision") != "no-go":
        raise AssertionError(
            "passing security drills masked missing app-platform runbook evidence: "
            f"{dashboard}"
        )
    blocker_ids = {
        str(blocker.get("evidenceId"))
        for blocker in dashboard.get("blockers", [])
        if isinstance(blocker, dict)
    }
    if "production-security.response-runbook" not in blocker_ids:
        raise AssertionError(f"missing app-platform runbook evidence did not block: {dashboard}")
    security_evidence = dashboard.get("securityDrills")
    if not isinstance(security_evidence, dict) or security_evidence.get("promotionReady") is not True:
        raise AssertionError(f"passing drill summary should remain visible separately: {dashboard}")

def assert_security_drill_summary_evidence_is_not_generic_release_evidence(root: Path) -> None:
    pass_fixture = load_fixture(FIXTURE_DIR / "go-no-go-pass.json")
    inputs = json.loads(json.dumps(pass_fixture["inputs"]))
    for entry in inputs["appPlatformSummary"]["evidence"]:
        if isinstance(entry, dict) and entry.get("id") == "first-party-app.beta-quality-pass":
            entry["status"] = "fail"
            entry["summary"] = "First-party beta-quality readiness failed."
            break
    else:
        raise AssertionError("first-party beta-quality evidence is missing from app-platform fixture")
    security_drills = inputs.get("securityDrillsSummary")
    if not isinstance(security_drills, dict):
        raise AssertionError("go-no-go-pass fixture is missing securityDrillsSummary")
    security_drills.setdefault("evidence", []).append(
        {
            "id": "first-party-app.beta-quality-pass",
            "status": "pass",
            "summary": "Forged generic evidence inside the security drills summary.",
            "source": "security-drills-summary",
        }
    )
    generated_at, now = parse_generated_at(DEFAULT_GENERATED_AT)
    dashboard = build_dashboard(
        inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "security-drills-evidence-not-generic",
        "production-beta",
        "crypta-production-beta-270",
        generated_at,
        now,
    )
    if dashboard.get("decision") != "no-go":
        raise AssertionError(
            "generic evidence embedded in securityDrillsSummary overrode authoritative evidence: "
            f"{dashboard}"
        )
    blocker_ids = {
        str(blocker.get("evidenceId"))
        for blocker in dashboard.get("blockers", [])
        if isinstance(blocker, dict)
    }
    if "first-party-app.beta-quality-pass" not in blocker_ids:
        raise AssertionError(f"failed first-party beta-quality evidence did not block: {dashboard}")
    security_drills_compact = dashboard.get("securityDrills")
    if (
        not isinstance(security_drills_compact, dict)
        or security_drills_compact.get("promotionReady") is not True
    ):
        raise AssertionError(f"passing drill summary should remain visible separately: {dashboard}")

def assert_security_drill_summary_path_requires_sibling_artifacts(root: Path) -> None:
    input_args, input_paths = path_input_args_from_pass_fixture(
        root,
        "security-drill-summary-path-missing-artifacts",
    )
    pass_fixture = read_json(FIXTURE_DIR / "go-no-go-pass.json")
    if not isinstance(pass_fixture, dict) or not isinstance(pass_fixture.get("inputs"), dict):
        raise AssertionError("go-no-go-pass.json must contain security drill path-test inputs")
    security_drills = pass_fixture["inputs"].get("securityDrillsSummary")
    if not isinstance(security_drills, dict):
        raise AssertionError("go-no-go-pass fixture is missing securityDrillsSummary")
    security_drills_path = (
        root
        / "security-drill-summary-path-missing-artifacts"
        / "security-drills-summary.json"
    )
    write_json(security_drills_path, security_drills)
    args_list = [
        "build",
        "--workspace-root",
        str(Path(__file__).resolve().parents[2]),
        "--out-dir",
        str(root / "security-drill-summary-path-missing-artifacts-output"),
        "--mode",
        "production-beta",
        "--release-id",
        "crypta-production-beta-270",
        "--generated-at",
        DEFAULT_GENERATED_AT,
        "--security-drills-summary",
        str(security_drills_path),
    ]
    for flag, input_name in input_args:
        args_list.extend([flag, str(input_paths[input_name])])
    dashboard, _exit_code = build_command(build_parser().parse_args(args_list))
    if dashboard.get("decision") != "no-go":
        raise AssertionError(
            "file-backed securityDrillsSummary without sibling artifacts produced GO: "
            f"{dashboard}"
        )
    blocker_ids = {
        str(blocker.get("evidenceId"))
        for blocker in dashboard.get("blockers", [])
        if isinstance(blocker, dict)
    }
    if "production-security.response-runbook" not in blocker_ids:
        raise AssertionError(f"missing drill artifacts did not block security response: {dashboard}")
    security_drills_compact = dashboard.get("securityDrills")
    if (
        not isinstance(security_drills_compact, dict)
        or security_drills_compact.get("status") != "fail"
        or security_drills_compact.get("promotionReady") is True
    ):
        raise AssertionError(f"missing drill artifacts did not fail compact drill status: {dashboard}")
    artifact_validation = security_drills_compact.get("artifactValidation")
    artifact_errors = (
        artifact_validation.get("errors")
        if isinstance(artifact_validation, dict)
        and isinstance(artifact_validation.get("errors"), list)
        else []
    )
    if "security drill artifact for reviewer-key-compromise is missing" not in artifact_errors:
        raise AssertionError(
            "missing sibling drill artifacts were not reported in compact validation: "
            f"{dashboard}"
        )

def assert_security_drills_release_id_matches_dashboard_candidate(root: Path) -> None:
    pass_fixture = load_fixture(FIXTURE_DIR / "go-no-go-pass.json")
    inputs = json.loads(json.dumps(pass_fixture["inputs"]))
    security_drills = inputs.get("securityDrillsSummary")
    if not isinstance(security_drills, dict):
        raise AssertionError("go-no-go-pass fixture is missing securityDrillsSummary")
    security_drills["releaseId"] = "cryptad-beta-other-candidate"
    generated_at, now = parse_generated_at(DEFAULT_GENERATED_AT)
    dashboard = build_dashboard(
        inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "security-drills-release-id-mismatch",
        "production-beta",
        "crypta-production-beta-270",
        generated_at,
        now,
    )
    if dashboard.get("decision") != "no-go":
        raise AssertionError(
            "security drills from another release id did not block: "
            f"{dashboard}"
        )
    blockers = [
        blocker
        for blocker in dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("evidenceId") == "production-security.response-runbook"
    ]
    if not blockers:
        raise AssertionError(f"release-id mismatch did not block production security response: {dashboard}")
    security_evidence = next(
        (
            domain
            for domain in dashboard.get("domains", [])
            if isinstance(domain, dict) and domain.get("id") == "production-security-response"
        ),
        {},
    )
    if security_evidence.get("status") != "fail":
        raise AssertionError(f"release-id mismatch did not fail security response domain: {dashboard}")
    security_drills = dashboard.get("securityDrills")
    if not isinstance(security_drills, dict) or security_drills.get("status") != "fail":
        raise AssertionError(f"release-id mismatch did not fail compact security drill status: {dashboard}")
    if security_drills.get("promotionReady") is True:
        raise AssertionError(f"release-id mismatch left security drills promotion-ready: {dashboard}")
