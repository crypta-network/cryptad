"""Implementation segment for the selftest portion of ``stable_1_0_readiness.py``."""

from __future__ import annotations

def run_self_test() -> None:
    expected_cases = {
        "ready",
        "allowed-limitations",
        "generated-at-does-not-control-freshness",
        "missing-production",
        "production-stub",
        "production-not-ready",
        "production-dirty-workspace",
        "production-workspace-status-unknown",
        "production-missing-signing-profile",
        "production-missing-signing-field",
        "production-non-string-app-key-id",
        "production-non-string-reviewer-key-id",
        "production-redaction-findings",
        "production-redaction-count",
        "production-boolean-schema-version",
        "production-failed-gate-status",
        "production-missing-required-promotion-gates",
        "production-pre-dist-artifact-refs",
        "go-no-go-no-go",
        "go-no-go-stub",
        "go-no-go-wrong-release-id",
        "go-no-go-non-production-mode",
        "go-no-go-boolean-schema-version",
        "go-no-go-failed-domain",
        "go-no-go-truncated-domains",
        "go-no-go-duplicate-domain",
        "go-no-go-warning-domain",
        "go-no-go-unreported-warning-domain",
        "go-no-go-waived-domain",
        "go-no-go-waiver-malformed-used-by",
        "go-no-go-waiver-count-decision-mismatch",
        "go-no-go-listed-blocker",
        "go-no-go-critical-summary-count",
        "go-no-go-malformed-critical-summary-count",
        "go-no-go-redaction-findings",
        "go-no-go-redaction-count",
        "go-no-go-redaction-fractional-count",
        "go-no-go-critical-redaction-summary-count",
        "go-no-go-redaction-malformed-findings",
        "go-no-go-redaction-raw-flag",
        "go-no-go-domain-redaction-failure",
        "release-certification-failed",
        "release-certification-not-passed",
        "release-certification-ecosystem-rc-not-passed",
        "release-certification-non-rc-mode",
        "release-certification-boolean-schema-version",
        "release-certification-stub",
        "release-certification-missing-redaction",
        "release-certification-redaction-status-schema",
        "release-certification-redaction-field-failed",
        "release-certification-redaction-truncated-proof",
        "release-certification-redaction-count",
        "release-certification-redaction-raw-flag",
        "release-certification-evidence-failed",
        "app-platform-duplicate-evidence-failed",
        "attached-evidence-redaction-findings",
        "app-platform-evidence-top-level-redaction-signals",
        "release-certification-evidence-redaction-findings",
        "release-certification-evidence-redacted-false",
        "release-certification-evidence-raw-stored",
        "release-certification-evidence-sensitive-stored",
        "release-certification-evidence-excluded-from-evidence-false",
        "release-certification-evidence-direct-excluded-from-evidence-false",
        "release-certification-evidence-direct-critical-redaction-count",
        "release-certification-evidence-malformed-redaction-findings",
        "release-certification-evidence-nested-redaction-findings",
        "app-platform-summary-missing",
        "app-platform-summary-failed",
        "app-platform-summary-malformed-envelope",
        "app-platform-summary-non-release-mode",
        "app-platform-summary-non-release-flag",
        "app-platform-summary-non-production",
        "app-platform-summary-fixture-only",
        "app-platform-summary-truncated-evidence",
        "app-platform-evidence-redaction-clean-false",
        "app-platform-evidence-redaction-status-fail",
        "app-platform-evidence-malformed-redaction-proof",
        "app-platform-evidence-nested-redaction-status-warn",
        "ecosystem-matrix-failed",
        "ecosystem-matrix-failed-row",
        "ecosystem-matrix-warning-row",
        "ecosystem-matrix-missing-rows",
        "ecosystem-matrix-truncated-rows",
        "ecosystem-matrix-non-list-rows",
        "ecosystem-matrix-malformed-row",
        "ecosystem-matrix-row-redaction-failure",
        "missing-platform-baseline",
        "malformed-platform-baseline-count",
        "missing-compatibility-window-details",
        "stable-api-breaking-change",
        "platform-api-status-only-redaction-failure",
        "missing-first-party",
        "diagnostics-nested-redaction-findings",
        "missing-third-party",
        "empty-third-party-sample-flow",
        "truncated-third-party-sample-flow",
        "missing-support-feedback-docs",
        "stale-security",
        "security-status-fail-redaction-pass",
        "security-malformed-fixture-only",
        "security-malformed-non-release",
        "malformed-security-scenario-list",
        "missing-security-scenario-result-list",
        "security-missing-schema-version",
        "security-boolean-schema-version",
        "security-truncated-summary",
        "security-redaction-unsafe-flag",
        "security-redaction-count",
        "security-release-id-mismatch",
        "missing-security-required-scenarios",
        "malformed-security-required-scenario-entry",
        "malformed-required-release-modes-policy",
        "malformed-soak-mode-policy",
        "fractional-stable-policy-integers",
        "scalar-platform-api-policy",
        "scalar-allowed-limitation-categories-policy",
        "scalar-non-waivable-blockers-policy",
        "malformed-category-policy-entry",
        "multi-node-release-id-mismatch",
        "multi-node-truncated-summary",
        "multi-node-raw-evidence-flag",
        "multi-node-redaction-count",
        "network-release-id-mismatch",
        "network-release-id-missing",
        "network-truncated-summary",
        "network-forged-operation-count",
        "stale-security-summary-age",
        "stale-security-artifact-age",
        "missing-security-artifacts",
        "non-list-security-artifacts",
        "empty-security-artifacts",
        "malformed-security-artifact-entry",
        "missing-security-artifact-digest",
        "malformed-security-artifact-digest",
        "missing-required-security-artifact",
        "duplicate-required-security-artifact",
        "failed-required-security-artifact",
        "missing-security-artifact-release-notes-template-status",
        "missing-security-artifact-advisory-template-status",
        "extra-pass-security-artifact",
        "extra-failed-security-artifact",
        "missing-live-network-evidence",
        "missing-previous-upgrade",
        "app-data-migration-scenario-failed",
        "network-redaction-missing",
        "network-redaction-truncated-proof",
        "network-redaction-status-missing",
        "network-redaction-findings",
        "network-redaction-count",
        "network-redaction-status-fail",
        "stale-soak-evidence",
        "insufficient-network",
        "known-issues-tracker-envelope-stub",
        "malformed-known-issues-tracker",
        "malformed-known-issue-entry",
        "malformed-known-issue-metadata",
        "non-string-known-issue-metadata",
        "known-issue-unsafe-redaction-proof",
        "known-issue-redaction-findings",
        "critical-known-issue",
        "critical-known-issue-future-fixed",
        "beta-only-limitation",
        "allowed-limitation-missing-metadata",
        "allowed-disallowed-category",
        "unknown-limitation-classification",
        "malformed-known-limitations",
        "boolean-known-limitations-schema-version",
        "malformed-known-limitation-entry",
        "missing-policy",
        "invalid-utf8-policy",
        "boolean-policy-schema-version",
        "redaction-unsafe",
        "invalid-waiver",
        "invalid-utf8-waiver",
        "boolean-waiver-schema-version",
        "incomplete-waiver-metadata",
        "non-string-waiver-metadata",
        "missing-waiver-required-fields",
        "waived-limitation-missing-metadata",
        "waived-limitation-valid",
        "allowed-trust-graph",
        "allowed-social-inbox",
    }
    case_manifest = read_json(FIXTURE_DIR / "stable-1.0-readiness-cases.json")
    manifest_cases = {
        str(case.get("id"))
        for case in case_manifest.get("cases", [])
        if isinstance(case, dict)
    } if isinstance(case_manifest, dict) else set()
    if manifest_cases != expected_cases:
        raise AssertionError(
            "stable readiness fixture manifest does not match self-test cases: "
            f"missing={sorted(expected_cases - manifest_cases)} extra={sorted(manifest_cases - expected_cases)}"
        )
    for signal_name, signal_value in (
        ("redactionFindings", [{"kind": "stable-readiness-self-test"}]),
        ("findingCount", 1),
        ("privateInsertUrisStored", True),
    ):
        signal_entry = {
            "id": "stable-readiness.synthetic-redaction-signal",
            "status": "pass",
            "details": {},
            signal_name: signal_value,
        }
        if not entry_has_redaction_findings(signal_entry):
            raise AssertionError(
                f"top-level evidence redaction signal was not detected: {signal_name}"
            )
    with tempfile.TemporaryDirectory(prefix="cryptad-stable-readiness-self-test-") as temp_name:
        root = Path(temp_name)
        docs_root = root / "docs"
        (docs_root / "public-beta").mkdir(parents=True)
        (docs_root / "templates").mkdir(parents=True)
        for path in DOC_PATHS:
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"# {Path(path).stem}\n", encoding="utf-8")

        run_case(root, "ready", None, "ready")

        def assert_allowed_limitation_owner(summary: dict[str, Any]) -> None:
            allowed = {
                str(record.get("id")): record
                for record in summary.get("allowedLimitations", [])
                if isinstance(record, dict)
            }
            trust_graph = allowed.get("stable-1.0.trust-graph-local-scope")
            if not isinstance(trust_graph, dict) or trust_graph.get("owner") != "crypta-core":
                raise AssertionError(
                    "Stable readiness did not preserve the allowed limitation owner: "
                    f"{trust_graph}"
                )

        run_case(
            root,
            "allowed-limitations",
            lambda _i, _l, _p: None,
            "ready-with-allowed-limitations",
            expect_allowed="stable-1.0.trust-graph-local-scope",
            post_check=assert_allowed_limitation_owner,
        )

        def assert_generated_at_does_not_control_freshness(summary: dict[str, Any]) -> None:
            if summary.get("generatedAt") != DEFAULT_GENERATED_AT:
                raise AssertionError(
                    "deterministic output timestamp was not preserved: "
                    f"{summary.get('generatedAt')}"
                )
            blocker_ids = {
                str(blocker.get("evidenceId"))
                for blocker in summary.get("blockers", [])
                if isinstance(blocker, dict)
            }
            if "stable-1.0.live-multi-node-soak" not in blocker_ids:
                raise AssertionError(
                    "real validation clock did not reject stale soak evidence: "
                    f"{summary.get('blockers')}"
                )

        run_case(
            root,
            "generated-at-does-not-control-freshness",
            None,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
            post_check=assert_generated_at_does_not_control_freshness,
            use_real_validation_time=True,
        )

        def missing_production(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs.pop("productionBetaSummary", None)

        run_case(root, "missing-production", missing_production, "not-ready", expect_blocker="stable-1.0.production-beta-state")

        def production_stub(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["productionBetaSummary"] = {
                "mode": "production-beta",
                "status": "pass",
                "promotionReady": True,
                "nonRelease": False,
                "releaseId": "cryptad-beta-270",
                "version": "270",
                "signingProfile": {
                    "kind": "production",
                    "generatedTestKeys": False,
                    "appKeyId": "production-app-key",
                    "reviewerKeyId": "production-reviewer-key",
                    "privateKeyMaterialIncluded": False,
                },
                "redaction": {"status": "pass", "findingCount": 0, "findings": []},
            }

        run_case(
            root,
            "production-stub",
            production_stub,
            "not-ready",
            expect_blocker="stable-1.0.production-beta-state",
        )

        def production_not_ready(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["productionBetaSummary"]["promotionReady"] = False

        run_case(root, "production-not-ready", production_not_ready, "not-ready", expect_blocker="stable-1.0.production-beta-state")

        def production_dirty_workspace(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["productionBetaSummary"]["dirtyWorkspace"] = True

        run_case(
            root,
            "production-dirty-workspace",
            production_dirty_workspace,
            "not-ready",
            expect_blocker="stable-1.0.production-beta-state",
        )

        def production_workspace_status_unknown(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["productionBetaSummary"]["workspaceStatusKnown"] = False

        run_case(
            root,
            "production-workspace-status-unknown",
            production_workspace_status_unknown,
            "not-ready",
            expect_blocker="stable-1.0.production-beta-state",
        )

        def production_missing_signing_profile(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["productionBetaSummary"].pop("signingProfile", None)

        run_case(
            root,
            "production-missing-signing-profile",
            production_missing_signing_profile,
            "not-ready",
            expect_blocker="stable-1.0.production-beta-state",
        )

        def production_missing_signing_field(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["productionBetaSummary"]["signingProfile"].pop("generatedTestKeys", None)

        run_case(
            root,
            "production-missing-signing-field",
            production_missing_signing_field,
            "not-ready",
            expect_blocker="stable-1.0.production-beta-state",
        )

        def production_non_string_app_key_id(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["productionBetaSummary"]["signingProfile"]["appKeyId"] = 123

        run_case(
            root,
            "production-non-string-app-key-id",
            production_non_string_app_key_id,
            "not-ready",
            expect_blocker="stable-1.0.production-beta-state",
        )

        def production_non_string_reviewer_key_id(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["productionBetaSummary"]["signingProfile"]["reviewerKeyId"] = {}

        run_case(
            root,
            "production-non-string-reviewer-key-id",
            production_non_string_reviewer_key_id,
            "not-ready",
            expect_blocker="stable-1.0.production-beta-state",
        )

        def production_redaction_findings(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["productionBetaSummary"]["redaction"] = {
                "schemaVersion": 1,
                "status": "pass",
                "findingCount": 1,
                "findings": [
                    {
                        "kind": "redaction-fixture",
                        "location": "production-beta-summary",
                        "summary": "Synthetic redaction finding for Stable readiness validation.",
                    }
                ],
            }

        run_case(
            root,
            "production-redaction-findings",
            production_redaction_findings,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def production_redaction_count(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["productionBetaSummary"]["redaction"] = {
                "status": "pass",
                "findingCount": 1,
            }

        run_case(
            root,
            "production-redaction-count",
            production_redaction_count,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def production_redaction_critical_count(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["productionBetaSummary"]["redaction"] = {
                "status": "pass",
                "findingCount": 0,
                "criticalFindingCount": 1,
            }

        run_case(
            root,
            "production-redaction-critical-count",
            production_redaction_critical_count,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def production_redaction_fractional_critical_count(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["productionBetaSummary"]["redaction"] = {
                "status": "pass",
                "findingCount": 0,
                "criticalFindingCount": 0.5,
            }

        run_case(
            root,
            "production-redaction-fractional-critical-count",
            production_redaction_fractional_critical_count,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def production_boolean_schema_version(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["productionBetaSummary"]["schemaVersion"] = True

        run_case(
            root,
            "production-boolean-schema-version",
            production_boolean_schema_version,
            "not-ready",
            expect_blocker="stable-1.0.production-beta-state",
        )

        def production_failed_gate_status(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            for gate in inputs["productionBetaSummary"]["promotion"]["gates"]:
                if gate.get("id") == "signing.production-keys":
                    gate["status"] = "fail"
                    return
            raise AssertionError("signing.production-keys gate missing from self-test fixture")

        run_case(
            root,
            "production-failed-gate-status",
            production_failed_gate_status,
            "not-ready",
            expect_blocker="stable-1.0.production-beta-state",
        )

        def production_missing_required_promotion_gates(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["productionBetaSummary"]["promotion"]["gates"] = [
                {"id": "production-beta.synthetic-passing-gate", "status": "pass"}
            ]

        run_case(
            root,
            "production-missing-required-promotion-gates",
            production_missing_required_promotion_gates,
            "not-ready",
            expect_blocker="stable-1.0.production-beta-state",
        )

        def production_pre_dist_artifact_refs(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            artifacts = inputs["productionBetaSummary"]["artifacts"]
            artifacts.pop("distArchive", None)
            artifacts.pop("checksums", None)

        def assert_pre_dist_artifact_refs(summary: dict[str, Any]) -> None:
            blocker_ids = {str(blocker.get("evidenceId")) for blocker in summary.get("blockers", [])}
            if "stable-1.0.production-beta-state" in blocker_ids:
                raise AssertionError(
                    "pre-dist production beta summary created production blocker: "
                    f"{summary.get('blockers')}"
                )

        run_case(
            root,
            "production-pre-dist-artifact-refs",
            production_pre_dist_artifact_refs,
            "ready",
            post_check=assert_pre_dist_artifact_refs,
        )

        def go_no_go_no_go(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["goNoGoSummary"]["decision"] = "no-go"
            inputs["goNoGoSummary"]["promotionReady"] = False

        run_case(root, "go-no-go-no-go", go_no_go_no_go, "not-ready", expect_blocker="stable-1.0.go-no-go-decision")

        def go_no_go_stub(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["goNoGoSummary"] = {
                "mode": "production-beta",
                "releaseId": "cryptad-beta-270",
                "decision": "go",
                "promotionReady": True,
                "redaction": {"status": "pass", "findingCount": 0, "findings": []},
            }

        run_case(
            root,
            "go-no-go-stub",
            go_no_go_stub,
            "not-ready",
            expect_blocker="stable-1.0.go-no-go-decision",
        )

        def go_no_go_wrong_release_id(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["goNoGoSummary"]["releaseId"] = "cryptad-beta-previous"

        run_case(
            root,
            "go-no-go-wrong-release-id",
            go_no_go_wrong_release_id,
            "not-ready",
            expect_blocker="stable-1.0.go-no-go-decision",
        )

        def go_no_go_non_production_mode(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["goNoGoSummary"]["mode"] = "developer-dry-run"

        run_case(
            root,
            "go-no-go-non-production-mode",
            go_no_go_non_production_mode,
            "not-ready",
            expect_blocker="stable-1.0.go-no-go-decision",
        )

        def go_no_go_boolean_schema_version(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["goNoGoSummary"]["schemaVersion"] = True

        run_case(
            root,
            "go-no-go-boolean-schema-version",
            go_no_go_boolean_schema_version,
            "not-ready",
            expect_blocker="stable-1.0.go-no-go-decision",
        )

        def go_no_go_failed_domain(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["goNoGoSummary"]["domains"][0]["status"] = "fail"

        run_case(
            root,
            "go-no-go-failed-domain",
            go_no_go_failed_domain,
            "not-ready",
            expect_blocker="stable-1.0.go-no-go-decision",
        )

        def go_no_go_truncated_domains(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["goNoGoSummary"]["domains"] = [
                {"id": "stub-domain", "status": "pass"}
            ]

        run_case(
            root,
            "go-no-go-truncated-domains",
            go_no_go_truncated_domains,
            "not-ready",
            expect_blocker="stable-1.0.go-no-go-decision",
        )

        def go_no_go_duplicate_domain(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            domains = inputs["goNoGoSummary"]["domains"]
            domains.append(copy.deepcopy(domains[0]))

        run_case(
            root,
            "go-no-go-duplicate-domain",
            go_no_go_duplicate_domain,
            "not-ready",
            expect_blocker="stable-1.0.go-no-go-decision",
        )

        def go_no_go_warning_domain(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            warning_domain_id = inputs["goNoGoSummary"]["domains"][0]["id"]
            inputs["goNoGoSummary"]["domains"][0]["status"] = "warn"
            inputs["goNoGoSummary"]["summary"]["warnings"] = 1
            inputs["goNoGoSummary"]["warnings"] = [
                {
                    "id": "production-beta.synthetic-warning",
                    "evidenceId": "production-beta.synthetic-evidence",
                    "domainId": warning_domain_id,
                    "severity": "warning",
                    "title": "Synthetic production beta warning",
                    "summary": "Synthetic production beta warning remains open for Stable review.",
                    "source": "production-beta-self-test",
                    "waivable": True,
                    "category": "self-test",
                }
            ]

        def assert_go_no_go_warning_domain(summary: dict[str, Any]) -> None:
            blocker_ids = {str(blocker.get("evidenceId")) for blocker in summary.get("blockers", [])}
            if "stable-1.0.go-no-go-decision" in blocker_ids:
                raise AssertionError(f"go-no-go-warning-domain created blocker: {summary.get('blockers')}")
            if summary.get("status") != "warn" or summary.get("warningCount") != 1:
                raise AssertionError(
                    "go-no-go-warning-domain did not preserve the Stable warning status/count: "
                    f"{summary}"
                )
            propagated_warnings = [
                warning
                for warning in summary.get("warnings", [])
                if isinstance(warning, dict)
                and warning.get("sourceWarningId") == "production-beta.synthetic-warning"
                and warning.get("sourceEvidenceId") == "production-beta.synthetic-evidence"
                and warning.get("evidenceId") == "stable-1.0.go-no-go-decision"
            ]
            if len(propagated_warnings) != 1:
                raise AssertionError(
                    "go-no-go-warning-domain did not propagate the dashboard warning: "
                    f"{summary.get('warnings')}"
                )

        run_case(
            root,
            "go-no-go-warning-domain",
            go_no_go_warning_domain,
            "ready",
            post_check=assert_go_no_go_warning_domain,
        )

        def go_no_go_unreported_warning_domain(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["goNoGoSummary"]["domains"][0]["status"] = "warn"

        run_case(
            root,
            "go-no-go-unreported-warning-domain",
            go_no_go_unreported_warning_domain,
            "not-ready",
            expect_blocker="stable-1.0.go-no-go-decision",
        )

        def go_no_go_waived_domain(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["goNoGoSummary"]["decision"] = "go-with-waivers"
            inputs["goNoGoSummary"]["summary"]["waiversUsed"] = 1
            inputs["goNoGoSummary"]["domains"][0]["status"] = "waived"
            inputs["goNoGoSummary"]["waivers"] = [
                {
                    "id": "production-beta.synthetic-waiver",
                    "usedBy": ["production-beta.synthetic-issue"],
                }
            ]

        def assert_go_no_go_waived_domain(summary: dict[str, Any]) -> None:
            if summary["status"] != "warn":
                raise AssertionError(f"go-no-go-waived-domain expected warn status: {summary}")
            blocker_ids = {str(blocker.get("evidenceId")) for blocker in summary.get("blockers", [])}
            if "stable-1.0.go-no-go-decision" in blocker_ids:
                raise AssertionError(f"go-no-go-waived-domain created blocker: {summary.get('blockers')}")
            warning_ids = {str(warning.get("evidenceId")) for warning in summary.get("warnings", [])}
            if "stable-1.0.go-no-go-decision" not in warning_ids:
                raise AssertionError(f"go-no-go-waived-domain missing waiver warning: {summary.get('warnings')}")

        run_case(
            root,
            "go-no-go-waived-domain",
            go_no_go_waived_domain,
            "ready",
            post_check=assert_go_no_go_waived_domain,
        )

        def go_no_go_waiver_malformed_used_by(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["goNoGoSummary"]["decision"] = "go-with-waivers"
            inputs["goNoGoSummary"]["summary"]["waiversUsed"] = 1
            inputs["goNoGoSummary"]["domains"][0]["status"] = "waived"
            inputs["goNoGoSummary"]["waivers"] = [
                {
                    "id": "production-beta.synthetic-waiver",
                    "usedBy": ["", 1],
                }
            ]

        run_case(
            root,
            "go-no-go-waiver-malformed-used-by",
            go_no_go_waiver_malformed_used_by,
            "not-ready",
            expect_blocker="stable-1.0.go-no-go-decision",
        )

        def go_no_go_waiver_count_decision_mismatch(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["goNoGoSummary"]["decision"] = "go"
            inputs["goNoGoSummary"]["summary"]["waiversUsed"] = 1
            inputs["goNoGoSummary"]["waivers"] = [
                {
                    "id": "production-beta.synthetic-waiver",
                    "usedBy": ["production-beta.synthetic-issue"],
                }
            ]

        run_case(
            root,
            "go-no-go-waiver-count-decision-mismatch",
            go_no_go_waiver_count_decision_mismatch,
            "not-ready",
            expect_blocker="stable-1.0.go-no-go-decision",
        )

        def go_no_go_listed_blocker(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["goNoGoSummary"]["summary"]["blockers"] = 1
            inputs["goNoGoSummary"]["blockers"] = [
                {
                    "id": "production-beta.go-no-go-forged-blocker",
                    "evidenceId": "production-beta.go-no-go-decision",
                    "summary": "Synthetic go/no-go blocker.",
                }
            ]

        run_case(
            root,
            "go-no-go-listed-blocker",
            go_no_go_listed_blocker,
            "not-ready",
            expect_blocker="stable-1.0.go-no-go-decision",
        )

        def go_no_go_critical_summary_count(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["goNoGoSummary"]["summary"]["criticalFindings"] = 1

        run_case(
            root,
            "go-no-go-critical-summary-count",
            go_no_go_critical_summary_count,
            "not-ready",
            expect_blocker="stable-1.0.go-no-go-decision",
        )

        def go_no_go_malformed_critical_summary_count(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["goNoGoSummary"]["summary"]["criticalFindings"] = 0.5

        run_case(
            root,
            "go-no-go-malformed-critical-summary-count",
            go_no_go_malformed_critical_summary_count,
            "not-ready",
            expect_blocker="stable-1.0.go-no-go-decision",
        )

        def go_no_go_redaction_findings(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["goNoGoSummary"]["redaction"] = {
                "schemaVersion": 1,
                "status": "pass",
                "findingCount": 1,
                "findings": [
                    {
                        "kind": "redaction-fixture",
                        "location": "go-no-go-summary",
                        "summary": "Synthetic dashboard redaction finding for Stable readiness validation.",
                    }
                ],
            }

        run_case(
            root,
            "go-no-go-redaction-findings",
            go_no_go_redaction_findings,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def go_no_go_redaction_count(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["goNoGoSummary"]["redaction"] = {
                "schemaVersion": 1,
                "status": "pass",
                "findingCount": 1,
            }

        run_case(
            root,
            "go-no-go-redaction-count",
            go_no_go_redaction_count,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def go_no_go_redaction_critical_count(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["goNoGoSummary"]["redaction"] = {
                "schemaVersion": 1,
                "status": "pass",
                "findingCount": 0,
                "criticalFindingCount": 1,
            }

        run_case(
            root,
            "go-no-go-redaction-critical-count",
            go_no_go_redaction_critical_count,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def go_no_go_redaction_fractional_count(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["goNoGoSummary"]["redaction"] = {
                "schemaVersion": 1,
                "status": "pass",
                "findingCount": 0.5,
            }

        run_case(
            root,
            "go-no-go-redaction-fractional-count",
            go_no_go_redaction_fractional_count,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def go_no_go_redaction_fractional_critical_count(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["goNoGoSummary"]["redaction"] = {
                "schemaVersion": 1,
                "status": "pass",
                "findingCount": 0,
                "criticalFindingCount": 0.5,
            }

        run_case(
            root,
            "go-no-go-redaction-fractional-critical-count",
            go_no_go_redaction_fractional_critical_count,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def go_no_go_critical_redaction_summary_count(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["goNoGoSummary"]["summary"]["criticalRedactionFindings"] = 1

        run_case(
            root,
            "go-no-go-critical-redaction-summary-count",
            go_no_go_critical_redaction_summary_count,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def go_no_go_redaction_malformed_findings(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["goNoGoSummary"]["redaction"] = {
                "status": "pass",
                "findings": "not-a-list",
            }

        run_case(
            root,
            "go-no-go-redaction-malformed-findings",
            go_no_go_redaction_malformed_findings,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def go_no_go_redaction_raw_flag(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["goNoGoSummary"]["redaction"] = {
                "schemaVersion": 1,
                "status": "pass",
                "findingCount": 0,
                "findings": [],
                "rawFetchedContentIncluded": True,
            }

        run_case(
            root,
            "go-no-go-redaction-raw-flag",
            go_no_go_redaction_raw_flag,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def go_no_go_domain_redaction_failure(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            domains = inputs["goNoGoSummary"].get("domains")
            if not isinstance(domains, list) or not domains:
                raise AssertionError("base go/no-go summary fixture has no domains")
            domains[0]["details"] = {
                "redaction": {
                    "status": "fail",
                    "findings": [],
                }
            }

        run_case(
            root,
            "go-no-go-domain-redaction-failure",
            go_no_go_domain_redaction_failure,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def release_certification_failed(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["releaseCertificationSummary"]["status"] = "fail"

        run_case(
            root,
            "release-certification-failed",
            release_certification_failed,
            "not-ready",
            expect_blocker="stable-1.0.release-certification",
        )

        def release_certification_not_passed(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["releaseCertificationSummary"]["releaseCandidatePassed"] = False

        run_case(
            root,
            "release-certification-not-passed",
            release_certification_not_passed,
            "not-ready",
            expect_blocker="stable-1.0.release-certification",
        )

        def release_certification_ecosystem_rc_not_passed(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["releaseCertificationSummary"]["ecosystemRcPassed"] = False

        run_case(
            root,
            "release-certification-ecosystem-rc-not-passed",
            release_certification_ecosystem_rc_not_passed,
            "not-ready",
            expect_blocker="stable-1.0.release-certification",
        )

        def release_certification_non_rc_mode(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["releaseCertificationSummary"]["mode"] = "pr"

        run_case(
            root,
            "release-certification-non-rc-mode",
            release_certification_non_rc_mode,
            "not-ready",
            expect_blocker="stable-1.0.release-certification",
        )

        def release_certification_boolean_schema_version(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["releaseCertificationSummary"]["schemaVersion"] = True

        run_case(
            root,
            "release-certification-boolean-schema-version",
            release_certification_boolean_schema_version,
            "not-ready",
            expect_blocker="stable-1.0.release-certification",
        )

        def release_certification_stub(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["releaseCertificationSummary"] = {
                "schemaVersion": 1,
                "tool": "release-certification",
                "mode": "release-candidate",
                "status": "pass",
                "releaseCandidatePassed": True,
                "redaction": copy.deepcopy(inputs["releaseCertificationSummary"]["redaction"]),
            }

        run_case(
            root,
            "release-certification-stub",
            release_certification_stub,
            "not-ready",
            expect_blocker="stable-1.0.release-certification",
        )

        def release_certification_missing_redaction(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["releaseCertificationSummary"].pop("redaction", None)

        run_case(
            root,
            "release-certification-missing-redaction",
            release_certification_missing_redaction,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def release_certification_redaction_status_schema(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["releaseCertificationSummary"]["redaction"] = {
                "status": "pass",
                "findingCount": 0,
                "findings": [],
            }

        run_case(
            root,
            "release-certification-redaction-status-schema",
            release_certification_redaction_status_schema,
            "ready",
        )

        def release_certification_redaction_field_failed(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["releaseCertificationSummary"]["redaction"]["privateInsertUrisExcluded"] = False

        run_case(
            root,
            "release-certification-redaction-field-failed",
            release_certification_redaction_field_failed,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def release_certification_redaction_truncated_proof(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["releaseCertificationSummary"]["redaction"] = {"status": "pass"}

        run_case(
            root,
            "release-certification-redaction-truncated-proof",
            release_certification_redaction_truncated_proof,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def release_certification_redaction_count(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["releaseCertificationSummary"]["redaction"]["findingCount"] = 1

        run_case(
            root,
            "release-certification-redaction-count",
            release_certification_redaction_count,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def release_certification_redaction_raw_flag(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["releaseCertificationSummary"]["redaction"]["rawFetchedContentIncluded"] = True

        run_case(
            root,
            "release-certification-redaction-raw-flag",
            release_certification_redaction_raw_flag,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def release_certification_evidence_failed(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            for entry in inputs["releaseCertificationSummary"]["evidence"]:
                if isinstance(entry, dict) and entry.get("id") == "platform-api.stable-breaking-change-check":
                    entry["status"] = "fail"
                    entry.setdefault("details", {})["errors"] = ["stable_api_endpoint_removed"]
                    break

        run_case(
            root,
            "release-certification-evidence-failed",
            release_certification_evidence_failed,
            "not-ready",
            expect_blocker="platform-api.stable-breaking-change-check",
        )

        def app_platform_duplicate_evidence_failed(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            for entry in inputs["appPlatformSummary"]["evidence"]:
                if isinstance(entry, dict) and entry.get("id") == "platform-api.contract":
                    entry["status"] = "fail"
                    entry.setdefault("details", {})["errors"] = [
                        "app-platform summary explicitly failed platform-api.contract"
                    ]
                    return

        run_case(
            root,
            "app-platform-duplicate-evidence-failed",
            app_platform_duplicate_evidence_failed,
            "not-ready",
            expect_blocker="platform-api.contract",
        )

        def app_platform_summary_missing(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs.pop("appPlatformSummary", None)

        run_case(
            root,
            "app-platform-summary-missing",
            app_platform_summary_missing,
            "not-ready",
            expect_blocker="stable-1.0.app-ecosystem-maturity",
        )

        def app_platform_summary_failed(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["appPlatformSummary"]["status"] = "fail"

        run_case(
            root,
            "app-platform-summary-failed",
            app_platform_summary_failed,
            "not-ready",
            expect_blocker="stable-1.0.app-ecosystem-maturity",
        )

        def app_platform_summary_malformed_envelope(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["appPlatformSummary"]["schemaVersion"] = True
            inputs["appPlatformSummary"]["tool"] = "not-app-platform-smoke"

        run_case(
            root,
            "app-platform-summary-malformed-envelope",
            app_platform_summary_malformed_envelope,
            "not-ready",
            expect_blocker="stable-1.0.app-ecosystem-maturity",
        )

        def app_platform_summary_non_release_mode(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["appPlatformSummary"]["mode"] = "pr"

        run_case(
            root,
            "app-platform-summary-non-release-mode",
            app_platform_summary_non_release_mode,
            "not-ready",
            expect_blocker="stable-1.0.app-ecosystem-maturity",
        )

        def app_platform_summary_non_release_flag(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["appPlatformSummary"]["nonRelease"] = True

        run_case(
            root,
            "app-platform-summary-non-release-flag",
            app_platform_summary_non_release_flag,
            "not-ready",
            expect_blocker="stable-1.0.app-ecosystem-maturity",
        )

        def app_platform_summary_non_production(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["appPlatformSummary"]["nonProduction"] = True

        run_case(
            root,
            "app-platform-summary-non-production",
            app_platform_summary_non_production,
            "not-ready",
            expect_blocker="stable-1.0.app-ecosystem-maturity",
        )

        def app_platform_summary_fixture_only(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["appPlatformSummary"]["fixtureOnly"] = True

        run_case(
            root,
            "app-platform-summary-fixture-only",
            app_platform_summary_fixture_only,
            "not-ready",
            expect_blocker="stable-1.0.app-ecosystem-maturity",
        )

        def app_platform_summary_truncated_evidence(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["appPlatformSummary"]["evidence"] = []

        def assert_app_platform_summary_truncated_evidence(summary: dict[str, Any]) -> None:
            domain_statuses = {
                str(domain.get("id")): str(domain.get("status"))
                for domain in summary.get("domains", [])
                if isinstance(domain, dict)
            }
            non_failing_domains = {
                domain_id
                for domain_id in ("platform-api-1.0", "app-ecosystem-maturity")
                if domain_statuses.get(domain_id) != "fail"
            }
            if non_failing_domains:
                raise AssertionError(
                    "truncated direct app-platform evidence did not fail domains: "
                    + ", ".join(sorted(non_failing_domains))
                )

        run_case(
            root,
            "app-platform-summary-truncated-evidence",
            app_platform_summary_truncated_evidence,
            "not-ready",
            expect_blocker="stable-1.0.app-ecosystem-maturity",
            post_check=assert_app_platform_summary_truncated_evidence,
        )

        def attached_evidence_redaction_findings(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["releaseCertificationSummary"]["evidence"].append(
                {
                    "id": "release-certification.non-stable-redaction-fixture",
                    "status": "pass",
                    "summary": "Synthetic otherwise-unused evidence row with redaction findings.",
                    "details": {
                        "redactionFindings": [
                            {
                                "kind": "stable-readiness-fixture",
                                "summary": "Synthetic attached evidence redaction finding.",
                            }
                        ]
                    },
                }
            )

        run_case(
            root,
            "attached-evidence-redaction-findings",
            attached_evidence_redaction_findings,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def app_platform_evidence_top_level_redaction_signals(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            for entry in inputs["appPlatformSummary"]["evidence"]:
                if isinstance(entry, dict) and entry.get("id") == "app-data.backup-restore-portability":
                    entry["redactionFindings"] = [
                        {
                            "kind": "stable-readiness-fixture",
                            "summary": "Synthetic top-level evidence redaction finding.",
                        }
                    ]
                    entry["findingCount"] = 1
                    entry["privateInsertUrisStored"] = True
                    return
            raise AssertionError("app-data.backup-restore-portability evidence row missing")

        def assert_app_platform_evidence_top_level_redaction_signals(
            summary: dict[str, Any],
        ) -> None:
            blocker_ids = {
                str(blocker.get("evidenceId"))
                for blocker in summary.get("blockers", [])
                if isinstance(blocker, dict)
            }
            required_blockers = {
                "app-data.backup-restore-portability",
                "stable-1.0.redaction",
            }
            if not required_blockers.issubset(blocker_ids):
                raise AssertionError(
                    "top-level evidence redaction signals did not create both blockers: "
                    f"{summary.get('blockers')}"
                )

        run_case(
            root,
            "app-platform-evidence-top-level-redaction-signals",
            app_platform_evidence_top_level_redaction_signals,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
            post_check=assert_app_platform_evidence_top_level_redaction_signals,
        )

        def app_platform_evidence_redaction_clean_false(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            for entry in inputs["appPlatformSummary"]["evidence"]:
                if (
                    isinstance(entry, dict)
                    and entry.get("id") == "app-data.backup-restore-portability"
                ):
                    entry.setdefault("details", {})["redactionClean"] = False
                    return
            raise AssertionError("app-data.backup-restore-portability evidence row missing")

        run_case(
            root,
            "app-platform-evidence-redaction-clean-false",
            app_platform_evidence_redaction_clean_false,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def app_platform_evidence_redaction_status_fail(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            for entry in inputs["appPlatformSummary"]["evidence"]:
                if (
                    isinstance(entry, dict)
                    and entry.get("id") == "app-data.backup-restore-portability"
                ):
                    entry.setdefault("details", {})["redactionStatus"] = "fail"
                    return
            raise AssertionError("app-data.backup-restore-portability evidence row missing")

        run_case(
            root,
            "app-platform-evidence-redaction-status-fail",
            app_platform_evidence_redaction_status_fail,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def app_platform_evidence_malformed_redaction_proof(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            for entry in inputs["appPlatformSummary"]["evidence"]:
                if (
                    isinstance(entry, dict)
                    and entry.get("id") == "app-data.backup-restore-portability"
                ):
                    entry.setdefault("details", {})[
                        "privateInsertUrisExcluded"
                    ] = "false"
                    return
            raise AssertionError("app-data.backup-restore-portability evidence row missing")

        run_case(
            root,
            "app-platform-evidence-malformed-redaction-proof",
            app_platform_evidence_malformed_redaction_proof,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def app_platform_evidence_nested_redaction_status_warn(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            for entry in inputs["appPlatformSummary"]["evidence"]:
                if (
                    isinstance(entry, dict)
                    and entry.get("id") == "app-data.backup-restore-portability"
                ):
                    entry.setdefault("details", {})["redaction"] = {
                        "status": "warn",
                        "findings": [],
                    }
                    return
            raise AssertionError("app-data.backup-restore-portability evidence row missing")

        run_case(
            root,
            "app-platform-evidence-nested-redaction-status-warn",
            app_platform_evidence_nested_redaction_status_warn,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def release_certification_evidence_redaction_findings(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            def mutate(entry: dict[str, Any]) -> None:
                entry.setdefault("details", {})["redactionFindings"] = [
                    {
                        "kind": "stable-readiness-fixture",
                        "summary": "Synthetic required-evidence redaction finding.",
                    }
                ]

            mutate_evidence(inputs, "app-platform.signed-bundles", mutate)

        run_case(
            root,
            "release-certification-evidence-redaction-findings",
            release_certification_evidence_redaction_findings,
            "not-ready",
            expect_blocker="app-platform.signed-bundles",
        )

        def release_certification_evidence_redacted_false(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            def mutate(entry: dict[str, Any]) -> None:
                entry.setdefault("details", {})["redaction"] = {
                    "status": "pass",
                    "findings": [],
                    "formPasswordsRedacted": False,
                }

            mutate_evidence(inputs, "app-platform.content-fetch", mutate)

        run_case(
            root,
            "release-certification-evidence-redacted-false",
            release_certification_evidence_redacted_false,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def release_certification_evidence_raw_stored(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            def mutate(entry: dict[str, Any]) -> None:
                entry.setdefault("details", {})["redaction"] = {
                    "status": "pass",
                    "findings": [],
                    "rawBodiesStored": True,
                }

            mutate_evidence(inputs, "live-network-beta.redaction", mutate)

        run_case(
            root,
            "release-certification-evidence-raw-stored",
            release_certification_evidence_raw_stored,
            "not-ready",
            expect_blocker="live-network-beta.redaction",
        )

        def release_certification_evidence_sensitive_stored(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            def mutate(entry: dict[str, Any]) -> None:
                entry.setdefault("details", {})["redaction"] = {
                    "status": "pass",
                    "findings": [],
                    "privateInsertUrisStored": True,
                }

            mutate_evidence(inputs, "live-network-beta.redaction", mutate)

        run_case(
            root,
            "release-certification-evidence-sensitive-stored",
            release_certification_evidence_sensitive_stored,
            "not-ready",
            expect_blocker="live-network-beta.redaction",
        )

        def release_certification_evidence_excluded_from_evidence_false(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            def mutate(entry: dict[str, Any]) -> None:
                entry.setdefault("details", {})["redaction"] = {
                    "status": "pass",
                    "findings": [],
                    "rawBackupPayloadsExcludedFromEvidence": False,
                }

            mutate_evidence(inputs, "app-data.backup-restore-portability", mutate)

        run_case(
            root,
            "release-certification-evidence-excluded-from-evidence-false",
            release_certification_evidence_excluded_from_evidence_false,
            "not-ready",
            expect_blocker="app-data.backup-restore-portability",
        )

        def release_certification_evidence_direct_excluded_from_evidence_false(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            def mutate(entry: dict[str, Any]) -> None:
                entry.setdefault("details", {})["rawBackupPayloadsExcludedFromEvidence"] = False

            mutate_evidence(inputs, "app-data.backup-restore-portability", mutate)

        run_case(
            root,
            "release-certification-evidence-direct-excluded-from-evidence-false",
            release_certification_evidence_direct_excluded_from_evidence_false,
            "not-ready",
            expect_blocker="app-data.backup-restore-portability",
        )

        def release_certification_evidence_direct_critical_redaction_count(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            def mutate(entry: dict[str, Any]) -> None:
                entry.setdefault("details", {})["criticalFindingCount"] = 1

            mutate_evidence(inputs, "app-data.backup-restore-portability", mutate)

        run_case(
            root,
            "release-certification-evidence-direct-critical-redaction-count",
            release_certification_evidence_direct_critical_redaction_count,
            "not-ready",
            expect_blocker="app-data.backup-restore-portability",
        )

        def release_certification_evidence_malformed_redaction_findings(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            def mutate(entry: dict[str, Any]) -> None:
                entry.setdefault("details", {})["redactionFindings"] = "not-a-list"

            mutate_evidence(inputs, "app-platform.signed-bundles", mutate)

        run_case(
            root,
            "release-certification-evidence-malformed-redaction-findings",
            release_certification_evidence_malformed_redaction_findings,
            "not-ready",
            expect_blocker="app-platform.signed-bundles",
        )

        def release_certification_evidence_nested_redaction_findings(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            def mutate(entry: dict[str, Any]) -> None:
                entry.setdefault("details", {})["redaction"] = {
                    "status": "pass",
                    "findings": [
                        {
                            "kind": "stable-readiness-fixture",
                            "summary": "Synthetic nested required-evidence redaction finding.",
                        }
                    ],
                }

            mutate_evidence(inputs, "app-platform.signed-bundles", mutate)

        run_case(
            root,
            "release-certification-evidence-nested-redaction-findings",
            release_certification_evidence_nested_redaction_findings,
            "not-ready",
            expect_blocker="app-platform.signed-bundles",
        )

        def ecosystem_matrix_failed(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["ecosystemMatrix"]["status"] = "fail"
            inputs["ecosystemMatrix"]["releaseBlockerCount"] = 1
            inputs["ecosystemMatrix"].setdefault("rows", []).append(
                {
                    "id": "stable-self-test-release-blocker",
                    "status": "fail",
                    "releaseBlocker": True,
                    "title": "Stable self-test release blocker",
                }
            )

        run_case(
            root,
            "ecosystem-matrix-failed",
            ecosystem_matrix_failed,
            "not-ready",
            expect_blocker="release-certification.ecosystem-matrix",
        )

        def ecosystem_matrix_failed_row(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            rows = inputs["ecosystemMatrix"].get("rows")
            if not isinstance(rows, list) or not rows:
                raise AssertionError("base ecosystem matrix fixture has no rows")
            rows[0]["status"] = "fail"
            rows[0]["releaseBlocker"] = False
            inputs["ecosystemMatrix"]["status"] = "pass"
            inputs["ecosystemMatrix"]["releaseBlockerCount"] = 0

        run_case(
            root,
            "ecosystem-matrix-failed-row",
            ecosystem_matrix_failed_row,
            "not-ready",
            expect_blocker="release-certification.ecosystem-matrix",
        )

        warning_row_id = ECOSYSTEM_MATRIX_REQUIRED_ROW_IDS[0]

        def ecosystem_matrix_warning_row(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            rows = inputs["ecosystemMatrix"].get("rows")
            if not isinstance(rows, list):
                raise AssertionError("base ecosystem matrix fixture has no rows")
            warning_row = next(
                (
                    row
                    for row in rows
                    if isinstance(row, dict) and row.get("id") == warning_row_id
                ),
                None,
            )
            if warning_row is None:
                raise AssertionError(f"base ecosystem matrix fixture has no {warning_row_id} row")
            warning_row["status"] = "warn"
            warning_row["releaseBlocker"] = False
            warning_row["summary"] = "Synthetic non-blocking matrix warning."
            inputs["ecosystemMatrix"]["status"] = "pass"
            inputs["ecosystemMatrix"]["releaseBlockerCount"] = 0
            counts = inputs["ecosystemMatrix"].setdefault("counts", {})
            counts["warn"] = 0
            counts["pass"] = len(rows)
            counts["releaseBlockers"] = 0

        def assert_ecosystem_matrix_warning_row(summary: dict[str, Any]) -> None:
            warning_row_blockers = [
                blocker
                for blocker in summary.get("blockers", [])
                if isinstance(blocker, dict)
                and blocker.get("evidenceId") == "release-certification.ecosystem-matrix"
                and blocker.get("title") == "Ecosystem matrix rows are not passing"
                and f"{warning_row_id}:warn" in str(blocker.get("summary", ""))
            ]
            if len(warning_row_blockers) != 1:
                raise AssertionError(
                    "ecosystem matrix warning row was not reported as non-passing: "
                    f"{summary.get('blockers')}"
                )

        run_case(
            root,
            "ecosystem-matrix-warning-row",
            ecosystem_matrix_warning_row,
            "not-ready",
            expect_blocker="release-certification.ecosystem-matrix",
            post_check=assert_ecosystem_matrix_warning_row,
        )

        def ecosystem_matrix_missing_rows(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["ecosystemMatrix"].pop("rows", None)

        run_case(
            root,
            "ecosystem-matrix-missing-rows",
            ecosystem_matrix_missing_rows,
            "not-ready",
            expect_blocker="release-certification.ecosystem-matrix",
        )

        def ecosystem_matrix_truncated_rows(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["ecosystemMatrix"]["rows"] = [
                {
                    "id": "stub-row",
                    "status": "pass",
                    "releaseBlocker": False,
                }
            ]
            inputs["ecosystemMatrix"]["counts"]["rows"] = 1

        run_case(
            root,
            "ecosystem-matrix-truncated-rows",
            ecosystem_matrix_truncated_rows,
            "not-ready",
            expect_blocker="release-certification.ecosystem-matrix",
        )

        def ecosystem_matrix_non_list_rows(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["ecosystemMatrix"]["rows"] = {"stable-readiness": "not-a-list"}

        run_case(
            root,
            "ecosystem-matrix-non-list-rows",
            ecosystem_matrix_non_list_rows,
            "not-ready",
            expect_blocker="release-certification.ecosystem-matrix",
        )

        def ecosystem_matrix_malformed_row(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["ecosystemMatrix"]["rows"].append("not-a-row-object")

        run_case(
            root,
            "ecosystem-matrix-malformed-row",
            ecosystem_matrix_malformed_row,
            "not-ready",
            expect_blocker="release-certification.ecosystem-matrix",
        )

        def ecosystem_matrix_row_redaction_failure(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            rows = inputs["ecosystemMatrix"].get("rows")
            if not isinstance(rows, list) or not rows:
                raise AssertionError("base ecosystem matrix fixture has no rows")
            rows[0]["details"] = {
                "redaction": {
                    "status": "fail",
                    "findings": [],
                }
            }
            inputs["ecosystemMatrix"].setdefault("coverage", {})["redactionPassed"] = True

        run_case(
            root,
            "ecosystem-matrix-row-redaction-failure",
            ecosystem_matrix_row_redaction_failure,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def missing_baseline(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            mutate_evidence(inputs, "platform-api.stable-baseline", remove=True)

        run_case(root, "missing-platform-baseline", missing_baseline, "not-ready", expect_blocker="platform-api.stable-baseline")

        def malformed_platform_baseline_count(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            def mutate(entry: dict[str, Any]) -> None:
                entry.setdefault("details", {}).setdefault("stableBaseline", {})["capabilityCount"] = "many"

            mutate_evidence(inputs, "platform-api.stable-baseline", mutate)

        run_case(
            root,
            "malformed-platform-baseline-count",
            malformed_platform_baseline_count,
            "not-ready",
            expect_blocker="stable-1.0.platform-api-compatibility",
        )

        def missing_compatibility_window_details(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            def mutate(entry: dict[str, Any]) -> None:
                entry.setdefault("details", {}).pop("compatibilityWindow", None)

            mutate_evidence(inputs, "platform-api.compatibility-window", mutate)

        run_case(
            root,
            "missing-compatibility-window-details",
            missing_compatibility_window_details,
            "not-ready",
            expect_blocker="stable-1.0.platform-api-compatibility",
        )

        def stable_breaking(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            def mutate(entry: dict[str, Any]) -> None:
                entry["status"] = "fail"
                entry.setdefault("details", {})["errors"] = ["stable_api_endpoint_removed"]

            mutate_evidence(inputs, "platform-api.stable-breaking-change-check", mutate)

        run_case(root, "stable-api-breaking-change", stable_breaking, "not-ready", expect_blocker="platform-api.stable-breaking-change-check")

        def platform_api_status_only_redaction_failure(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            def mutate(entry: dict[str, Any]) -> None:
                entry.setdefault("details", {})["redaction"] = {"status": "fail"}

            mutate_evidence(inputs, "platform-api.contract", mutate)

        run_case(
            root,
            "platform-api-status-only-redaction-failure",
            platform_api_status_only_redaction_failure,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def missing_first_party(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            mutate_evidence(inputs, "first-party-app.beta-quality-pass", remove=True)

        run_case(root, "missing-first-party", missing_first_party, "not-ready", expect_blocker="first-party-app.beta-quality-pass")

        def diagnostics_nested_redaction_findings(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            def mutate(entry: dict[str, Any]) -> None:
                entry.setdefault("details", {})["redaction"] = {
                    "status": "pass",
                    "findings": [
                        {
                            "kind": "redaction-fixture",
                            "location": "app-platform-diagnostics",
                            "summary": "Synthetic nested diagnostics redaction finding.",
                        }
                    ],
                }

            mutate_evidence(inputs, "app-platform.privacy-preserving-beta-diagnostics", mutate)

        run_case(
            root,
            "diagnostics-nested-redaction-findings",
            diagnostics_nested_redaction_findings,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def missing_third_party(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            mutate_evidence(inputs, "third-party-intake.beta-catalog-install-smoke", remove=True)

        run_case(root, "missing-third-party", missing_third_party, "not-ready", expect_blocker="third-party-intake.beta-catalog-install-smoke")

        def empty_third_party_sample_flow(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            def mutate(entry: dict[str, Any]) -> None:
                entry.setdefault("details", {})["sampleFlow"] = []

            mutate_evidence(inputs, "third-party-developer.sample-app-flow", mutate)

        run_case(
            root,
            "empty-third-party-sample-flow",
            empty_third_party_sample_flow,
            "not-ready",
            expect_blocker="stable-1.0.third-party-intake",
        )

        def truncated_third_party_sample_flow(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            def mutate(entry: dict[str, Any]) -> None:
                entry.setdefault("details", {})["sampleFlow"] = ["placeholder step"]

            mutate_evidence(inputs, "third-party-developer.sample-app-flow", mutate)

        run_case(
            root,
            "truncated-third-party-sample-flow",
            truncated_third_party_sample_flow,
            "not-ready",
            expect_blocker="stable-1.0.third-party-intake",
        )

        def missing_support_feedback_docs(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            mutate_evidence(inputs, "public-beta.support-feedback-docs", remove=True)

        run_case(
            root,
            "missing-support-feedback-docs",
            missing_support_feedback_docs,
            "not-ready",
            expect_blocker="public-beta.support-feedback-docs",
        )

        def stale_security(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["securityDrillsSummary"]["staleScenarios"] = ["reviewer-key-compromise"]
            inputs["securityDrillsSummary"]["passedScenarios"] = [
                item for item in inputs["securityDrillsSummary"]["passedScenarios"] if item != "reviewer-key-compromise"
            ]

        run_case(root, "stale-security", stale_security, "not-ready", expect_blocker="stable-1.0.security-drills")

        def security_status_fail_redaction_pass(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["securityDrillsSummary"]["status"] = "fail"
            inputs["securityDrillsSummary"]["redaction"] = {
                "status": "pass",
                "findingCount": 0,
                "findings": [],
            }

        def expect_security_status_fail_not_redaction(summary: dict[str, Any]) -> None:
            blocker_ids = {str(blocker.get("evidenceId")) for blocker in summary.get("blockers", [])}
            if "stable-1.0.redaction" in blocker_ids:
                raise AssertionError(
                    "ordinary security summary failure was reported as a redaction blocker: "
                    f"{summary.get('blockers')}"
                )
            evidence_statuses = {
                str(entry.get("id")): str(entry.get("status"))
                for entry in summary.get("evidence", [])
                if isinstance(entry, dict)
            }
            if evidence_statuses.get("stable-1.0.redaction") != "pass":
                raise AssertionError(
                    "ordinary security summary failure changed stable-1.0.redaction evidence: "
                    f"{evidence_statuses}"
                )

        run_case(
            root,
            "security-status-fail-redaction-pass",
            security_status_fail_redaction_pass,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
            post_check=expect_security_status_fail_not_redaction,
        )

        def security_malformed_fixture_only(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["securityDrillsSummary"]["fixtureOnly"] = "true"

        run_case(
            root,
            "security-malformed-fixture-only",
            security_malformed_fixture_only,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def security_malformed_non_release(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["securityDrillsSummary"]["nonRelease"] = "true"

        run_case(
            root,
            "security-malformed-non-release",
            security_malformed_non_release,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def malformed_security_scenario_list(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["securityDrillsSummary"]["passedScenarios"] = None

        run_case(
            root,
            "malformed-security-scenario-list",
            malformed_security_scenario_list,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def missing_security_scenario_result_list(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["securityDrillsSummary"].pop("failedScenarios", None)

        run_case(
            root,
            "missing-security-scenario-result-list",
            missing_security_scenario_result_list,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def security_missing_schema_version(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["securityDrillsSummary"].pop("schemaVersion", None)

        run_case(
            root,
            "security-missing-schema-version",
            security_missing_schema_version,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def security_boolean_schema_version(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["securityDrillsSummary"]["schemaVersion"] = True

        run_case(
            root,
            "security-boolean-schema-version",
            security_boolean_schema_version,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def security_truncated_summary(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            for field in ("requiredScenarios", "counts", "maxAgeDays", "mode"):
                inputs["securityDrillsSummary"].pop(field, None)

        run_case(
            root,
            "security-truncated-summary",
            security_truncated_summary,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def security_redaction_unsafe_flag(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["securityDrillsSummary"]["redaction"] = {
                "status": "pass",
                "findings": [],
                "rawSensitiveMaterialExcluded": False,
            }

        run_case(
            root,
            "security-redaction-unsafe-flag",
            security_redaction_unsafe_flag,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def security_redaction_count(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["securityDrillsSummary"]["redaction"] = {
                "status": "pass",
                "findingCount": 1,
            }

        def expect_stable_redaction_evidence_failed(summary: dict[str, Any]) -> None:
            evidence_statuses = {
                str(entry.get("id")): str(entry.get("status"))
                for entry in summary.get("evidence", [])
                if isinstance(entry, dict)
            }
            if evidence_statuses.get("stable-1.0.redaction") != "fail":
                raise AssertionError(
                    "security redaction blocker did not fail stable-1.0.redaction evidence: "
                    f"{evidence_statuses}"
                )

        run_case(
            root,
            "security-redaction-count",
            security_redaction_count,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
            post_check=expect_stable_redaction_evidence_failed,
        )

        def security_redaction_critical_count(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["securityDrillsSummary"]["redaction"] = {
                "status": "pass",
                "findingCount": 0,
                "criticalFindingCount": 1,
            }

        run_case(
            root,
            "security-redaction-critical-count",
            security_redaction_critical_count,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
            post_check=expect_stable_redaction_evidence_failed,
        )

        def security_release_id_mismatch(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["securityDrillsSummary"]["releaseId"] = "cryptad-beta-previous"

        run_case(
            root,
            "security-release-id-mismatch",
            security_release_id_mismatch,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def missing_security_required_scenarios(
            _inputs: dict[str, Any],
            _limitations: dict[str, Any],
            paths: dict[str, Path],
        ) -> None:
            policy = copy.deepcopy(read_json(DEFAULT_POLICY) or {})
            if isinstance(policy.get("securityDrillCriteria"), dict):
                policy["securityDrillCriteria"].pop("requiredScenarios", None)
            policy_path = paths["stableKnownLimitations"].parent / "missing-security-required-scenarios-policy.json"
            write_json(policy_path, policy)
            paths["policy"] = policy_path

        run_case(
            root,
            "missing-security-required-scenarios",
            missing_security_required_scenarios,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def malformed_security_required_scenario_entry(
            _inputs: dict[str, Any],
            _limitations: dict[str, Any],
            paths: dict[str, Path],
        ) -> None:
            policy = copy.deepcopy(read_json(DEFAULT_POLICY) or {})
            if isinstance(policy.get("securityDrillCriteria"), dict):
                policy["securityDrillCriteria"]["requiredScenarios"] = [
                    "reviewer-key-compromise",
                    1,
                ]
            policy_path = paths["stableKnownLimitations"].parent / "malformed-security-required-scenario-entry-policy.json"
            write_json(policy_path, policy)
            paths["policy"] = policy_path

        run_case(
            root,
            "malformed-security-required-scenario-entry",
            malformed_security_required_scenario_entry,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def malformed_required_release_modes_policy(
            _inputs: dict[str, Any],
            _limitations: dict[str, Any],
            paths: dict[str, Path],
        ) -> None:
            policy = copy.deepcopy(read_json(DEFAULT_POLICY) or {})
            policy["requiredReleaseModes"] = [1]
            policy_path = paths["stableKnownLimitations"].parent / "malformed-required-release-modes-policy.json"
            write_json(policy_path, policy)
            paths["policy"] = policy_path

        run_case(
            root,
            "malformed-required-release-modes-policy",
            malformed_required_release_modes_policy,
            "not-ready",
            expect_blocker="stable-1.0.production-beta-state",
        )

        def malformed_soak_mode_policy(
            _inputs: dict[str, Any],
            _limitations: dict[str, Any],
            paths: dict[str, Path],
        ) -> None:
            policy = copy.deepcopy(read_json(DEFAULT_POLICY) or {})
            if isinstance(policy.get("requiredSoak"), dict):
                policy["requiredSoak"]["acceptedMultiNodeModes"] = [1]
                policy["requiredSoak"]["acceptedNetworkScaleModes"] = ["live-rc-soak", 2]
            policy_path = paths["stableKnownLimitations"].parent / "malformed-soak-mode-policy.json"
            write_json(policy_path, policy)
            paths["policy"] = policy_path

        run_case(
            root,
            "malformed-soak-mode-policy",
            malformed_soak_mode_policy,
            "not-ready",
            expect_blocker="stable-1.0.live-multi-node-soak",
        )

        def fractional_stable_policy_integers(
            _inputs: dict[str, Any],
            _limitations: dict[str, Any],
            paths: dict[str, Path],
        ) -> None:
            policy = copy.deepcopy(read_json(DEFAULT_POLICY) or {})
            if isinstance(policy.get("requiredSoak"), dict):
                policy["requiredSoak"]["minimumOperationCount"] = 629.5
                policy["requiredSoak"]["maximumEvidenceAgeDays"] = 30.5
            if isinstance(policy.get("securityDrillCriteria"), dict):
                policy["securityDrillCriteria"]["maximumEvidenceAgeDays"] = 30.5
            policy_path = paths["stableKnownLimitations"].parent / "fractional-stable-policy-integers.json"
            write_json(policy_path, policy)
            paths["policy"] = policy_path

        run_case(
            root,
            "fractional-stable-policy-integers",
            fractional_stable_policy_integers,
            "not-ready",
            expect_blocker="stable-1.0.live-multi-node-soak",
        )

        def scalar_platform_api_policy(
            _inputs: dict[str, Any],
            _limitations: dict[str, Any],
            paths: dict[str, Path],
        ) -> None:
            policy = copy.deepcopy(read_json(DEFAULT_POLICY) or {})
            policy["platformApi10Criteria"] = 1
            policy_path = paths["stableKnownLimitations"].parent / "scalar-platform-api-policy.json"
            write_json(policy_path, policy)
            paths["policy"] = policy_path

        run_case(
            root,
            "scalar-platform-api-policy",
            scalar_platform_api_policy,
            "not-ready",
            expect_blocker="stable-1.0.platform-api-compatibility",
        )

        def scalar_allowed_limitation_categories_policy(
            _inputs: dict[str, Any],
            _limitations: dict[str, Any],
            paths: dict[str, Path],
        ) -> None:
            policy = copy.deepcopy(read_json(DEFAULT_POLICY) or {})
            policy["allowedLimitationCategories"] = 1
            policy_path = paths["stableKnownLimitations"].parent / "scalar-allowed-limitation-categories-policy.json"
            write_json(policy_path, policy)
            paths["policy"] = policy_path

        run_case(
            root,
            "scalar-allowed-limitation-categories-policy",
            scalar_allowed_limitation_categories_policy,
            "not-ready",
            expect_blocker="stable-1.0.known-limitations",
        )

        def scalar_non_waivable_blockers_policy(
            _inputs: dict[str, Any],
            _limitations: dict[str, Any],
            paths: dict[str, Path],
        ) -> None:
            policy = copy.deepcopy(read_json(DEFAULT_POLICY) or {})
            policy["nonWaivableBlockers"] = 1
            policy_path = paths["stableKnownLimitations"].parent / "scalar-non-waivable-blockers-policy.json"
            write_json(policy_path, policy)
            paths["policy"] = policy_path

        run_case(
            root,
            "scalar-non-waivable-blockers-policy",
            scalar_non_waivable_blockers_policy,
            "not-ready",
            expect_blocker="stable-1.0.known-limitations",
        )

        def malformed_category_policy_entry(
            _inputs: dict[str, Any],
            limitations: dict[str, Any],
            paths: dict[str, Path],
        ) -> None:
            policy = copy.deepcopy(read_json(DEFAULT_POLICY) or {})
            policy["allowedLimitationCategories"] = ["redaction-failure"]
            policy["disallowedLimitationCategories"] = [1]
            policy_path = paths["stableKnownLimitations"].parent / "malformed-category-policy-entry.json"
            write_json(policy_path, policy)
            paths["policy"] = policy_path
            limitations["limitations"].append(
                {
                    "id": "stable-1.0.allowed-redaction-failure-policy-gap",
                    "title": "Disallowed category with malformed policy",
                    "classification": "allowed-for-stable-1.0",
                    "category": "redaction-failure",
                    "status": "open",
                    "summary": "Self-test malformed category policy entry.",
                }
            )

        run_case(
            root,
            "malformed-category-policy-entry",
            malformed_category_policy_entry,
            "not-ready",
            expect_blocker="stable-1.0.known-limitations",
        )

        def multi_node_release_id_mismatch(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["multiNodeSoakSummary"]["releaseId"] = "cryptad-beta-previous"

        run_case(
            root,
            "multi-node-release-id-mismatch",
            multi_node_release_id_mismatch,
            "not-ready",
            expect_blocker="stable-1.0.live-multi-node-soak",
        )

        def multi_node_truncated_summary(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            scenario_statuses = {
                scenario_id: "pass"
                for scenario_id in multi_node_beta_soak.SCENARIO_EVIDENCE_IDS
            }
            inputs["multiNodeSoakSummary"] = {
                "mode": "hybrid",
                "generatedAt": DEFAULT_GENERATED_AT,
                "releaseId": "cryptad-beta-270",
                "status": "pass",
                "promotionReady": True,
                "currentCandidate": {
                    "version": "270",
                    "catalogChannel": "stable",
                    "productionBetaSummaryProvided": True,
                },
                "scenarioStatuses": scenario_statuses,
                "previousCandidateUpgrade": {
                    "status": "pass",
                    "firstPartyAppMigrationStatus": "pass",
                    "backupBeforeUpdateStatus": "pass",
                    "restoreIntoCleanNodeStatus": "pass",
                    "rollbackStatus": "pass",
                    "socialInboxMigrationStatus": "pass",
                    "trustGraphMigrationStatus": "pass",
                    "supportBundleRedactionStatus": "pass",
                },
                "redaction": {"status": "pass", "findings": []},
            }

        run_case(
            root,
            "multi-node-truncated-summary",
            multi_node_truncated_summary,
            "not-ready",
            expect_blocker="stable-1.0.live-multi-node-soak",
        )

        def multi_node_raw_evidence_flag(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["multiNodeSoakSummary"]["previousCandidateUpgrade"]["rawDataIncluded"] = True

        run_case(
            root,
            "multi-node-raw-evidence-flag",
            multi_node_raw_evidence_flag,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def multi_node_redaction_count(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["multiNodeSoakSummary"]["redaction"] = {
                "status": "pass",
                "findingCount": 1,
            }

        run_case(
            root,
            "multi-node-redaction-count",
            multi_node_redaction_count,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def network_release_id_mismatch(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["networkScaleSoakSummary"]["releaseId"] = "cryptad-beta-previous"

        run_case(
            root,
            "network-release-id-mismatch",
            network_release_id_mismatch,
            "not-ready",
            expect_blocker="stable-1.0.live-multi-node-soak",
        )

        def network_release_id_missing(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            network = inputs["networkScaleSoakSummary"]
            network.pop("releaseId", None)
            network.pop("candidateReleaseId", None)
            network.pop("currentCandidate", None)

        run_case(
            root,
            "network-release-id-missing",
            network_release_id_missing,
            "not-ready",
            expect_blocker="stable-1.0.live-multi-node-soak",
        )

        def network_truncated_summary(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            network = inputs["networkScaleSoakSummary"]
            truncated = {
                "mode": network.get("mode"),
                "status": network.get("status"),
                "generatedAt": network.get("generatedAt"),
                "operationCount": 9999,
                "redaction": copy.deepcopy(network.get("redaction")),
            }
            if "releaseId" in network:
                truncated["releaseId"] = network["releaseId"]
            inputs["networkScaleSoakSummary"] = truncated

        run_case(
            root,
            "network-truncated-summary",
            network_truncated_summary,
            "not-ready",
            expect_blocker="stable-1.0.live-multi-node-soak",
        )

        def network_forged_operation_count(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            network = inputs["networkScaleSoakSummary"]
            network["operationCount"] = 9999
            apps = network.get("apps") if isinstance(network.get("apps"), dict) else {}
            for app_id in NETWORK_SCALE_REQUIRED_APPS:
                app = apps.get(app_id)
                if isinstance(app, dict):
                    app["pollAttempts"] = 0
                    app["updatesObserved"] = 0
                    app["subscriptions"] = 0
            trust_graph = network.get("trustGraph")
            if isinstance(trust_graph, dict):
                trust_graph["importsAttempted"] = 0

        run_case(
            root,
            "network-forged-operation-count",
            network_forged_operation_count,
            "not-ready",
            expect_blocker="stable-1.0.live-multi-node-soak",
        )

        def stale_security_summary_age(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["securityDrillsSummary"]["generatedAt"] = "1969-11-01T00:00:00Z"

        run_case(root, "stale-security-summary-age", stale_security_summary_age, "not-ready", expect_blocker="stable-1.0.security-drills")

        def stale_security_artifact_age(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            artifact = inputs["securityDrillsSummary"]["artifacts"][0]
            artifact["stale"] = True
            artifact["ageDays"] = 31
            artifact["staleReason"] = "Artifact exceeds the Stable 1.0 freshness window."

        run_case(root, "stale-security-artifact-age", stale_security_artifact_age, "not-ready", expect_blocker="stable-1.0.security-drills")

        def missing_security_artifact_age_days(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            artifact = inputs["securityDrillsSummary"]["artifacts"][0]
            artifact.pop("generatedAt", None)
            artifact.pop("ageDays", None)
            artifact["stale"] = False

        run_case(
            root,
            "missing-security-artifact-age-days",
            missing_security_artifact_age_days,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def negative_security_artifact_age_days(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            artifact = inputs["securityDrillsSummary"]["artifacts"][0]
            artifact.pop("generatedAt", None)
            artifact["stale"] = False
            artifact["ageDays"] = -1

        run_case(
            root,
            "negative-security-artifact-age-days",
            negative_security_artifact_age_days,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def missing_security_artifacts(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["securityDrillsSummary"].pop("artifacts", None)

        run_case(
            root,
            "missing-security-artifacts",
            missing_security_artifacts,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def non_list_security_artifacts(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["securityDrillsSummary"]["artifacts"] = {"scenario": "reviewer-key-compromise"}

        run_case(
            root,
            "non-list-security-artifacts",
            non_list_security_artifacts,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def empty_security_artifacts(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["securityDrillsSummary"]["artifacts"] = []

        run_case(
            root,
            "empty-security-artifacts",
            empty_security_artifacts,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def malformed_security_artifact_entry(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["securityDrillsSummary"]["artifacts"][0] = "not-an-artifact-object"

        run_case(
            root,
            "malformed-security-artifact-entry",
            malformed_security_artifact_entry,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def missing_security_artifact_digest(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            for artifact in inputs["securityDrillsSummary"]["artifacts"]:
                artifact.pop("digest", None)

        run_case(
            root,
            "missing-security-artifact-digest",
            missing_security_artifact_digest,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def malformed_security_artifact_digest(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["securityDrillsSummary"]["artifacts"][0]["digest"] = "sha256:not-a-valid-digest"

        run_case(
            root,
            "malformed-security-artifact-digest",
            malformed_security_artifact_digest,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def missing_required_security_artifact(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["securityDrillsSummary"]["artifacts"] = [
                artifact
                for artifact in inputs["securityDrillsSummary"]["artifacts"]
                if artifact.get("scenario") != "reviewer-key-compromise"
            ]

        run_case(
            root,
            "missing-required-security-artifact",
            missing_required_security_artifact,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def duplicate_required_security_artifact(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            for artifact in inputs["securityDrillsSummary"]["artifacts"]:
                if artifact.get("scenario") == "reviewer-key-compromise":
                    inputs["securityDrillsSummary"]["artifacts"].append(copy.deepcopy(artifact))
                    return

        run_case(
            root,
            "duplicate-required-security-artifact",
            duplicate_required_security_artifact,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def failed_required_security_artifact(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            for artifact in inputs["securityDrillsSummary"]["artifacts"]:
                if artifact.get("scenario") == "reviewer-key-compromise":
                    artifact["status"] = "fail"
                    return

        run_case(
            root,
            "failed-required-security-artifact",
            failed_required_security_artifact,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def missing_security_artifact_release_notes_template_status(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            for artifact in inputs["securityDrillsSummary"]["artifacts"]:
                artifact.pop("releaseNotesTemplateStatus", None)

        run_case(
            root,
            "missing-security-artifact-release-notes-template-status",
            missing_security_artifact_release_notes_template_status,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def missing_security_artifact_advisory_template_status(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            for artifact in inputs["securityDrillsSummary"]["artifacts"]:
                artifact.pop("advisoryTemplateStatus", None)

        run_case(
            root,
            "missing-security-artifact-advisory-template-status",
            missing_security_artifact_advisory_template_status,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def extra_pass_security_artifact(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            artifact = copy.deepcopy(inputs["securityDrillsSummary"]["artifacts"][0])
            artifact["scenario"] = "unrequired-production-drill"
            artifact["artifact"] = "unrequired-production-drill.json"
            inputs["securityDrillsSummary"]["artifacts"].append(artifact)

        run_case(
            root,
            "extra-pass-security-artifact",
            extra_pass_security_artifact,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def extra_failed_security_artifact(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            artifact = copy.deepcopy(inputs["securityDrillsSummary"]["artifacts"][0])
            artifact["scenario"] = "unrequired-production-drill"
            artifact["artifact"] = "unrequired-production-drill.json"
            artifact["status"] = "fail"
            inputs["securityDrillsSummary"]["artifacts"].append(artifact)

        run_case(
            root,
            "extra-failed-security-artifact",
            extra_failed_security_artifact,
            "not-ready",
            expect_blocker="stable-1.0.security-drills",
        )

        def missing_live_network_evidence(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["releaseCertificationSummary"]["evidence"] = [
                entry
                for entry in inputs["releaseCertificationSummary"]["evidence"]
                if not isinstance(entry, dict) or entry.get("id") != "live-network-beta.content-fetch"
            ]

        run_case(
            root,
            "missing-live-network-evidence",
            missing_live_network_evidence,
            "not-ready",
            expect_blocker="live-network-beta.content-fetch",
        )

        def missing_previous_upgrade(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["multiNodeSoakSummary"]["previousCandidateUpgrade"]["status"] = "missing"

        run_case(root, "missing-previous-upgrade", missing_previous_upgrade, "not-ready", expect_blocker="stable-1.0.previous-candidate-upgrade")

        def app_data_migration_scenario_failed(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["multiNodeSoakSummary"]["scenarioStatuses"]["app-data-migration"] = "fail"

        run_case(
            root,
            "app-data-migration-scenario-failed",
            app_data_migration_scenario_failed,
            "not-ready",
            expect_blocker="multi-node-beta.app-data-migration",
        )

        def network_redaction_missing(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["networkScaleSoakSummary"].pop("redaction", None)

        run_case(
            root,
            "network-redaction-missing",
            network_redaction_missing,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def network_redaction_truncated_proof(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["networkScaleSoakSummary"]["redaction"] = {"status": "pass"}

        run_case(
            root,
            "network-redaction-truncated-proof",
            network_redaction_truncated_proof,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def network_redaction_status_missing(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["networkScaleSoakSummary"]["redaction"] = {"findings": []}

        run_case(
            root,
            "network-redaction-status-missing",
            network_redaction_status_missing,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def network_redaction_findings(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["networkScaleSoakSummary"]["redaction"] = {
                "status": "pass",
                "findings": [
                    {
                        "kind": "redaction-fixture",
                        "location": "network-scale-soak-summary",
                        "summary": "Synthetic network redaction finding for Stable readiness validation.",
                    }
                ],
            }

        run_case(
            root,
            "network-redaction-findings",
            network_redaction_findings,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def network_redaction_count(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["networkScaleSoakSummary"]["redaction"] = {
                "status": "pass",
                "findingCount": 1,
            }

        run_case(
            root,
            "network-redaction-count",
            network_redaction_count,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def network_redaction_status_fail(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["networkScaleSoakSummary"]["redaction"] = {"status": "fail"}

        run_case(
            root,
            "network-redaction-status-fail",
            network_redaction_status_fail,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def stale_soak_evidence(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["multiNodeSoakSummary"]["generatedAt"] = "1969-11-01T00:00:00Z"
            inputs["networkScaleSoakSummary"]["generatedAt"] = "1969-11-01T00:00:00Z"

        run_case(root, "stale-soak-evidence", stale_soak_evidence, "not-ready", expect_blocker="stable-1.0.live-multi-node-soak")

        def insufficient_network(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["networkScaleSoakSummary"]["apps"] = {}
            inputs["networkScaleSoakSummary"]["trustGraph"] = {"importsAttempted": 0}

        run_case(root, "insufficient-network", insufficient_network, "not-ready", expect_blocker="stable-1.0.live-multi-node-soak")

        def known_issues_tracker_envelope_stub(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["publicBetaKnownIssues"] = {
                "schemaVersion": 1,
                "tracker": "stub-known-issues",
                "redactionPolicy": {
                    "rawSupportBundlesStored": False,
                    "rawAppDataStored": False,
                    "rawContentStored": False,
                    "privateInsertUrisStored": False,
                    "absoluteLocalPathsStored": False,
                },
                "knownIssues": [],
            }

        run_case(
            root,
            "known-issues-tracker-envelope-stub",
            known_issues_tracker_envelope_stub,
            "not-ready",
            expect_blocker="public-beta.known-issues-tracker",
        )

        def malformed_known_issues_tracker(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["publicBetaKnownIssues"].pop("knownIssues", None)

        run_case(
            root,
            "malformed-known-issues-tracker",
            malformed_known_issues_tracker,
            "not-ready",
            expect_blocker="public-beta.known-issues-tracker",
        )

        def malformed_known_issue_entry(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["publicBetaKnownIssues"]["knownIssues"] = ["not-an-object"]

        run_case(
            root,
            "malformed-known-issue-entry",
            malformed_known_issue_entry,
            "not-ready",
            expect_blocker="public-beta.known-issues-tracker",
        )

        def malformed_known_issue_metadata(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["publicBetaKnownIssues"]["knownIssues"].append(
                {
                    "knownIssueId": "PBKI-TRUNCATED-001",
                    "workaroundSummary": "Synthetic truncated record.",
                }
            )

        run_case(
            root,
            "malformed-known-issue-metadata",
            malformed_known_issue_metadata,
            "not-ready",
            expect_blocker="public-beta.known-issues-tracker",
        )

        def synthetic_known_issue(**overrides: Any) -> dict[str, Any]:
            record = {
                "knownIssueId": "PBKI-SELF-TEST-001",
                "status": "open",
                "severity": "severity/medium",
                "area": "area/support",
                "affectedChannels": ["stable-first-party"],
                "affectedAppIds": [],
                "affectedVersions": ["cryptad-beta-270"],
                "firstSeenReleaseId": "cryptad-beta-270",
                "fixedInReleaseId": "unfixed",
                "workaroundSummary": "Synthetic redacted workaround summary.",
                "supportBundleEvidenceAllowed": "digest-and-summary-only",
                "redactionNotes": "Synthetic record contains metadata only.",
                "backlogLinkOrPlaceholder": "BACKLOG-STABLE-SELF-TEST",
            }
            record.update(overrides)
            return record

        def non_string_known_issue_metadata(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["publicBetaKnownIssues"]["knownIssues"].append(
                synthetic_known_issue(severity=None)
            )

        run_case(
            root,
            "non-string-known-issue-metadata",
            non_string_known_issue_metadata,
            "not-ready",
            expect_blocker="public-beta.known-issues-tracker",
        )

        def known_issue_unsafe_redaction_proof(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["publicBetaKnownIssues"]["knownIssues"].append(
                synthetic_known_issue(rawSupportBundlesStored=True)
            )

        run_case(
            root,
            "known-issue-unsafe-redaction-proof",
            known_issue_unsafe_redaction_proof,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def known_issue_redaction_findings(
            inputs: dict[str, Any],
            _limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            inputs["publicBetaKnownIssues"]["knownIssues"].append(
                synthetic_known_issue(
                    redactionFindings=[
                        {
                            "kind": "raw-support-bundle",
                            "summary": "Synthetic known-issue redaction finding.",
                        }
                    ]
                )
            )

        run_case(
            root,
            "known-issue-redaction-findings",
            known_issue_redaction_findings,
            "not-ready",
            expect_blocker="stable-1.0.redaction",
        )

        def critical_known_issue(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["publicBetaKnownIssues"]["knownIssues"].append(
                synthetic_known_issue(
                    knownIssueId="PBKI-CRITICAL-001",
                    status="open",
                    severity="severity/critical",
                    fixedInReleaseId="unfixed",
                )
            )

        run_case(root, "critical-known-issue", critical_known_issue, "not-ready", expect_blocker="stable-1.0.critical-known-issue")

        def critical_known_issue_future_fixed(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["publicBetaKnownIssues"]["knownIssues"].append(
                synthetic_known_issue(
                    knownIssueId="PBKI-CRITICAL-002",
                    status="open",
                    severity="severity/critical",
                    fixedInReleaseId="cryptad-beta-999",
                )
            )

        run_case(
            root,
            "critical-known-issue-future-fixed",
            critical_known_issue_future_fixed,
            "not-ready",
            expect_blocker="stable-1.0.critical-known-issue",
        )

        def beta_only_limitation(_inputs: dict[str, Any], limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            limitations["limitations"].append(
                {
                    "id": "stable-1.0.beta-only-open",
                    "title": "Beta-only limitation remains",
                    "classification": "beta-only",
                    "category": "no-live-or-multi-node-evidence",
                    "status": "open",
                    "summary": "Self-test beta-only limitation.",
                }
            )

        run_case(root, "beta-only-limitation", beta_only_limitation, "not-ready", expect_blocker="stable-1.0.known-limitations")

        def allowed_limitation_missing_metadata(
            _inputs: dict[str, Any],
            limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            limitations["limitations"].append(
                {
                    "id": "stable-1.0.allowed-unbounded",
                    "classification": "allowed-for-stable-1.0",
                    "category": "trust-graph-local-scope",
                    "status": "open",
                }
            )

        run_case(
            root,
            "allowed-limitation-missing-metadata",
            allowed_limitation_missing_metadata,
            "not-ready",
            expect_blocker="stable-1.0.known-limitations",
        )

        def allowed_disallowed_category(_inputs: dict[str, Any], limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            limitations["limitations"].append(
                {
                    "id": "stable-1.0.allowed-redaction-failure",
                    "title": "Disallowed category mislabeled allowed",
                    "classification": "allowed-for-stable-1.0",
                    "category": "redaction-failure",
                    "status": "open",
                    "summary": "Self-test disallowed category marked allowed.",
                }
            )

        run_case(root, "allowed-disallowed-category", allowed_disallowed_category, "not-ready", expect_blocker="stable-1.0.known-limitations")

        def unknown_limitation_classification(_inputs: dict[str, Any], limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            limitations["limitations"].append(
                {
                    "id": "stable-1.0.unknown-classification",
                    "title": "Unknown classification typo",
                    "classification": "allowed-for-stable",
                    "category": "no-rollback-path",
                    "status": "open",
                    "summary": "Self-test unknown classification.",
                }
            )

        run_case(root, "unknown-limitation-classification", unknown_limitation_classification, "not-ready", expect_blocker="stable-1.0.known-limitations")

        def malformed_known_limitations(
            _inputs: dict[str, Any],
            limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            limitations.clear()
            limitations["limitations"] = []

        run_case(
            root,
            "malformed-known-limitations",
            malformed_known_limitations,
            "not-ready",
            expect_blocker="stable-1.0.known-limitations",
        )

        def boolean_known_limitations_schema_version(
            _inputs: dict[str, Any],
            limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            limitations["schemaVersion"] = True

        run_case(
            root,
            "boolean-known-limitations-schema-version",
            boolean_known_limitations_schema_version,
            "not-ready",
            expect_blocker="stable-1.0.known-limitations",
        )

        def malformed_known_limitation_entry(
            _inputs: dict[str, Any],
            limitations: dict[str, Any],
            _paths: dict[str, Path],
        ) -> None:
            limitations["limitations"] = ["not-an-object"]

        run_case(
            root,
            "malformed-known-limitation-entry",
            malformed_known_limitation_entry,
            "not-ready",
            expect_blocker="stable-1.0.known-limitations",
        )

        def missing_policy(_inputs: dict[str, Any], _limitations: dict[str, Any], paths: dict[str, Path]) -> None:
            paths["policy"] = paths["stableKnownLimitations"].parent / "missing-policy.json"

        run_case(root, "missing-policy", missing_policy, "not-ready", expect_blocker="stable-1.0.readiness-gate")

        def invalid_utf8_policy(
            _inputs: dict[str, Any],
            _limitations: dict[str, Any],
            paths: dict[str, Path],
        ) -> None:
            policy_path = paths["stableKnownLimitations"].parent / "invalid-utf8-policy.json"
            policy_path.write_bytes(b"\xff\xfeinvalid-policy")
            paths["policy"] = policy_path

        run_case(
            root,
            "invalid-utf8-policy",
            invalid_utf8_policy,
            "not-ready",
            expect_blocker="stable-1.0.readiness-gate",
        )

        def boolean_policy_schema_version(
            _inputs: dict[str, Any],
            _limitations: dict[str, Any],
            paths: dict[str, Path],
        ) -> None:
            policy = copy.deepcopy(read_json(DEFAULT_POLICY) or {})
            policy["schemaVersion"] = True
            policy_path = paths["stableKnownLimitations"].parent / "boolean-schema-policy.json"
            write_json(policy_path, policy)
            paths["policy"] = policy_path

        run_case(
            root,
            "boolean-policy-schema-version",
            boolean_policy_schema_version,
            "not-ready",
            expect_blocker="stable-1.0.readiness-gate",
        )

        def redaction_unsafe(inputs: dict[str, Any], _limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            inputs["goNoGoSummary"]["unsafeHeader"] = "Authorization: Bearer selftestsecret"

        run_case(root, "redaction-unsafe", redaction_unsafe, "not-ready", expect_blocker="stable-1.0.redaction")

        def invalid_waiver(inputs: dict[str, Any], _limitations: dict[str, Any], paths: dict[str, Path]) -> Path:
            inputs["productionBetaSummary"]["promotionReady"] = False
            waiver_path = paths["stableKnownLimitations"].parent / "waivers.json"
            write_json(
                waiver_path,
                {
                    "schemaVersion": 1,
                    "waivers": [
                        {
                            "id": "stable-waive-production",
                            "evidenceId": "stable-1.0.production-beta-state",
                            "scope": "stable-1.0",
                            "status": "approved",
                            "expiresAt": "2999-01-01T00:00:00Z",
                        }
                    ],
                },
            )
            return waiver_path

        run_case(root, "invalid-waiver", invalid_waiver, "not-ready", expect_blocker="stable-1.0.waiver-validation")

        def invalid_utf8_waiver(
            _inputs: dict[str, Any],
            _limitations: dict[str, Any],
            paths: dict[str, Path],
        ) -> Path:
            waiver_path = paths["stableKnownLimitations"].parent / "invalid-utf8-waivers.json"
            waiver_path.write_bytes(b"\xff\xfeinvalid-waiver")
            return waiver_path

        run_case(
            root,
            "invalid-utf8-waiver",
            invalid_utf8_waiver,
            "not-ready",
            expect_blocker="stable-1.0.waiver-validation",
        )

        def boolean_waiver_schema_version(
            _inputs: dict[str, Any],
            limitations: dict[str, Any],
            paths: dict[str, Path],
        ) -> Path:
            limitations["limitations"].append(
                {
                    "id": "stable-1.0.boolean-schema-waiver-followup",
                    "title": "Boolean schema waiver follow-up",
                    "classification": "requires-waiver-before-stable",
                    "category": "ui-polish-accessibility-warning",
                    "status": "open",
                    "summary": "Self-test waiver-required limitation.",
                }
            )
            waiver_path = paths["stableKnownLimitations"].parent / "boolean-schema-waivers.json"
            write_json(
                waiver_path,
                {
                    "schemaVersion": True,
                    "waivers": [
                        {
                            "id": "stable-waive-boolean-schema",
                            "evidenceId": "stable-1.0.boolean-schema-waiver-followup",
                            "scope": "stable-1.0",
                            "status": "approved",
                            "rationale": "Self-test waiver with malformed boolean schema version.",
                            "approvedBy": "stable-release-manager",
                            "owner": "stable-readiness",
                            "expiresAt": "2999-01-01T00:00:00Z",
                            "references": ["docs/stable-1.0-readiness-gate.md"],
                        }
                    ],
                },
            )
            return waiver_path

        run_case(
            root,
            "boolean-waiver-schema-version",
            boolean_waiver_schema_version,
            "not-ready",
            expect_blocker="stable-1.0.waiver-validation",
        )

        def incomplete_waiver_metadata(
            _inputs: dict[str, Any],
            limitations: dict[str, Any],
            paths: dict[str, Path],
        ) -> Path:
            limitations["limitations"].append(
                {
                    "id": "stable-1.0.waiver-required-doc-followup",
                    "title": "Waiver-required docs follow-up",
                    "classification": "requires-waiver-before-stable",
                    "category": "ui-polish-accessibility-warning",
                    "status": "open",
                    "summary": "Self-test waiver-required limitation.",
                }
            )
            waiver_path = paths["stableKnownLimitations"].parent / "incomplete-waivers.json"
            write_json(
                waiver_path,
                {
                    "schemaVersion": 1,
                    "waivers": [
                        {
                            "id": "stable-waive-doc-followup",
                            "evidenceId": "stable-1.0.waiver-required-doc-followup",
                            "scope": "stable-1.0",
                            "status": "approved",
                            "expiresAt": "2999-01-01T00:00:00Z",
                        }
                    ],
                },
            )
            return waiver_path

        run_case(root, "incomplete-waiver-metadata", incomplete_waiver_metadata, "not-ready", expect_blocker="stable-1.0.waiver-validation")

        non_string_waiver_limitation_id = "stable-1.0.non-string-waiver-metadata"

        def non_string_waiver_metadata(
            _inputs: dict[str, Any],
            limitations: dict[str, Any],
            paths: dict[str, Path],
        ) -> Path:
            limitations["limitations"].append(
                {
                    "id": non_string_waiver_limitation_id,
                    "title": "Non-string Stable waiver metadata follow-up",
                    "classification": "requires-waiver-before-stable",
                    "category": "ui-polish-accessibility-warning",
                    "status": "open",
                    "summary": "Self-test limitation requiring typed waiver approval metadata.",
                    "evidenceIds": ["stable-1.0.support-feedback-readiness"],
                    "boundedBy": "The follow-up is bounded to non-blocking UI polish.",
                }
            )
            waiver_path = paths["stableKnownLimitations"].parent / "non-string-metadata-waivers.json"
            write_json(
                waiver_path,
                {
                    "schemaVersion": 1,
                    "waivers": [
                        {
                            "id": "stable-waive-non-string-metadata",
                            "evidenceId": non_string_waiver_limitation_id,
                            "scope": "stable-1.0",
                            "status": "approved",
                            "rationale": None,
                            "approvedBy": None,
                            "owner": None,
                            "expiresAt": "2999-01-01T00:00:00Z",
                            "references": [None],
                        }
                    ],
                },
            )
            return waiver_path

        def assert_non_string_waiver_metadata(summary: dict[str, Any]) -> None:
            waiver = next(
                (
                    record
                    for record in summary.get("waivers", [])
                    if isinstance(record, dict)
                    and record.get("id") == "stable-waive-non-string-metadata"
                ),
                None,
            )
            if not isinstance(waiver, dict) or waiver.get("active") is not False:
                raise AssertionError(f"malformed Stable waiver became active: {waiver}")
            validation_errors = set(waiver.get("validationErrors", []))
            expected_errors = {
                "rationale is required",
                "approvedBy is required",
                "owner is required",
                "references must contain only non-empty strings",
            }
            if not expected_errors.issubset(validation_errors):
                raise AssertionError(
                    "malformed Stable waiver omitted type validation errors: "
                    f"{waiver.get('validationErrors')}"
                )

        run_case(
            root,
            "non-string-waiver-metadata",
            non_string_waiver_metadata,
            "not-ready",
            expect_blocker="stable-1.0.waiver-validation",
            post_check=assert_non_string_waiver_metadata,
        )

        def missing_waiver_required_fields(
            _inputs: dict[str, Any],
            limitations: dict[str, Any],
            paths: dict[str, Path],
        ) -> Path:
            limitations["limitations"].append(
                {
                    "id": "stable-1.0.missing-required-waiver-fields",
                    "title": "Missing required waiver fields follow-up",
                    "classification": "requires-waiver-before-stable",
                    "category": "ui-polish-accessibility-warning",
                    "status": "open",
                    "summary": "Self-test waiver-required limitation.",
                }
            )
            waiver_path = paths["stableKnownLimitations"].parent / "missing-required-field-waivers.json"
            write_json(
                waiver_path,
                {
                    "schemaVersion": 1,
                    "waivers": [
                        {
                            "scope": "stable-1.0",
                            "rationale": "Self-test waiver with missing binding and approval status.",
                            "approvedBy": "stable-release-manager",
                            "owner": "stable-readiness",
                            "expiresAt": "2999-01-01T00:00:00Z",
                            "references": ["docs/stable-1.0-readiness-gate.md"],
                        }
                    ],
                },
            )
            return waiver_path

        run_case(
            root,
            "missing-waiver-required-fields",
            missing_waiver_required_fields,
            "not-ready",
            expect_blocker="stable-1.0.waiver-validation",
        )

        def approved_limitation_waiver(
            paths: dict[str, Path],
            limitation_id: str,
            name: str,
        ) -> Path:
            waiver_path = paths["stableKnownLimitations"].parent / f"{name}-waivers.json"
            write_json(
                waiver_path,
                {
                    "schemaVersion": 1,
                    "waivers": [
                        {
                            "id": f"stable-waive-{name}",
                            "evidenceId": limitation_id,
                            "scope": "stable-1.0",
                            "status": "approved",
                            "rationale": "Synthetic approved Stable limitation waiver.",
                            "approvedBy": "stable-release-manager",
                            "owner": "stable-readiness",
                            "expiresAt": "2999-01-01T00:00:00Z",
                            "references": ["docs/stable-1.0-readiness-gate.md"],
                        }
                    ],
                },
            )
            return waiver_path

        malformed_waived_limitation_id = "stable-1.0.waived-metadata-missing"

        def waived_limitation_missing_metadata(
            _inputs: dict[str, Any],
            limitations: dict[str, Any],
            paths: dict[str, Path],
        ) -> Path:
            limitations["limitations"].append(
                {
                    "id": malformed_waived_limitation_id,
                    "classification": "requires-waiver-before-stable",
                    "status": "open",
                }
            )
            return approved_limitation_waiver(
                paths,
                malformed_waived_limitation_id,
                "metadata-missing",
            )

        def assert_waived_limitation_missing_metadata(summary: dict[str, Any]) -> None:
            metadata_blockers = [
                blocker
                for blocker in summary.get("blockers", [])
                if isinstance(blocker, dict)
                and blocker.get("title")
                == "Waiver-required Stable limitation record is malformed"
                and blocker.get("limitationId") == malformed_waived_limitation_id
            ]
            if len(metadata_blockers) != 1:
                raise AssertionError(
                    "malformed waived limitation did not produce its metadata blocker: "
                    f"{summary.get('blockers')}"
                )
            blocker_summary = str(metadata_blockers[0].get("summary", ""))
            for missing_field in ("title", "category", "summary", "boundedBy", "evidenceIds"):
                if missing_field not in blocker_summary:
                    raise AssertionError(
                        f"malformed waived limitation blocker omitted {missing_field}: "
                        f"{metadata_blockers[0]}"
                    )

        run_case(
            root,
            "waived-limitation-missing-metadata",
            waived_limitation_missing_metadata,
            "not-ready",
            expect_blocker="stable-1.0.known-limitations",
            post_check=assert_waived_limitation_missing_metadata,
        )

        valid_waived_limitation_id = "stable-1.0.waived-metadata-complete"

        def waived_limitation_valid(
            _inputs: dict[str, Any],
            limitations: dict[str, Any],
            paths: dict[str, Path],
        ) -> Path:
            limitations["limitations"].append(
                {
                    "id": valid_waived_limitation_id,
                    "title": "Bounded Stable follow-up covered by waiver",
                    "classification": "requires-waiver-before-stable",
                    "category": "ui-polish-accessibility-warning",
                    "status": "open",
                    "summary": "Synthetic auditable waiver-required limitation.",
                    "owner": "stable-readiness",
                    "evidenceIds": ["stable-1.0.support-feedback-readiness"],
                    "boundedBy": "The follow-up remains bounded to non-blocking UI polish.",
                }
            )
            return approved_limitation_waiver(
                paths,
                valid_waived_limitation_id,
                "metadata-complete",
            )

        def assert_waived_limitation_valid(summary: dict[str, Any]) -> None:
            matching_warnings = [
                warning
                for warning in summary.get("warnings", [])
                if isinstance(warning, dict)
                and warning.get("title") == "Stable limitation is covered by waiver"
                and valid_waived_limitation_id in str(warning.get("summary", ""))
            ]
            if len(matching_warnings) != 1 or summary.get("status") != "warn":
                raise AssertionError(
                    "auditable waived limitation was not preserved as a Stable warning: "
                    f"{summary}"
                )

        run_case(
            root,
            "waived-limitation-valid",
            waived_limitation_valid,
            "ready",
            post_check=assert_waived_limitation_valid,
        )

        def only_trust_graph(_inputs: dict[str, Any], limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            for limitation in limitations["limitations"]:
                if limitation["id"] != "stable-1.0.trust-graph-local-scope":
                    limitation["status"] = "resolved"

        run_case(root, "allowed-trust-graph", only_trust_graph, "ready-with-allowed-limitations", expect_allowed="stable-1.0.trust-graph-local-scope")

        def only_social(_inputs: dict[str, Any], limitations: dict[str, Any], _paths: dict[str, Path]) -> None:
            for limitation in limitations["limitations"]:
                if limitation["id"] != "stable-1.0.social-inbox-no-legacy-protocol":
                    limitation["status"] = "resolved"

        run_case(root, "allowed-social-inbox", only_social, "ready-with-allowed-limitations", expect_allowed="stable-1.0.social-inbox-no-legacy-protocol")

    print("stable 1.0 readiness self-test passed")
