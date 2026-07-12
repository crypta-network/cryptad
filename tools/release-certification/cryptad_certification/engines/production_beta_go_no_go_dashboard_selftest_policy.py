"""Implementation segment for the selftest policy portion of ``production_beta_go_no_go_dashboard.py``."""

from __future__ import annotations

def assert_required_stable_readiness_release_id_matches_dashboard_candidate(root: Path) -> None:
    pass_fixture = load_fixture(FIXTURE_DIR / "go-no-go-pass.json")
    release_id = str(pass_fixture.get("releaseId", "crypta-production-beta-270"))
    inputs = json.loads(json.dumps(pass_fixture["inputs"]))
    inputs["stableReadinessSummary"] = {
        "schemaVersion": 1,
        "kind": "stable-1.0-readiness",
        "tool": "stable-1.0-readiness",
        "generatedAt": DEFAULT_GENERATED_AT,
        "releaseId": release_id,
        "status": "pass",
        "decision": "ready",
        "stableReady": True,
        "blockerCount": 0,
        "warningCount": 0,
        "allowedLimitationCount": 0,
        "disallowedLimitationCount": 0,
        "blockers": [],
        "warnings": [],
        "allowedLimitations": [],
        "disallowedLimitations": [],
        "domains": [
            {
                "id": domain_id,
                "status": "pass",
                "summary": "Synthetic Stable domain passed.",
                "evidenceIds": [],
                "blockers": [],
                "warnings": [],
                "allowedLimitations": [],
            }
            for domain_id in STABLE_1_0_READINESS_DOMAIN_IDS
        ],
        "redaction": {"status": "pass", "findings": []},
        "evidence": [
            {
                "id": evidence_id,
                "status": "pass",
                "summary": f"{evidence_id} passed.",
                "details": {"decision": "ready", "stableReady": True}
                if evidence_id == "stable-1.0.readiness-gate"
                else {},
            }
            for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
        ],
    }
    generated_at, now = parse_generated_at(DEFAULT_GENERATED_AT)
    matching_dashboard = build_dashboard(
        inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-release-id-match",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if matching_dashboard.get("decision") != "go":
        raise AssertionError(
            "matching required Stable readiness summary blocked a passing dashboard: "
            f"{matching_dashboard}"
        )
    matching_stable = matching_dashboard.get("stableReadiness")
    if not isinstance(matching_stable, dict) or matching_stable.get("releaseIdMatchesDashboard") is not True:
        raise AssertionError(f"matching Stable readiness binding was not reported: {matching_dashboard}")

    for tool_suffix, tool_value in (
        ("missing", None),
        ("wrong", "other-stable-tool"),
    ):
        invalid_tool_inputs = json.loads(json.dumps(inputs))
        if tool_value is None:
            invalid_tool_inputs["stableReadinessSummary"].pop("tool", None)
        else:
            invalid_tool_inputs["stableReadinessSummary"]["tool"] = tool_value
        invalid_tool_dashboard = build_dashboard(
            invalid_tool_inputs,
            {},
            [FIXTURE_DIR / "go-no-go-pass.json"],
            None,
            Path(__file__).resolve().parents[2],
            root / f"stable-readiness-{tool_suffix}-tool",
            "production-beta",
            release_id,
            generated_at,
            now,
            require_stable_readiness=True,
        )
        invalid_tool_blockers = [
            blocker
            for blocker in invalid_tool_dashboard.get("blockers", [])
            if isinstance(blocker, dict)
            and blocker.get("id") == "stable-1.0.readiness-summary.tool"
            and blocker.get("severity") == "blocker"
        ]
        if invalid_tool_dashboard.get("decision") != "no-go" or len(invalid_tool_blockers) != 1:
            raise AssertionError(
                f"Stable summary with {tool_suffix} tool did not block: {invalid_tool_dashboard}"
            )

    for count_suffix, warning_count in (
        ("string", "bad"),
        ("boolean", True),
        ("fractional", 0.5),
        ("negative", -1),
    ):
        malformed_warning_inputs = json.loads(json.dumps(inputs))
        malformed_warning_inputs["stableReadinessSummary"]["warningCount"] = warning_count
        malformed_warning_dashboard = build_dashboard(
            malformed_warning_inputs,
            {},
            [FIXTURE_DIR / "go-no-go-pass.json"],
            None,
            Path(__file__).resolve().parents[2],
            root / f"stable-readiness-malformed-warning-count-{count_suffix}",
            "production-beta",
            release_id,
            generated_at,
            now,
            require_stable_readiness=True,
        )
        malformed_warning_blockers = [
            blocker
            for blocker in malformed_warning_dashboard.get("blockers", [])
            if isinstance(blocker, dict)
            and blocker.get("id") == "stable-1.0.readiness-summary.warning-count-invalid"
            and blocker.get("severity") == "blocker"
        ]
        if (
            malformed_warning_dashboard.get("decision") != "no-go"
            or len(malformed_warning_blockers) != 1
        ):
            raise AssertionError(
                f"malformed Stable warningCount {warning_count!r} did not block: "
                f"{malformed_warning_dashboard}"
            )

    for warning_suffix, warning_records in (
        ("object", {}),
        ("string", "not-a-list"),
    ):
        malformed_warning_inputs = json.loads(json.dumps(inputs))
        malformed_warning_inputs["stableReadinessSummary"]["warnings"] = warning_records
        malformed_warning_dashboard = build_dashboard(
            malformed_warning_inputs,
            {},
            [FIXTURE_DIR / "go-no-go-pass.json"],
            None,
            Path(__file__).resolve().parents[2],
            root / f"stable-readiness-malformed-warning-records-{warning_suffix}",
            "production-beta",
            release_id,
            generated_at,
            now,
            require_stable_readiness=True,
        )
        malformed_warning_blockers = [
            blocker
            for blocker in malformed_warning_dashboard.get("blockers", [])
            if isinstance(blocker, dict)
            and blocker.get("id") == "stable-1.0.readiness-summary.warning-records-invalid"
            and blocker.get("severity") == "blocker"
        ]
        if (
            malformed_warning_dashboard.get("decision") != "no-go"
            or len(malformed_warning_blockers) != 1
        ):
            raise AssertionError(
                f"malformed Stable warnings {warning_records!r} did not block: "
                f"{malformed_warning_dashboard}"
            )

    summary_warning_inputs = json.loads(json.dumps(inputs))
    summary_warning = {
        "id": "stable-1.0.synthetic-warning",
        "evidenceId": "stable-1.0.support-feedback-readiness",
        "severity": "warning",
        "title": "Synthetic Stable warning",
        "summary": "Synthetic Stable warning remains open for release-manager review.",
        "source": "stable-readiness-self-test",
        "waivable": True,
        "category": "self-test",
    }
    summary_warning_value = summary_warning_inputs["stableReadinessSummary"]
    summary_warning_value.update(
        {
            "status": "warn",
            "warningCount": 1,
            "warnings": [summary_warning],
        }
    )
    summary_warning_domain = next(
        domain
        for domain in summary_warning_value["domains"]
        if isinstance(domain, dict) and domain.get("id") == "support-feedback-readiness"
    )
    summary_warning_domain.update(
        {
            "status": "warn",
            "summary": summary_warning["summary"],
            "warnings": [summary_warning],
        }
    )
    summary_warning_dashboard = build_dashboard(
        summary_warning_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-summary-warning",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if summary_warning_dashboard.get("decision") != "go":
        raise AssertionError(
            "warning-only Stable summary blocked a passing dashboard: "
            f"{summary_warning_dashboard}"
        )
    surfaced_summary_warnings = [
        warning
        for warning in summary_warning_dashboard.get("warnings", [])
        if isinstance(warning, dict)
        and warning.get("id") == "stable-1.0.readiness-summary.evidence-warnings"
        and "stable-1.0.synthetic-warning" in str(warning.get("summary", ""))
    ]
    if len(surfaced_summary_warnings) != 1:
        raise AssertionError(
            "Stable summary warning was not surfaced exactly once: "
            f"{summary_warning_dashboard.get('warnings')}"
        )

    status_only_summary_warning_inputs = json.loads(json.dumps(inputs))
    status_only_summary_warning_inputs["stableReadinessSummary"]["status"] = "warn"
    status_only_summary_warning_dashboard = build_dashboard(
        status_only_summary_warning_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-status-only-summary-warning",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    status_only_summary_warning_blockers = [
        blocker
        for blocker in status_only_summary_warning_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.warning-status-invalid"
        and blocker.get("severity") == "blocker"
    ]
    if status_only_summary_warning_dashboard.get("decision") != "no-go" or len(
        status_only_summary_warning_blockers
    ) != 1:
        raise AssertionError(
            "status-only Stable summary warning did not block: "
            f"{status_only_summary_warning_dashboard}"
        )

    status_only_warning_inputs = json.loads(json.dumps(inputs))
    status_only_warning_domain = next(
        domain
        for domain in status_only_warning_inputs["stableReadinessSummary"]["domains"]
        if isinstance(domain, dict) and domain.get("id") == "support-feedback-readiness"
    )
    status_only_warning_domain.update(
        {
            "status": "warn",
            "summary": "Synthetic Stable domain reports an unsurfaced warning.",
        }
    )
    status_only_warning_dashboard = build_dashboard(
        status_only_warning_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-status-only-domain-warning",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    status_only_warning_blockers = [
        blocker
        for blocker in status_only_warning_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.domain-failed"
        and blocker.get("evidenceId") == "stable-1.0.readiness-gate"
        and blocker.get("severity") == "blocker"
        and "support-feedback-readiness" in str(blocker.get("summary", ""))
    ]
    if status_only_warning_dashboard.get("decision") != "no-go" or len(
        status_only_warning_blockers
    ) != 1:
        raise AssertionError(
            "status-only Stable domain warning did not block: "
            f"{status_only_warning_dashboard}"
        )

    required_redaction_domain_warn_inputs = json.loads(json.dumps(inputs))
    required_redaction_domain = next(
        domain
        for domain in required_redaction_domain_warn_inputs["stableReadinessSummary"]["domains"]
        if isinstance(domain, dict) and domain.get("id") == "redaction"
    )
    required_redaction_domain.update(
        {
            "status": "warn",
            "summary": "Synthetic Stable redaction warning domain.",
            "evidenceIds": ["stable-1.0.redaction"],
            "warnings": [
                {
                    "id": "stable-redaction-domain-warning",
                    "evidenceId": "stable-1.0.redaction",
                    "summary": "Synthetic Stable redaction warning.",
                }
            ],
        }
    )
    required_redaction_domain_warn_dashboard = build_dashboard(
        required_redaction_domain_warn_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-required-redaction-domain-warn",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if required_redaction_domain_warn_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable redaction domain warning did not block: "
            f"{required_redaction_domain_warn_dashboard}"
        )
    required_redaction_domain_warn_blockers = [
        blocker
        for blocker in required_redaction_domain_warn_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.redaction-domain-failed"
        and blocker.get("evidenceId") == "stable-1.0.redaction"
        and blocker.get("severity") == "critical"
        and blocker.get("waivable") is False
    ]
    if not required_redaction_domain_warn_blockers:
        raise AssertionError(
            "required Stable redaction warning domain was not critical/non-waivable: "
            f"{required_redaction_domain_warn_dashboard}"
        )

    advisory_redaction_evidence_inputs = json.loads(json.dumps(inputs))
    for entry in advisory_redaction_evidence_inputs["stableReadinessSummary"]["evidence"]:
        if isinstance(entry, dict) and entry.get("id") == "stable-1.0.redaction":
            entry["status"] = "fail"
            entry["summary"] = "Synthetic failed Stable redaction evidence."
            break
    else:
        raise AssertionError("synthetic Stable summary is missing stable-1.0.redaction evidence")
    advisory_redaction_evidence_dashboard = build_dashboard(
        advisory_redaction_evidence_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-advisory-redaction-evidence",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=False,
    )
    if advisory_redaction_evidence_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "advisory Stable redaction evidence failure did not block: "
            f"{advisory_redaction_evidence_dashboard}"
        )
    advisory_redaction_evidence_blockers = [
        blocker
        for blocker in advisory_redaction_evidence_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.redaction-evidence-failed"
        and blocker.get("evidenceId") == "stable-1.0.redaction"
        and blocker.get("severity") == "critical"
        and blocker.get("waivable") is False
    ]
    if not advisory_redaction_evidence_blockers:
        raise AssertionError(
            "advisory Stable redaction evidence failure was not critical/non-waivable: "
            f"{advisory_redaction_evidence_dashboard}"
        )

    advisory_redaction_domain_inputs = json.loads(json.dumps(inputs))
    advisory_redaction_domain = next(
        domain
        for domain in advisory_redaction_domain_inputs["stableReadinessSummary"]["domains"]
        if isinstance(domain, dict) and domain.get("id") == "redaction"
    )
    advisory_redaction_domain.update(
        {
            "status": "fail",
            "summary": "Synthetic failed Stable redaction domain.",
            "evidenceIds": ["stable-1.0.redaction"],
            "blockers": [
                {
                    "id": "stable-redaction-domain-blocker",
                    "evidenceId": "stable-1.0.redaction",
                    "summary": "Synthetic Stable redaction domain blocker.",
                }
            ],
        }
    )
    advisory_redaction_domain_dashboard = build_dashboard(
        advisory_redaction_domain_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-advisory-redaction-domain",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=False,
    )
    if advisory_redaction_domain_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "advisory Stable redaction domain failure did not block: "
            f"{advisory_redaction_domain_dashboard}"
        )
    advisory_redaction_domain_blockers = [
        blocker
        for blocker in advisory_redaction_domain_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.redaction-domain-failed"
        and blocker.get("evidenceId") == "stable-1.0.redaction"
        and blocker.get("severity") == "critical"
        and blocker.get("waivable") is False
    ]
    if not advisory_redaction_domain_blockers:
        raise AssertionError(
            "advisory Stable redaction domain failure was not critical/non-waivable: "
            f"{advisory_redaction_domain_dashboard}"
        )

    missing_domains_inputs = json.loads(json.dumps(inputs))
    missing_domains_inputs["stableReadinessSummary"].pop("domains", None)
    missing_domains_dashboard = build_dashboard(
        missing_domains_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-missing-domains",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if missing_domains_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with omitted domains did not block: "
            f"{missing_domains_dashboard}"
        )
    missing_domains_blockers = [
        blocker
        for blocker in missing_domains_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.domain-failed"
        and blocker.get("evidenceId") == "stable-1.0.readiness-gate"
    ]
    if not missing_domains_blockers:
        raise AssertionError(
            "omitted Stable readiness domains were not reported as a required blocker: "
            f"{missing_domains_dashboard}"
        )

    truncated_domains_inputs = json.loads(json.dumps(inputs))
    truncated_domains_inputs["stableReadinessSummary"]["domains"] = [
        {
            "id": "stub-domain",
            "status": "pass",
            "summary": "Synthetic truncated Stable domain row.",
            "evidenceIds": [],
            "blockers": [],
            "warnings": [],
            "allowedLimitations": [],
        }
    ]
    truncated_domains_dashboard = build_dashboard(
        truncated_domains_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-truncated-domains",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if truncated_domains_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with truncated domains did not block: "
            f"{truncated_domains_dashboard}"
        )
    truncated_domains_blockers = [
        blocker
        for blocker in truncated_domains_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.domain-failed"
        and blocker.get("evidenceId") == "stable-1.0.readiness-gate"
    ]
    if not truncated_domains_blockers:
        raise AssertionError(
            "truncated Stable readiness domains were not reported as a required blocker: "
            f"{truncated_domains_dashboard}"
        )

    failed_domain_inputs = json.loads(json.dumps(inputs))
    failed_domain_inputs["stableReadinessSummary"]["domains"][0]["status"] = "fail"
    failed_domain_inputs["stableReadinessSummary"]["domains"][0]["summary"] = (
        "Synthetic failed Stable domain row."
    )
    failed_domain_dashboard = build_dashboard(
        failed_domain_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-failed-domain",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if failed_domain_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with a failed domain row did not block: "
            f"{failed_domain_dashboard}"
        )
    failed_domain_blockers = [
        blocker
        for blocker in failed_domain_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.domain-failed"
        and blocker.get("evidenceId") == "stable-1.0.readiness-gate"
    ]
    if not failed_domain_blockers:
        raise AssertionError(
            "failed Stable domain row was not reported as a required blocker: "
            f"{failed_domain_dashboard}"
        )

    malformed_allowed_domain_inputs = json.loads(json.dumps(inputs))
    malformed_allowed_domain_inputs["stableReadinessSummary"]["domains"][0]["allowedLimitations"] = [1]
    malformed_allowed_domain_dashboard = build_dashboard(
        malformed_allowed_domain_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-domain-malformed-allowed-limitation",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if malformed_allowed_domain_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with a malformed domain allowed limitation did not block: "
            f"{malformed_allowed_domain_dashboard}"
        )
    malformed_allowed_domain_blockers = [
        blocker
        for blocker in malformed_allowed_domain_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.domain-failed"
        and blocker.get("evidenceId") == "stable-1.0.readiness-gate"
    ]
    if not malformed_allowed_domain_blockers:
        raise AssertionError(
            "malformed Stable domain allowed limitation was not reported as a required blocker: "
            f"{malformed_allowed_domain_dashboard}"
        )

    hidden_allowed_domain_inputs = json.loads(json.dumps(inputs))
    hidden_allowed_limitation = {
        "id": "stable-1.0.self-test-hidden-allowed-limitation",
        "title": "Hidden self-test allowed Stable limitation",
        "category": "ui-polish-accessibility-warning",
        "classification": "allowed-for-stable-1.0",
        "status": "open",
        "summary": "Synthetic domain-scoped Stable limitation.",
        "evidenceIds": ["stable-1.0.known-limitations"],
        "boundedBy": "Self-test release manager bound for a non-blocking Stable limitation.",
    }
    hidden_allowed_domain = next(
        domain
        for domain in hidden_allowed_domain_inputs["stableReadinessSummary"]["domains"]
        if isinstance(domain, dict) and domain.get("id") == "known-limitations"
    )
    hidden_allowed_domain.update(
        {
            "status": "warn",
            "summary": "Synthetic Stable domain contains a hidden allowed limitation.",
            "allowedLimitations": [hidden_allowed_limitation],
        }
    )
    hidden_allowed_domain_dashboard = build_dashboard(
        hidden_allowed_domain_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-domain-hidden-allowed-limitation",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    hidden_allowed_domain_blockers = [
        blocker
        for blocker in hidden_allowed_domain_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.domain-failed"
        and "not present in top-level allowedLimitations" in str(blocker.get("summary", ""))
    ]
    if hidden_allowed_domain_dashboard.get("decision") != "no-go" or len(
        hidden_allowed_domain_blockers
    ) != 1:
        raise AssertionError(
            "domain-scoped Stable allowed limitation was not surfaced as inconsistent: "
            f"{hidden_allowed_domain_dashboard}"
        )

    blocker_domain_inputs = json.loads(json.dumps(inputs))
    blocker_domain_inputs["stableReadinessSummary"]["domains"][0]["blockers"] = [
        {
            "id": "stable-self-test-domain-blocker",
            "evidenceId": "stable-1.0.production-beta-state",
            "summary": "Synthetic Stable domain blocker.",
        }
    ]
    blocker_domain_dashboard = build_dashboard(
        blocker_domain_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-domain-blocker",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if blocker_domain_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with a domain blocker did not block: "
            f"{blocker_domain_dashboard}"
        )
    blocker_domain_blockers = [
        blocker
        for blocker in blocker_domain_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.domain-failed"
        and blocker.get("evidenceId") == "stable-1.0.readiness-gate"
    ]
    if not blocker_domain_blockers:
        raise AssertionError(
            "Stable domain blocker was not reported as a required blocker: "
            f"{blocker_domain_dashboard}"
        )

    missing_schema_inputs = json.loads(json.dumps(inputs))
    missing_schema_inputs["stableReadinessSummary"].pop("schemaVersion", None)
    missing_schema_dashboard = build_dashboard(
        missing_schema_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-missing-schema-version",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if missing_schema_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with missing schemaVersion did not block: "
            f"{missing_schema_dashboard}"
        )
    missing_schema_blockers = [
        blocker
        for blocker in missing_schema_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.schema-version"
        and blocker.get("evidenceId") == "stable-1.0.readiness-gate"
    ]
    if not missing_schema_blockers:
        raise AssertionError(
            "missing Stable schemaVersion was not reported as a required blocker: "
            f"{missing_schema_dashboard}"
        )

    mismatched_inputs = json.loads(json.dumps(inputs))
    mismatched_inputs["stableReadinessSummary"]["releaseId"] = "crypta-production-beta-previous"
    mismatched_dashboard = build_dashboard(
        mismatched_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-release-id-mismatch",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if mismatched_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "Stable readiness from another release id did not block: "
            f"{mismatched_dashboard}"
        )
    mismatched_stable = mismatched_dashboard.get("stableReadiness")
    if not isinstance(mismatched_stable, dict) or mismatched_stable.get("releaseIdMatchesDashboard") is not False:
        raise AssertionError(f"mismatched Stable readiness binding was not reported: {mismatched_dashboard}")
    blockers = [
        blocker
        for blocker in mismatched_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("evidenceId") == "stable-1.0.readiness-gate"
        and blocker.get("id") == "stable-1.0.readiness-summary.release-id"
    ]
    if not blockers:
        raise AssertionError(f"release-id mismatch did not block Stable readiness: {mismatched_dashboard}")

    truncated_inputs = json.loads(json.dumps(inputs))
    truncated_inputs["stableReadinessSummary"]["evidence"] = [
        entry
        for entry in truncated_inputs["stableReadinessSummary"]["evidence"]
        if entry.get("id") != "stable-1.0.security-drills"
    ]
    truncated_dashboard = build_dashboard(
        truncated_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-truncated-evidence",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if truncated_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with missing evidence did not block: "
            f"{truncated_dashboard}"
        )
    truncated_blockers = [
        blocker
        for blocker in truncated_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.evidence-missing"
    ]
    if not truncated_blockers:
        raise AssertionError(f"missing Stable evidence blocker was not reported: {truncated_dashboard}")

    duplicate_inputs = json.loads(json.dumps(inputs))
    duplicate_evidence = duplicate_inputs["stableReadinessSummary"]["evidence"]
    for index, entry in enumerate(duplicate_evidence):
        if isinstance(entry, dict) and entry.get("id") == "stable-1.0.security-drills":
            failed_entry = json.loads(json.dumps(entry))
            failed_entry["status"] = "fail"
            failed_entry["summary"] = "Synthetic failed duplicate Stable security drills evidence."
            duplicate_evidence.insert(index, failed_entry)
            break
    else:
        raise AssertionError("synthetic Stable summary is missing stable-1.0.security-drills evidence")
    duplicate_dashboard = build_dashboard(
        duplicate_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-duplicate-evidence",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if duplicate_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with duplicate failed evidence did not block: "
            f"{duplicate_dashboard}"
        )
    duplicate_blockers = [
        blocker
        for blocker in duplicate_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.evidence-duplicate"
    ]
    if not duplicate_blockers:
        raise AssertionError(f"duplicate Stable evidence blocker was not reported: {duplicate_dashboard}")

    redaction_inputs = json.loads(json.dumps(inputs))
    for entry in redaction_inputs["stableReadinessSummary"]["evidence"]:
        if isinstance(entry, dict) and entry.get("id") == "stable-1.0.redaction":
            entry["details"] = {
                "redactionFindings": [
                    {"kind": "stable-readiness-fixture", "summary": "Synthetic Stable redaction finding."}
                ]
            }
            break
    else:
        raise AssertionError("synthetic Stable summary is missing stable-1.0.redaction evidence")
    redaction_dashboard = build_dashboard(
        redaction_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-evidence-redaction",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if redaction_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with evidence-row redaction findings did not block: "
            f"{redaction_dashboard}"
        )
    redaction_blockers = [
        blocker
        for blocker in redaction_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.evidence-redaction"
        and blocker.get("evidenceId") == "stable-1.0.redaction"
        and blocker.get("severity") == "critical"
    ]
    if not redaction_blockers:
        raise AssertionError(
            "Stable evidence-row redaction findings were not reported as a critical blocker: "
            f"{redaction_dashboard}"
        )

    extra_redaction_inputs = json.loads(json.dumps(inputs))
    extra_redaction_inputs["stableReadinessSummary"]["evidence"].append(
        {
            "id": "stable-1.0.extra-redaction-fixture",
            "status": "pass",
            "summary": "Synthetic extra Stable evidence row with redaction findings.",
            "details": {
                "redactionFindings": [
                    {
                        "kind": "stable-readiness-fixture",
                        "summary": "Synthetic extra Stable evidence redaction finding.",
                    }
                ]
            },
        }
    )
    extra_redaction_dashboard = build_dashboard(
        extra_redaction_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-extra-evidence-redaction",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if extra_redaction_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with extra evidence-row redaction findings did not block: "
            f"{extra_redaction_dashboard}"
        )
    extra_redaction_blockers = [
        blocker
        for blocker in extra_redaction_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.evidence-redaction"
        and blocker.get("evidenceId") == "stable-1.0.redaction"
        and blocker.get("severity") == "critical"
        and "stable-1.0.extra-redaction-fixture" in str(blocker.get("summary", ""))
    ]
    if not extra_redaction_blockers:
        raise AssertionError(
            "Stable extra evidence-row redaction findings were not reported as a critical blocker: "
            f"{extra_redaction_dashboard}"
        )

    malformed_row_redaction_inputs = json.loads(json.dumps(inputs))
    for entry in malformed_row_redaction_inputs["stableReadinessSummary"]["evidence"]:
        if isinstance(entry, dict) and entry.get("id") == "stable-1.0.production-beta-state":
            entry["details"] = {"redactionFindings": 0}
            break
    else:
        raise AssertionError("synthetic Stable summary is missing stable-1.0.production-beta-state evidence")
    malformed_row_redaction_dashboard = build_dashboard(
        malformed_row_redaction_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-evidence-malformed-row-redaction",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if malformed_row_redaction_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with malformed falsey row redactionFindings did not block: "
            f"{malformed_row_redaction_dashboard}"
        )
    malformed_row_redaction_blockers = [
        blocker
        for blocker in malformed_row_redaction_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.evidence-redaction"
        and blocker.get("evidenceId") == "stable-1.0.redaction"
        and blocker.get("severity") == "critical"
    ]
    if not malformed_row_redaction_blockers:
        raise AssertionError(
            "Stable falsey malformed evidence-row redaction findings were not reported as a critical blocker: "
            f"{malformed_row_redaction_dashboard}"
        )

    nested_redaction_inputs = json.loads(json.dumps(inputs))
    for entry in nested_redaction_inputs["stableReadinessSummary"]["evidence"]:
        if isinstance(entry, dict) and entry.get("id") == "stable-1.0.production-beta-state":
            entry["details"] = {
                "redaction": {
                    "status": "pass",
                    "findingCount": 1,
                    "findings": [
                        {
                            "kind": "stable-readiness-fixture",
                            "summary": "Synthetic nested Stable evidence redaction finding.",
                        }
                    ],
                }
            }
            break
    else:
        raise AssertionError("synthetic Stable summary is missing stable-1.0.production-beta-state evidence")
    nested_redaction_dashboard = build_dashboard(
        nested_redaction_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-evidence-nested-redaction",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if nested_redaction_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with nested evidence redaction findings did not block: "
            f"{nested_redaction_dashboard}"
        )
    nested_redaction_blockers = [
        blocker
        for blocker in nested_redaction_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.evidence-redaction"
        and blocker.get("evidenceId") == "stable-1.0.redaction"
        and blocker.get("severity") == "critical"
    ]
    if not nested_redaction_blockers:
        raise AssertionError(
            "Stable nested evidence-row redaction findings were not reported as a critical blocker: "
            f"{nested_redaction_dashboard}"
        )

    raw_stored_redaction_inputs = json.loads(json.dumps(inputs))
    for entry in raw_stored_redaction_inputs["stableReadinessSummary"]["evidence"]:
        if isinstance(entry, dict) and entry.get("id") == "stable-1.0.production-beta-state":
            entry["details"] = {
                "redaction": {
                    "status": "pass",
                    "findings": [],
                    "rawCatalogStored": True,
                }
            }
            break
    else:
        raise AssertionError("synthetic Stable summary is missing stable-1.0.production-beta-state evidence")
    raw_stored_redaction_dashboard = build_dashboard(
        raw_stored_redaction_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-evidence-raw-stored-redaction",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if raw_stored_redaction_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with raw-stored evidence redaction did not block: "
            f"{raw_stored_redaction_dashboard}"
        )
    raw_stored_redaction_blockers = [
        blocker
        for blocker in raw_stored_redaction_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.evidence-redaction"
        and blocker.get("evidenceId") == "stable-1.0.redaction"
        and blocker.get("severity") == "critical"
    ]
    if not raw_stored_redaction_blockers:
        raise AssertionError(
            "Stable raw-stored evidence-row redaction was not reported as a critical blocker: "
            f"{raw_stored_redaction_dashboard}"
        )

    sensitive_stored_redaction_inputs = json.loads(json.dumps(inputs))
    for entry in sensitive_stored_redaction_inputs["stableReadinessSummary"]["evidence"]:
        if isinstance(entry, dict) and entry.get("id") == "stable-1.0.redaction":
            entry["details"] = {"privateInsertUrisStored": True}
            break
    else:
        raise AssertionError("synthetic Stable summary is missing stable-1.0.redaction evidence")
    sensitive_stored_redaction_dashboard = build_dashboard(
        sensitive_stored_redaction_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-evidence-sensitive-stored-redaction",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if sensitive_stored_redaction_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with privateInsertUrisStored=true did not block: "
            f"{sensitive_stored_redaction_dashboard}"
        )
    sensitive_stored_redaction_blockers = [
        blocker
        for blocker in sensitive_stored_redaction_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.evidence-redaction"
        and blocker.get("evidenceId") == "stable-1.0.redaction"
        and blocker.get("severity") == "critical"
    ]
    if not sensitive_stored_redaction_blockers:
        raise AssertionError(
            "Stable sensitive-stored proof was not reported as a critical blocker: "
            f"{sensitive_stored_redaction_dashboard}"
        )

    redacted_false_inputs = json.loads(json.dumps(inputs))
    for entry in redacted_false_inputs["stableReadinessSummary"]["evidence"]:
        if isinstance(entry, dict) and entry.get("id") == "stable-1.0.redaction":
            entry["details"] = {"formPasswordsRedacted": False}
            break
    else:
        raise AssertionError("synthetic Stable summary is missing stable-1.0.redaction evidence")
    redacted_false_dashboard = build_dashboard(
        redacted_false_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-evidence-redacted-false",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if redacted_false_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with formPasswordsRedacted=false did not block: "
            f"{redacted_false_dashboard}"
        )
    redacted_false_blockers = [
        blocker
        for blocker in redacted_false_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.evidence-redaction"
        and blocker.get("evidenceId") == "stable-1.0.redaction"
        and blocker.get("severity") == "critical"
    ]
    if not redacted_false_blockers:
        raise AssertionError(
            "Stable false redacted proof was not reported as a critical blocker: "
            f"{redacted_false_dashboard}"
        )

    direct_detail_redaction_inputs = json.loads(json.dumps(inputs))
    for entry in direct_detail_redaction_inputs["stableReadinessSummary"]["evidence"]:
        if isinstance(entry, dict) and entry.get("id") == "stable-1.0.production-beta-state":
            entry["details"] = {"rawBackupPayloadsExcludedFromEvidence": False}
            break
    else:
        raise AssertionError("synthetic Stable summary is missing stable-1.0.production-beta-state evidence")
    direct_detail_redaction_dashboard = build_dashboard(
        direct_detail_redaction_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-evidence-direct-detail-redaction",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if direct_detail_redaction_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with direct detail redaction proof did not block: "
            f"{direct_detail_redaction_dashboard}"
        )
    direct_detail_redaction_blockers = [
        blocker
        for blocker in direct_detail_redaction_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.evidence-redaction"
        and blocker.get("evidenceId") == "stable-1.0.redaction"
        and blocker.get("severity") == "critical"
    ]
    if not direct_detail_redaction_blockers:
        raise AssertionError(
            "Stable direct detail redaction proof was not reported as a critical blocker: "
            f"{direct_detail_redaction_dashboard}"
        )

    for signal_name, signal_value in (
        ("redactionFindings", [{"kind": "stable-readiness-fixture"}]),
        ("findingCount", 1),
        ("privateInsertUrisStored", True),
    ):
        top_level_row_redaction_inputs = json.loads(json.dumps(inputs))
        for entry in top_level_row_redaction_inputs["stableReadinessSummary"]["evidence"]:
            if isinstance(entry, dict) and entry.get("id") == "stable-1.0.production-beta-state":
                entry[signal_name] = signal_value
                break
        else:
            raise AssertionError(
                "synthetic Stable summary is missing stable-1.0.production-beta-state evidence"
            )
        top_level_row_redaction_dashboard = build_dashboard(
            top_level_row_redaction_inputs,
            {},
            [FIXTURE_DIR / "go-no-go-pass.json"],
            None,
            Path(__file__).resolve().parents[2],
            root / f"stable-readiness-evidence-top-level-{signal_name}",
            "production-beta",
            release_id,
            generated_at,
            now,
            require_stable_readiness=True,
        )
        if top_level_row_redaction_dashboard.get("decision") != "no-go":
            raise AssertionError(
                f"required Stable readiness with top-level {signal_name} did not block: "
                f"{top_level_row_redaction_dashboard}"
            )
        top_level_row_redaction_blockers = [
            blocker
            for blocker in top_level_row_redaction_dashboard.get("blockers", [])
            if isinstance(blocker, dict)
            and blocker.get("id") == "stable-1.0.readiness-summary.evidence-redaction"
            and blocker.get("evidenceId") == "stable-1.0.redaction"
            and blocker.get("severity") == "critical"
        ]
        if not top_level_row_redaction_blockers:
            raise AssertionError(
                f"Stable top-level {signal_name} was not reported as a critical blocker: "
                f"{top_level_row_redaction_dashboard}"
            )

    top_level_raw_redaction_inputs = json.loads(json.dumps(inputs))
    top_level_raw_redaction_inputs["stableReadinessSummary"]["redaction"] = {
        "status": "pass",
        "findingCount": 0,
        "findings": [],
        "rawFetchedContentIncluded": True,
    }
    top_level_raw_redaction_dashboard = build_dashboard(
        top_level_raw_redaction_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-top-level-raw-included-redaction",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if top_level_raw_redaction_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with top-level raw-included redaction did not block: "
            f"{top_level_raw_redaction_dashboard}"
        )
    top_level_raw_redaction_blockers = [
        blocker
        for blocker in top_level_raw_redaction_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.redaction"
        and blocker.get("evidenceId") == "stable-1.0.redaction"
        and blocker.get("severity") == "critical"
    ]
    if not top_level_raw_redaction_blockers:
        raise AssertionError(
            "Stable top-level raw-included redaction was not reported as a critical blocker: "
            f"{top_level_raw_redaction_dashboard}"
        )

    excluded_from_evidence_inputs = json.loads(json.dumps(inputs))
    excluded_from_evidence_inputs["stableReadinessSummary"]["redaction"] = {
        "status": "pass",
        "findingCount": 0,
        "findings": [],
        "rawBackupPayloadsExcludedFromEvidence": False,
    }
    excluded_from_evidence_dashboard = build_dashboard(
        excluded_from_evidence_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-excluded-from-evidence-redaction",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if excluded_from_evidence_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with ExcludedFromEvidence=false redaction did not block: "
            f"{excluded_from_evidence_dashboard}"
        )
    excluded_from_evidence_blockers = [
        blocker
        for blocker in excluded_from_evidence_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.redaction"
        and blocker.get("evidenceId") == "stable-1.0.redaction"
        and blocker.get("severity") == "critical"
    ]
    if not excluded_from_evidence_blockers:
        raise AssertionError(
            "Stable ExcludedFromEvidence=false redaction was not reported as a critical blocker: "
            f"{excluded_from_evidence_dashboard}"
        )

    redaction_count_inputs = json.loads(json.dumps(inputs))
    redaction_count_inputs["stableReadinessSummary"]["redaction"] = {
        "status": "pass",
        "findingCount": 1,
    }
    redaction_count_dashboard = build_dashboard(
        redaction_count_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-redaction-count",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if redaction_count_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with top-level redaction findingCount did not block: "
            f"{redaction_count_dashboard}"
        )
    redaction_count_blockers = [
        blocker
        for blocker in redaction_count_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.redaction"
        and blocker.get("evidenceId") == "stable-1.0.redaction"
        and blocker.get("severity") == "critical"
    ]
    if not redaction_count_blockers:
        raise AssertionError(
            "Stable top-level redaction findingCount was not reported as a critical blocker: "
            f"{redaction_count_dashboard}"
        )

    for critical_count_value, critical_count_suffix in (
        (1, "critical-count"),
        (0.5, "fractional-critical-count"),
    ):
        critical_redaction_count_inputs = json.loads(json.dumps(inputs))
        critical_redaction_count_inputs["stableReadinessSummary"]["redaction"] = {
            "status": "pass",
            "findings": [],
            "findingCount": 0,
            "criticalFindingCount": critical_count_value,
        }
        critical_redaction_count_dashboard = build_dashboard(
            critical_redaction_count_inputs,
            {},
            [FIXTURE_DIR / "go-no-go-pass.json"],
            None,
            Path(__file__).resolve().parents[2],
            root / f"stable-readiness-redaction-{critical_count_suffix}",
            "production-beta",
            release_id,
            generated_at,
            now,
            require_stable_readiness=True,
        )
        if critical_redaction_count_dashboard.get("decision") != "no-go":
            raise AssertionError(
                "required Stable readiness with top-level redaction criticalFindingCount "
                f"{critical_count_value!r} did not block: {critical_redaction_count_dashboard}"
            )
        critical_redaction_count_blockers = [
            blocker
            for blocker in critical_redaction_count_dashboard.get("blockers", [])
            if isinstance(blocker, dict)
            and blocker.get("id") == "stable-1.0.readiness-summary.redaction"
            and blocker.get("evidenceId") == "stable-1.0.redaction"
            and blocker.get("severity") == "critical"
            and blocker.get("waivable") is False
        ]
        if not critical_redaction_count_blockers:
            raise AssertionError(
                "Stable top-level redaction criticalFindingCount was not reported as a "
                f"non-waivable critical blocker: {critical_redaction_count_dashboard}"
            )

    redaction_fractional_count_inputs = json.loads(json.dumps(inputs))
    redaction_fractional_count_inputs["stableReadinessSummary"]["redaction"] = {
        "status": "pass",
        "findingCount": 0.5,
    }
    redaction_fractional_count_dashboard = build_dashboard(
        redaction_fractional_count_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-redaction-fractional-count",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if redaction_fractional_count_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with fractional top-level redaction findingCount did not block: "
            f"{redaction_fractional_count_dashboard}"
        )
    redaction_fractional_count_blockers = [
        blocker
        for blocker in redaction_fractional_count_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.redaction"
        and blocker.get("evidenceId") == "stable-1.0.redaction"
        and blocker.get("severity") == "critical"
    ]
    if not redaction_fractional_count_blockers:
        raise AssertionError(
            "Stable fractional top-level redaction findingCount was not reported as a critical blocker: "
            f"{redaction_fractional_count_dashboard}"
        )

    malformed_redaction_findings_inputs = json.loads(json.dumps(inputs))
    malformed_redaction_findings_inputs["stableReadinessSummary"]["redaction"] = {
        "status": "pass",
        "findings": "malformed-redaction-proof",
    }
    malformed_redaction_findings_dashboard = build_dashboard(
        malformed_redaction_findings_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-malformed-redaction-findings",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if malformed_redaction_findings_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with malformed top-level redaction findings did not block: "
            f"{malformed_redaction_findings_dashboard}"
        )
    malformed_redaction_findings_blockers = [
        blocker
        for blocker in malformed_redaction_findings_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.redaction"
        and blocker.get("evidenceId") == "stable-1.0.redaction"
        and blocker.get("severity") == "critical"
    ]
    if not malformed_redaction_findings_blockers:
        raise AssertionError(
            "Stable top-level malformed redaction findings were not reported as a critical blocker: "
            f"{malformed_redaction_findings_dashboard}"
        )

    remaining_blockers_inputs = json.loads(json.dumps(inputs))
    remaining_blockers_inputs["stableReadinessSummary"]["blockerCount"] = 1
    remaining_blockers_inputs["stableReadinessSummary"]["disallowedLimitationCount"] = 1
    remaining_blockers_dashboard = build_dashboard(
        remaining_blockers_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-remaining-blockers",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if remaining_blockers_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with remaining blockers did not block: "
            f"{remaining_blockers_dashboard}"
        )
    remaining_blocker_issues = [
        blocker
        for blocker in remaining_blockers_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.remaining-blockers"
        and blocker.get("evidenceId") == "stable-1.0.readiness-gate"
    ]
    if not remaining_blocker_issues:
        raise AssertionError(
            "Stable readiness remaining blockers were not reported as a required blocker: "
            f"{remaining_blockers_dashboard}"
        )

    blocker_record_inputs = json.loads(json.dumps(inputs))
    blocker_record_inputs["stableReadinessSummary"]["blockers"] = [
        {"id": "stable-self-test-blocker", "evidenceId": "stable-1.0.readiness-gate"}
    ]
    blocker_record_inputs["stableReadinessSummary"]["disallowedLimitations"] = [
        {"id": "stable-self-test-disallowed"}
    ]
    blocker_record_dashboard = build_dashboard(
        blocker_record_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-blocker-records",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if blocker_record_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with blocker records but zero counts did not block: "
            f"{blocker_record_dashboard}"
        )
    blocker_record_issues = [
        blocker
        for blocker in blocker_record_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.remaining-blockers"
        and blocker.get("evidenceId") == "stable-1.0.readiness-gate"
    ]
    if not blocker_record_issues:
        raise AssertionError(
            "Stable readiness blocker records were not reported as a required blocker: "
            f"{blocker_record_dashboard}"
        )

    allowed_record_inputs = json.loads(json.dumps(inputs))
    allowed_record_inputs["stableReadinessSummary"]["allowedLimitations"] = [
        {
            "id": "stable-1.0.self-test-allowed-limitation",
            "title": "Self-test allowed Stable limitation",
            "category": "ui-polish-accessibility-warning",
            "classification": "allowed-for-stable-1.0",
            "status": "open",
            "summary": "Synthetic bounded Stable 1.0 limitation.",
            "evidenceIds": ["stable-1.0.known-limitations"],
            "boundedBy": "Self-test release manager bound for a non-blocking Stable limitation.",
        }
    ]
    allowed_record_dashboard = build_dashboard(
        allowed_record_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-allowed-limitation-record-mismatch",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if allowed_record_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with allowed limitation records but zero count did not block: "
            f"{allowed_record_dashboard}"
        )
    allowed_record_issues = [
        blocker
        for blocker in allowed_record_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.allowed-limitations-invalid"
        and blocker.get("evidenceId") == "stable-1.0.known-limitations"
    ]
    if not allowed_record_issues:
        raise AssertionError(
            "Stable readiness allowed limitation count mismatch was not reported as a required blocker: "
            f"{allowed_record_dashboard}"
        )

    malformed_allowed_inputs = json.loads(json.dumps(inputs))
    malformed_allowed_inputs["stableReadinessSummary"]["allowedLimitationCount"] = 1
    malformed_allowed_inputs["stableReadinessSummary"]["allowedLimitations"] = [1]
    malformed_allowed_inputs["stableReadinessSummary"]["decision"] = "ready-with-allowed-limitations"
    malformed_allowed_dashboard = build_dashboard(
        malformed_allowed_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-malformed-allowed-limitation",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if malformed_allowed_dashboard.get("decision") != "no-go":
        raise AssertionError(
            "required Stable readiness with malformed allowed limitation records did not block: "
            f"{malformed_allowed_dashboard}"
        )
    malformed_allowed_issues = [
        blocker
        for blocker in malformed_allowed_dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("id") == "stable-1.0.readiness-summary.allowed-limitations-invalid"
        and blocker.get("evidenceId") == "stable-1.0.known-limitations"
    ]
    if not malformed_allowed_issues:
        raise AssertionError(
            "Stable readiness malformed allowed limitation record was not reported as a required blocker: "
            f"{malformed_allowed_dashboard}"
        )

    allowed_warning_inputs = json.loads(json.dumps(inputs))
    allowed_warning_inputs["stableReadinessSummary"]["allowedLimitationCount"] = 1
    allowed_warning_inputs["stableReadinessSummary"]["allowedLimitations"] = [
        {
            "id": "stable-1.0.self-test-allowed-limitation",
            "title": "Self-test allowed Stable limitation",
            "category": "ui-polish-accessibility-warning",
            "classification": "allowed-for-stable-1.0",
            "status": "open",
            "summary": "Synthetic bounded Stable 1.0 limitation.",
            "evidenceIds": ["stable-1.0.known-limitations"],
            "boundedBy": "Self-test release manager bound for a non-blocking Stable limitation.",
        }
    ]
    allowed_warning_dashboard = build_dashboard(
        allowed_warning_inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "stable-readiness-allowed-limitation-warning",
        "production-beta",
        release_id,
        generated_at,
        now,
        require_stable_readiness=True,
    )
    if allowed_warning_dashboard.get("decision") != "go":
        raise AssertionError(
            "valid Stable readiness allowed limitations should warn without blocking: "
            f"{allowed_warning_dashboard}"
        )
    allowed_warning_issues = [
        warning
        for warning in allowed_warning_dashboard.get("warnings", [])
        if isinstance(warning, dict)
        and warning.get("id") == "stable-1.0.readiness-summary.allowed-limitations"
        and warning.get("evidenceId") == "stable-1.0.known-limitations"
    ]
    if not allowed_warning_issues:
        raise AssertionError(
            "Stable readiness allowed limitations were not reported as a dashboard warning: "
            f"{allowed_warning_dashboard}"
        )

def assert_validator_security_drill_redaction_findings_are_non_waivable(root: Path) -> None:
    pass_fixture = load_fixture(FIXTURE_DIR / "go-no-go-pass.json")
    inputs = json.loads(json.dumps(pass_fixture["inputs"]))
    security_drills = inputs.get("securityDrillsSummary")
    if not isinstance(security_drills, dict):
        raise AssertionError("go-no-go-pass fixture is missing securityDrillsSummary")
    security_drills["mode"] = "release-candidate"
    security_drills["rawSupportBundleBody"] = "fixture-payload"
    redaction = security_drills.get("redaction")
    if not isinstance(redaction, dict):
        raise AssertionError("go-no-go-pass fixture securityDrillsSummary is missing redaction")
    redaction["status"] = "pass"
    redaction["findings"] = []
    redaction["rawSensitiveMaterialExcluded"] = True
    waiver_value = {
        "schemaVersion": 1,
        "waivers": [
            {
                "id": "waive-validator-security-drill-redaction",
                "evidenceId": "production-security.response-runbook",
                "severity": "blocker",
                "scope": "release-candidate",
                "rationale": "Regression fixture: validator redaction findings are non-waivable.",
                "approvedBy": "release-manager",
                "owner": "release",
                "createdAt": "1970-01-01T00:00:00Z",
                "expiresAt": "2099-01-01T00:00:00Z",
                "references": ["validator-security-drill-redaction"],
            }
        ],
    }
    generated_at, now = parse_generated_at(DEFAULT_GENERATED_AT)
    dashboard = build_dashboard(
        inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        waiver_value,
        Path(__file__).resolve().parents[2],
        root / "validator-security-drill-redaction",
        "release-candidate",
        "crypta-production-beta-270",
        generated_at,
        now,
    )
    if dashboard.get("decision") != "no-go":
        raise AssertionError(
            "validator-detected security drill redaction was waived: "
            f"{dashboard}"
        )
    if int(dashboard.get("summary", {}).get("waiversUsed", 0)) != 0:
        raise AssertionError("validator-detected security drill redaction waiver was incorrectly used")
    critical_redaction_blockers = [
        blocker
        for blocker in dashboard.get("blockers", [])
        if isinstance(blocker, dict)
        and blocker.get("evidenceId") == "production-security.response-runbook"
        and blocker.get("category") == "redaction"
        and blocker.get("severity") == "critical"
        and blocker.get("waivable") is False
    ]
    if not critical_redaction_blockers:
        raise AssertionError(
            "validator-detected security drill redaction did not create a critical non-waivable blocker: "
            f"{dashboard}"
        )

def assert_standalone_security_response_summary_is_honored(root: Path) -> None:
    pass_fixture = load_fixture(FIXTURE_DIR / "go-no-go-pass.json")
    inputs = json.loads(json.dumps(pass_fixture["inputs"]))
    inputs.pop("securityDrillsSummary", None)
    inputs["securityResponseSummary"] = {
        "status": "pass",
        "summary": "Standalone production security response summary passed.",
    }
    app_summary = inputs["appPlatformSummary"]
    evidence = app_summary["evidence"]
    app_summary["evidence"] = [
        entry
        for entry in evidence
        if not (isinstance(entry, dict) and entry.get("id") == "production-security.response-runbook")
    ]
    if len(app_summary["evidence"]) == len(evidence):
        raise AssertionError("standalone security response self-test did not remove duplicated app-platform evidence")
    generated_at, now = parse_generated_at(DEFAULT_GENERATED_AT)
    dashboard = build_dashboard(
        inputs,
        {},
        [FIXTURE_DIR / "go-no-go-pass.json"],
        None,
        Path(__file__).resolve().parents[2],
        root / "standalone-security-response",
        "developer-dry-run",
        "crypta-production-beta-270-standalone-security-response",
        generated_at,
        now,
    )
    if dashboard.get("decision") != "go":
        raise AssertionError(f"standalone security-response summary produced {dashboard.get('decision')}: {dashboard}")
    security_domain = next(
        (domain for domain in dashboard.get("domains", []) if domain.get("id") == "production-security-response"),
        {},
    )
    if security_domain.get("status") != "pass":
        raise AssertionError(f"standalone security-response domain did not pass: {security_domain}")

def assert_legacy_security_response_summary_fallback_is_honored(root: Path) -> None:
    pass_fixture = load_fixture(FIXTURE_DIR / "go-no-go-pass.json")
    inputs = json.loads(json.dumps(pass_fixture["inputs"]))
    inputs.pop("securityDrillsSummary", None)
    inputs["securityResponseSummary"] = {
        "status": "pass",
        "summary": "Legacy production security response summary passed.",
    }
    for summary_name in ("appPlatformSummary", "releaseCertificationSummary"):
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
        root / "legacy-security-response-fallback",
        "developer-dry-run",
        "crypta-production-beta-270-legacy-security-response-fallback",
        generated_at,
        now,
    )
    if dashboard.get("decision") != "go":
        raise AssertionError(f"legacy security-response fallback produced {dashboard.get('decision')}: {dashboard}")
    security_domain = next(
        (domain for domain in dashboard.get("domains", []) if domain.get("id") == "production-security-response"),
        {},
    )
    if security_domain.get("status") != "pass":
        raise AssertionError(f"legacy security-response fallback domain did not pass: {security_domain}")

def path_input_args_from_pass_fixture(root: Path, input_dir_name: str) -> tuple[tuple[tuple[str, str], ...], dict[str, Path]]:
    pass_fixture = read_json(FIXTURE_DIR / "go-no-go-pass.json")
    if not isinstance(pass_fixture, dict) or not isinstance(pass_fixture.get("inputs"), dict):
        raise AssertionError("go-no-go-pass.json must contain path-test inputs")
    inputs = pass_fixture["inputs"]
    input_args = (
        ("--production-beta-summary", "productionBetaSummary"),
        ("--release-certification-summary", "releaseCertificationSummary"),
        ("--ecosystem-matrix", "ecosystemMatrix"),
        ("--app-platform-summary", "appPlatformSummary"),
        ("--live-network-summary", "liveNetworkSummary"),
        ("--network-scale-soak-summary", "networkScaleSoakSummary"),
        ("--multi-node-beta-soak-summary", "multiNodeBetaSoakSummary"),
        ("--security-response-summary", "securityResponseSummary"),
    )
    input_dir = root / input_dir_name
    input_paths: dict[str, Path] = {}
    for _flag, input_name in input_args:
        value = inputs.get(input_name)
        if not isinstance(value, dict):
            raise AssertionError(f"go-no-go-pass.json missing {input_name}")
        path = input_dir / f"{input_name}.json"
        write_json(path, value)
        input_paths[input_name] = path
    return input_args, input_paths

def assert_symlink_inputs_are_rejected(root: Path) -> None:
    input_args, input_paths = path_input_args_from_pass_fixture(root, "symlink-inputs")
    link_dir = root / "symlink-links"
    link_dir.mkdir(parents=True)
    summary_link = link_dir / "productionBetaSummary.json"
    summary_link.symlink_to(input_paths["productionBetaSummary"])
    out_dir = root / "symlink-output"
    args_list = [
        "build",
        "--workspace-root",
        str(Path(__file__).resolve().parents[2]),
        "--out-dir",
        str(out_dir),
        "--mode",
        "production-beta",
    ]
    for flag, input_name in input_args:
        value = summary_link if input_name == "productionBetaSummary" else input_paths[input_name]
        args_list.extend([flag, str(value)])
    dashboard, _exit_code = build_command(build_parser().parse_args(args_list))
    if dashboard.get("decision") != "no-go":
        raise AssertionError("symlinked dashboard input did not force no-go")
    redaction = read_json(out_dir / OUTPUT_REDACTION)
    findings = redaction.get("findings") if isinstance(redaction, dict) else []
    if not any(
        isinstance(finding, dict) and finding.get("kind") == "forbidden-symlink" for finding in findings
    ):
        raise AssertionError("symlinked dashboard input did not produce a forbidden-symlink finding")

def assert_protected_secret_values_are_scanned_and_redacted(root: Path) -> None:
    secret_name = "CRYPTAD_DASHBOARD_TEST_TOKEN"
    secret_value = "dashboard-protected-secret-12345"
    short_secret_name = "CRYPTAD_DASHBOARD_TEST_SHORT_TOKEN"
    long_secret_name = "CRYPTAD_DASHBOARD_TEST_LONG_TOKEN"
    file_secret_name = "CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE"
    short_secret_value = "dashboard-overlap-secret"
    long_secret_suffix = "TAILLEAK12345"
    long_secret_value = f"{short_secret_value}-{long_secret_suffix}"
    generic_token = "generic-dashboard-token-12345"
    generic_password = "generic-dashboard-password-12345"
    generic_private_key_base64 = "Z2VuZXJpYy1kYXNoYm9hcmQtcHJpdmF0ZS1rZXktMTIzNDU="
    previous = os.environ.get(secret_name)
    previous_short = os.environ.get(short_secret_name)
    previous_long = os.environ.get(long_secret_name)
    previous_file = os.environ.get(file_secret_name)
    os.environ[secret_name] = secret_value
    os.environ[short_secret_name] = short_secret_value
    os.environ[long_secret_name] = long_secret_value
    try:
        input_args, input_paths = path_input_args_from_pass_fixture(root, "protected-secret-inputs")
        protected_dir = root / "protected"
        protected_dir.mkdir(parents=True)
        file_secret_bytes = b"\x01cryptad-dashboard-file-backed-private-key\x02\xff"
        file_secret_path = protected_dir / "app-signing-private.der"
        file_secret_path.write_bytes(file_secret_bytes)
        file_secret_base64 = base64.b64encode(file_secret_bytes).decode("ascii")
        os.environ[file_secret_name] = str(file_secret_path.relative_to(root))
        production_summary = read_json(input_paths["productionBetaSummary"])
        if not isinstance(production_summary, dict):
            raise AssertionError("productionBetaSummary path input is missing")
        production_summary["status"] = "fail"
        production_summary["promotionReady"] = False
        production_summary["failures"] = [
            f"dashboard input leaked {secret_value} without an environment variable name",
            f"dashboard input leaked overlapping protected value {long_secret_value}",
            f"dashboard input leaked file-backed signing material {file_secret_base64}",
        ]
        production_summary["token"] = generic_token
        production_summary["password"] = generic_password
        production_summary["privateKeyBase64"] = generic_private_key_base64
        write_json(input_paths["productionBetaSummary"], production_summary)
        out_dir = root / "protected-secret-output"
        args_list = [
            "build",
            "--workspace-root",
            str(root),
            "--out-dir",
            str(out_dir),
            "--mode",
            "production-beta",
            "--generated-at",
            DEFAULT_GENERATED_AT,
        ]
        for flag, input_name in input_args:
            args_list.extend([flag, str(input_paths[input_name])])
        dashboard, _exit_code = build_command(build_parser().parse_args(args_list))
        finding_kinds = {
            str(finding.get("kind"))
            for finding in dashboard.get("redaction", {}).get("findings", [])
            if isinstance(finding, dict)
        }
        if dashboard["decision"] != "no-go" or "protected-secret-value" not in finding_kinds:
            raise AssertionError(f"protected secret value did not block dashboard: {dashboard}")
        if "sensitive-field-value" not in finding_kinds:
            raise AssertionError(f"generic sensitive fields did not block dashboard: {dashboard}")
        generated_text = (out_dir / OUTPUT_JSON).read_text(encoding="utf-8") + (
            out_dir / OUTPUT_MARKDOWN
        ).read_text(encoding="utf-8")
        if secret_value in generated_text:
            raise AssertionError("dashboard artifacts leaked a protected secret value")
        for forbidden in (
            short_secret_value,
            long_secret_value,
            long_secret_suffix,
            file_secret_base64,
            generic_token,
            generic_password,
            generic_private_key_base64,
        ):
            if forbidden in generated_text:
                raise AssertionError(f"dashboard artifacts leaked overlapping protected secret content: {forbidden}")
    finally:
        if previous is None:
            os.environ.pop(secret_name, None)
        else:
            os.environ[secret_name] = previous
        if previous_short is None:
            os.environ.pop(short_secret_name, None)
        else:
            os.environ[short_secret_name] = previous_short
        if previous_long is None:
            os.environ.pop(long_secret_name, None)
        else:
            os.environ[long_secret_name] = previous_long
        if previous_file is None:
            os.environ.pop(file_secret_name, None)
        else:
            os.environ[file_secret_name] = previous_file

def assert_supplied_waiver_file_errors_block_launch(root: Path) -> None:
    input_args, input_paths = path_input_args_from_pass_fixture(root, "path-inputs")
    valid_waiver = {
        "id": "waiver-malformed-references",
        "evidenceId": "app-store.submission-cli",
        "severity": "blocker",
        "scope": "production-beta-only",
        "rationale": "Self-test malformed references record.",
        "approvedBy": "release-manager@example.invalid",
        "owner": "release-engineering",
        "createdAt": "2026-06-24T00:00:00Z",
        "expiresAt": "2099-06-30T00:00:00Z",
    }

    def waiver_with_references(references: Any) -> str:
        waiver = dict(valid_waiver)
        waiver["references"] = references
        return json.dumps({"schemaVersion": 1, "waivers": [waiver]}, sort_keys=True)

    waiver_cases = {
        "missing": None,
        "malformed": "{",
        "non-object": "[]",
        "references-null": waiver_with_references(None),
        "references-number": waiver_with_references(123),
    }
    for case_name, content in waiver_cases.items():
        waiver_path = root / f"{case_name}-waivers.json"
        if content is not None:
            write_text(waiver_path, content)
        args_list = [
            "build",
            "--workspace-root",
            str(root),
            "--out-dir",
            str(root / f"{case_name}-waiver-output"),
            "--mode",
            "production-beta",
            "--generated-at",
            DEFAULT_GENERATED_AT,
            "--waivers",
            str(waiver_path),
        ]
        for flag, input_name in input_args:
            args_list.extend([flag, str(input_paths[input_name])])
        dashboard, _exit_code = build_command(build_parser().parse_args(args_list))
        if dashboard["decision"] != "no-go":
            raise AssertionError(f"{case_name} waiver file expected no-go, got {dashboard['decision']}")
        blocker_ids = {
            str(blocker.get("evidenceId"))
            for blocker in dashboard.get("blockers", [])
            if isinstance(blocker, dict)
        }
        if "production-beta.waiver-validation" not in blocker_ids:
            raise AssertionError(f"{case_name} waiver file did not produce a waiver-validation blocker: {dashboard}")

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run offline dashboard fixture tests.")
    subparsers = parser.add_subparsers(dest="command")
    build = subparsers.add_parser("build", help="Build dashboard artifacts.")
    build.add_argument("--workspace-root", type=Path, default=Path.cwd())
    build.add_argument("--out-dir", type=Path, required=True)
    build.add_argument("--mode", choices=MODES, default=None)
    build.add_argument("--release-id", default="")
    build.add_argument("--generated-at", default="")
    build.add_argument("--production-beta-summary", type=Path)
    build.add_argument("--release-certification-summary", type=Path)
    build.add_argument("--ecosystem-matrix", type=Path)
    build.add_argument("--app-platform-summary", type=Path)
    build.add_argument("--live-network-summary", type=Path)
    build.add_argument("--network-scale-soak-summary", type=Path)
    build.add_argument("--multi-node-beta-soak-summary", type=Path)
    build.add_argument("--security-drills-summary", type=Path)
    build.add_argument("--security-response-summary", type=Path)
    build.add_argument("--stable-readiness-summary", "--stable-1-0-readiness-summary", type=Path)
    build.add_argument("--require-stable-readiness", action="store_true")
    build.add_argument("--waivers", type=Path)
    build.add_argument("--fixtures", type=Path, help="Build from a checked-in dashboard fixture bundle.")
    return parser

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        run_self_test()
        return 0
    if args.command == "build":
        dashboard, exit_code = build_command(args)
        print(f"Production beta go/no-go dashboard {dashboard['decision']}: {args.out_dir / OUTPUT_JSON}")
        return exit_code
    parser.print_help()
    return 2
