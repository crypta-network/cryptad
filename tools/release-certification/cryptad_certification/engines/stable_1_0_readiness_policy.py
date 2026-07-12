"""Implementation segment for the policy portion of ``stable_1_0_readiness.py``."""

from __future__ import annotations

def evaluate_policy(
    policy: dict[str, Any] | None,
    policy_path: Path,
    workspace_root: Path,
) -> dict[str, Any]:
    domain_id = "readiness-policy"
    blockers: list[dict[str, Any]] = []
    source = display_path(policy_path, workspace_root)
    if not isinstance(policy, dict):
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.readiness-gate",
                "Stable 1.0 readiness policy is missing or unreadable",
                "Stable 1.0 readiness requires a readable policy JSON file.",
                source,
            )
        )
    else:
        if not schema_version_is_current(policy.get("schemaVersion")) or policy.get("kind") != "stable-1.0-readiness-policy":
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.readiness-gate",
                    "Stable 1.0 readiness policy schema is invalid",
                    "Stable 1.0 readiness requires schemaVersion=1 and kind=stable-1.0-readiness-policy.",
                    source,
                )
            )
        _, required_mode_errors = string_array_values(
            policy.get("requiredReleaseModes"),
            "requiredReleaseModes",
            ("production-beta",),
        )
        for mode_error in required_mode_errors:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.production-beta-state",
                    "Stable release mode policy is invalid",
                    mode_error + ".",
                    source,
                )
            )
        platform_api_policy_value = policy.get("platformApi10Criteria")
        platform_api_policy = (
            platform_api_policy_value if isinstance(platform_api_policy_value, dict) else {}
        )
        if not isinstance(platform_api_policy_value, dict):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.platform-api-compatibility",
                    "Stable Platform API policy is invalid",
                    "platformApi10Criteria must be present as an object.",
                    source,
                )
            )
        elif not non_empty_string(platform_api_policy.get("stableBaselineName")):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.platform-api-compatibility",
                    "Stable Platform API baseline policy is invalid",
                    "platformApi10Criteria.stableBaselineName must be a non-empty string.",
                    source,
                )
            )
        required_soak = policy.get("requiredSoak") if isinstance(policy.get("requiredSoak"), dict) else {}
        security = (
            policy.get("securityDrillCriteria")
            if isinstance(policy.get("securityDrillCriteria"), dict)
            else {}
        )
        for key, default in (
            ("acceptedMultiNodeModes", ("hybrid", "live")),
            ("acceptedNetworkScaleModes", ("simulated-rc-soak", "live-rc-soak")),
        ):
            _, mode_errors = string_array_values(
                required_soak.get(key),
                f"requiredSoak.{key}",
                default,
            )
            for mode_error in mode_errors:
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.live-multi-node-soak",
                        "Stable soak accepted mode policy is invalid",
                        mode_error + ".",
                        source,
                    )
                )
        if positive_int(required_soak.get("minimumOperationCount")) is None:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.live-multi-node-soak",
                    "Stable soak operation-count policy is missing",
                    "requiredSoak.minimumOperationCount must be a positive integer.",
                    source,
                )
            )
        if positive_int(required_soak.get("maximumEvidenceAgeDays")) is None:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.live-multi-node-soak",
                    "Stable soak evidence age policy is missing",
                    "requiredSoak.maximumEvidenceAgeDays must be a positive integer.",
                    source,
                )
            )
        if positive_int(security.get("maximumEvidenceAgeDays")) is None:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.security-drills",
                    "Stable security drill evidence age policy is missing",
                    "securityDrillCriteria.maximumEvidenceAgeDays must be a positive integer.",
                    source,
                )
            )
        scenario_value = security.get("requiredScenarios")
        if "requiredScenarios" not in security or scenario_value is None:
            scenario_errors = ["securityDrillCriteria.requiredScenarios must be present as an array"]
        else:
            _, scenario_errors = string_array_values(
                scenario_value,
                "securityDrillCriteria.requiredScenarios",
                (),
            )
        for scenario_error in scenario_errors:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.security-drills",
                    "Stable security drill scenario policy is invalid",
                    scenario_error + ".",
                    source,
                )
            )
        for key in ("allowedLimitationCategories", "disallowedLimitationCategories", "nonWaivableBlockers"):
            if key not in policy:
                policy_list_errors = [f"{key} must be present as an array"]
            else:
                _, policy_list_errors = string_array_values(policy.get(key), key, ())
            for policy_list_error in policy_list_errors:
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.known-limitations",
                        "Stable readiness policy category list is invalid",
                        policy_list_error + ".",
                        source,
                    )
                )
    return domain_result(
        domain_id,
        "Stable 1.0 readiness policy",
        ("stable-1.0.readiness-gate",),
        blockers,
        [],
    )

def evaluate_platform_api(evidence: dict[str, dict[str, Any]], policy: dict[str, Any]) -> dict[str, Any]:
    domain_id = "platform-api-1.0"
    blockers = add_required_evidence_blockers(
        evidence,
        domain_id,
        PLATFORM_API_EVIDENCE_IDS,
        "release-certification",
    )
    baseline_entry = evidence.get("platform-api.stable-baseline")
    baseline_details = evidence_details(baseline_entry)
    baseline = baseline_details.get("stableBaseline") if isinstance(baseline_details.get("stableBaseline"), dict) else {}
    platform_api_policy = (
        policy.get("platformApi10Criteria")
        if isinstance(policy.get("platformApi10Criteria"), dict)
        else {}
    )
    required_name = non_empty_string(platform_api_policy.get("stableBaselineName")) or "1.0"
    if entry_ok(baseline_entry) and baseline.get("name") != required_name:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.platform-api-compatibility",
                "Platform API stable baseline identity is not 1.0",
                f"Stable baseline name is {baseline.get('name', 'missing')}; required {required_name}.",
                "platform-api.stable-baseline",
            )
        )
    capability_count = positive_int(baseline.get("capabilityCount"))
    if entry_ok(baseline_entry) and capability_count is None:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.platform-api-compatibility",
                "Platform API stable baseline has no capabilities",
                (
                    "Stable 1.0 requires a non-empty Platform API 1.0 baseline; "
                    f"capabilityCount is {baseline.get('capabilityCount', 'missing')}."
                ),
                "platform-api.stable-baseline",
            )
        )
    breaking = evidence.get("platform-api.stable-breaking-change-check")
    breaking_details = evidence_details(breaking)
    breaking_errors = breaking_details.get("errors")
    if isinstance(breaking_errors, list) and breaking_errors:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.stable-api-breaking-change",
                "Stable API breaking-change check reported errors",
                f"Stable API breaking-change errors: {len(breaking_errors)}.",
                "platform-api.stable-breaking-change-check",
            )
        )
    compatibility_entry = evidence.get("platform-api.compatibility-window")
    compatibility = evidence_details(compatibility_entry).get("compatibilityWindow")
    if entry_ok(compatibility_entry) and not isinstance(compatibility, dict):
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.platform-api-compatibility",
                "Platform API compatibility-window details are missing",
                "Stable 1.0 requires platform-api.compatibility-window details.compatibilityWindow metadata.",
                "platform-api.compatibility-window",
            )
        )
    if isinstance(compatibility, dict):
        if compatibility.get("previousSnapshotRequiredInProductionBeta") is not True:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.platform-api-compatibility",
                    "Platform API previous-snapshot policy is not enforced",
                    "Stable 1.0 requires previous contract snapshot enforcement.",
                    "platform-api.compatibility-window",
                )
            )
        if compatibility.get("criticalStableRemovalWaiverAllowed") is not False:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.stable-api-breaking-change",
                    "Critical stable removals appear waiverable",
                    "Stable 1.0 does not accept critical stable removal waivers.",
                    "platform-api.compatibility-window",
                )
            )
    deprecation = evidence_details(evidence.get("platform-api.deprecation-window-policy"))
    if deprecation.get("criticalStableRemovalWaiverAllowed") is not False:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.stable-api-breaking-change",
                "Stable deprecation policy allows critical removal waivers",
                "Stable 1.0 requires non-waivable critical stable removal blockers.",
                "platform-api.deprecation-window-policy",
            )
        )
    return domain_result(
        domain_id,
        "Platform API 1.0 compatibility",
        PLATFORM_API_EVIDENCE_IDS,
        blockers,
        [],
    )

def evaluate_app_ecosystem(
    evidence: dict[str, dict[str, Any]],
    app_platform_summary: dict[str, Any] | None,
) -> dict[str, Any]:
    domain_id = "app-ecosystem-maturity"
    blockers = [
        *app_platform_summary_envelope_blockers(app_platform_summary, domain_id),
        *add_required_evidence_blockers(
            evidence,
            domain_id,
            APP_ECOSYSTEM_EVIDENCE_IDS,
            "release-certification",
        ),
    ]
    for evidence_id in (
        "app-platform.first-party",
        "app-catalog.first-party-maintenance-policy",
        "first-party-app.beta-quality-pass",
        "app-review.first-party-catalog",
    ):
        apps = apps_from_entry(evidence.get(evidence_id))
        missing = sorted(set(APP_IDS) - apps)
        if entry_ok(evidence.get(evidence_id)) and missing:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.first-party-stable-app-readiness",
                    "First-party stable app coverage is incomplete",
                    f"{evidence_id} is missing apps: {', '.join(missing)}.",
                    evidence_id,
                )
            )
    maintenance = evidence_details(evidence.get("app-catalog.first-party-maintenance-policy"))
    maintenance_apps = maintenance.get("apps") if isinstance(maintenance.get("apps"), dict) else {}
    for app_id in APP_IDS:
        app_policy = maintenance_apps.get(app_id) if isinstance(maintenance_apps.get(app_id), dict) else {}
        maint = app_policy.get("maintenance") if isinstance(app_policy.get("maintenance"), dict) else {}
        backup = str(maint.get("backupRestore", "missing"))
        migration = str(maint.get("migrationPolicy", "missing"))
        if backup in {"unsupported", "missing", ""}:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.first-party-stable-app-readiness",
                    "Stable first-party app lacks backup/restore policy",
                    f"{app_id} backupRestore is {backup}.",
                    "app-catalog.first-party-maintenance-policy",
                )
            )
        if migration in {"missing", ""}:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.first-party-stable-app-readiness",
                    "Stable first-party app lacks migration policy",
                    f"{app_id} migrationPolicy is {migration}.",
                    "app-catalog.first-party-maintenance-policy",
                )
            )
    diagnostics = evidence.get("app-platform.privacy-preserving-beta-diagnostics")
    if recursive_redaction_failure(evidence_details(diagnostics)):
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.redaction",
                "First-party diagnostics evidence has redaction failures",
                "Stable 1.0 cannot ship with privacy/security diagnostics redaction failures.",
                "app-platform.privacy-preserving-beta-diagnostics",
            )
        )
    return domain_result(domain_id, "App ecosystem maturity", APP_ECOSYSTEM_EVIDENCE_IDS, blockers, [])

def evaluate_third_party(evidence: dict[str, dict[str, Any]]) -> dict[str, Any]:
    domain_id = "third-party-intake"
    blockers = add_required_evidence_blockers(
        evidence,
        domain_id,
        THIRD_PARTY_EVIDENCE_IDS,
        "release-certification",
    )
    sample = evidence_details(evidence.get("third-party-developer.sample-app-flow"))
    sample_flow = sample.get("sampleFlow")
    normalized_sample_flow = (
        [str(step).strip().lower().replace("-", " ") for step in sample_flow]
        if isinstance(sample_flow, list)
        else []
    )
    missing_sample_milestones = [
        milestone
        for milestone in THIRD_PARTY_SAMPLE_FLOW_MILESTONES
        if not any(milestone in step for step in normalized_sample_flow)
    ]
    if entry_ok(evidence.get("third-party-developer.sample-app-flow")) and (
        not isinstance(sample_flow, list)
        or not sample_flow
        or missing_sample_milestones
    ):
        missing_detail = (
            " Missing milestones: " + ", ".join(missing_sample_milestones) + "."
            if missing_sample_milestones
            else ""
        )
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.third-party-intake",
                "Third-party sample app flow is not represented",
                (
                    "Stable 1.0 requires a sample submission through pre-review, review, "
                    "catalog candidate, and the separately required install smoke."
                    + missing_detail
                ),
                "third-party-developer.sample-app-flow",
            )
        )
    return domain_result(domain_id, "Third-party app criteria", THIRD_PARTY_EVIDENCE_IDS, blockers, [])

def evaluate_security(
    evidence: dict[str, dict[str, Any]],
    security_summary: dict[str, Any] | None,
    policy: dict[str, Any],
    now: dt.datetime,
    candidate_release_id: str,
) -> dict[str, Any]:
    domain_id = "security-drills"
    blockers = add_required_evidence_blockers(
        evidence,
        domain_id,
        SECURITY_RESPONSE_EVIDENCE_IDS,
        "release-certification",
    )
    security_criteria = (
        policy.get("securityDrillCriteria")
        if isinstance(policy.get("securityDrillCriteria"), dict)
        else {}
    )
    required = {
        str(item).strip()
        for item in security_criteria.get("requiredScenarios", [])
        if isinstance(item, str) and item.strip()
    }
    max_age_days = positive_int(security_criteria.get("maximumEvidenceAgeDays"))
    if not required:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.security-drills",
                "Security drill scenario policy is missing",
                "securityDrillCriteria.requiredScenarios must name every required Stable 1.0 drill scenario.",
                "stable-readiness-policy",
            )
        )
    if max_age_days is None:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.security-drills",
                "Security drill freshness policy is missing",
                "securityDrillCriteria.maximumEvidenceAgeDays must be a positive integer.",
                "stable-readiness-policy",
            )
        )
    if not isinstance(security_summary, dict):
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.security-drills",
                "Security drill summary is missing",
                "Stable 1.0 requires the redacted production security drill summary.",
                "security-drills-summary",
            )
        )
    else:
        if security_summary.get("kind") != "cryptad-security-response-drills-summary":
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.security-drills",
                    "Security drill summary has the wrong kind",
                    "Stable 1.0 requires kind=cryptad-security-response-drills-summary.",
                    "security-drills-summary",
                )
            )
        if not schema_version_is_current(security_summary.get("schemaVersion")):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.security-drills",
                    "Security drill summary schema version is unsupported",
                    "Stable 1.0 requires securityDrillsSummary.schemaVersion=1.",
                    "security-drills-summary",
                )
            )
        blockers.extend(security_summary_structure_blockers(security_summary, required, domain_id))
        if not status_ok(security_summary.get("status")) or security_summary.get("promotionReady") is not True:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.security-drills",
                    "Security drill summary is not promotion-ready",
                    "All required Stable 1.0 security drill scenarios must pass.",
                    "security-drills-summary",
                )
            )
        security_release_id = str(security_summary.get("releaseId", "")).strip()
        if candidate_release_id and security_release_id != candidate_release_id:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.security-drills",
                    "Security drill summary is not bound to this release",
                    (
                        "Stable 1.0 requires the security drill releaseId to match the "
                        f"production beta releaseId; security={security_release_id or 'missing'}, "
                        f"production={candidate_release_id}."
                    ),
                    "security-drills-summary",
                )
            )
        if max_age_days is not None:
            freshness = evidence_age_blocker(
                domain_id=domain_id,
                evidence_id="stable-1.0.security-drills",
                title="Security drill summary",
                source="security-drills-summary",
                generated_at=security_summary.get("generatedAt"),
                now=now,
                maximum_age_days=max_age_days,
                label="security drill summary",
            )
            if freshness is not None:
                blockers.append(freshness)
            blockers.extend(
                security_artifact_blockers(
                    security_summary.get("artifacts"),
                    required,
                    domain_id,
                    now,
                    max_age_days,
                )
            )
        scenario_sets: dict[str, set[str]] = {}
        for field in (
            "passedScenarios",
            "failedScenarios",
            "missingScenarios",
            "staleScenarios",
            "malformedScenarios",
        ):
            scenario_sets[field], scenario_blocker = security_scenario_set(
                security_summary,
                field,
                domain_id,
            )
            if scenario_blocker is not None:
                blockers.append(scenario_blocker)
        passed = scenario_sets["passedScenarios"]
        failed = scenario_sets["failedScenarios"]
        missing = scenario_sets["missingScenarios"]
        stale = scenario_sets["staleScenarios"]
        malformed = scenario_sets["malformedScenarios"]
        not_passing = sorted((required - passed) | failed | missing | stale | malformed)
        if not_passing:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.security-drills",
                    "Required security drill scenarios are not passing",
                    "Scenario blockers: " + ", ".join(not_passing),
                    "security-drills-summary",
                )
            )
        redaction = security_summary.get("redaction") if isinstance(security_summary.get("redaction"), dict) else {}
        if (
            normalize_status(redaction.get("status", "missing")) != "pass"
            or redaction.get("findings")
            or recursive_redaction_field_failure(security_summary)
        ):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.redaction",
                    "Security drill redaction did not pass",
                    "Stable 1.0 security drill artifacts must be redaction-safe.",
                    "security-drills-summary",
                )
            )
        release_notes = security_summary.get("releaseNotes") if isinstance(security_summary.get("releaseNotes"), dict) else {}
        advisory = security_summary.get("advisoryTemplate") if isinstance(security_summary.get("advisoryTemplate"), dict) else {}
        if normalize_status(release_notes.get("templateStatus", "missing")) != "pass":
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.security-drills",
                    "Security release notes template is missing",
                    "Stable 1.0 requires a security release notes template or draft.",
                    "security-drills-summary",
                )
            )
        if normalize_status(advisory.get("templateStatus", "missing")) != "pass":
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.security-drills",
                    "Security advisory template is missing",
                    "Stable 1.0 requires advisory and denylist response template evidence.",
                    "security-drills-summary",
                )
            )
        non_release_marker_errors = [
            f"{field} must be false"
            for field in ("fixtureOnly", "nonRelease")
            if field in security_summary and security_summary.get(field) is not False
        ]
        if non_release_marker_errors:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.security-drills",
                    "Security drill summary is marked non-release",
                    (
                        "Stable 1.0 cannot depend on fixture-only or non-release security drill "
                        "evidence; "
                        + "; ".join(non_release_marker_errors)
                        + "."
                    ),
                    "security-drills-summary",
                )
            )
    return domain_result(domain_id, "Security drill criteria", SECURITY_RESPONSE_EVIDENCE_IDS, blockers, [])

def network_operation_count(network_summary: dict[str, Any] | None) -> int:
    if not isinstance(network_summary, dict):
        return 0
    count = 0
    apps = network_summary.get("apps") if isinstance(network_summary.get("apps"), dict) else {}
    for app_id in NETWORK_SCALE_REQUIRED_APPS:
        app_summary = apps.get(app_id)
        if isinstance(app_summary, dict):
            for key in ("pollAttempts", "updatesObserved", "subscriptions"):
                value = strict_non_negative_int(app_summary.get(key))
                if value is not None:
                    count += value
    trust = network_summary.get("trustGraph") if isinstance(network_summary.get("trustGraph"), dict) else {}
    value = strict_non_negative_int(trust.get("importsAttempted"))
    if value is not None:
        count += value
    return count

def network_scale_structure_blockers(
    network: dict[str, Any],
    domain_id: str,
) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    duration_hours = strict_positive_int(network.get("durationHoursSimulated"))
    if duration_hours is None or duration_hours < 24:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.live-multi-node-soak",
                "Network-scale soak duration evidence is missing or insufficient",
                "Stable 1.0 requires durationHoursSimulated to cover at least 24 hours.",
                "network-scale-soak-summary",
            )
        )
    apps = network.get("apps")
    app_errors: list[str] = []
    if not isinstance(apps, dict):
        app_errors.append("apps")
        apps = {}
    for app_id in NETWORK_SCALE_REQUIRED_APPS:
        app = apps.get(app_id) if isinstance(apps, dict) else None
        if not isinstance(app, dict):
            app_errors.append(app_id)
            continue
        if app.get("rawContentPersisted") is not False:
            app_errors.append(f"{app_id}.rawContentPersisted")
    if app_errors:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.live-multi-node-soak",
                "Network-scale app soak sections are missing or unsafe",
                "Stable 1.0 requires social-inbox and feed-reader soak sections with rawContentPersisted=false: "
                + ", ".join(app_errors)
                + ".",
                "network-scale-soak-summary",
            )
        )
    trust_graph = network.get("trustGraph")
    if not isinstance(trust_graph, dict) or trust_graph.get("rawStatementsInEvidence") is not False:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.live-multi-node-soak",
                "Network-scale Trust Graph evidence is missing or unsafe",
                "Stable 1.0 requires trustGraph.rawStatementsInEvidence=false.",
                "network-scale-soak-summary",
            )
        )
    budgets = network.get("budgets")
    missing_budget_fields = missing_true_fields(budgets, NETWORK_SCALE_BUDGET_PROOF_FIELDS)
    if missing_budget_fields:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.live-multi-node-soak",
                "Network-scale budget enforcement proof is missing",
                "Stable 1.0 requires network-scale budget enforcement fields to be true: "
                + ", ".join(missing_budget_fields)
                + ".",
                "network-scale-soak-summary",
            )
        )
    return blockers

def evaluate_live_multi_node_soak(
    evidence: dict[str, dict[str, Any]],
    multi_node: dict[str, Any] | None,
    network: dict[str, Any] | None,
    policy: dict[str, Any],
    now: dt.datetime,
    candidate_release_id: str,
) -> dict[str, Any]:
    domain_id = "live-multi-node-soak"
    blockers = add_required_evidence_blockers(
        evidence,
        domain_id,
        (*LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS, *NETWORK_SCALE_EVIDENCE_IDS),
        "release-certification",
    )
    required_soak = policy.get("requiredSoak") if isinstance(policy.get("requiredSoak"), dict) else {}
    accepted_multi, accepted_multi_errors = string_array_values(
        required_soak.get("acceptedMultiNodeModes"),
        "requiredSoak.acceptedMultiNodeModes",
        ("hybrid", "live"),
    )
    accepted_network, accepted_network_errors = string_array_values(
        required_soak.get("acceptedNetworkScaleModes"),
        "requiredSoak.acceptedNetworkScaleModes",
        ("simulated-rc-soak", "live-rc-soak"),
    )
    for mode_error in [*accepted_multi_errors, *accepted_network_errors]:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.live-multi-node-soak",
                "Stable soak accepted mode policy is invalid",
                mode_error + ".",
                "stable-readiness-policy",
            )
        )
    min_ops = positive_int(required_soak.get("minimumOperationCount")) or 500
    max_age_days = positive_int(required_soak.get("maximumEvidenceAgeDays"))
    if max_age_days is None:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.live-multi-node-soak",
                "Stable soak freshness policy is missing",
                "requiredSoak.maximumEvidenceAgeDays must be a positive integer.",
                "stable-readiness-policy",
            )
        )
    if not isinstance(multi_node, dict):
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.live-multi-node-soak",
                "Multi-node beta soak summary is missing",
                "Stable 1.0 requires previous-candidate upgrade and multi-node soak evidence.",
                "multi-node-beta-soak-summary",
            )
        )
    else:
        if candidate_release_id:
            release_identities = multi_node_candidate_release_ids(multi_node)
            mismatched_release_ids = [
                (source, release_id)
                for source, release_id in release_identities
                if release_id != candidate_release_id
            ]
            if not release_identities or mismatched_release_ids:
                if mismatched_release_ids:
                    release_id_source, multi_node_release_id = mismatched_release_ids[0]
                else:
                    release_id_source, multi_node_release_id = "missing", "missing"
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.live-multi-node-soak",
                        "Multi-node soak summary is not bound to this release",
                        "Stable 1.0 requires multi-node soak evidence to match the production beta "
                        f"releaseId; multi-node {release_id_source}={multi_node_release_id or 'missing'}, "
                        f"production={candidate_release_id}.",
                        "multi-node-beta-soak-summary",
                    )
                )
        validation_errors = multi_node_beta_soak.validate_summary(multi_node, strict=True)
        if validation_errors:
            validation_summary = "; ".join(validation_errors[:5])
            if len(validation_errors) > 5:
                validation_summary += f"; +{len(validation_errors) - 5} more"
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.live-multi-node-soak",
                    "Multi-node beta soak summary schema is invalid",
                    (
                        "Stable 1.0 requires a complete multi-node beta soak summary from the "
                        f"producer schema; validation errors: {validation_summary}."
                    ),
                    "multi-node-beta-soak-summary",
                )
            )
        mode = str(multi_node.get("mode", "missing"))
        if mode not in accepted_multi:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.live-multi-node-soak",
                    "Multi-node evidence mode is not Stable-compatible",
                    f"Multi-node mode is {mode}; accepted modes are {', '.join(sorted(accepted_multi))}.",
                    "multi-node-beta-soak-summary",
                )
            )
        if not status_ok(multi_node.get("status")) or multi_node.get("promotionReady") is not True:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.live-multi-node-soak",
                    "Multi-node beta soak summary is not promotion-ready",
                    "Stable 1.0 requires passing multi-node beta soak and upgrade evidence.",
                    "multi-node-beta-soak-summary",
                )
            )
        if max_age_days is not None:
            freshness = evidence_age_blocker(
                domain_id=domain_id,
                evidence_id="stable-1.0.live-multi-node-soak",
                title="Multi-node soak summary",
                source="multi-node-beta-soak-summary",
                generated_at=multi_node.get("generatedAt"),
                now=now,
                maximum_age_days=max_age_days,
                label="multi-node soak summary",
            )
            if freshness is not None:
                blockers.append(freshness)
        redaction = multi_node.get("redaction") if isinstance(multi_node.get("redaction"), dict) else {}
        if (
            normalize_status(redaction.get("status", "missing")) != "pass"
            or redaction.get("findings")
            or recursive_redaction_field_failure(multi_node)
        ):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.redaction",
                    "Multi-node soak redaction did not pass",
                    "Stable 1.0 soak artifacts must not leak raw content, app data, private URIs, tokens, or paths.",
                    "multi-node-beta-soak-summary",
                )
            )
        scenario_statuses = (
            multi_node.get("scenarioStatuses")
            if isinstance(multi_node.get("scenarioStatuses"), dict)
            else {}
        )
        scenario_to_evidence = dict(multi_node_beta_soak.SCENARIO_EVIDENCE_IDS)
        for scenario_id, evidence_id in scenario_to_evidence.items():
            if normalize_status(scenario_statuses.get(scenario_id, "missing")) != "pass":
                blockers.append(
                    blocker_issue(
                        domain_id,
                        evidence_id,
                        "Multi-node Stable 1.0 scenario is not passing",
                        f"{scenario_id} status is {scenario_statuses.get(scenario_id, 'missing')}.",
                        "multi-node-beta-soak-summary",
                    )
                )
        upgrade = multi_node.get("previousCandidateUpgrade")
        if not isinstance(upgrade, dict):
            upgrade = multi_node_beta_soak.compact_previous_candidate_upgrade(multi_node)
        if not isinstance(upgrade, dict) or normalize_status(upgrade.get("status", "missing")) != "pass":
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.previous-candidate-upgrade",
                    "Previous-candidate upgrade evidence is missing or failing",
                    "Stable 1.0 requires a passing previous-candidate upgrade drill with backup/restore and app-data migration.",
                    "multi-node-beta-soak-summary",
                )
            )
        else:
            for key in (
                "firstPartyAppMigrationStatus",
                "backupBeforeUpdateStatus",
                "restoreIntoCleanNodeStatus",
                "rollbackStatus",
                "socialInboxMigrationStatus",
                "trustGraphMigrationStatus",
                "supportBundleRedactionStatus",
            ):
                if normalize_status(upgrade.get(key, "missing")) != "pass":
                    blockers.append(
                        blocker_issue(
                            domain_id,
                            "stable-1.0.previous-candidate-upgrade",
                            "Previous-candidate upgrade subcheck is not passing",
                            f"{key} is {upgrade.get(key, 'missing')}.",
                            "multi-node-beta-soak-summary",
                        )
                    )
    if not isinstance(network, dict):
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.live-multi-node-soak",
                "Network-scale soak summary is missing",
                "Stable 1.0 requires network-scale or live RC soak evidence.",
                "network-scale-soak-summary",
            )
        )
    else:
        if candidate_release_id:
            release_identities = network_scale_candidate_release_ids(network)
            mismatched_release_ids = [
                (source, release_id)
                for source, release_id in release_identities
                if release_id != candidate_release_id
            ]
            if not release_identities or mismatched_release_ids:
                if mismatched_release_ids:
                    release_id_source, network_release_id = mismatched_release_ids[0]
                else:
                    release_id_source, network_release_id = "missing", "missing"
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.live-multi-node-soak",
                        "Network-scale soak summary is not bound to this release",
                        "Stable 1.0 requires network-scale soak evidence to match the production beta "
                        f"releaseId; network {release_id_source}={network_release_id or 'missing'}, "
                        f"production={candidate_release_id}.",
                        "network-scale-soak-summary",
                    )
                )
        mode = str(network.get("mode", "missing"))
        if mode not in accepted_network:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.live-multi-node-soak",
                    "Network-scale soak mode is not Stable-compatible",
                    f"Network-scale mode is {mode}; accepted modes are {', '.join(sorted(accepted_network))}.",
                    "network-scale-soak-summary",
                )
            )
        if not status_ok(network.get("status")):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.live-multi-node-soak",
                    "Network-scale soak summary is not passing",
                    f"Network-scale status is {network.get('status', 'missing')}.",
                    "network-scale-soak-summary",
                )
            )
        blockers.extend(network_scale_structure_blockers(network, domain_id))
        if max_age_days is not None:
            freshness = evidence_age_blocker(
                domain_id=domain_id,
                evidence_id="stable-1.0.live-multi-node-soak",
                title="Network-scale soak summary",
                source="network-scale-soak-summary",
                generated_at=network.get("generatedAt"),
                now=now,
                maximum_age_days=max_age_days,
                label="network-scale soak summary",
            )
            if freshness is not None:
                blockers.append(freshness)
        operations = network_operation_count(network)
        if operations < min_ops:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.live-multi-node-soak",
                    "Network-scale soak operation count is insufficient",
                    f"Network-scale operation count is {operations}; policy minimum is {min_ops}.",
                    "network-scale-soak-summary",
                )
            )
        redaction = network.get("redaction") if isinstance(network.get("redaction"), dict) else None
        redaction_status = (
            normalize_status(redaction.get("status", "missing"))
            if isinstance(redaction, dict)
            else "missing"
        )
        missing_redaction_proof_fields = missing_true_fields(redaction, NETWORK_SCALE_REDACTION_PROOF_FIELDS)
        if (
            redaction_status != "pass"
            or (isinstance(redaction, dict) and redaction.get("findings"))
            or missing_redaction_proof_fields
            or recursive_redaction_field_failure(network)
        ):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.redaction",
                    "Network-scale soak redaction did not pass",
                    (
                        "Stable 1.0 network-scale artifacts must be metadata-only with complete "
                        f"redaction proof fields; missing or false fields: "
                        f"{', '.join(missing_redaction_proof_fields) or 'none'}."
                    ),
                    "network-scale-soak-summary",
                )
            )
    return domain_result(
        domain_id,
        "Live, multi-node, and network-scale evidence",
        (
            *LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS,
            *NETWORK_SCALE_EVIDENCE_IDS,
            *MULTI_NODE_SCENARIO_EVIDENCE_IDS,
        ),
        blockers,
        [],
    )

def evaluate_legacy(evidence: dict[str, dict[str, Any]]) -> dict[str, Any]:
    domain_id = "legacy-plugin-migration"
    blockers = add_required_evidence_blockers(
        evidence,
        domain_id,
        LEGACY_EVIDENCE_IDS,
        "release-certification",
    )
    final_surface = evidence_details(evidence.get("legacy-admin.final-admin-surface"))
    categories = final_surface.get("categories") if isinstance(final_surface.get("categories"), dict) else {}
    mutating_gap = final_surface.get("waveFivePromotedRouteIds")
    if isinstance(mutating_gap, list) and mutating_gap:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.legacy-admin-mutating-path",
                "Legacy admin promoted new Wave 5 paths",
                "Stable 1.0 forbids new legacy admin mutating paths outside explicit emergency-only classification.",
                "legacy-admin.final-admin-surface",
            )
        )
    if not isinstance(categories, dict) or "removedByDefaultAdmin" not in categories:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.legacy-plugin-migration",
                "Legacy admin final-surface categories are missing",
                "Stable 1.0 requires explicit maintenance-only, retained browse, and emergency fallback boundaries.",
                "legacy-admin.final-admin-surface",
            )
        )
    migration = evidence_details(evidence.get("legacy-plugin.migration-finalization")).get("checks")
    if isinstance(migration, dict):
        for key in (
            "cookbookExists",
            "migrationMatrixPresent",
            "webOfTrustMapsToTrustGraphLocalRc",
            "freetalkSoneMapsToSocialInboxRc",
            "freemailFutureMailPatternOnly",
            "oldPluginCompatibilityAbsent",
            "sourceSurfaceAuditPasses",
            "redactionChecksPass",
        ):
            if migration.get(key) is not True:
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.legacy-plugin-migration",
                        "Legacy plugin migration criterion is not passing",
                        f"{key} is not true.",
                        "legacy-plugin.migration-finalization",
                    )
                )
    return domain_result(domain_id, "Legacy admin and plugin migration", LEGACY_EVIDENCE_IDS, blockers, [])

def evaluate_support_feedback(
    evidence: dict[str, dict[str, Any]],
    known_issues: dict[str, Any] | None,
    workspace_root: Path,
    candidate_release_id: str,
) -> dict[str, Any]:
    domain_id = "support-feedback-readiness"
    blockers = add_required_evidence_blockers(
        evidence,
        domain_id,
        SUPPORT_FEEDBACK_EVIDENCE_IDS,
        "release-certification",
    )
    if not isinstance(known_issues, dict):
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.known-limitations",
                "Public beta known issues tracker is missing",
                "Stable 1.0 requires a redaction-safe known issues tracker.",
                "public-beta-known-issues",
            )
        )
    else:
        if (
            not schema_version_is_current(known_issues.get("schemaVersion"))
            or known_issues.get("tracker") != "public-beta-known-issues"
        ):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "public-beta.known-issues-tracker",
                    "Public beta known issues tracker envelope is malformed",
                    (
                        "Stable 1.0 requires publicBetaKnownIssues.schemaVersion=1 "
                        "and tracker=public-beta-known-issues before accepting the issue list."
                    ),
                    "public-beta-known-issues",
                )
            )
        redaction_policy = known_issues.get("redactionPolicy") if isinstance(known_issues.get("redactionPolicy"), dict) else {}
        for key, expected in (
            ("rawSupportBundlesStored", False),
            ("rawAppDataStored", False),
            ("rawContentStored", False),
            ("privateInsertUrisStored", False),
            ("absoluteLocalPathsStored", False),
        ):
            if redaction_policy.get(key) is not expected:
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.support-feedback-redaction",
                        "Known issues tracker redaction policy is unsafe",
                        f"redactionPolicy.{key} must be {str(expected).lower()}.",
                        "public-beta-known-issues",
                    )
                )
        if recursive_redaction_field_failure(known_issues):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.redaction",
                    "Known issues tracker contains unsafe redaction signals",
                    (
                        "Stable 1.0 known-issues evidence must not contain raw stored data, "
                        "unsafe redaction proofs, or redaction findings."
                    ),
                    "public-beta-known-issues",
                )
            )
        known_issue_records = known_issues.get("knownIssues")
        if not isinstance(known_issue_records, list):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "public-beta.known-issues-tracker",
                    "Public beta known issues tracker schema is malformed",
                    "publicBetaKnownIssues.knownIssues must be a list so Stable 1.0 can verify unresolved critical issues.",
                    "public-beta-known-issues",
                )
            )
            known_issue_records = []
        for index, known_issue in enumerate(known_issue_records):
            if not isinstance(known_issue, dict):
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "public-beta.known-issues-tracker",
                        "Public beta known issue record is malformed",
                        f"publicBetaKnownIssues.knownIssues[{index}] must be an object.",
                        "public-beta-known-issues",
                    )
                )
                continue
            missing_fields = [
                field
                for field in KNOWN_ISSUE_REQUIRED_FIELDS
                if field not in known_issue
                or (
                    field in KNOWN_ISSUE_REQUIRED_STRING_FIELDS
                    and isinstance(known_issue.get(field), str)
                    and not known_issue.get(field, "").strip()
                )
            ]
            malformed_string_fields = [
                field
                for field in KNOWN_ISSUE_REQUIRED_STRING_FIELDS
                if field in known_issue and not isinstance(known_issue.get(field), str)
            ]
            malformed_list_fields = [
                field
                for field in KNOWN_ISSUE_REQUIRED_LIST_FIELDS
                if field in known_issue and not isinstance(known_issue.get(field), list)
            ]
            if missing_fields or malformed_string_fields or malformed_list_fields:
                detail_parts = []
                if missing_fields:
                    detail_parts.append("missing required fields: " + ", ".join(missing_fields))
                if malformed_string_fields:
                    detail_parts.append(
                        "fields must be non-empty strings: " + ", ".join(malformed_string_fields)
                    )
                if malformed_list_fields:
                    detail_parts.append(
                        "fields must be lists: " + ", ".join(malformed_list_fields)
                    )
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "public-beta.known-issues-tracker",
                        "Public beta known issue record is missing required metadata",
                        f"publicBetaKnownIssues.knownIssues[{index}] is malformed; " + "; ".join(detail_parts) + ".",
                        "public-beta-known-issues",
                    )
                )
                continue
            severity = str(known_issue.get("severity", "")).lower()
            status = str(known_issue.get("status", "")).lower()
            fixed = str(known_issue.get("fixedInReleaseId", "")).strip().lower()
            candidate_fixed = bool(candidate_release_id and fixed == candidate_release_id.lower())
            open_issue = status not in {"fixed", "resolved", "closed"} and not candidate_fixed
            if open_issue and ("critical" in severity or "blocker" in severity):
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.critical-known-issue",
                        "Unresolved critical known issue blocks Stable 1.0",
                        f"Known issue {known_issue.get('knownIssueId', 'unknown')} is unresolved with severity {known_issue.get('severity', 'missing')}.",
                        "public-beta-known-issues",
                    )
                )
    missing_docs = [path for path in DOC_PATHS if not (workspace_root / path).is_file()]
    if missing_docs:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.release-notes-known-limitations",
                "Stable 1.0 readiness documentation is incomplete",
                "Missing docs: " + ", ".join(missing_docs),
                "workspace-docs",
            )
        )
    return domain_result(domain_id, "Public beta support and feedback readiness", SUPPORT_FEEDBACK_EVIDENCE_IDS, blockers, [])

def limitation_open(limitation: dict[str, Any]) -> bool:
    return str(limitation.get("status", "")).lower() not in {"resolved", "fixed", "closed", "done"}

def safe_limitation(limitation: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "id",
        "title",
        "category",
        "classification",
        "status",
        "summary",
        "evidenceIds",
        "boundedBy",
    )
    return {key: limitation[key] for key in keys if key in limitation}

def auditable_limitation_metadata_errors(
    record: Any,
    label: str,
    expected_classification: str,
) -> list[str]:
    if not isinstance(record, dict):
        return [f"{label} must be an object"]
    errors: list[str] = []
    for field in AUDITABLE_LIMITATION_REQUIRED_STRING_FIELDS:
        if not non_empty_string(record.get(field)):
            errors.append(f"{label}.{field} must be a non-empty string")
    classification = str(record.get("classification", "")).strip().lower()
    if classification and classification != expected_classification:
        errors.append(f"{label}.classification must be {expected_classification}")
    evidence_ids = record.get("evidenceIds")
    if not isinstance(evidence_ids, list) or not evidence_ids:
        errors.append(f"{label}.evidenceIds must be a non-empty list")
    elif any(not non_empty_string(item) for item in evidence_ids):
        errors.append(f"{label}.evidenceIds must contain only non-empty strings")
    return errors

def evaluate_known_limitations(
    limitations_doc: dict[str, Any] | None,
    waivers: list[StableWaiver],
    policy: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    domain_id = "known-limitations"
    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    allowed: list[dict[str, Any]] = []
    disallowed: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []
    allowed_categories = policy_string_set(policy, "allowedLimitationCategories")
    disallowed_categories = policy_string_set(policy, "disallowedLimitationCategories")
    malformed_limitations_doc = (
        not isinstance(limitations_doc, dict)
        or not schema_version_is_current(limitations_doc.get("schemaVersion"))
        or limitations_doc.get("kind") != "stable-1.0-known-limitations"
        or not isinstance(limitations_doc.get("limitations"), list)
        or not limitations_doc.get("limitations")
    )
    if malformed_limitations_doc:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.known-limitations",
                "Stable 1.0 known limitations source is missing or malformed",
                "Stable 1.0 requires a deterministic known limitations source with schemaVersion=1, kind=stable-1.0-known-limitations, and a non-empty limitations array.",
                "stable-known-limitations",
            )
        )
        return domain_result(domain_id, "Known limitations", ("stable-1.0.known-limitations",), blockers, warnings), allowed, disallowed, resolved
    for index, raw in enumerate(limitations_doc.get("limitations", [])):
        if not isinstance(raw, dict):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.known-limitations",
                    "Stable 1.0 known limitation record is malformed",
                    f"stableKnownLimitations.limitations[{index}] must be an object.",
                    "stable-known-limitations",
                )
            )
            continue
        limitation = safe_limitation(raw)
        classification = str(raw.get("classification", "")).lower()
        is_open = limitation_open(raw)
        if not is_open:
            resolved.append(limitation)
            continue
        limitation_id = str(raw.get("id", "stable-1.0.unknown-limitation"))
        category = str(raw.get("category", "")).strip()
        if classification == "allowed-for-stable-1.0":
            metadata_errors = auditable_limitation_metadata_errors(
                raw,
                f"stableKnownLimitations.limitations[{index}]",
                "allowed-for-stable-1.0",
            )
            if metadata_errors:
                disallowed.append(limitation)
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.known-limitations",
                        "Allowed Stable limitation record is malformed",
                        "Allowed Stable limitations must be explicit and bounded: "
                        + "; ".join(metadata_errors)
                        + ".",
                        "stable-known-limitations",
                        limitation_id=limitation_id,
                    )
                )
            elif category in disallowed_categories:
                disallowed.append(limitation)
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.known-limitations",
                        "Stable-forbidden limitation category was marked allowed",
                        f"{limitation_id} uses disallowed category {category} and cannot be allowed for Stable 1.0.",
                        "stable-known-limitations",
                        limitation_id=limitation_id,
                    )
                )
            elif category not in allowed_categories:
                disallowed.append(limitation)
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.known-limitations",
                        "Allowed Stable limitation category is not policy-approved",
                        f"{limitation_id} uses category {category or 'missing'}, which is not in allowedLimitationCategories.",
                        "stable-known-limitations",
                        limitation_id=limitation_id,
                    )
                )
            else:
                allowed.append(limitation)
        elif classification == "requires-waiver-before-stable":
            metadata_errors = auditable_limitation_metadata_errors(
                raw,
                f"stableKnownLimitations.limitations[{index}]",
                "requires-waiver-before-stable",
            )
            if metadata_errors:
                disallowed.append(limitation)
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.known-limitations",
                        "Waiver-required Stable limitation record is malformed",
                        "Waiver-required Stable limitations must be explicit and bounded before "
                        "a waiver can be honored: "
                        + "; ".join(metadata_errors)
                        + ".",
                        "stable-known-limitations",
                        limitation_id=limitation_id,
                    )
                )
            else:
                waiver = active_waiver_for(waivers, limitation_id, f"limitation.{limitation_id}")
                if waiver is None:
                    blockers.append(
                        blocker_issue(
                            domain_id,
                            "stable-1.0.known-limitations",
                            "Stable limitation requires a waiver",
                            f"{limitation_id} is open and requires an explicit Stable 1.0 waiver.",
                            "stable-known-limitations",
                            waivable=True,
                            limitation_id=limitation_id,
                        )
                    )
                else:
                    warnings.append(
                        warning_issue(
                            domain_id,
                            "stable-1.0.known-limitations",
                            "Stable limitation is covered by waiver",
                            f"{limitation_id} remains open under waiver {waiver.id}.",
                            "stable-known-limitations",
                        )
                    )
        elif classification in {"blocks-stable-1.0", "beta-only"}:
            disallowed.append(limitation)
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.known-limitations",
                    "Stable-forbidden limitation remains open",
                    f"{limitation_id} is {classification} and remains {raw.get('status', 'open')}.",
                    "stable-known-limitations",
                    limitation_id=limitation_id,
                )
            )
        else:
            disallowed.append(limitation)
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.known-limitations",
                    "Known limitation has an unknown classification",
                    f"{limitation_id} classification is {raw.get('classification', 'missing')}; Stable 1.0 requires a recognized classification.",
                    "stable-known-limitations",
                    limitation_id=limitation_id,
                )
            )
    return domain_result(domain_id, "Known limitations", ("stable-1.0.known-limitations",), blockers, warnings, allowed), allowed, disallowed, resolved

def validate_waivers_against_blockers(
    waivers: list[StableWaiver],
    blockers: list[dict[str, Any]],
    policy: dict[str, Any],
) -> list[dict[str, Any]]:
    validation: list[dict[str, Any]] = []
    non_waivable = policy_string_set(policy, "nonWaivableBlockers")
    for waiver in waivers:
        if waiver.validation_errors:
            validation.append(
                blocker_issue(
                    "known-limitations",
                    "stable-1.0.waiver-validation",
                    "Stable 1.0 waiver is invalid",
                    f"Waiver {waiver.id} is invalid: {'; '.join(waiver.validation_errors)}.",
                    waiver.source,
                )
            )
            continue
        for blocker in blockers:
            if not waiver.matches(
                str(blocker.get("id", "")),
                str(blocker.get("evidenceId", "")),
                str(blocker.get("limitationId", "")),
            ):
                continue
            if not blocker.get("waivable") or blocker.get("evidenceId") in non_waivable or blocker.get("id") in non_waivable:
                validation.append(
                    blocker_issue(
                        "known-limitations",
                        "stable-1.0.waiver-validation",
                        "Waiver targets a non-waivable Stable 1.0 blocker",
                        f"Waiver {waiver.id} cannot waive {blocker.get('evidenceId')}.",
                        waiver.source,
                    )
                )
    return validation

def build_inputs(settings: Settings) -> tuple[dict[str, Any], dict[str, Path], list[Path]]:
    paths: dict[str, Path] = {}
    values: dict[str, Any] = {}
    scan_targets: list[Path] = []
    mapping = {
        "productionBetaSummary": settings.production_beta_summary,
        "goNoGoSummary": settings.go_no_go_summary,
        "releaseCertificationSummary": settings.release_certification_summary,
        "ecosystemMatrix": settings.ecosystem_matrix,
        "appPlatformSummary": settings.app_platform_summary,
        "multiNodeSoakSummary": settings.multi_node_soak_summary,
        "networkScaleSoakSummary": settings.network_scale_soak_summary,
        "securityDrillsSummary": settings.security_drills_summary,
        "publicBetaKnownIssues": settings.public_beta_known_issues,
        "policy": settings.policy,
        "stableKnownLimitations": settings.stable_known_limitations,
        "waivers": settings.waivers,
    }
    for name, path in mapping.items():
        if path is None:
            continue
        paths[name] = path
        scan_targets.append(path)
        value = read_json(path)
        if value is not None:
            values[name] = value
    return values, paths, scan_targets

def evidence_item(evidence_id: str, status: str, summary: str, details: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": evidence_id,
        "status": status,
        "requiredForStable10": True,
        "summary": summary,
        "details": details,
    }
