"""Implementation segment for the domains portion of ``stable_1_0_readiness.py``."""

from __future__ import annotations

def evaluate_production_beta_state(
    production: dict[str, Any] | None,
    go_no_go: dict[str, Any] | None,
    policy: dict[str, Any],
) -> dict[str, Any]:
    domain_id = "production-beta-state"
    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    required_modes, required_mode_errors = string_array_values(
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
                "stable-readiness-policy",
            )
        )
    if not isinstance(production, dict):
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.production-beta-state",
                "Production beta summary is missing",
                "Stable 1.0 readiness requires a production beta summary.",
                "production-beta-summary",
            )
        )
    else:
        provenance_errors = schema_tool_errors(
            production,
            expected_tool="production-beta-release",
            evidence_label="productionBetaSummary",
        )
        for error in provenance_errors:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.production-beta-state",
                    "Production beta summary schema is malformed",
                    error + ".",
                    "production-beta-summary",
                )
            )
        if not non_empty_string(production.get("generatedAt")):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.production-beta-state",
                    "Production beta summary timestamp is missing",
                    "Stable 1.0 readiness requires generatedAt from the production beta release pipeline.",
                    "production-beta-summary",
                )
            )
        mode = str(production.get("mode", "missing"))
        if mode not in required_modes:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.production-beta-state",
                    "Production beta mode is not Stable-compatible",
                    f"Production beta summary mode is {mode}; required modes are {', '.join(sorted(required_modes))}.",
                    "production-beta-summary",
                )
            )
        if not status_ok(production.get("status")) or production.get("promotionReady") is not True:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.production-beta-state",
                    "Production beta summary is not promotion-ready",
                    "Stable 1.0 readiness requires production beta status pass and promotionReady=true.",
                    "production-beta-summary",
                )
            )
        if production.get("nonRelease") is not False:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.production-beta-state",
                    "Production beta summary is marked non-release",
                    "Stable 1.0 cannot depend on developer dry-run, fixture, emergency-skip, dirty workspace, or test-signing evidence.",
                    "production-beta-summary",
                )
            )
        workspace_marker_errors: list[str] = []
        if (
            "workspaceStatusKnown" in production
            and production.get("workspaceStatusKnown") is not True
        ):
            workspace_marker_errors.append(
                f"workspaceStatusKnown is {production.get('workspaceStatusKnown')!r}"
            )
        if "dirtyWorkspace" in production and production.get("dirtyWorkspace") is not False:
            workspace_marker_errors.append(
                f"dirtyWorkspace is {production.get('dirtyWorkspace')!r}"
            )
        if workspace_marker_errors:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.production-beta-state",
                    "Production beta workspace status is not clean",
                    (
                        "Stable 1.0 requires workspaceStatusKnown=true and dirtyWorkspace=false "
                        "when those production summary markers are present; "
                        + "; ".join(workspace_marker_errors)
                        + "."
                    ),
                    "production-beta-summary",
                )
            )
        pipeline_stages = production.get("pipelineStages")
        if not isinstance(pipeline_stages, dict) or not pipeline_stages:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.production-beta-state",
                    "Production beta pipeline stages are missing",
                    "Stable 1.0 readiness requires pipelineStages from the production beta release pipeline.",
                    "production-beta-summary",
                )
            )
            pipeline_stages = {}
        missing_or_failed_stages = [
            stage_id
            for stage_id in PRODUCTION_BETA_REQUIRED_PIPELINE_STAGES
            if not isinstance(pipeline_stages.get(stage_id), dict)
            or normalize_status(pipeline_stages.get(stage_id, {}).get("status", "missing")) != "pass"
        ]
        if missing_or_failed_stages:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.production-beta-state",
                    "Production beta required pipeline stages did not pass",
                    "Missing or non-pass pipeline stages: " + ", ".join(missing_or_failed_stages) + ".",
                    "production-beta-summary",
                )
            )
        artifacts = production.get("artifacts")
        if not isinstance(artifacts, dict):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.production-beta-state",
                    "Production beta artifact references are missing",
                    "Stable 1.0 readiness requires production beta artifact references.",
                    "production-beta-summary",
                )
            )
            artifacts = {}
        missing_artifacts = [
            artifact_id
            for artifact_id in PRODUCTION_BETA_REQUIRED_ARTIFACTS
            if not non_empty_string(artifacts.get(artifact_id))
        ]
        if missing_artifacts:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.production-beta-state",
                    "Production beta artifact references are incomplete",
                    "Missing artifact references: " + ", ".join(missing_artifacts) + ".",
                    "production-beta-summary",
                )
            )
        promotion = production.get("promotion")
        if not isinstance(promotion, dict):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.production-beta-state",
                    "Production beta promotion proof is missing",
                    "Stable 1.0 readiness requires the production beta promotion gate summary.",
                    "production-beta-summary",
                )
            )
            promotion = {}
        if (
            normalize_status(promotion.get("status", "missing")) != "pass"
            or promotion.get("promotionReady") is not True
            or promotion.get("nonRelease") is not False
        ):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.production-beta-state",
                    "Production beta promotion proof is not passing",
                    (
                        "Stable 1.0 readiness requires promotion.status=pass, "
                        "promotion.promotionReady=true, and promotion.nonRelease=false."
                    ),
                    "production-beta-summary",
                )
            )
        failed_gate_count, malformed_failed_gate_count = non_negative_count(
            promotion.get("failedGateCount", 0)
        )
        if malformed_failed_gate_count or failed_gate_count > 0:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.production-beta-state",
                    "Production beta promotion gates are failing",
                    (
                        "promotion.failedGateCount is "
                        + ("malformed" if malformed_failed_gate_count else str(failed_gate_count))
                        + "."
                    ),
                    "production-beta-summary",
                )
            )
        gate_errors = list_shape_errors(promotion.get("gates"), "productionBetaSummary.promotion.gates")
        for error in gate_errors:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.production-beta-state",
                    "Production beta promotion gates are missing or malformed",
                    error + ".",
                    "production-beta-summary",
                )
            )
        signing = production.get("signingProfile")
        if not isinstance(signing, dict):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.production-beta-state",
                    "Production beta signing profile is missing",
                    "Stable 1.0 requires explicit production signing and reviewer-key evidence.",
                    "production-beta-summary",
                )
            )
        else:
            required_signing_fields = (
                "kind",
                "generatedTestKeys",
                "appKeyId",
                "reviewerKeyId",
                "privateKeyMaterialIncluded",
            )
            required_signing_string_fields = {"appKeyId", "reviewerKeyId"}
            missing_fields = [
                field
                for field in required_signing_fields
                if field not in signing
                or signing.get(field) is None
                or (isinstance(signing.get(field), str) and not signing.get(field).strip())
                or (
                    field in required_signing_string_fields
                    and not non_empty_string(signing.get(field))
                )
            ]
            if missing_fields:
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.production-beta-state",
                        "Production beta signing evidence is incomplete or malformed",
                        "Stable 1.0 signing profile has missing or malformed fields: "
                        + ", ".join(missing_fields)
                        + ".",
                        "production-beta-summary",
                    )
                )
            if (
                signing.get("generatedTestKeys") is not False
                or str(signing.get("kind", "")) != "production"
                or signing.get("privateKeyMaterialIncluded") is not False
            ):
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.production-beta-state",
                        "Production beta summary uses non-production signing evidence",
                        "Stable 1.0 requires production signing and reviewer evidence, not fixture or generated test keys.",
                        "production-beta-summary",
                    )
                )
        redaction = production.get("redaction") if isinstance(production.get("redaction"), dict) else {}
        if (
            normalize_status(redaction.get("status", "missing")) != "pass"
            or redaction.get("findings")
            or recursive_redaction_failure(redaction)
        ):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.redaction",
                    "Production beta redaction did not pass",
                    "Stable 1.0 readiness cannot use redaction-unsafe production beta artifacts.",
                    "production-beta-summary",
                )
            )
        gates_value = promotion.get("gates") if isinstance(promotion.get("gates"), list) else []
        promotion_gate_ids = {
            non_empty_string(gate.get("id"))
            for gate in gates_value
            if isinstance(gate, dict) and non_empty_string(gate.get("id"))
        }
        missing_promotion_gates = [
            gate_id
            for gate_id in PRODUCTION_BETA_REQUIRED_PROMOTION_GATES
            if gate_id not in promotion_gate_ids
        ]
        if missing_promotion_gates:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.production-beta-state",
                    "Production beta promotion proof is incomplete",
                    "Missing required production promotion gates: "
                    + ", ".join(missing_promotion_gates)
                    + ".",
                    "production-beta-summary",
                )
            )
        failed_gates = []
        for index, gate in enumerate(gates_value):
            if not isinstance(gate, dict):
                continue
            gate_status = normalize_status(gate.get("status", "missing"))
            if gate_status != "pass":
                gate_id = non_empty_string(gate.get("id")) or f"gates[{index}]"
                failed_gates.append(f"{gate_id}:{gate_status}")
        if failed_gates:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.production-beta-state",
                    "Production beta promotion gates include failures",
                    "Failed production gates: " + ", ".join(failed_gates[:8]) + ".",
                    "production-beta-summary",
                )
            )
        if not malformed_failed_gate_count and failed_gate_count != len(failed_gates):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.production-beta-state",
                    "Production beta promotion gate count is inconsistent",
                    (
                        f"promotion.failedGateCount is {failed_gate_count}, "
                        f"but promotion.gates contains {len(failed_gates)} non-passing entries."
                    ),
                    "production-beta-summary",
                )
            )
    if not isinstance(go_no_go, dict):
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.go-no-go-decision",
                "Production beta go/no-go dashboard is missing",
                "Stable 1.0 readiness requires the production beta dashboard decision.",
                "go-no-go-summary",
            )
        )
    else:
        decision = str(go_no_go.get("decision", "missing"))
        dashboard_mode = str(go_no_go.get("mode", "missing"))
        provenance_errors = schema_tool_errors(
            go_no_go,
            expected_tool="production-beta-go-no-go-dashboard",
            evidence_label="goNoGoSummary",
        )
        for error in provenance_errors:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.go-no-go-decision",
                    "Go/no-go dashboard summary schema is malformed",
                    error + ".",
                    "go-no-go-summary",
                )
            )
        dashboard_summary = go_no_go.get("summary") if isinstance(go_no_go.get("summary"), dict) else {}
        if not dashboard_summary:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.go-no-go-decision",
                    "Go/no-go dashboard summary counts are missing",
                    "Stable 1.0 readiness requires the go/no-go dashboard summary counts.",
                    "go-no-go-summary",
                )
            )
        for field in GO_NO_GO_SUMMARY_COUNT_FIELDS:
            if field == "criticalFindings":
                parsed_count = strict_non_negative_int(dashboard_summary.get(field, 0))
                count, malformed_count = (parsed_count or 0), parsed_count is None
            else:
                count, malformed_count = non_negative_count(dashboard_summary.get(field, 0))
            if malformed_count:
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.go-no-go-decision",
                        "Go/no-go dashboard summary count is malformed",
                        f"goNoGoSummary.summary.{field} must be a non-negative integer.",
                        "go-no-go-summary",
                    )
                )
            elif field == "criticalRedactionFindings" and count > 0:
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.redaction",
                        "Go/no-go dashboard reports critical redaction findings",
                        (
                            "Stable 1.0 readiness cannot depend on a redaction-unsafe dashboard; "
                            f"goNoGoSummary.summary.criticalRedactionFindings is {count}."
                        ),
                        "go-no-go-summary",
                    )
                )
            elif field == "criticalFindings" and count > 0:
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.go-no-go-decision",
                        "Go/no-go dashboard reports critical findings",
                        (
                            "Stable 1.0 readiness cannot depend on a dashboard with unresolved "
                            f"critical findings; goNoGoSummary.summary.criticalFindings is {count}."
                        ),
                        "go-no-go-summary",
                    )
                )
        waivers_used_count, malformed_waivers_used_count = non_negative_count(
            dashboard_summary.get("waiversUsed", 0)
        )
        waiver_records = go_no_go.get("waivers")
        waiver_record_errors = list_shape_errors(
            waiver_records,
            "goNoGoSummary.waivers",
            allow_empty=True,
        )
        used_waiver_record_count = 0
        if isinstance(waiver_records, list):
            malformed_used_by_indexes = [
                str(index)
                for index, waiver in enumerate(waiver_records)
                if isinstance(waiver, dict)
                and not isinstance(waiver.get("usedBy"), list)
            ]
            if malformed_used_by_indexes:
                waiver_record_errors.append(
                    "goNoGoSummary.waivers usedBy must be a list; malformed indexes: "
                    + ", ".join(malformed_used_by_indexes)
                )
            malformed_used_by_entry_indexes = [
                f"{waiver_index}.{used_by_index}"
                for waiver_index, waiver in enumerate(waiver_records)
                if isinstance(waiver, dict)
                and isinstance(waiver.get("usedBy"), list)
                for used_by_index, issue_id in enumerate(waiver["usedBy"])
                if not non_empty_string(issue_id)
            ]
            if malformed_used_by_entry_indexes:
                waiver_record_errors.append(
                    "goNoGoSummary.waivers usedBy entries must be non-empty strings; "
                    "malformed waiver.entry indexes: "
                    + ", ".join(malformed_used_by_entry_indexes)
                )
            used_waiver_record_count = sum(
                1
                for waiver in waiver_records
                if isinstance(waiver, dict)
                and isinstance(waiver.get("usedBy"), list)
                and bool(waiver.get("usedBy"))
                and all(non_empty_string(issue_id) for issue_id in waiver["usedBy"])
            )
        if (
            not malformed_waivers_used_count
            and not waiver_record_errors
            and waivers_used_count != used_waiver_record_count
        ):
            waiver_record_errors.append(
                f"goNoGoSummary.summary.waiversUsed is {waivers_used_count}, "
                f"but waivers contains {used_waiver_record_count} used record(s)"
            )
        if not malformed_waivers_used_count:
            if waivers_used_count > 0 and decision != "go-with-waivers":
                waiver_record_errors.append(
                    "goNoGoSummary.decision must be go-with-waivers when waiversUsed is positive"
                )
            elif decision == "go-with-waivers" and waivers_used_count == 0:
                waiver_record_errors.append(
                    "goNoGoSummary.decision is go-with-waivers but waiversUsed is zero"
                )
        if waiver_record_errors:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.go-no-go-decision",
                    "Go/no-go dashboard waiver metadata is inconsistent",
                    "; ".join(waiver_record_errors) + ".",
                    "go-no-go-summary",
                )
            )
        domain_errors = list_shape_errors(go_no_go.get("domains"), "goNoGoSummary.domains")
        for error in domain_errors:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.go-no-go-decision",
                    "Go/no-go dashboard domains are missing or malformed",
                    error + ".",
                    "go-no-go-summary",
                )
            )
        warning_domain_ids: list[str] = []
        if isinstance(go_no_go.get("domains"), list):
            dashboard_domains = go_no_go["domains"]
            domain_ids = [
                non_empty_string(domain.get("id"))
                for domain in dashboard_domains
                if isinstance(domain, dict) and non_empty_string(domain.get("id"))
            ]
            expected_domain_ids = set(GO_NO_GO_DOMAIN_IDS)
            actual_domain_ids = set(domain_ids)
            missing_domain_ids = sorted(expected_domain_ids - actual_domain_ids)
            duplicate_domain_ids = sorted(
                domain_id
                for domain_id in actual_domain_ids
                if domain_ids.count(domain_id) > 1
            )
            unexpected_domain_ids = sorted(actual_domain_ids - expected_domain_ids)
            missing_id_indexes = [
                str(index)
                for index, domain in enumerate(dashboard_domains)
                if isinstance(domain, dict) and not non_empty_string(domain.get("id"))
            ]
            if (
                missing_domain_ids
                or duplicate_domain_ids
                or unexpected_domain_ids
                or missing_id_indexes
            ):
                domain_id_errors: list[str] = []
                if missing_domain_ids:
                    domain_id_errors.append(
                        "missing required domain IDs: " + ", ".join(missing_domain_ids)
                    )
                if duplicate_domain_ids:
                    domain_id_errors.append(
                        "duplicate domain IDs: " + ", ".join(duplicate_domain_ids)
                    )
                if unexpected_domain_ids:
                    domain_id_errors.append(
                        "unexpected domain IDs: " + ", ".join(unexpected_domain_ids)
                    )
                if missing_id_indexes:
                    domain_id_errors.append(
                        "domain rows missing IDs at indexes: " + ", ".join(missing_id_indexes)
                    )
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.go-no-go-decision",
                        "Go/no-go dashboard domain set is incomplete",
                        "Go/no-go dashboard " + "; ".join(domain_id_errors) + ".",
                        "go-no-go-summary",
                    )
                )
            non_passing_domains: list[str] = []
            malformed_domain_statuses: list[str] = []
            for index, dashboard_domain in enumerate(dashboard_domains):
                if not isinstance(dashboard_domain, dict):
                    continue
                raw_domain_status = str(dashboard_domain.get("status", "missing")).strip().lower()
                domain_label = non_empty_string(dashboard_domain.get("id")) or f"domains[{index}]"
                if raw_domain_status == "waived":
                    if decision == "go-with-waivers":
                        continue
                    non_passing_domains.append(f"{domain_label}:waived")
                    continue
                domain_status = normalize_status(dashboard_domain.get("status", "missing"))
                if domain_status == "missing":
                    malformed_domain_statuses.append(domain_label)
                elif domain_status == "warn":
                    warning_domain_ids.append(domain_label)
                elif domain_status not in {"pass", "warn"}:
                    non_passing_domains.append(f"{domain_label}:{domain_status}")
            if malformed_domain_statuses:
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.go-no-go-decision",
                        "Go/no-go dashboard domain status is malformed",
                        (
                            "Dashboard domain rows must include Stable-compatible status values; "
                            "malformed domains: "
                            + ", ".join(malformed_domain_statuses)
                            + "."
                        ),
                        "go-no-go-summary",
                    )
                )
            if non_passing_domains:
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.go-no-go-decision",
                        "Go/no-go dashboard has non-passing domains",
                        (
                            "Stable 1.0 readiness requires the production beta dashboard domain "
                            "breakdown to be passing; non-passing domains: "
                            + ", ".join(non_passing_domains)
                            + "."
                        ),
                        "go-no-go-summary",
                    )
                )
        for list_field in ("blockers", "warnings"):
            issue_errors = list_shape_errors(
                go_no_go.get(list_field),
                f"goNoGoSummary.{list_field}",
                allow_empty=True,
            )
            for error in issue_errors:
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.go-no-go-decision",
                        "Go/no-go dashboard issue list is malformed",
                        error + ".",
                        "go-no-go-summary",
                    )
                )
        blockers_count, blockers_count_malformed = non_negative_count(dashboard_summary.get("blockers", 0))
        if (
            isinstance(go_no_go.get("blockers"), list)
            and not blockers_count_malformed
            and blockers_count != len(go_no_go.get("blockers", []))
        ):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.go-no-go-decision",
                    "Go/no-go dashboard blocker count is inconsistent",
                    (
                        f"goNoGoSummary.summary.blockers is {blockers_count}, "
                        f"but blockers contains {len(go_no_go.get('blockers', []))} entries."
                    ),
                    "go-no-go-summary",
                )
            )
        dashboard_blockers = go_no_go.get("blockers") if isinstance(go_no_go.get("blockers"), list) else []
        if dashboard_blockers or (not blockers_count_malformed and blockers_count > 0):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.go-no-go-decision",
                    "Go/no-go dashboard still reports blockers",
                    (
                        "Stable 1.0 readiness requires the production beta go/no-go dashboard "
                        f"to have zero blockers; summary.blockers={blockers_count}, "
                        f"blockers entries={len(dashboard_blockers)}."
                    ),
                    "go-no-go-summary",
                )
            )
        dashboard_warnings = (
            go_no_go.get("warnings") if isinstance(go_no_go.get("warnings"), list) else []
        )
        warnings_count, warnings_count_malformed = non_negative_count(
            dashboard_summary.get("warnings", 0)
        )
        if (
            isinstance(go_no_go.get("warnings"), list)
            and not warnings_count_malformed
            and warnings_count != len(dashboard_warnings)
        ):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.go-no-go-decision",
                    "Go/no-go dashboard warning count is inconsistent",
                    (
                        f"goNoGoSummary.summary.warnings is {warnings_count}, "
                        f"but warnings contains {len(dashboard_warnings)} entries."
                    ),
                    "go-no-go-summary",
                )
            )
        warning_record_domain_ids = {
            non_empty_string(warning.get("domainId"))
            for warning in dashboard_warnings
            if isinstance(warning, dict) and non_empty_string(warning.get("domainId"))
        }
        malformed_warning_domain_indexes = [
            str(index)
            for index, warning in enumerate(dashboard_warnings)
            if isinstance(warning, dict) and not non_empty_string(warning.get("domainId"))
        ]
        missing_warning_domain_ids = sorted(
            set(warning_domain_ids) - warning_record_domain_ids
        )
        unknown_warning_domain_ids = sorted(
            warning_record_domain_ids - set(GO_NO_GO_DOMAIN_IDS)
        )
        if (
            malformed_warning_domain_indexes
            or missing_warning_domain_ids
            or unknown_warning_domain_ids
        ):
            warning_domain_errors: list[str] = []
            if malformed_warning_domain_indexes:
                warning_domain_errors.append(
                    "warning records missing domainId at indexes: "
                    + ", ".join(malformed_warning_domain_indexes)
                )
            if missing_warning_domain_ids:
                warning_domain_errors.append(
                    "warn domains without warning records: "
                    + ", ".join(missing_warning_domain_ids)
                )
            if unknown_warning_domain_ids:
                warning_domain_errors.append(
                    "warning records with unknown domainId: "
                    + ", ".join(unknown_warning_domain_ids)
                )
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.go-no-go-decision",
                    "Go/no-go dashboard warning domains are inconsistent",
                    "Go/no-go dashboard " + "; ".join(warning_domain_errors) + ".",
                    "go-no-go-summary",
                )
            )
        warnings.extend(
            propagated_dashboard_warning(domain_id, dashboard_warning, index)
            for index, dashboard_warning in enumerate(dashboard_warnings)
            if isinstance(dashboard_warning, dict)
        )
        if dashboard_mode != "production-beta":
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.go-no-go-decision",
                    "Production beta go/no-go dashboard mode is not Stable-compatible",
                    f"Go/no-go dashboard mode is {dashboard_mode}; Stable 1.0 requires production-beta.",
                    "go-no-go-summary",
                )
            )
        if isinstance(production, dict):
            production_release_id = str(production.get("releaseId", "")).strip()
            dashboard_release_id = str(go_no_go.get("releaseId", "")).strip()
            if not production_release_id or dashboard_release_id != production_release_id:
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.go-no-go-decision",
                        "Production beta go/no-go dashboard is not bound to this release",
                        (
                            "Stable 1.0 requires the go/no-go dashboard releaseId to match "
                            f"the production beta summary releaseId; dashboard={dashboard_release_id or 'missing'}, "
                            f"production={production_release_id or 'missing'}."
                        ),
                        "go-no-go-summary",
                    )
                )
        if decision not in {"go", "go-with-waivers"}:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.go-no-go-decision",
                    "Production beta go/no-go decision blocks Stable 1.0",
                    f"Go/no-go decision is {decision}.",
                    "go-no-go-summary",
                )
            )
        elif decision == "go-with-waivers":
            warnings.append(
                warning_issue(
                    domain_id,
                    "stable-1.0.go-no-go-decision",
                    "Production beta launch depends on waivers",
                    "Release managers must confirm production beta waivers do not cover Stable-forbidden blockers.",
                    "go-no-go-summary",
                )
            )
        if go_no_go.get("promotionReady") is not True:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.go-no-go-decision",
                    "Production beta dashboard is not promotion-ready",
                    "Stable 1.0 readiness requires dashboard promotionReady=true.",
                    "go-no-go-summary",
                )
            )
        redaction = go_no_go.get("redaction") if isinstance(go_no_go.get("redaction"), dict) else {}
        redaction_findings_value = redaction.get("findings")
        malformed_redaction_findings = (
            "findings" in redaction and not isinstance(redaction_findings_value, list)
        )
        redaction_findings = (
            redaction_findings_value if isinstance(redaction_findings_value, list) else []
        )
        redaction_finding_count, malformed_redaction_finding_count = non_negative_count(
            redaction.get("findingCount", len(redaction_findings))
        )
        (
            redaction_critical_finding_count,
            malformed_redaction_critical_finding_count,
        ) = non_negative_count(redaction.get("criticalFindingCount", 0))
        dashboard_redaction_payload_unsafe = recursive_redaction_field_failure(go_no_go)
        redaction_payload_unaccounted = dashboard_redaction_payload_unsafe and not (
            normalize_status(redaction.get("status", "missing")) != "pass"
            or redaction_findings
            or malformed_redaction_findings
            or malformed_redaction_finding_count
            or redaction_finding_count > 0
            or malformed_redaction_critical_finding_count
            or redaction_critical_finding_count > 0
        )
        if (
            normalize_status(redaction.get("status", "missing")) != "pass"
            or redaction_findings
            or malformed_redaction_findings
            or malformed_redaction_finding_count
            or redaction_finding_count > 0
            or malformed_redaction_critical_finding_count
            or redaction_critical_finding_count > 0
            or dashboard_redaction_payload_unsafe
        ):
            if malformed_redaction_findings:
                redaction_detail = "redaction.findings is not a list"
            elif malformed_redaction_finding_count:
                redaction_detail = "findingCount is malformed"
            elif malformed_redaction_critical_finding_count:
                redaction_detail = "criticalFindingCount is malformed"
            elif redaction_critical_finding_count > 0:
                redaction_detail = f"criticalFindingCount is {redaction_critical_finding_count}"
            elif redaction_payload_unaccounted:
                redaction_detail = "dashboard redaction payload contains unsafe raw or unwaivable findings"
            else:
                redaction_detail = f"findingCount is {redaction_finding_count}"
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.redaction",
                    "Go/no-go dashboard redaction did not pass",
                    (
                        "Stable 1.0 readiness cannot depend on a redaction-unsafe dashboard; "
                        f"{redaction_detail}."
                    ),
                    "go-no-go-summary",
                )
            )
    return domain_result(
        domain_id,
        "Production beta release state",
        ("stable-1.0.production-beta-state", "stable-1.0.go-no-go-decision"),
        blockers,
        warnings,
    )

def evaluate_release_certification_summary(release_certification: dict[str, Any] | None) -> dict[str, Any]:
    domain_id = "release-certification-summary"
    blockers: list[dict[str, Any]] = []
    if not isinstance(release_certification, dict):
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.release-certification",
                "Release certification summary is missing",
                "Stable 1.0 readiness requires a passing release-certification summary.",
                "release-certification-summary",
            )
        )
    else:
        schema_version = release_certification.get("schemaVersion")
        tool = str(release_certification.get("tool", "missing"))
        status = normalize_status(release_certification.get("status", "missing"))
        mode = str(release_certification.get("mode", "missing"))
        release_candidate_passed = release_certification.get("releaseCandidatePassed")
        ecosystem_rc_passed = release_certification.get("ecosystemRcPassed")
        evidence_records = release_certification.get("evidence")
        if not schema_version_is_current(schema_version) or tool != "release-certification":
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.release-certification",
                    "Release certification summary schema is malformed",
                    (
                        "Stable 1.0 readiness requires schemaVersion=1 and "
                        f"tool=release-certification; schemaVersion is {schema_version!r}, tool is {tool}."
                    ),
                    "release-certification-summary",
                )
            )
        if not isinstance(evidence_records, list) or not evidence_records:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.release-certification",
                    "Release certification evidence is missing",
                    "Stable 1.0 readiness requires a non-empty release-certification evidence array.",
                    "release-certification-summary",
                )
            )
        elif any(not isinstance(entry, dict) for entry in evidence_records):
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.release-certification",
                    "Release certification evidence is malformed",
                    "Stable 1.0 readiness requires every release-certification evidence entry to be an object.",
                    "release-certification-summary",
                )
            )
        else:
            malformed_evidence_indexes = [
                str(index)
                for index, entry in enumerate(evidence_records)
                if not non_empty_string(entry.get("id")) or normalize_status(entry.get("status", "missing")) == "missing"
            ]
            if malformed_evidence_indexes:
                blockers.append(
                    blocker_issue(
                        domain_id,
                        "stable-1.0.release-certification",
                        "Release certification evidence is malformed",
                        "Release-certification evidence entries must include id and status; malformed indexes: "
                        + ", ".join(malformed_evidence_indexes)
                        + ".",
                        "release-certification-summary",
                    )
                )
        if mode != "release-candidate":
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.release-certification",
                    "Release certification summary is not from release-candidate mode",
                    f"Stable 1.0 readiness requires release-candidate certification evidence; mode is {mode}.",
                    "release-certification-summary",
                )
            )
        if status != "pass" or release_candidate_passed is not True or ecosystem_rc_passed is not True:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.release-certification",
                    "Release certification summary is not passing",
                    (
                        "Stable 1.0 readiness requires release-certification status pass "
                        "with releaseCandidatePassed=true and ecosystemRcPassed=true; "
                        f"status is {status}, releaseCandidatePassed is {release_candidate_passed!r}, "
                        f"ecosystemRcPassed is {ecosystem_rc_passed!r}."
                    ),
                    "release-certification-summary",
                )
            )
        redaction = (
            release_certification.get("redaction")
            if isinstance(release_certification.get("redaction"), dict)
            else None
        )
        redaction_passed, _redaction_details = release_certification_redaction_passed(redaction)
        if not redaction_passed:
            blockers.append(
                blocker_issue(
                    domain_id,
                    "stable-1.0.redaction",
                    "Release certification redaction evidence is missing or failed",
                    "Stable 1.0 readiness cannot use redaction-unsafe release-certification artifacts.",
                    "release-certification-summary",
                )
            )
    return domain_result(
        domain_id,
        "Release certification aggregate",
        ("stable-1.0.release-certification",),
        blockers,
        [],
    )

def evaluate_ecosystem_matrix(matrix: dict[str, Any] | None) -> dict[str, Any]:
    domain_id = "ecosystem-certification-matrix"
    evidence_id = "release-certification.ecosystem-matrix"
    blockers: list[dict[str, Any]] = []
    if not isinstance(matrix, dict):
        blockers.append(
            blocker_issue(
                domain_id,
                evidence_id,
                "Ecosystem certification matrix is missing",
                "Stable 1.0 readiness requires the ecosystem certification matrix.",
                "ecosystem-certification-matrix",
            )
        )
        return domain_result(domain_id, "Ecosystem certification matrix", (evidence_id,), blockers, [])
    envelope_errors = schema_tool_errors(
        matrix,
        expected_tool=certification.TOOL_NAME,
        evidence_label="ecosystemMatrix",
    )
    if matrix.get("kind") != "ecosystem-certification-matrix":
        envelope_errors.append("ecosystemMatrix.kind must be ecosystem-certification-matrix")
    if matrix.get("mode") != "release-candidate":
        envelope_errors.append("ecosystemMatrix.mode must be release-candidate")
    if envelope_errors:
        blockers.append(
            blocker_issue(
                domain_id,
                evidence_id,
                "Ecosystem certification matrix schema is malformed",
                "; ".join(envelope_errors) + ".",
                "ecosystem-certification-matrix",
            )
        )
    status = normalize_status(matrix.get("status"))
    release_blocker_count, malformed_release_blocker_count = dashboard.parse_release_blocker_count(
        matrix.get("releaseBlockerCount", 0)
    )
    rows_value = matrix.get("rows")
    rows: list[dict[str, Any]] = []
    if not isinstance(rows_value, list) or not rows_value:
        blockers.append(
            blocker_issue(
                domain_id,
                evidence_id,
                "Ecosystem certification matrix rows are missing",
                "Stable 1.0 readiness requires a non-empty ecosystem matrix rows array.",
                "ecosystem-certification-matrix",
            )
        )
    else:
        malformed_row_indexes = [
            str(index)
            for index, row in enumerate(rows_value)
            if not isinstance(row, dict)
        ]
        if malformed_row_indexes:
            blockers.append(
                blocker_issue(
                    domain_id,
                    evidence_id,
                    "Ecosystem certification matrix rows are malformed",
                    "Matrix rows must be objects; malformed row indexes: " + ", ".join(malformed_row_indexes) + ".",
                    "ecosystem-certification-matrix",
                )
            )
        else:
            malformed_shape_indexes = [
                str(index)
                for index, row in enumerate(rows_value)
                if not non_empty_string(row.get("id"))
                or normalize_status(row.get("status", "missing")) == "missing"
                or not isinstance(row.get("releaseBlocker"), bool)
            ]
            if malformed_shape_indexes:
                blockers.append(
                    blocker_issue(
                        domain_id,
                        evidence_id,
                        "Ecosystem certification matrix row shape is malformed",
                        "Matrix rows must include id, status, and boolean releaseBlocker; malformed row indexes: "
                        + ", ".join(malformed_shape_indexes)
                        + ".",
                        "ecosystem-certification-matrix",
                    )
                )
        rows = [row for row in rows_value if isinstance(row, dict)]
    row_ids = [non_empty_string(row.get("id")) for row in rows if non_empty_string(row.get("id"))]
    expected_row_ids = set(ECOSYSTEM_MATRIX_REQUIRED_ROW_IDS)
    actual_row_ids = set(row_ids)
    missing_row_ids = sorted(expected_row_ids - actual_row_ids)
    duplicate_row_ids = sorted(
        row_id for row_id in actual_row_ids if row_ids.count(row_id) > 1
    )
    unexpected_row_ids = sorted(actual_row_ids - expected_row_ids)
    if missing_row_ids or duplicate_row_ids or unexpected_row_ids:
        row_id_errors: list[str] = []
        if missing_row_ids:
            row_id_errors.append("missing required row IDs: " + ", ".join(missing_row_ids))
        if duplicate_row_ids:
            row_id_errors.append("duplicate row IDs: " + ", ".join(duplicate_row_ids))
        if unexpected_row_ids:
            row_id_errors.append("unexpected row IDs: " + ", ".join(unexpected_row_ids))
        blockers.append(
            blocker_issue(
                domain_id,
                evidence_id,
                "Ecosystem certification matrix row set is incomplete",
                "Ecosystem certification matrix " + "; ".join(row_id_errors) + ".",
                "ecosystem-certification-matrix",
            )
        )
    counts = matrix.get("counts") if isinstance(matrix.get("counts"), dict) else {}
    row_count, malformed_row_count = (
        non_negative_count(counts.get("rows"))
        if "rows" in counts
        else (len(rows), False)
    )
    row_count_mismatch = (
        "rows" in counts
        and isinstance(rows_value, list)
        and row_count != len(rows_value)
    )
    if malformed_row_count or row_count_mismatch:
        details = (
            "counts.rows is not a non-negative integer"
            if malformed_row_count
            else f"counts.rows is {row_count}, but rows contains {len(rows_value)} entries"
        )
        blockers.append(
            blocker_issue(
                domain_id,
                evidence_id,
                "Ecosystem certification matrix row count is malformed",
                details + ".",
                "ecosystem-certification-matrix",
            )
        )
    if status != "pass" or malformed_release_blocker_count or release_blocker_count > 0:
        details: list[str] = []
        if status != "pass":
            details.append(f"status is {status}")
        if malformed_release_blocker_count:
            details.append("releaseBlockerCount is not a non-negative integer")
        elif release_blocker_count > 0:
            details.append(f"releaseBlockerCount is {release_blocker_count}")
        blockers.append(
            blocker_issue(
                domain_id,
                evidence_id,
                "Ecosystem certification matrix is not Stable-ready",
                "Ecosystem certification matrix "
                + ("; ".join(details) if details else "contains release blockers")
                + ".",
                "ecosystem-certification-matrix",
            )
        )
    coverage = matrix.get("coverage") if isinstance(matrix.get("coverage"), dict) else {}
    if coverage.get("redactionPassed") is False:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.redaction",
                "Ecosystem matrix redaction coverage failed",
                "Stable 1.0 readiness cannot depend on a matrix whose coverage reports redactionPassed=false.",
                "ecosystem-certification-matrix",
            )
        )
    redaction_failed_sources: list[str] = []
    if recursive_redaction_field_failure(coverage):
        redaction_failed_sources.append("coverage")
    for row in rows:
        row_id = str(row.get("id", "matrix-row"))
        if recursive_redaction_field_failure(row):
            redaction_failed_sources.append(row_id)
    if redaction_failed_sources:
        blockers.append(
            blocker_issue(
                domain_id,
                "stable-1.0.redaction",
                "Ecosystem matrix contains redaction failures",
                "Stable 1.0 readiness cannot depend on matrix coverage or rows with redaction findings: "
                + ", ".join(redaction_failed_sources)
                + ".",
                "ecosystem-certification-matrix",
            )
        )
    non_passing_rows = [
        f"{row.get('id', 'matrix-row')}:{normalize_status(row.get('status', 'missing'))}"
        for row in rows
        if normalize_status(row.get("status", "missing"))
        in {"warn", "fail", "missing", "skip"}
    ]
    if non_passing_rows:
        blockers.append(
            blocker_issue(
                domain_id,
                evidence_id,
                "Ecosystem matrix rows are not passing",
                "Ecosystem matrix rows are non-passing: "
                + ", ".join(non_passing_rows)
                + ".",
                "ecosystem-certification-matrix",
            )
        )
    for row in rows:
        row_id = str(row.get("id", "matrix-row"))
        if row.get("releaseBlocker") is not True:
            continue
        blockers.append(
            blocker_issue(
                domain_id,
                row_id,
                "Ecosystem matrix row is release-blocking",
                f"Ecosystem matrix row {row_id} is marked releaseBlocker=true.",
                "ecosystem-certification-matrix",
            )
        )
    return domain_result(domain_id, "Ecosystem certification matrix", (evidence_id,), blockers, [])
