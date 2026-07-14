"""Implementation segment for the gates portion of ``release_certification.py``."""

from __future__ import annotations

def evaluate_platform_api_gate(
    current: dict[str, dict[str, Any]],
    previous: dict[str, dict[str, Any]],
    mode: str,
    require_history: bool,
) -> GateResult:
    current_item = current.get("platform-api.contract")
    previous_item = previous.get("platform-api.contract")
    current_status = evidence_status(current_item)
    details = {"currentStatus": current_status}
    failures: list[str] = []
    warnings: list[str] = []
    if current_status in {"fail", "missing", "skip"}:
        failures.append("Platform API contract evidence is not passing")
    elif current_status == "warn":
        warnings.append("Platform API contract evidence is warning")
    for evidence_id in PLATFORM_API_STABLE_FREEZE_EVIDENCE_IDS:
        evidence = current.get(evidence_id)
        status = evidence_status(evidence)
        details.setdefault("stableFreezeEvidence", {})[evidence_id] = status
        if status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is not passing")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
        elif status == "warn":
            if mode == "release-candidate" and require_history:
                failures.append(f"{evidence_id} evidence is warning in release-candidate mode")
                add_evidence_issue(details, "failureEvidenceIds", evidence_id)
            else:
                warnings.append(f"{evidence_id} evidence is warning")
                add_evidence_issue(details, "warningEvidenceIds", evidence_id)
    current_details = evidence_details(current_item)
    previous_details = evidence_details(previous_item)
    current_baseline_reported = stable_baseline_reported(current_details)
    previous_baseline_reported = stable_baseline_reported(previous_details)
    current_window = current_details.get("compatibilityWindow")
    previous_window = previous_details.get("compatibilityWindow")
    if not isinstance(current_window, dict):
        failures.append("Current Platform API compatibility-window metadata is unavailable")
        add_evidence_issue(details, "failureEvidenceIds", "platform-api.compatibility-window")
        add_evidence_issue(
            details, "unwaivableFailureEvidenceIds", "platform-api.compatibility-window"
        )
        current_window = {}
    if current_window.get("criticalStableRemovalWaiverAllowed") is not False:
        failures.append("Critical stable API removal waiver policy is not explicitly rejected")
        add_evidence_issue(details, "failureEvidenceIds", "platform-api.deprecation-window-policy")
        add_evidence_issue(
            details, "unwaivableFailureEvidenceIds", "platform-api.deprecation-window-policy"
        )
    if previous_details and not isinstance(previous_window, dict):
        message = "Previous Platform API compatibility-window metadata is unavailable"
        if mode == "release-candidate" and require_history:
            failures.append(message)
            add_evidence_issue(
                details, "failureEvidenceIds", "platform-api.previous-contract-snapshot"
            )
            add_evidence_issue(
                details,
                "unwaivableFailureEvidenceIds",
                "platform-api.previous-contract-snapshot",
            )
        else:
            warnings.append(message)
            add_evidence_issue(
                details, "warningEvidenceIds", "platform-api.previous-contract-snapshot"
            )
    elif isinstance(previous_window, dict):
        previous_baseline_name = previous_window.get("baselineName")
        current_baseline_name = current_window.get("baselineName")
        previous_baseline_contract = previous_window.get("baselineContractVersion")
        current_baseline_contract = current_window.get("baselineContractVersion")
        if (
            previous_baseline_name != current_baseline_name
            or previous_baseline_contract != current_baseline_contract
        ):
            failures.append("Platform API compatibility-window baseline identity changed")
            add_evidence_issue(
                details, "failureEvidenceIds", "platform-api.stable-breaking-change-check"
            )
            add_evidence_issue(
                details,
                "unwaivableFailureEvidenceIds",
                "platform-api.stable-breaking-change-check",
            )
    details["current"] = {
        "contractVersion": current_details.get("contractVersion"),
        "endpointCount": current_details.get("endpointCount"),
        "capabilityCount": current_details.get("capabilityCount"),
        "compatibilityWindow": current_window,
        "stableDescriptorCount": stable_descriptor_count(current_details),
        "stableBaselineCapabilityCount": stable_baseline_count(
            current_details,
            "capabilityCount",
            "stableBaselineCapabilityCount",
            "capabilities",
            "stableBaselineCapabilities",
        ),
        "stableBaselineEndpointCount": stable_baseline_count(
            current_details,
            "endpointCount",
            "stableBaselineEndpointCount",
            "endpoints",
            "stableBaselineEndpoints",
        ),
        "stableEndpointCapabilitySetCount": len(stable_endpoint_capability_map(current_details)),
        "stableEndpointActionLabelSetCount": len(stable_endpoint_action_label_map(current_details)),
        "stableEndpointAppAccessSetCount": len(stable_endpoint_access_map(current_details)),
        "flaggedStability": current_details.get("flaggedStability", []),
    }
    if previous_details:
        details["previous"] = {
            "contractVersion": previous_details.get("contractVersion"),
            "endpointCount": previous_details.get("endpointCount"),
            "capabilityCount": previous_details.get("capabilityCount"),
            "compatibilityWindow": previous_window if isinstance(previous_window, dict) else None,
            "stableDescriptorCount": stable_descriptor_count(previous_details),
            "stableBaselineCapabilityCount": stable_baseline_count(
                previous_details,
                "capabilityCount",
                "stableBaselineCapabilityCount",
                "capabilities",
                "stableBaselineCapabilities",
            ),
            "stableBaselineEndpointCount": stable_baseline_count(
                previous_details,
                "endpointCount",
                "stableBaselineEndpointCount",
                "endpoints",
                "stableBaselineEndpoints",
            ),
            "stableEndpointCapabilitySetCount": len(stable_endpoint_capability_map(previous_details)),
            "stableEndpointActionLabelSetCount": len(
                stable_endpoint_action_label_map(previous_details)
            ),
            "stableEndpointAppAccessSetCount": len(stable_endpoint_access_map(previous_details)),
        }
    previous_version = detail_int(previous_details, "contractVersion")
    current_version = detail_int(current_details, "contractVersion")
    if previous_version is not None and current_version is not None and current_version < previous_version:
        failures.append(f"Contract version moved backward from {previous_version} to {current_version}")
    if current_baseline_reported and previous_details and not previous_baseline_reported:
        if mode == "release-candidate" and require_history:
            failures.append(
                "Previous Platform API stable baseline metadata is unavailable; "
                "stable baseline comparison is required"
            )
            add_evidence_issue(
                details, "failureEvidenceIds", "platform-api.previous-contract-snapshot"
            )
            add_evidence_issue(
                details, "failureEvidenceIds", "platform-api.stable-breaking-change-check"
            )
            add_evidence_issue(
                details,
                "unwaivableFailureEvidenceIds",
                "platform-api.previous-contract-snapshot",
            )
            add_evidence_issue(
                details,
                "unwaivableFailureEvidenceIds",
                "platform-api.stable-breaking-change-check",
            )
        else:
            warnings.append(
                "Previous Platform API stable baseline metadata is unavailable; "
                "stable baseline comparison is status-limited"
            )
            add_evidence_issue(
                details, "warningEvidenceIds", "platform-api.stable-breaking-change-check"
            )
    compared_stable_baseline_counts = False
    if current_baseline_reported and previous_baseline_reported:
        for baseline_count_key, explicit_count_key, label in (
            ("endpointCount", "stableBaselineEndpointCount", "endpoint"),
            ("capabilityCount", "stableBaselineCapabilityCount", "capability"),
        ):
            previous_count = stable_baseline_count(
                previous_details,
                baseline_count_key,
                explicit_count_key,
                "endpoints" if label == "endpoint" else "capabilities",
                "stableBaselineEndpoints" if label == "endpoint" else "stableBaselineCapabilities",
            )
            current_count = stable_baseline_count(
                current_details,
                baseline_count_key,
                explicit_count_key,
                "endpoints" if label == "endpoint" else "capabilities",
                "stableBaselineEndpoints" if label == "endpoint" else "stableBaselineCapabilities",
            )
            if previous_count is None or current_count is None:
                continue
            compared_stable_baseline_counts = True
            if current_count < previous_count:
                failures.append(
                    f"Stable baseline {label} count decreased from {previous_count} to {current_count}"
                )
                add_evidence_issue(
                    details, "failureEvidenceIds", "platform-api.stable-breaking-change-check"
                )
                add_evidence_issue(
                    details,
                    "unwaivableFailureEvidenceIds",
                    "platform-api.stable-breaking-change-check",
                )
    if (
        not compared_stable_baseline_counts
        and not current_baseline_reported
        and not previous_baseline_reported
    ):
        previous_stable_count = stable_descriptor_count(previous_details)
        current_stable_count = stable_descriptor_count(current_details)
        if (
            previous_stable_count is not None
            and current_stable_count is not None
            and current_stable_count < previous_stable_count
        ):
            failures.append(
                "Stable Platform API descriptor count decreased from "
                f"{previous_stable_count} to {current_stable_count}"
            )
    if current_baseline_reported or previous_baseline_reported:
        previous_endpoints = stable_baseline_named_set(
            previous_details,
            "endpoints",
            "stableBaselineEndpoints",
            "stableEndpoints",
            "endpoints",
        )
        current_endpoints = stable_baseline_named_set(
            current_details,
            "endpoints",
            "stableBaselineEndpoints",
            "stableEndpoints",
            "endpoints",
        )
        current_endpoints_reported = stable_baseline_named_set_reported(
            current_details, "endpoints", "stableBaselineEndpoints"
        )
    else:
        previous_endpoints = stable_named_set(previous_details, "stableEndpoints", "endpoints")
        current_endpoints = stable_named_set(current_details, "stableEndpoints", "endpoints")
        current_endpoints_reported = stable_named_set_reported(
            current_details, "stableEndpoints", "endpoints"
        )
    removed_endpoints = (
        sorted(previous_endpoints - current_endpoints)
        if previous_endpoints
        and current_endpoints_reported
        and (previous_baseline_reported or not current_baseline_reported)
        else []
    )
    if removed_endpoints:
        failures.append(f"Stable endpoints were removed: {', '.join(removed_endpoints)}")
        add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
        add_evidence_issue(
            details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
        )
    previous_endpoint_metadata_keys = stable_endpoint_metadata_keys(previous_details)
    current_endpoint_metadata_keys = stable_endpoint_metadata_keys(current_details)
    previous_endpoint_capabilities = stable_endpoint_capability_map(previous_details)
    current_endpoint_capabilities = stable_endpoint_capability_map(current_details)
    previous_endpoint_capabilities_reported = stable_endpoint_capability_map_reported(previous_details)
    current_endpoint_capabilities_reported = stable_endpoint_capability_map_reported(current_details)
    missing_current_endpoint_capabilities = sorted(
        current_endpoint_metadata_keys - set(current_endpoint_capabilities)
    )
    missing_previous_endpoint_capabilities = sorted(
        previous_endpoint_metadata_keys - set(previous_endpoint_capabilities)
    )
    current_endpoint_capability_count_gap = stable_endpoint_metadata_count_gap(
        current_details, current_endpoint_capabilities
    )
    previous_endpoint_capability_count_gap = stable_endpoint_metadata_count_gap(
        previous_details, previous_endpoint_capabilities
    )
    if current_endpoints and not current_endpoint_capabilities_reported:
        failures.append("Current stable endpoint required-capability metadata is unavailable")
        add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
        add_evidence_issue(
            details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
        )
    elif missing_current_endpoint_capabilities or current_endpoint_capability_count_gap:
        if missing_current_endpoint_capabilities:
            failures.append(
                "Current stable endpoint required-capability metadata is incomplete: "
                + ", ".join(missing_current_endpoint_capabilities)
            )
            details["stableEndpointRequiredCapabilitiesMissing"] = (
                missing_current_endpoint_capabilities
            )
        else:
            failures.append(
                "Current stable endpoint required-capability metadata is incomplete: "
                f"expected {current_endpoint_capability_count_gap['expected']} entries, "
                f"found {current_endpoint_capability_count_gap['actual']}"
            )
            details["stableEndpointRequiredCapabilitiesExpectedCount"] = (
                current_endpoint_capability_count_gap["expected"]
            )
            details["stableEndpointRequiredCapabilitiesSetCount"] = (
                current_endpoint_capability_count_gap["actual"]
            )
        add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
        add_evidence_issue(
            details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
        )
    elif previous_endpoints and previous_baseline_reported and (
        not previous_endpoint_capabilities_reported
        or missing_previous_endpoint_capabilities
        or previous_endpoint_capability_count_gap
    ):
        if previous_endpoint_capabilities_reported:
            if missing_previous_endpoint_capabilities:
                message = (
                    "Previous stable endpoint required-capability metadata is incomplete: "
                    + ", ".join(missing_previous_endpoint_capabilities)
                )
                details["previousStableEndpointRequiredCapabilitiesMissing"] = (
                    missing_previous_endpoint_capabilities
                )
            else:
                message = (
                    "Previous stable endpoint required-capability metadata is incomplete: "
                    f"expected {previous_endpoint_capability_count_gap['expected']} entries, "
                    f"found {previous_endpoint_capability_count_gap['actual']}"
                )
                details["previousStableEndpointRequiredCapabilitiesExpectedCount"] = (
                    previous_endpoint_capability_count_gap["expected"]
                )
                details["previousStableEndpointRequiredCapabilitiesSetCount"] = (
                    previous_endpoint_capability_count_gap["actual"]
                )
        else:
            message = "Previous stable endpoint required-capability metadata is unavailable"
        if mode == "release-candidate" and require_history:
            failures.append(message)
            add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
            add_evidence_issue(
                details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
            )
        else:
            warnings.append(message)
            add_evidence_issue(details, "warningEvidenceIds", "platform-api.stable-breaking-change-check")
    elif (
        previous_endpoint_capabilities
        and current_endpoint_capabilities_reported
        and (previous_baseline_reported or not current_baseline_reported)
    ):
        changed_endpoint_capabilities = []
        for endpoint in sorted(set(previous_endpoint_capabilities) & set(current_endpoint_capabilities)):
            previous_caps = previous_endpoint_capabilities[endpoint]
            current_caps = current_endpoint_capabilities[endpoint]
            if previous_caps != current_caps:
                changed_endpoint_capabilities.append(
                    {
                        "endpoint": endpoint,
                        "previous": list(previous_caps),
                        "current": list(current_caps),
                    }
                )
        if changed_endpoint_capabilities:
            failures.append(
                "Stable endpoint required capabilities changed: "
                + ", ".join(change["endpoint"] for change in changed_endpoint_capabilities)
            )
            add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
            add_evidence_issue(
                details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
            )
            details["stableEndpointCapabilityChanges"] = changed_endpoint_capabilities
    previous_endpoint_access = stable_endpoint_access_map(previous_details)
    current_endpoint_access = stable_endpoint_access_map(current_details)
    previous_endpoint_access_reported = stable_endpoint_access_map_reported(previous_details)
    current_endpoint_access_reported = stable_endpoint_access_map_reported(current_details)
    missing_current_endpoint_access = sorted(current_endpoint_metadata_keys - set(current_endpoint_access))
    missing_previous_endpoint_access = sorted(previous_endpoint_metadata_keys - set(previous_endpoint_access))
    current_endpoint_access_count_gap = stable_endpoint_metadata_count_gap(
        current_details, current_endpoint_access
    )
    previous_endpoint_access_count_gap = stable_endpoint_metadata_count_gap(
        previous_details, previous_endpoint_access
    )
    if current_endpoints and not current_endpoint_access_reported:
        failures.append("Current stable endpoint app-principal access metadata is unavailable")
        add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
        add_evidence_issue(
            details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
        )
    elif missing_current_endpoint_access or current_endpoint_access_count_gap:
        if missing_current_endpoint_access:
            failures.append(
                "Current stable endpoint app-principal access metadata is incomplete: "
                + ", ".join(missing_current_endpoint_access)
            )
            details["stableEndpointAppAccessMissing"] = missing_current_endpoint_access
        else:
            failures.append(
                "Current stable endpoint app-principal access metadata is incomplete: "
                f"expected {current_endpoint_access_count_gap['expected']} entries, "
                f"found {current_endpoint_access_count_gap['actual']}"
            )
            details["stableEndpointAppAccessExpectedCount"] = (
                current_endpoint_access_count_gap["expected"]
            )
            details["stableEndpointAppAccessSetCount"] = current_endpoint_access_count_gap[
                "actual"
            ]
        add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
        add_evidence_issue(
            details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
        )
    elif previous_endpoints and previous_baseline_reported and (
        not previous_endpoint_access_reported
        or missing_previous_endpoint_access
        or previous_endpoint_access_count_gap
    ):
        if previous_endpoint_access_reported:
            if missing_previous_endpoint_access:
                message = (
                    "Previous stable endpoint app-principal access metadata is incomplete: "
                    + ", ".join(missing_previous_endpoint_access)
                )
                details["previousStableEndpointAppAccessMissing"] = missing_previous_endpoint_access
            else:
                message = (
                    "Previous stable endpoint app-principal access metadata is incomplete: "
                    f"expected {previous_endpoint_access_count_gap['expected']} entries, "
                    f"found {previous_endpoint_access_count_gap['actual']}"
                )
                details["previousStableEndpointAppAccessExpectedCount"] = (
                    previous_endpoint_access_count_gap["expected"]
                )
                details["previousStableEndpointAppAccessSetCount"] = (
                    previous_endpoint_access_count_gap["actual"]
                )
        else:
            message = "Previous stable endpoint app-principal access metadata is unavailable"
        if mode == "release-candidate" and require_history:
            failures.append(message)
            add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
            add_evidence_issue(
                details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
            )
        else:
            warnings.append(message)
            add_evidence_issue(details, "warningEvidenceIds", "platform-api.stable-breaking-change-check")
    elif (
        previous_endpoint_access
        and current_endpoint_access_reported
        and (previous_baseline_reported or not current_baseline_reported)
    ):
        changed_endpoint_access = []
        for endpoint in sorted(set(previous_endpoint_access) & set(current_endpoint_access)):
            previous_access = previous_endpoint_access[endpoint]
            current_access = current_endpoint_access[endpoint]
            if previous_access != current_access:
                changed_endpoint_access.append(
                    {
                        "endpoint": endpoint,
                        "previous": endpoint_access_detail(previous_access),
                        "current": endpoint_access_detail(current_access),
                    }
                )
        if changed_endpoint_access:
            failures.append(
                "Stable endpoint app-principal access changed: "
                + ", ".join(change["endpoint"] for change in changed_endpoint_access)
            )
            add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
            add_evidence_issue(
                details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
            )
            details["stableEndpointAccessChanges"] = changed_endpoint_access
    previous_endpoint_action_labels = stable_endpoint_action_label_map(previous_details)
    current_endpoint_action_labels = stable_endpoint_action_label_map(current_details)
    previous_endpoint_action_labels_reported = stable_endpoint_action_label_map_reported(
        previous_details
    )
    current_endpoint_action_labels_reported = stable_endpoint_action_label_map_reported(
        current_details
    )
    missing_current_endpoint_action_labels = sorted(
        current_endpoint_metadata_keys - set(current_endpoint_action_labels)
    )
    missing_previous_endpoint_action_labels = sorted(
        previous_endpoint_metadata_keys - set(previous_endpoint_action_labels)
    )
    current_endpoint_action_label_count_gap = stable_endpoint_metadata_count_gap(
        current_details, current_endpoint_action_labels
    )
    previous_endpoint_action_label_count_gap = stable_endpoint_metadata_count_gap(
        previous_details, previous_endpoint_action_labels
    )
    if current_endpoints and not current_endpoint_action_labels_reported:
        failures.append("Current stable endpoint action-label metadata is unavailable")
        add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
        add_evidence_issue(
            details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
        )
    elif missing_current_endpoint_action_labels or current_endpoint_action_label_count_gap:
        if missing_current_endpoint_action_labels:
            failures.append(
                "Current stable endpoint action-label metadata is incomplete: "
                + ", ".join(missing_current_endpoint_action_labels)
            )
            details["stableEndpointActionLabelsMissing"] = (
                missing_current_endpoint_action_labels
            )
        else:
            failures.append(
                "Current stable endpoint action-label metadata is incomplete: "
                f"expected {current_endpoint_action_label_count_gap['expected']} entries, "
                f"found {current_endpoint_action_label_count_gap['actual']}"
            )
            details["stableEndpointActionLabelsExpectedCount"] = (
                current_endpoint_action_label_count_gap["expected"]
            )
            details["stableEndpointActionLabelsSetCount"] = (
                current_endpoint_action_label_count_gap["actual"]
            )
        add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
        add_evidence_issue(
            details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
        )
    elif previous_endpoints and previous_baseline_reported and (
        not previous_endpoint_action_labels_reported
        or missing_previous_endpoint_action_labels
        or previous_endpoint_action_label_count_gap
    ):
        if previous_endpoint_action_labels_reported:
            if missing_previous_endpoint_action_labels:
                message = (
                    "Previous stable endpoint action-label metadata is incomplete: "
                    + ", ".join(missing_previous_endpoint_action_labels)
                )
                details["previousStableEndpointActionLabelsMissing"] = (
                    missing_previous_endpoint_action_labels
                )
            else:
                message = (
                    "Previous stable endpoint action-label metadata is incomplete: "
                    f"expected {previous_endpoint_action_label_count_gap['expected']} entries, "
                    f"found {previous_endpoint_action_label_count_gap['actual']}"
                )
                details["previousStableEndpointActionLabelsExpectedCount"] = (
                    previous_endpoint_action_label_count_gap["expected"]
                )
                details["previousStableEndpointActionLabelsSetCount"] = (
                    previous_endpoint_action_label_count_gap["actual"]
                )
        else:
            message = "Previous stable endpoint action-label metadata is unavailable"
        if mode == "release-candidate" and require_history:
            failures.append(message)
            add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
            add_evidence_issue(
                details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
            )
        else:
            warnings.append(message)
            add_evidence_issue(details, "warningEvidenceIds", "platform-api.stable-breaking-change-check")
    elif (
        previous_endpoint_action_labels
        and current_endpoint_action_labels_reported
        and (previous_baseline_reported or not current_baseline_reported)
    ):
        missing_endpoint_action_labels = sorted(
            set(previous_endpoint_action_labels) - set(current_endpoint_action_labels)
        )
        if missing_endpoint_action_labels:
            failures.append(
                "Current stable endpoint action-label metadata is incomplete: "
                + ", ".join(missing_endpoint_action_labels)
            )
            add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
            add_evidence_issue(
                details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
            )
            details["stableEndpointActionLabelsMissing"] = missing_endpoint_action_labels
        changed_endpoint_action_labels = []
        for endpoint in sorted(
            set(previous_endpoint_action_labels) & set(current_endpoint_action_labels)
        ):
            previous_label = previous_endpoint_action_labels[endpoint]
            current_label = current_endpoint_action_labels[endpoint]
            if previous_label != current_label:
                changed_endpoint_action_labels.append(
                    {
                        "endpoint": endpoint,
                        "previous": previous_label,
                        "current": current_label,
                    }
                )
        if changed_endpoint_action_labels:
            failures.append(
                "Stable endpoint action labels changed: "
                + ", ".join(change["endpoint"] for change in changed_endpoint_action_labels)
            )
            add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
            add_evidence_issue(
                details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
            )
            details["stableEndpointActionLabelChanges"] = changed_endpoint_action_labels
    if current_baseline_reported or previous_baseline_reported:
        previous_capabilities = stable_baseline_named_set(
            previous_details,
            "capabilities",
            "stableBaselineCapabilities",
            "stableCapabilities",
            "capabilities",
        )
        current_capabilities = stable_baseline_named_set(
            current_details,
            "capabilities",
            "stableBaselineCapabilities",
            "stableCapabilities",
            "capabilities",
        )
        current_capabilities_reported = stable_baseline_named_set_reported(
            current_details, "capabilities", "stableBaselineCapabilities"
        )
    else:
        previous_capabilities = stable_named_set(previous_details, "stableCapabilities", "capabilities")
        current_capabilities = stable_named_set(current_details, "stableCapabilities", "capabilities")
        current_capabilities_reported = stable_named_set_reported(
            current_details, "stableCapabilities", "capabilities"
        )
    removed_capabilities = (
        sorted(previous_capabilities - current_capabilities)
        if previous_capabilities
        and current_capabilities_reported
        and (previous_baseline_reported or not current_baseline_reported)
        else []
    )
    if removed_capabilities:
        failures.append(f"Stable capabilities were removed: {', '.join(removed_capabilities)}")
        add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
        add_evidence_issue(
            details, "unwaivableFailureEvidenceIds", "platform-api.stable-breaking-change-check"
        )
    if current_details.get("flaggedStability"):
        warnings.append("Contract evidence contains stability warnings")
    if not previous_details:
        if mode == "release-candidate" and require_history:
            failures.append("Previous Platform API contract details were unavailable; stable baseline comparison is required")
            add_evidence_issue(details, "failureEvidenceIds", "platform-api.stable-breaking-change-check")
            add_evidence_issue(
                details,
                "unwaivableFailureEvidenceIds",
                "platform-api.stable-breaking-change-check",
            )
        else:
            warnings.append("Previous Platform API contract details were unavailable; comparison is status-limited")
            add_evidence_issue(details, "warningEvidenceIds", "platform-api.stable-breaking-change-check")
    if failures:
        add_evidence_issue(details, "failureEvidenceIds", "platform-api.contract")
    if warnings:
        add_evidence_issue(details, "warningEvidenceIds", "platform-api.contract")
    return gate_from_issues(
        "ecosystem.platform-api-compatibility",
        "Platform API compatibility evidence is stable.",
        failures,
        warnings,
        details,
    )

def evaluate_first_party_apps_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> GateResult:
    current_item = current.get("app-platform.first-party")
    previous_item = previous.get("app-platform.first-party")
    beta_quality_item = current.get(FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID)
    beta_quality_details = evidence_details(beta_quality_item)
    current_details = evidence_details(current_item)
    previous_details = evidence_details(previous_item)
    current_apps = app_ids_from_details(current_details)
    previous_apps = app_ids_from_details(previous_details)
    required_apps = set(EXPECTED_FIRST_PARTY_APPS)
    failures: list[str] = []
    warnings: list[str] = []
    status = evidence_status(current_item)
    if status in {"fail", "missing", "skip"}:
        failures.append("First-party app evidence is not passing")
    elif status == "warn":
        warnings.append("First-party app evidence is warning")
    beta_quality_status = evidence_status(beta_quality_item)
    if beta_quality_status in {"fail", "missing", "skip"}:
        failures.append("First-party beta-quality evidence is not passing")
    elif beta_quality_status == "warn":
        warnings.append("First-party beta-quality evidence is warning")
    missing_required = sorted(required_apps - current_apps)
    if missing_required:
        failures.append(f"Required first-party apps are absent: {', '.join(missing_required)}")
    disappeared = sorted(previous_apps - current_apps) if previous_apps else []
    if disappeared:
        failures.append(f"Previously certified first-party apps disappeared: {', '.join(disappeared)}")
    gate_details = {
        "currentApps": sorted(current_apps),
        "previousApps": sorted(previous_apps),
        "requiredApps": sorted(required_apps),
        "betaQualityStatus": beta_quality_status,
    }
    if status in {"fail", "missing", "skip"} or missing_required or disappeared:
        add_evidence_issue(gate_details, "failureEvidenceIds", "app-platform.first-party")
    if beta_quality_status in {"fail", "missing", "skip"}:
        add_evidence_issue(
            gate_details, "failureEvidenceIds", FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID
        )
    if status == "warn":
        add_evidence_issue(gate_details, "warningEvidenceIds", "app-platform.first-party")
    if beta_quality_status == "warn":
        add_evidence_issue(
            gate_details, "warningEvidenceIds", FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID
        )
    if beta_quality_details.get("redactionFindings"):
        add_evidence_issue(
            gate_details, "unwaivableFailureEvidenceIds", FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID
        )
    return gate_from_issues(
        "ecosystem.first-party-apps",
        "First-party app evidence covers required apps.",
        failures,
        warnings,
        gate_details,
    )

def evaluate_app_ui_quality_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> GateResult:
    failures: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {}
    for evidence_id in ("app-ui.lint", "app-ui.design-system", "app-ui.first-party-adoption"):
        status = evidence_status(current.get(evidence_id))
        previous_status = evidence_status(previous.get(evidence_id))
        details[evidence_id] = {"currentStatus": status, "previousStatus": previous_status}
        if status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is not passing")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
        elif status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            add_evidence_issue(details, "warningEvidenceIds", evidence_id)
        if previous_status == "pass" and status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} regressed from pass to {status}")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
    current_warnings = total_ui_warnings(evidence_details(current.get("app-ui.lint")))
    previous_warnings = total_ui_warnings(evidence_details(previous.get("app-ui.lint")))
    details["lintWarnings"] = {"current": current_warnings, "previous": previous_warnings}
    if current_warnings is not None and previous_warnings is not None and current_warnings > previous_warnings:
        warnings.append(f"UI lint warnings increased from {previous_warnings} to {current_warnings}")
        add_evidence_issue(details, "warningEvidenceIds", "app-ui.lint")
    return gate_from_issues(
        "ecosystem.app-ui-quality",
        "First-party app UI lint and design-system evidence passed.",
        failures,
        warnings,
        details,
    )

def evaluate_app_review_trust_gate(
    current: dict[str, dict[str, Any]],
    previous: dict[str, dict[str, Any]],
    metadata: dict[str, Any],
    mode: str,
) -> GateResult:
    failures: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {}
    for evidence_id in (
        "app-review.trusted-receipts",
        "app-review.policy",
        "app-review.governance",
        "app-review.reviewer-key-lifecycle",
        "app-review.transparency-log",
        "app-review.review-history-api",
        "app-review.first-party-catalog",
        "app-review.first-party-review-chain",
    ):
        status = evidence_status(current.get(evidence_id))
        previous_status = evidence_status(previous.get(evidence_id))
        details[evidence_id] = {"currentStatus": status, "previousStatus": previous_status}
        if status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is not passing")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
        elif status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            add_evidence_issue(details, "warningEvidenceIds", evidence_id)
        if previous_status == "pass" and status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} regressed from pass to {status}")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
    catalog_details = evidence_details(current.get("app-review.first-party-catalog"))
    coverage = nested_dict(catalog_details, "coverage")
    first_party_apps = sorted_strings(catalog_details.get("firstPartyApps"))
    trusted_positive = int_value(coverage.get("trustedPositiveReceipts"))
    missing_receipts = int_value(coverage.get("missingReceipts"))
    details["firstPartyReceiptCoverage"] = {
        "firstPartyApps": first_party_apps,
        "trustedPositiveReceipts": trusted_positive,
        "missingReceipts": missing_receipts,
    }
    if mode == "release-candidate":
        if trusted_positive is None or trusted_positive < len(first_party_apps):
            failures.append("First-party catalog lacks trusted positive review receipts for every app")
            add_evidence_issue(details, "failureEvidenceIds", "app-review.first-party-catalog")
        if missing_receipts and missing_receipts > 0:
            failures.append("First-party catalog has missing trusted review receipts")
            add_evidence_issue(details, "failureEvidenceIds", "app-review.first-party-catalog")
    policy_details = evidence_details(current.get("app-review.policy"))
    previous_policy_details = evidence_details(previous.get("app-review.policy"))
    policy_marker = policy_details.get("policyId") or policy_details.get("policyVersion") or policy_details.get("mode")
    previous_policy_marker = (
        previous_policy_details.get("policyId")
        or previous_policy_details.get("policyVersion")
        or previous_policy_details.get("mode")
    )
    if previous_policy_marker and policy_marker and previous_policy_marker != policy_marker:
        if not release_metadata_note_present(metadata, "releaseNotes", "reviewPolicyChange", "reviewPolicyVersion"):
            warnings.append("Review policy marker changed without release-note metadata")
            add_evidence_issue(details, "warningEvidenceIds", "app-review.policy")
    return gate_from_issues(
        "ecosystem.app-review-trust",
        "Trusted app-review receipt and policy evidence passed.",
        failures,
        warnings,
        details,
    )

def evaluate_app_update_rollback_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> GateResult:
    failures: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {}
    for evidence_id in (
        "app-update.lifecycle",
        "app-update.scheduler",
        "app-update.live-catalog-refresh",
        "app-update.rollback",
        "app-update.data-migration-contract",
    ):
        status = evidence_status(current.get(evidence_id))
        previous_status = evidence_status(previous.get(evidence_id))
        details[evidence_id] = {"currentStatus": status, "previousStatus": previous_status}
        if status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is not passing")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
        elif status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            add_evidence_issue(details, "warningEvidenceIds", evidence_id)
        if previous_status == "pass" and status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} regressed from pass to {status}")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
    rollback_details = evidence_details(current.get("app-update.rollback"))
    details["rollbackScope"] = rollback_details.get("rollbackScope")
    details["preservesDataCacheRun"] = rollback_details.get("preservesDataCacheRun")
    if rollback_details.get("rollbackScope") != "installed-bundle-only":
        warnings.append("Rollback evidence does not prove installed-bundle-only scope")
        add_evidence_issue(details, "warningEvidenceIds", "app-update.rollback")
    if rollback_details.get("preservesDataCacheRun") is not True:
        warnings.append("Rollback evidence does not prove data/cache/run preservation")
        add_evidence_issue(details, "warningEvidenceIds", "app-update.rollback")
    return gate_from_issues(
        "ecosystem.app-update-rollback",
        "App-update lifecycle, scheduler, and rollback evidence passed.",
        failures,
        warnings,
        details,
    )

def evaluate_operator_rc_recovery_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> GateResult:
    failures: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {"evidenceIds": list(OPERATOR_RC_EVIDENCE_IDS)}
    for evidence_id in OPERATOR_RC_EVIDENCE_IDS:
        status = evidence_status(current.get(evidence_id))
        previous_status = evidence_status(previous.get(evidence_id))
        details[evidence_id] = {"currentStatus": status, "previousStatus": previous_status}
        if status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is not passing")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
        elif status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            add_evidence_issue(details, "warningEvidenceIds", evidence_id)
        if previous_status == "pass" and status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} regressed from pass to {status}")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
    redaction_details = evidence_details(current.get("operator-rc.redaction"))
    checks = redaction_details.get("checks") if isinstance(redaction_details, dict) else None
    if isinstance(checks, dict) and checks.get("redactorTest") is not True:
        failures.append("Operator RC redaction evidence did not prove support-bundle redaction")
        add_evidence_issue(details, "failureEvidenceIds", "operator-rc.redaction")
    details["planBeforeExecute"] = evidence_status(current.get("operator-rc.recovery-plan-execute"))
    details["supportBundleWizard"] = evidence_status(current.get("operator-rc.support-bundle-wizard"))
    return gate_from_issues(
        "ecosystem.operator-rc-recovery",
        "Operator RC recovery and support workflow evidence passed.",
        failures,
        warnings,
        details,
    )

def evaluate_ecosystem_security_advisory_revocation_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> GateResult:
    failures: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {}
    for evidence_id in ECOSYSTEM_SECURITY_EVIDENCE_IDS:
        status = evidence_status(current.get(evidence_id))
        previous_status = evidence_status(previous.get(evidence_id))
        details[evidence_id] = {"currentStatus": status, "previousStatus": previous_status}
        if status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is not passing")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
        elif status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            add_evidence_issue(details, "warningEvidenceIds", evidence_id)
        if previous_status == "pass" and status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} regressed from pass to {status}")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
    redaction_details = evidence_details(
        current.get("ecosystem-security.advisory-revocation-redaction")
    )
    redaction = nested_dict(redaction_details, "redaction")
    if redaction and redaction.get("leaks"):
        failures.append("Ecosystem security redaction evidence contains forbidden payload leaks")
        add_evidence_issue(
            details, "failureEvidenceIds", "ecosystem-security.advisory-revocation-redaction"
        )
    details["evidenceIds"] = list(ECOSYSTEM_SECURITY_EVIDENCE_IDS)
    return gate_from_issues(
        "ecosystem.security-advisory-revocation",
        "Ecosystem security advisory, denylist, and review revocation evidence passed.",
        failures,
        warnings,
        details,
    )

def evaluate_live_network_beta_gate(
    current: dict[str, dict[str, Any]],
    settings: Settings,
) -> GateResult:
    entries = {
        evidence_id: current.get(evidence_id)
        for evidence_id in LIVE_NETWORK_BETA_EVIDENCE_IDS
    }
    details_by_id = {
        evidence_id: evidence_details(entry)
        for evidence_id, entry in entries.items()
    }
    enabled = settings.live_network_beta_enabled or any(
        bool(details.get("enabled")) for details in details_by_id.values()
    )
    required = settings.live_network_beta_required
    statuses = {
        evidence_id: evidence_status(entry)
        for evidence_id, entry in entries.items()
    }
    required_ids = [
        evidence_id
        for evidence_id in LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS
        if required or evidence_required(entries.get(evidence_id))
    ]
    failures: list[str] = []
    warnings: list[str] = []
    failure_evidence_ids: list[str] = []
    warning_evidence_ids: list[str] = []
    if not enabled and not required:
        return GateResult(
            "ecosystem.live-network-beta",
            "pass",
            False,
            "Live-network beta certification was not requested.",
            {
                "enabled": False,
                "required": False,
                "statuses": statuses,
                "requiredEvidenceIds": [],
                "optionalEvidenceIds": ["live-network-beta.app-service-score"],
                "node": {},
                "redaction": {},
                "stepCounts": {},
                "artifactPaths": [],
            },
        )
    for evidence_id in required_ids:
        status = statuses[evidence_id]
        if status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is {status}")
            add_evidence_issue(details_by_id.setdefault(evidence_id, {}), "failureEvidenceIds", evidence_id)
            failure_evidence_ids.append(evidence_id)
        elif status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            add_evidence_issue(details_by_id.setdefault(evidence_id, {}), "warningEvidenceIds", evidence_id)
            warning_evidence_ids.append(evidence_id)
    if enabled and not required:
        for evidence_id, status in statuses.items():
            if status in {"fail", "missing", "warn"}:
                warnings.append(f"{evidence_id} evidence is {status}")
                add_evidence_issue(details_by_id.setdefault(evidence_id, {}), "warningEvidenceIds", evidence_id)
                warning_evidence_ids.append(evidence_id)
    optional_service_status = statuses.get("live-network-beta.app-service-score", "missing")
    optional_service_details = details_by_id.get("live-network-beta.app-service-score", {})
    optional_service_requested = bool(optional_service_details.get("enabled"))
    if enabled and optional_service_status in {"fail", "missing", "warn"}:
        warnings.append(
            f"live-network-beta.app-service-score evidence is {optional_service_status}; app-service score invocation remains optional"
        )
        warning_evidence_ids.append("live-network-beta.app-service-score")
    elif enabled and optional_service_status == "skip" and optional_service_requested:
        warnings.append(
            "live-network-beta.app-service-score evidence is skip after score invocation was requested; app-service score invocation remains optional"
        )
        warning_evidence_ids.append("live-network-beta.app-service-score")
    redaction_status = statuses.get("live-network-beta.redaction", "missing")
    if redaction_status in {"fail", "missing", "skip"} and required:
        add_evidence_issue(details_by_id.setdefault("live-network-beta.redaction", {}), "failureEvidenceIds", "live-network-beta.redaction")
        failure_evidence_ids.append("live-network-beta.redaction")

    representative_details = next(
        (details for details in details_by_id.values() if details),
        {},
    )
    failures = sorted(dict.fromkeys(failures))
    warnings = sorted(dict.fromkeys(warnings))
    compact_details: dict[str, Any] = {
        "enabled": enabled,
        "required": required,
        "statuses": statuses,
        "requiredEvidenceIds": required_ids,
        "optionalEvidenceIds": ["live-network-beta.app-service-score"],
        "node": representative_details.get("node", {}),
        "redaction": representative_details.get("redaction", {}),
        "stepCounts": representative_details.get("stepCounts", {}),
        "artifactPaths": representative_details.get("artifactPaths", []),
    }
    if failures:
        compact_details["failureEvidenceIds"] = sorted(dict.fromkeys(failure_evidence_ids))
    if warnings:
        compact_details["warningEvidenceIds"] = sorted(dict.fromkeys(warning_evidence_ids))
    return gate_from_issues(
        "ecosystem.live-network-beta",
        "Live-network beta certification evidence is complete.",
        failures,
        warnings,
        compact_details,
    )

def evaluate_multi_node_beta_gate(
    current: dict[str, dict[str, Any]],
    settings: Settings,
) -> GateResult:
    entries = {evidence_id: current.get(evidence_id) for evidence_id in MULTI_NODE_BETA_EVIDENCE_IDS}
    statuses = {evidence_id: evidence_status(entry) for evidence_id, entry in entries.items()}
    details_by_id = {evidence_id: evidence_details(entry) for evidence_id, entry in entries.items()}
    required = settings.multi_node_soak_required or settings.mode == "release-candidate"
    failures: list[str] = []
    warnings: list[str] = []
    failure_evidence_ids: list[str] = []
    warning_evidence_ids: list[str] = []
    for evidence_id, status in statuses.items():
        if status in {"fail", "missing", "skip"}:
            message = f"{evidence_id} evidence is {status}"
            if required:
                failures.append(message)
                failure_evidence_ids.append(evidence_id)
            else:
                warnings.append(message)
                warning_evidence_ids.append(evidence_id)
        elif status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            warning_evidence_ids.append(evidence_id)
    redaction_details = details_by_id.get("multi-node-beta.redaction", {})
    redaction_findings = redaction_details.get("redactionFindings")
    if isinstance(redaction_findings, list) and redaction_findings:
        failures.append("multi-node-beta.redaction has unwaivable redaction findings")
        failure_evidence_ids.append("multi-node-beta.redaction")
    representative_details = details_by_id.get("multi-node-beta.soak", {})
    compact_details = {
        "required": required,
        "statuses": statuses,
        "mode": representative_details.get("mode", "missing"),
        "durationProfile": representative_details.get("durationProfile", "missing"),
        "promotionReady": bool(representative_details.get("promotionReady", False)),
        "scenarioStatuses": representative_details.get("scenarioStatuses", {}),
        "blockers": representative_details.get("blockers", []),
        "warnings": representative_details.get("warnings", []),
    }
    if failure_evidence_ids:
        compact_details["failureEvidenceIds"] = sorted(dict.fromkeys(failure_evidence_ids))
    if warning_evidence_ids:
        compact_details["warningEvidenceIds"] = sorted(dict.fromkeys(warning_evidence_ids))
    return gate_from_issues(
        "ecosystem.multi-node-beta",
        "Multi-node beta soak and upgrade drill evidence is complete.",
        sorted(dict.fromkeys(failures)),
        sorted(dict.fromkeys(warnings)),
        compact_details,
    )

def evaluate_app_vault_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> GateResult:
    item = current.get("app-vault.capabilities")
    previous_item = previous.get("app-vault.capabilities")
    status = evidence_status(item)
    previous_status = evidence_status(previous_item)
    vault_details = evidence_details(item)
    details: dict[str, Any] = {}
    failures: list[str] = []
    warnings: list[str] = []
    if status in {"fail", "missing", "skip"}:
        failures.append("Vault capability evidence is not passing")
        add_evidence_issue(details, "failureEvidenceIds", "app-vault.capabilities")
    elif status == "warn":
        warnings.append("Vault capability evidence is warning")
        add_evidence_issue(details, "warningEvidenceIds", "app-vault.capabilities")
    if previous_status == "pass" and status in {"fail", "missing", "skip"}:
        failures.append(f"Vault capability evidence regressed from pass to {status}")
        add_evidence_issue(details, "failureEvidenceIds", "app-vault.capabilities")
    capabilities = set(sorted_strings(vault_details.get("capabilities")))
    missing_capabilities = sorted(set(EXPECTED_VAULT_CAPABILITIES) - capabilities)
    if missing_capabilities:
        failures.append(f"Vault capability evidence is missing capabilities: {', '.join(missing_capabilities)}")
        add_evidence_issue(details, "failureEvidenceIds", "app-vault.capabilities")
    checks_pass = all_boolean_checks_pass(vault_details)
    if checks_pass is False:
        failures.append("Vault capability checks are not all passing")
        add_evidence_issue(details, "failureEvidenceIds", "app-vault.capabilities")
    redaction = nested_dict(vault_details, "redaction")
    for key in ("secretValuesRedacted", "identityPrivateMaterialRedacted"):
        if redaction.get(key) is not True:
            failures.append(f"Vault redaction check {key} failed or missing")
            add_evidence_issue(details, "failureEvidenceIds", "app-vault.capabilities")
    for evidence_id in ("app-platform.identity-profile-publish",):
        route_status = evidence_status(current.get(evidence_id))
        previous_route_status = evidence_status(previous.get(evidence_id))
        details[evidence_id] = {
            "currentStatus": route_status,
            "previousStatus": previous_route_status,
        }
        if route_status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is not passing")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
        elif route_status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            add_evidence_issue(details, "warningEvidenceIds", evidence_id)
        if previous_route_status == "pass" and route_status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} regressed from pass to {route_status}")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
    details.update(
        {"currentStatus": status, "previousStatus": previous_status, "capabilities": sorted(capabilities)}
    )
    return gate_from_issues(
        "ecosystem.app-vault",
        "App-vault capability and redaction evidence passed.",
        failures,
        warnings,
        details,
    )

def evaluate_sandbox_provider_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]], mode: str, metadata: dict[str, Any]
) -> GateResult:
    item = current.get("apphost.sandbox-provider")
    previous_item = previous.get("apphost.sandbox-provider")
    sandbox_details = evidence_details(item)
    previous_details = evidence_details(previous_item)
    status = evidence_status(item)
    previous_status = evidence_status(previous_item)
    support_level = str(sandbox_details.get("supportLevel", "")).lower()
    previous_support_level = str(previous_details.get("supportLevel", "")).lower()
    enforcement_required = mode == "release-candidate" or str(metadata.get("sandboxEnforcementRequired", "")).lower() == "true"
    issue_details: dict[str, Any] = {}
    failures: list[str] = []
    warnings: list[str] = []
    if status in {"fail", "missing", "skip"}:
        if enforcement_required:
            failures.append("Sandbox-provider evidence is not passing")
            add_evidence_issue(issue_details, "failureEvidenceIds", "apphost.sandbox-provider")
        else:
            warnings.append("Sandbox-provider evidence is not passing")
            add_evidence_issue(issue_details, "warningEvidenceIds", "apphost.sandbox-provider")
    elif status == "warn":
        warnings.append("Sandbox-provider evidence is warning")
        add_evidence_issue(issue_details, "warningEvidenceIds", "apphost.sandbox-provider")
    if previous_status == "pass" and status in {"fail", "missing", "skip"} and enforcement_required:
        failures.append(f"Sandbox-provider evidence regressed from pass to {status}")
        add_evidence_issue(issue_details, "failureEvidenceIds", "apphost.sandbox-provider")
    if previous_support_level == "enforced" and support_level and support_level != "enforced":
        if enforcement_required:
            failures.append(f"Sandbox support regressed from enforced to {support_level}")
            add_evidence_issue(issue_details, "failureEvidenceIds", "apphost.sandbox-provider")
        else:
            warnings.append(f"Sandbox support regressed from enforced to {support_level}")
            add_evidence_issue(issue_details, "warningEvidenceIds", "apphost.sandbox-provider")
    if enforcement_required and support_level != "enforced":
        failures.append("Enforced sandbox-provider evidence is required but not present")
        add_evidence_issue(issue_details, "failureEvidenceIds", "apphost.sandbox-provider")
    return gate_from_issues(
        "ecosystem.sandbox-provider",
        "Sandbox-provider evidence remains enforced where required.",
        failures,
        warnings,
        {
            "currentStatus": status,
            "previousStatus": previous_status,
            "supportLevel": support_level,
            "previousSupportLevel": previous_support_level,
            "enforcementRequired": enforcement_required,
            "failureEvidenceIds": issue_details.get("failureEvidenceIds", []),
            "warningEvidenceIds": issue_details.get("warningEvidenceIds", []),
        },
    )

def evaluate_reference_content_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> GateResult:
    item = current.get("reference-apps.content")
    previous_item = previous.get("reference-apps.content")
    profile_item = current.get("reference-app.profile-publisher")
    previous_profile_item = previous.get("reference-app.profile-publisher")
    profile_app_data_item = current.get("reference-app.profile-publisher-app-data")
    previous_profile_app_data_item = previous.get("reference-app.profile-publisher-app-data")
    feed_reader_item = current.get("reference-app.feed-reader")
    previous_feed_reader_item = previous.get("reference-app.feed-reader")
    feed_reader_subscription_item = current.get("reference-app.feed-reader-subscriptions")
    previous_feed_reader_subscription_item = previous.get("reference-app.feed-reader-subscriptions")
    feed_reader_app_data_item = current.get("reference-app.feed-reader-app-data")
    previous_feed_reader_app_data_item = previous.get("reference-app.feed-reader-app-data")
    trust_graph_item = current.get("reference-app.trust-graph")
    previous_trust_graph_item = previous.get("reference-app.trust-graph")
    trust_graph_durable_exchange_item = current.get("reference-app.trust-graph-durable-exchange")
    previous_trust_graph_durable_exchange_item = previous.get(
        "reference-app.trust-graph-durable-exchange"
    )
    trust_graph_app_data_item = current.get("reference-app.trust-graph-app-data-preview")
    previous_trust_graph_app_data_item = previous.get(
        "reference-app.trust-graph-app-data-preview"
    )
    social_message_signing_item = current.get("app-platform.social-message-signing")
    previous_social_message_signing_item = previous.get("app-platform.social-message-signing")
    social_inbox_item = current.get("reference-app.social-inbox")
    previous_social_inbox_item = previous.get("reference-app.social-inbox")
    social_inbox_signed_message_item = current.get("reference-app.social-inbox-signed-message")
    previous_social_inbox_signed_message_item = previous.get(
        "reference-app.social-inbox-signed-message"
    )
    social_inbox_subscription_item = current.get("reference-app.social-inbox-subscriptions")
    previous_social_inbox_subscription_item = previous.get(
        "reference-app.social-inbox-subscriptions"
    )
    social_inbox_app_data_item = current.get("reference-app.social-inbox-app-data")
    previous_social_inbox_app_data_item = previous.get("reference-app.social-inbox-app-data")
    social_inbox_trust_item = current.get("reference-app.social-inbox-trust-annotations")
    previous_social_inbox_trust_item = previous.get(
        "reference-app.social-inbox-trust-annotations"
    )
    social_inbox_rc_threading_item = current.get("reference-app.social-inbox-rc-threading")
    previous_social_inbox_rc_threading_item = previous.get(
        "reference-app.social-inbox-rc-threading"
    )
    trust_social_beta_hardening_item = current.get("app-platform.trust-social-beta-hardening")
    previous_trust_social_beta_hardening_item = previous.get(
        "app-platform.trust-social-beta-hardening"
    )
    trust_social_content_format_profiles_item = current.get(
        "app-platform.trust-social-content-format-profiles"
    )
    previous_trust_social_content_format_profiles_item = previous.get(
        "app-platform.trust-social-content-format-profiles"
    )
    social_mail_migration_item = current.get("migration.social-mail-preview")
    previous_social_mail_migration_item = previous.get("migration.social-mail-preview")
    generated_document_item = current.get("app-platform.generated-document-insert")
    previous_generated_document_item = previous.get("app-platform.generated-document-insert")
    content_fetch_item = current.get("app-platform.content-fetch")
    previous_content_fetch_item = previous.get("app-platform.content-fetch")
    content_subscription_item = current.get("app-platform.content-subscriptions")
    previous_content_subscription_item = previous.get("app-platform.content-subscriptions")
    content_subscription_scheduler_item = current.get("network-content.subscription-scheduler")
    previous_content_subscription_scheduler_item = previous.get(
        "network-content.subscription-scheduler"
    )
    app_data_store_item = current.get("app-platform.durable-app-data-store")
    previous_app_data_store_item = previous.get("app-platform.durable-app-data-store")
    trust_graph_preview_item = current.get("app-platform.trust-graph-preview")
    previous_trust_graph_preview_item = previous.get("app-platform.trust-graph-preview")
    trust_graph_durable_store_item = current.get("app-platform.trust-graph-durable-store")
    previous_trust_graph_durable_store_item = previous.get(
        "app-platform.trust-graph-durable-store"
    )
    trust_graph_exchange_item = current.get("app-platform.trust-graph-exchange")
    previous_trust_graph_exchange_item = previous.get("app-platform.trust-graph-exchange")
    trust_statement_signing_item = current.get("app-platform.trust-statement-signing")
    previous_trust_statement_signing_item = previous.get("app-platform.trust-statement-signing")
    app_services_registry_item = current.get("app-services.registry")
    previous_app_services_registry_item = previous.get("app-services.registry")
    app_services_grants_item = current.get("app-services.grants")
    previous_app_services_grants_item = previous.get("app-services.grants")
    app_services_dependency_graph_item = current.get("app-services.dependency-graph")
    previous_app_services_dependency_graph_item = previous.get("app-services.dependency-graph")
    app_services_grant_bundles_item = current.get("app-services.grant-bundles")
    previous_app_services_grant_bundles_item = previous.get("app-services.grant-bundles")
    app_services_grant_expiry_item = current.get("app-services.grant-expiry-renewal")
    previous_app_services_grant_expiry_item = previous.get("app-services.grant-expiry-renewal")
    app_services_provider_revalidation_item = current.get("app-services.provider-revalidation")
    previous_app_services_provider_revalidation_item = previous.get("app-services.provider-revalidation")
    app_services_provider_item = current.get("app-services.trust-score-provider")
    previous_app_services_provider_item = previous.get("app-services.trust-score-provider")
    social_inbox_service_grant_item = current.get("reference-app.social-inbox-service-grant")
    previous_social_inbox_service_grant_item = previous.get(
        "reference-app.social-inbox-service-grant"
    )
    social_inbox_service_dependency_item = current.get(
        "reference-app.social-inbox-service-dependency"
    )
    previous_social_inbox_service_dependency_item = previous.get(
        "reference-app.social-inbox-service-dependency"
    )
    app_services_web_shell_item = current.get("app-services.web-shell")
    previous_app_services_web_shell_item = previous.get("app-services.web-shell")
    app_services_redaction_item = current.get("app-services.redaction")
    previous_app_services_redaction_item = previous.get("app-services.redaction")
    app_services_dependency_redaction_item = current.get("app-services.dependency-redaction")
    previous_app_services_dependency_redaction_item = previous.get(
        "app-services.dependency-redaction"
    )
    details = evidence_details(item)
    profile_details = evidence_details(profile_item)
    profile_app_data_details = evidence_details(profile_app_data_item)
    feed_reader_details = evidence_details(feed_reader_item)
    feed_reader_subscription_details = evidence_details(feed_reader_subscription_item)
    feed_reader_app_data_details = evidence_details(feed_reader_app_data_item)
    trust_graph_details = evidence_details(trust_graph_item)
    trust_graph_durable_exchange_details = evidence_details(trust_graph_durable_exchange_item)
    trust_graph_app_data_details = evidence_details(trust_graph_app_data_item)
    social_message_signing_details = evidence_details(social_message_signing_item)
    social_inbox_details = evidence_details(social_inbox_item)
    social_inbox_signed_message_details = evidence_details(social_inbox_signed_message_item)
    social_inbox_subscription_details = evidence_details(social_inbox_subscription_item)
    social_inbox_app_data_details = evidence_details(social_inbox_app_data_item)
    social_inbox_trust_details = evidence_details(social_inbox_trust_item)
    social_inbox_rc_threading_details = evidence_details(social_inbox_rc_threading_item)
    social_mail_migration_details = evidence_details(social_mail_migration_item)
    generated_document_details = evidence_details(generated_document_item)
    content_fetch_details = evidence_details(content_fetch_item)
    content_subscription_details = evidence_details(content_subscription_item)
    content_subscription_scheduler_details = evidence_details(
        content_subscription_scheduler_item
    )
    app_data_store_details = evidence_details(app_data_store_item)
    trust_graph_preview_details = evidence_details(trust_graph_preview_item)
    trust_graph_durable_store_details = evidence_details(trust_graph_durable_store_item)
    trust_graph_exchange_details = evidence_details(trust_graph_exchange_item)
    trust_statement_signing_details = evidence_details(trust_statement_signing_item)
    app_services_registry_details = evidence_details(app_services_registry_item)
    app_services_grants_details = evidence_details(app_services_grants_item)
    app_services_dependency_graph_details = evidence_details(app_services_dependency_graph_item)
    app_services_grant_bundles_details = evidence_details(app_services_grant_bundles_item)
    app_services_grant_expiry_details = evidence_details(app_services_grant_expiry_item)
    app_services_provider_revalidation_details = evidence_details(
        app_services_provider_revalidation_item
    )
    app_services_provider_details = evidence_details(app_services_provider_item)
    social_inbox_service_grant_details = evidence_details(social_inbox_service_grant_item)
    social_inbox_service_dependency_details = evidence_details(
        social_inbox_service_dependency_item
    )
    app_services_web_shell_details = evidence_details(app_services_web_shell_item)
    app_services_redaction_details = evidence_details(app_services_redaction_item)
    app_services_dependency_redaction_details = evidence_details(
        app_services_dependency_redaction_item
    )
    checks = nested_dict(details, "checks")
    profile_checks = nested_dict(profile_details, "checks")
    profile_app_data_checks = nested_dict(profile_app_data_details, "checks")
    feed_reader_checks = nested_dict(feed_reader_details, "checks")
    feed_reader_app_data_checks = nested_dict(feed_reader_app_data_details, "checks")
    trust_graph_checks = nested_dict(trust_graph_details, "checks")
    trust_graph_durable_exchange_checks = nested_dict(
        trust_graph_durable_exchange_details, "checks"
    )
    trust_graph_app_data_checks = nested_dict(trust_graph_app_data_details, "checks")
    social_message_signing_checks = nested_dict(social_message_signing_details, "checks")
    social_inbox_checks = nested_dict(social_inbox_details, "checks")
    social_inbox_signed_message_checks = nested_dict(
        social_inbox_signed_message_details, "checks"
    )
    social_inbox_subscription_checks = nested_dict(social_inbox_subscription_details, "checks")
    social_inbox_app_data_checks = nested_dict(social_inbox_app_data_details, "checks")
    social_inbox_trust_checks = nested_dict(social_inbox_trust_details, "checks")
    social_inbox_rc_threading_checks = nested_dict(social_inbox_rc_threading_details, "checks")
    social_inbox_service_grant_checks = nested_dict(social_inbox_service_grant_details, "checks")
    social_mail_migration_checks = nested_dict(social_mail_migration_details, "checks")
    app_services_registry_checks = nested_dict(app_services_registry_details, "checks")
    app_services_grants_checks = nested_dict(app_services_grants_details, "checks")
    app_services_dependency_graph_checks = nested_dict(app_services_dependency_graph_details, "checks")
    app_services_grant_bundles_checks = nested_dict(app_services_grant_bundles_details, "checks")
    app_services_grant_expiry_checks = nested_dict(app_services_grant_expiry_details, "checks")
    app_services_provider_revalidation_checks = nested_dict(
        app_services_provider_revalidation_details, "checks"
    )
    app_services_provider_checks = nested_dict(app_services_provider_details, "checks")
    app_services_web_shell_checks = nested_dict(app_services_web_shell_details, "checks")
    app_services_redaction_checks = nested_dict(app_services_redaction_details, "checks")
    social_inbox_service_dependency_checks = nested_dict(
        social_inbox_service_dependency_details, "checks"
    )
    app_services_dependency_redaction_checks = nested_dict(
        app_services_dependency_redaction_details, "checks"
    )
    status = evidence_status(item)
    previous_status = evidence_status(previous_item)
    profile_status = evidence_status(profile_item)
    previous_profile_status = evidence_status(previous_profile_item)
    profile_app_data_status = evidence_status(profile_app_data_item)
    previous_profile_app_data_status = evidence_status(previous_profile_app_data_item)
    feed_reader_status = evidence_status(feed_reader_item)
    previous_feed_reader_status = evidence_status(previous_feed_reader_item)
    feed_reader_subscription_status = evidence_status(feed_reader_subscription_item)
    previous_feed_reader_subscription_status = evidence_status(
        previous_feed_reader_subscription_item
    )
    feed_reader_app_data_status = evidence_status(feed_reader_app_data_item)
    previous_feed_reader_app_data_status = evidence_status(previous_feed_reader_app_data_item)
    trust_graph_status = evidence_status(trust_graph_item)
    previous_trust_graph_status = evidence_status(previous_trust_graph_item)
    trust_graph_durable_exchange_status = evidence_status(trust_graph_durable_exchange_item)
    previous_trust_graph_durable_exchange_status = evidence_status(
        previous_trust_graph_durable_exchange_item
    )
    trust_graph_app_data_status = evidence_status(trust_graph_app_data_item)
    previous_trust_graph_app_data_status = evidence_status(previous_trust_graph_app_data_item)
    social_message_signing_status = evidence_status(social_message_signing_item)
    previous_social_message_signing_status = evidence_status(
        previous_social_message_signing_item
    )
    social_inbox_status = evidence_status(social_inbox_item)
    previous_social_inbox_status = evidence_status(previous_social_inbox_item)
    social_inbox_signed_message_status = evidence_status(social_inbox_signed_message_item)
    previous_social_inbox_signed_message_status = evidence_status(
        previous_social_inbox_signed_message_item
    )
    social_inbox_subscription_status = evidence_status(social_inbox_subscription_item)
    previous_social_inbox_subscription_status = evidence_status(
        previous_social_inbox_subscription_item
    )
    social_inbox_app_data_status = evidence_status(social_inbox_app_data_item)
    previous_social_inbox_app_data_status = evidence_status(previous_social_inbox_app_data_item)
    social_inbox_trust_status = evidence_status(social_inbox_trust_item)
    previous_social_inbox_trust_status = evidence_status(previous_social_inbox_trust_item)
    social_inbox_rc_threading_status = evidence_status(social_inbox_rc_threading_item)
    previous_social_inbox_rc_threading_status = evidence_status(
        previous_social_inbox_rc_threading_item
    )
    trust_social_beta_hardening_status = evidence_status(trust_social_beta_hardening_item)
    previous_trust_social_beta_hardening_status = evidence_status(
        previous_trust_social_beta_hardening_item
    )
    trust_social_content_format_profiles_status = evidence_status(
        trust_social_content_format_profiles_item
    )
    previous_trust_social_content_format_profiles_status = evidence_status(
        previous_trust_social_content_format_profiles_item
    )
    social_mail_migration_status = evidence_status(social_mail_migration_item)
    previous_social_mail_migration_status = evidence_status(previous_social_mail_migration_item)
    generated_document_status = evidence_status(generated_document_item)
    previous_generated_document_status = evidence_status(previous_generated_document_item)
    content_fetch_status = evidence_status(content_fetch_item)
    previous_content_fetch_status = evidence_status(previous_content_fetch_item)
    content_subscription_status = evidence_status(content_subscription_item)
    previous_content_subscription_status = evidence_status(previous_content_subscription_item)
    content_subscription_scheduler_status = evidence_status(content_subscription_scheduler_item)
    previous_content_subscription_scheduler_status = evidence_status(
        previous_content_subscription_scheduler_item
    )
    app_data_store_status = evidence_status(app_data_store_item)
    previous_app_data_store_status = evidence_status(previous_app_data_store_item)
    trust_graph_preview_status = evidence_status(trust_graph_preview_item)
    previous_trust_graph_preview_status = evidence_status(previous_trust_graph_preview_item)
    trust_graph_durable_store_status = evidence_status(trust_graph_durable_store_item)
    previous_trust_graph_durable_store_status = evidence_status(
        previous_trust_graph_durable_store_item
    )
    trust_graph_exchange_status = evidence_status(trust_graph_exchange_item)
    previous_trust_graph_exchange_status = evidence_status(previous_trust_graph_exchange_item)
    trust_statement_signing_status = evidence_status(trust_statement_signing_item)
    previous_trust_statement_signing_status = evidence_status(
        previous_trust_statement_signing_item
    )
    app_services_registry_status = evidence_status(app_services_registry_item)
    previous_app_services_registry_status = evidence_status(previous_app_services_registry_item)
    app_services_grants_status = evidence_status(app_services_grants_item)
    previous_app_services_grants_status = evidence_status(previous_app_services_grants_item)
    app_services_dependency_graph_status = evidence_status(app_services_dependency_graph_item)
    previous_app_services_dependency_graph_status = evidence_status(
        previous_app_services_dependency_graph_item
    )
    app_services_grant_bundles_status = evidence_status(app_services_grant_bundles_item)
    previous_app_services_grant_bundles_status = evidence_status(
        previous_app_services_grant_bundles_item
    )
    app_services_grant_expiry_status = evidence_status(app_services_grant_expiry_item)
    previous_app_services_grant_expiry_status = evidence_status(
        previous_app_services_grant_expiry_item
    )
    app_services_provider_revalidation_status = evidence_status(
        app_services_provider_revalidation_item
    )
    previous_app_services_provider_revalidation_status = evidence_status(
        previous_app_services_provider_revalidation_item
    )
    app_services_provider_status = evidence_status(app_services_provider_item)
    previous_app_services_provider_status = evidence_status(previous_app_services_provider_item)
    social_inbox_service_grant_status = evidence_status(social_inbox_service_grant_item)
    previous_social_inbox_service_grant_status = evidence_status(
        previous_social_inbox_service_grant_item
    )
    social_inbox_service_dependency_status = evidence_status(social_inbox_service_dependency_item)
    previous_social_inbox_service_dependency_status = evidence_status(
        previous_social_inbox_service_dependency_item
    )
    app_services_web_shell_status = evidence_status(app_services_web_shell_item)
    previous_app_services_web_shell_status = evidence_status(previous_app_services_web_shell_item)
    app_services_redaction_status = evidence_status(app_services_redaction_item)
    previous_app_services_redaction_status = evidence_status(previous_app_services_redaction_item)
    app_services_dependency_redaction_status = evidence_status(
        app_services_dependency_redaction_item
    )
    previous_app_services_dependency_redaction_status = evidence_status(
        previous_app_services_dependency_redaction_item
    )
    gate_details: dict[str, Any] = {}
    failures: list[str] = []
    warnings: list[str] = []
    if status in {"fail", "missing", "skip"}:
        failures.append("Site Publisher reference-content evidence is not passing")
        add_evidence_issue(gate_details, "failureEvidenceIds", "reference-apps.content")
    elif status == "warn":
        warnings.append("Site Publisher reference-content evidence is warning")
        add_evidence_issue(gate_details, "warningEvidenceIds", "reference-apps.content")
    if previous_status == "pass" and status in {"fail", "missing", "skip"}:
        failures.append(f"Site Publisher evidence regressed from pass to {status}")
        add_evidence_issue(gate_details, "failureEvidenceIds", "reference-apps.content")
    if details.get("appId") not in {"site-publisher", None}:
        failures.append("Reference content app evidence is not for site-publisher")
        add_evidence_issue(gate_details, "failureEvidenceIds", "reference-apps.content")
    if checks:
        for key in ("usesContentInsertDirectory", "usesContentInsertFile", "usesSdkBootstrap"):
            if checks.get(key) is not True:
                failures.append(f"Reference content app check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "reference-apps.content")
    elif status == "pass":
        warnings.append("Reference content app coverage lacks detailed staged app checks")
        add_evidence_issue(gate_details, "warningEvidenceIds", "reference-apps.content")
    for evidence_id, current_status, previous_status_value in (
        ("reference-app.profile-publisher", profile_status, previous_profile_status),
        (
            "reference-app.profile-publisher-app-data",
            profile_app_data_status,
            previous_profile_app_data_status,
        ),
        ("reference-app.feed-reader", feed_reader_status, previous_feed_reader_status),
        (
            "reference-app.feed-reader-subscriptions",
            feed_reader_subscription_status,
            previous_feed_reader_subscription_status,
        ),
        (
            "reference-app.feed-reader-app-data",
            feed_reader_app_data_status,
            previous_feed_reader_app_data_status,
        ),
        ("reference-app.trust-graph", trust_graph_status, previous_trust_graph_status),
        (
            "reference-app.trust-graph-durable-exchange",
            trust_graph_durable_exchange_status,
            previous_trust_graph_durable_exchange_status,
        ),
        (
            "reference-app.trust-graph-app-data-preview",
            trust_graph_app_data_status,
            previous_trust_graph_app_data_status,
        ),
        (
            "app-platform.social-message-signing",
            social_message_signing_status,
            previous_social_message_signing_status,
        ),
        ("reference-app.social-inbox", social_inbox_status, previous_social_inbox_status),
        (
            "reference-app.social-inbox-signed-message",
            social_inbox_signed_message_status,
            previous_social_inbox_signed_message_status,
        ),
        (
            "reference-app.social-inbox-subscriptions",
            social_inbox_subscription_status,
            previous_social_inbox_subscription_status,
        ),
        (
            "reference-app.social-inbox-app-data",
            social_inbox_app_data_status,
            previous_social_inbox_app_data_status,
        ),
        (
            "reference-app.social-inbox-trust-annotations",
            social_inbox_trust_status,
            previous_social_inbox_trust_status,
        ),
        (
            "reference-app.social-inbox-rc-threading",
            social_inbox_rc_threading_status,
            previous_social_inbox_rc_threading_status,
        ),
        (
            "app-platform.trust-social-beta-hardening",
            trust_social_beta_hardening_status,
            previous_trust_social_beta_hardening_status,
        ),
        (
            "app-platform.trust-social-content-format-profiles",
            trust_social_content_format_profiles_status,
            previous_trust_social_content_format_profiles_status,
        ),
        (
            "migration.social-mail-preview",
            social_mail_migration_status,
            previous_social_mail_migration_status,
        ),
        (
            "app-platform.generated-document-insert",
            generated_document_status,
            previous_generated_document_status,
        ),
        ("app-platform.content-fetch", content_fetch_status, previous_content_fetch_status),
        (
            "app-platform.content-subscriptions",
            content_subscription_status,
            previous_content_subscription_status,
        ),
        (
            "network-content.subscription-scheduler",
            content_subscription_scheduler_status,
            previous_content_subscription_scheduler_status,
        ),
        (
            "app-platform.durable-app-data-store",
            app_data_store_status,
            previous_app_data_store_status,
        ),
        (
            "app-platform.trust-graph-preview",
            trust_graph_preview_status,
            previous_trust_graph_preview_status,
        ),
        (
            "app-platform.trust-graph-durable-store",
            trust_graph_durable_store_status,
            previous_trust_graph_durable_store_status,
        ),
        (
            "app-platform.trust-graph-exchange",
            trust_graph_exchange_status,
            previous_trust_graph_exchange_status,
        ),
        (
            "app-platform.trust-statement-signing",
            trust_statement_signing_status,
            previous_trust_statement_signing_status,
        ),
        ("app-services.registry", app_services_registry_status, previous_app_services_registry_status),
        ("app-services.grants", app_services_grants_status, previous_app_services_grants_status),
        (
            "app-services.dependency-graph",
            app_services_dependency_graph_status,
            previous_app_services_dependency_graph_status,
        ),
        (
            "app-services.grant-bundles",
            app_services_grant_bundles_status,
            previous_app_services_grant_bundles_status,
        ),
        (
            "app-services.grant-expiry-renewal",
            app_services_grant_expiry_status,
            previous_app_services_grant_expiry_status,
        ),
        (
            "app-services.provider-revalidation",
            app_services_provider_revalidation_status,
            previous_app_services_provider_revalidation_status,
        ),
        (
            "app-services.trust-score-provider",
            app_services_provider_status,
            previous_app_services_provider_status,
        ),
        (
            "reference-app.social-inbox-service-grant",
            social_inbox_service_grant_status,
            previous_social_inbox_service_grant_status,
        ),
        (
            "reference-app.social-inbox-service-dependency",
            social_inbox_service_dependency_status,
            previous_social_inbox_service_dependency_status,
        ),
        (
            "app-services.web-shell",
            app_services_web_shell_status,
            previous_app_services_web_shell_status,
        ),
        (
            "app-services.redaction",
            app_services_redaction_status,
            previous_app_services_redaction_status,
        ),
        (
            "app-services.dependency-redaction",
            app_services_dependency_redaction_status,
            previous_app_services_dependency_redaction_status,
        ),
    ):
        if current_status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is not passing")
            add_evidence_issue(gate_details, "failureEvidenceIds", evidence_id)
        elif current_status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            add_evidence_issue(gate_details, "warningEvidenceIds", evidence_id)
        if previous_status_value == "pass" and current_status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} regressed from pass to {current_status}")
            add_evidence_issue(gate_details, "failureEvidenceIds", evidence_id)
    if profile_details.get("appId") not in {"profile-publisher", None}:
        failures.append("Profile Publisher evidence is not for profile-publisher")
        add_evidence_issue(gate_details, "failureEvidenceIds", "reference-app.profile-publisher")
    if profile_checks:
        for key in (
            "usesBrowserSafeIdentityCreation",
            "usesProfileDocumentRoute",
            "usesGeneratedDocumentInsertRoute",
            "usesSdkBootstrap",
        ):
            if profile_checks.get(key) is not True:
                failures.append(f"Profile Publisher reference app check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "reference-app.profile-publisher")
    elif profile_status == "pass":
        warnings.append("Profile Publisher coverage lacks detailed staged app checks")
        add_evidence_issue(gate_details, "warningEvidenceIds", "reference-app.profile-publisher")
    if profile_app_data_checks:
        for key in (
            "manifestUsesAppDataContract",
            "usesSdkJsonRecordHelpers",
            "persistsBoundedDraftState",
            "docsAndEvidenceMentionDurableAppData",
        ):
            if profile_app_data_checks.get(key) is not True:
                failures.append(f"Profile Publisher app-data check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.profile-publisher-app-data",
                )
    elif profile_app_data_status == "pass":
        warnings.append("Profile Publisher app-data coverage lacks detailed checks")
        add_evidence_issue(
            gate_details, "warningEvidenceIds", "reference-app.profile-publisher-app-data"
        )
    if feed_reader_details.get("appId") not in {"feed-reader", None}:
        failures.append("Feed Reader evidence is not for feed-reader")
        add_evidence_issue(gate_details, "failureEvidenceIds", "reference-app.feed-reader")
    if feed_reader_checks:
        for key in (
            "usesContentFetchRouteOrHelper",
            "usesContentSubscriptionHelpers",
            "usesGeneratedDocumentInsertRoute",
            "usesSdkBootstrap",
        ):
            if feed_reader_checks.get(key) is not True:
                failures.append(f"Feed Reader reference app check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "reference-app.feed-reader")
    elif feed_reader_status == "pass":
        warnings.append("Feed Reader coverage lacks detailed staged app checks")
        add_evidence_issue(gate_details, "warningEvidenceIds", "reference-app.feed-reader")
    feed_reader_subscription_checks = nested_dict(feed_reader_subscription_details, "checks")
    if feed_reader_subscription_checks:
        for key in (
            "manifestDeclaresSubscribeAndV9",
            "appUsesPlatformSubscriptionWorkflow",
            "noTabLocalFollowLoop",
            "sdkHelpersAvailable",
            "docsDescribeSubscriptionFlow",
        ):
            if feed_reader_subscription_checks.get(key) is not True:
                failures.append(f"Feed Reader subscription check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.feed-reader-subscriptions",
                )
    elif feed_reader_subscription_status == "pass":
        warnings.append("Feed Reader subscription coverage lacks detailed staged app checks")
        add_evidence_issue(
            gate_details, "warningEvidenceIds", "reference-app.feed-reader-subscriptions"
        )
    if feed_reader_app_data_checks:
        for key in (
            "manifestUsesAppDataContract",
            "usesSdkJsonRecordHelpers",
            "persistsBoundedReaderState",
            "docsAndEvidenceMentionDurableAppData",
        ):
            if feed_reader_app_data_checks.get(key) is not True:
                failures.append(f"Feed Reader app-data check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.feed-reader-app-data",
                )
    elif feed_reader_app_data_status == "pass":
        warnings.append("Feed Reader app-data coverage lacks detailed checks")
        add_evidence_issue(
            gate_details, "warningEvidenceIds", "reference-app.feed-reader-app-data"
        )
    if trust_graph_details.get("appId") not in {"trust-graph", None}:
        failures.append("Trust Graph Local RC evidence is not for trust-graph")
        add_evidence_issue(gate_details, "failureEvidenceIds", "reference-app.trust-graph")
    if trust_graph_checks:
        for key in (
            "manifestDeclaresTrustGraph",
            "manifestDeclaresTrustPermissions",
            "manifestUsesContractV22",
            "usesTrustHelpers",
            "usesBoundedTrustSigningHelper",
            "usesTrustExchangeAndQueuePreview",
            "docsDescribePreviewLimits",
            "docsDescribeTrustScoreService",
            "manifestAdvertisesTrustScoreService",
        ):
            if trust_graph_checks.get(key) is not True:
                failures.append(f"Trust Graph Local RC reference app check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "reference-app.trust-graph")
    elif trust_graph_status == "pass":
        warnings.append("Trust Graph Local RC coverage lacks detailed staged app checks")
        add_evidence_issue(gate_details, "warningEvidenceIds", "reference-app.trust-graph")
    if trust_graph_app_data_checks:
        for key in (
            "manifestUsesAppDataContract",
            "usesSdkJsonRecordHelpers",
            "persistsOnlyUiLocalPreviewState",
            "docsSeparateAppDataAndTrustBackend",
        ):
            if trust_graph_app_data_checks.get(key) is not True:
                failures.append(f"Trust Graph app-data preview check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.trust-graph-app-data-preview",
                )
    elif trust_graph_app_data_status == "pass":
        warnings.append("Trust Graph app-data preview coverage lacks detailed checks")
        add_evidence_issue(
            gate_details, "warningEvidenceIds", "reference-app.trust-graph-app-data-preview"
        )
    if social_message_signing_checks:
        for key in (
            "routeInContract",
            "contractVersionV11",
            "capabilitiesInContract",
            "handlerUsesFixedDomainAppVaultSigning",
            "requestRejectsGenericSigningInputs",
            "sdkHelperUsesBoundedRoute",
            "docsDescribeBoundedSigningBoundary",
        ):
            if social_message_signing_checks.get(key) is not True:
                failures.append(f"Social message signing check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "app-platform.social-message-signing",
                )
    if social_inbox_details.get("appId") not in {"social-inbox", None}:
        failures.append("Social Inbox evidence is not for social-inbox")
        add_evidence_issue(gate_details, "failureEvidenceIds", "reference-app.social-inbox")
    if social_inbox_checks:
        for key in (
            "manifestDeclaresSocialInbox",
            "manifestDeclaresSocialPermissions",
            "manifestUsesContractV12",
            "manifestDeclaresTrustScoreServiceRequest",
            "usesAppVaultIdentityFlow",
            "usesProfileMetadataFlow",
            "usesGeneratedOutboxInsert",
            "usesSubscriptionAndFetchFlow",
            "usesDurableAppData",
            "usesTrustAnnotations",
            "previewAndNonGoalCopyPresent",
            "noRawAdminOrBrowserStorage",
        ):
            if social_inbox_checks.get(key) is not True:
                failures.append(f"Social Inbox reference app check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "reference-app.social-inbox")
    elif social_inbox_status == "pass":
        warnings.append("Social Inbox coverage lacks detailed staged app checks")
        add_evidence_issue(gate_details, "warningEvidenceIds", "reference-app.social-inbox")
    if social_inbox_signed_message_checks:
        for key in (
            "manifestAllowsBoundedSigning",
            "usesSdkBoundedSigner",
            "verifiesImportedMessageSignatures",
            "documentShapeIsBounded",
            "docsDescribeSignedMessageFormat",
        ):
            if social_inbox_signed_message_checks.get(key) is not True:
                failures.append(f"Social Inbox signed-message check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.social-inbox-signed-message",
                )
    if social_inbox_subscription_checks:
        for key in (
            "manifestDeclaresSubscriptionPermissions",
            "uiDisclosesSubscriptionWorkflow",
            "appUsesPlatformSubscriptionLifecycle",
            "manualFetchUsesBoundedContentFetch",
            "docsDescribeDurableUskSources",
        ):
            if social_inbox_subscription_checks.get(key) is not True:
                failures.append(f"Social Inbox subscription check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.social-inbox-subscriptions",
                )
    if social_inbox_app_data_checks:
        for key in (
            "manifestDeclaresAppDataPermissions",
            "usesSdkJsonRecordHelpers",
            "persistsNamedBoundedRecords",
            "signingDoesNotOverwritePublishSummary",
            "storesSafeSummariesOnly",
            "permissionDisclosureMentionsAppData",
            "docsDescribePrivacyRules",
            "noBrowserStorageOrRawAdminPath",
        ):
            if social_inbox_app_data_checks.get(key) is not True:
                failures.append(f"Social Inbox app-data check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.social-inbox-app-data",
                )
    if social_inbox_trust_checks:
        for key in (
            "manifestDeclaresAppServiceCapabilities",
            "manifestDeclaresTrustScoreRequest",
            "appQueriesAuthorScores",
            "uiShowsNeutralAndScoredStates",
            "unknownScoresRemainUnscored",
            "docsFrameScoresAsAnnotations",
        ):
            if social_inbox_trust_checks.get(key) is not True:
                failures.append(f"Social Inbox trust annotation check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.social-inbox-trust-annotations",
                )
    if social_inbox_rc_threading_checks:
        for key in (
            "threadBuildingLogic",
            "threadRenderingIsBoundedAndDomSafe",
            "replyActionUsesExistingReplyTo",
            "channelFilteringIsLocal",
            "boundedLocalSearch",
            "threadActionsPersistSafeState",
            "authorProfileDisplayIsSafe",
            "dedupePreservesSafeSourceSummaries",
            "subscriptionRefreshUxIsExplicit",
            "trustGraphMediatedOnly",
            "noUnsafeBrowserPersistenceOrExecution",
            "manifestUsesAdditiveBetaSchemaContract",
            "appWritesExistingSchemaVersion",
            "docsFrameRcReferenceAndNonGoals",
            "evidenceIdDocumented",
        ):
            if social_inbox_rc_threading_checks.get(key) is not True:
                failures.append(f"Social Inbox RC threading check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.social-inbox-rc-threading",
                )
    if social_inbox_service_grant_checks:
        for key in (
            "socialManifestRequestsServiceGrant",
            "socialManifestUsesAppServiceCapabilities",
            "socialUsesSdkServicesNamespace",
            "socialUiShowsGrantStates",
            "socialDocsDescribeRevocation",
        ):
            if social_inbox_service_grant_checks.get(key) is not True:
                failures.append(f"Social Inbox service-grant check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.social-inbox-service-grant",
                )
    if social_inbox_service_dependency_checks:
        for key in (
            "socialManifestDeclaresOptionalDependency",
            "socialDegradesSafely",
            "socialDependencyDocsPresent",
        ):
            if social_inbox_service_dependency_checks.get(key) is not True:
                failures.append(f"Social Inbox service-dependency check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.social-inbox-service-dependency",
                )
    if app_services_registry_checks:
        for key in (
            "contractV12AndCapabilitiesPresent",
            "routeFamilyPresent",
            "descriptorParserPresent",
            "runtimeWiresSharedCoordinator",
            "sdkHelpersPresent",
            "testsCoverManifestAndRouter",
        ):
            if app_services_registry_checks.get(key) is not True:
                failures.append(f"App-service registry check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "app-services.registry")
    if app_services_grants_checks:
        for key in (
            "grantModelHasRequiredFields",
            "grantStatusesPresent",
            "storesAreFileBackedAndInMemory",
            "coordinatorEnforcesApprovalRevocation",
            "testsCoverGrantLifecycle",
        ):
            if app_services_grants_checks.get(key) is not True:
                failures.append(f"App-service grant check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "app-services.grants")
    if app_services_dependency_graph_checks:
        for key in (
            "dependencyModelsPresent",
            "dependencyParserStrictFieldsPresent",
            "dependencyRoutesPresent",
            "dependencyTestsPresent",
        ):
            if app_services_dependency_graph_checks.get(key) is not True:
                failures.append(f"App-service dependency graph check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-services.dependency-graph"
                )
    if app_services_grant_bundles_checks:
        for key in (
            "bundleModelsAndStorePresent",
            "bundleRoutesPresent",
            "bundleCoordinatorHostOnly",
            "bundleTestsPresent",
        ):
            if app_services_grant_bundles_checks.get(key) is not True:
                failures.append(f"App-service grant-bundle check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-services.grant-bundles"
                )
    if app_services_grant_expiry_checks:
        for key in (
            "grantExpiryFieldsPresent",
            "expiredGrantsFailClosed",
            "renewalRevalidates",
        ):
            if app_services_grant_expiry_checks.get(key) is not True:
                failures.append(f"App-service grant expiry check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-services.grant-expiry-renewal"
                )
    if app_services_provider_revalidation_checks:
        for key in (
            "compatibilityFingerprintPresent",
            "descriptorDriftNonAuthorizing",
            "descriptorMatchingChecksVersionScopeContextKindAdapter",
        ):
            if app_services_provider_revalidation_checks.get(key) is not True:
                failures.append(f"App-service provider revalidation check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-services.provider-revalidation"
                )
    if app_services_provider_checks:
        for key in (
            "trustGraphManifestAdvertisesService",
            "adapterIsBoundedNotProxy",
            "providerDocsAndUiDescribePreviewGrantBoundary",
            "adapterTestsCoverRedaction",
        ):
            if app_services_provider_checks.get(key) is not True:
                failures.append(f"Trust-score provider check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-services.trust-score-provider"
                )
    if app_services_web_shell_checks:
        for key in (
            "webShellLoadsAppServiceData",
            "webShellRendersGrantActions",
            "webShellOmitsPrivateMaterial",
            "webShellTestsPresent",
        ):
            if app_services_web_shell_checks.get(key) is not True:
                failures.append(f"App-service Web Shell check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "app-services.web-shell")
    if app_services_redaction_checks:
        for key in (
            "auditModelIsRedacted",
            "invocationReturnsHashNotRawSubject",
            "grantJsonContainsOnlyFingerprint",
            "docsStateNoGenericProxyOrLocalhostTrust",
            "evidenceIdsDocumented",
        ):
            if app_services_redaction_checks.get(key) is not True:
                failures.append(f"App-service redaction check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "app-services.redaction")
    if app_services_dependency_redaction_checks:
        for key in (
            "dependencyJsonPathFreeByConstruction",
            "bundlePublicJsonFieldsSafe",
            "uiAndEvidenceAvoidRawSensitiveValues",
        ):
            if app_services_dependency_redaction_checks.get(key) is not True:
                failures.append(f"App-service dependency-redaction check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-services.dependency-redaction"
                )
    if social_mail_migration_checks:
        for key in (
            "migrationFramingPresent",
            "nonGoalsDocumented",
            "appComposesExpectedPlatformSurfaces",
            "uiStatesPreviewBoundary",
            "evidenceIdsDocumented",
        ):
            if social_mail_migration_checks.get(key) is not True:
                failures.append(f"Social/mail migration preview check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "migration.social-mail-preview",
                )
    generated_checks = nested_dict(generated_document_details, "checks")
    if generated_checks and generated_checks.get("routeDocumented") is not True:
        failures.append("Generated document insert route documentation check failed")
        add_evidence_issue(gate_details, "failureEvidenceIds", "app-platform.generated-document-insert")
    content_fetch_checks = nested_dict(content_fetch_details, "checks")
    if content_fetch_checks and content_fetch_checks.get("routeDocumented") is not True:
        failures.append("Content fetch route documentation check failed")
        add_evidence_issue(gate_details, "failureEvidenceIds", "app-platform.content-fetch")
    content_subscription_checks = nested_dict(content_subscription_details, "checks")
    if content_subscription_checks:
        for key in ("currentContractVersionV9", "routesPresent", "capabilityGatesPresent"):
            if content_subscription_checks.get(key) is not True:
                failures.append(f"Content subscription API check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-platform.content-subscriptions"
                )
    app_data_store_checks = nested_dict(app_data_store_details, "checks")
    if app_data_store_checks:
        for key in (
            "contractV9AndCapabilities",
            "routesRequireAppPrincipalAndCapabilities",
            "fileBackedStoreIsPathSafeAndAtomic",
            "serviceBoundsQuotaAndImportExport",
            "docsCoverLimitsAndRedaction",
        ):
            if app_data_store_checks.get(key) is not True:
                failures.append(f"Durable app-data store check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-platform.durable-app-data-store"
                )
    content_subscription_scheduler_checks = nested_dict(
        content_subscription_scheduler_details, "checks"
    )
    if content_subscription_scheduler_checks:
        for key in (
            "deterministicTickAndNoOverlap",
            "conservativeLimits",
            "dedupeAndMetadataOnly",
            "pressureGateStableSignals",
            "durablePathFreeStore",
        ):
            if content_subscription_scheduler_checks.get(key) is not True:
                failures.append(f"Content subscription scheduler check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "network-content.subscription-scheduler",
                )
    trust_preview_checks = nested_dict(trust_graph_preview_details, "checks")
    if trust_preview_checks:
        for key in ("contractVersionV7", "routesPresent", "capabilityGatesPresent"):
            if trust_preview_checks.get(key) is not True:
                failures.append(f"Trust graph preview API check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-platform.trust-graph-preview"
                )
    trust_durable_store_checks = nested_dict(trust_graph_durable_store_details, "checks")
    if trust_durable_store_checks:
        for key in ("fileBackedStorePresent", "runtimeInjectsDurableStore", "durabilityTestsPresent"):
            if trust_durable_store_checks.get(key) is not True:
                failures.append(f"Trust graph durable store check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-platform.trust-graph-durable-store"
                )
    trust_exchange_checks = nested_dict(trust_graph_exchange_details, "checks")
    if trust_exchange_checks:
        for key in ("contractVersionV10", "contractDescriptorsPresent", "sdkExchangeHelpersPresent"):
            if trust_exchange_checks.get(key) is not True:
                failures.append(f"Trust graph exchange check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-platform.trust-graph-exchange"
                )
    if trust_graph_durable_exchange_checks:
        for key in (
            "manifestUsesContractV22",
            "usesSdkExchangeHelpers",
            "noRawApiOrManualFetch",
        ):
            if trust_graph_durable_exchange_checks.get(key) is not True:
                failures.append(f"Trust Graph Local RC durable exchange app check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.trust-graph-durable-exchange",
                )
    trust_signing_checks = nested_dict(trust_statement_signing_details, "checks")
    if trust_signing_checks:
        for key in ("routeInContract", "capabilitiesInContract", "handlerSignsCanonicalPayload"):
            if trust_signing_checks.get(key) is not True:
                failures.append(f"Trust statement signing check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-platform.trust-statement-signing"
                )
    gate_details.update(
        {
            "currentStatus": status,
            "previousStatus": previous_status,
            "appId": details.get("appId"),
            "profilePublisherStatus": profile_status,
            "previousProfilePublisherStatus": previous_profile_status,
            "profilePublisherAppDataStatus": profile_app_data_status,
            "previousProfilePublisherAppDataStatus": previous_profile_app_data_status,
            "feedReaderStatus": feed_reader_status,
            "previousFeedReaderStatus": previous_feed_reader_status,
            "feedReaderAppDataStatus": feed_reader_app_data_status,
            "previousFeedReaderAppDataStatus": previous_feed_reader_app_data_status,
            "trustGraphStatus": trust_graph_status,
            "previousTrustGraphStatus": previous_trust_graph_status,
            "trustGraphAppDataPreviewStatus": trust_graph_app_data_status,
            "previousTrustGraphAppDataPreviewStatus": previous_trust_graph_app_data_status,
            "socialMessageSigningStatus": social_message_signing_status,
            "previousSocialMessageSigningStatus": previous_social_message_signing_status,
            "socialInboxStatus": social_inbox_status,
            "previousSocialInboxStatus": previous_social_inbox_status,
            "socialInboxSignedMessageStatus": social_inbox_signed_message_status,
            "previousSocialInboxSignedMessageStatus": previous_social_inbox_signed_message_status,
            "socialInboxSubscriptionStatus": social_inbox_subscription_status,
            "previousSocialInboxSubscriptionStatus": previous_social_inbox_subscription_status,
            "socialInboxAppDataStatus": social_inbox_app_data_status,
            "previousSocialInboxAppDataStatus": previous_social_inbox_app_data_status,
            "socialInboxTrustAnnotationStatus": social_inbox_trust_status,
            "previousSocialInboxTrustAnnotationStatus": previous_social_inbox_trust_status,
            "socialInboxRcThreadingStatus": social_inbox_rc_threading_status,
            "previousSocialInboxRcThreadingStatus": previous_social_inbox_rc_threading_status,
            "trustSocialBetaHardeningStatus": trust_social_beta_hardening_status,
            "previousTrustSocialBetaHardeningStatus": previous_trust_social_beta_hardening_status,
            "trustSocialContentFormatProfilesStatus": (
                trust_social_content_format_profiles_status
            ),
            "previousTrustSocialContentFormatProfilesStatus": (
                previous_trust_social_content_format_profiles_status
            ),
            "socialMailMigrationStatus": social_mail_migration_status,
            "previousSocialMailMigrationStatus": previous_social_mail_migration_status,
            "generatedDocumentInsertStatus": generated_document_status,
            "previousGeneratedDocumentInsertStatus": previous_generated_document_status,
            "contentFetchStatus": content_fetch_status,
            "previousContentFetchStatus": previous_content_fetch_status,
            "appDataStoreStatus": app_data_store_status,
            "previousAppDataStoreStatus": previous_app_data_store_status,
            "trustGraphPreviewStatus": trust_graph_preview_status,
            "previousTrustGraphPreviewStatus": previous_trust_graph_preview_status,
            "trustStatementSigningStatus": trust_statement_signing_status,
            "previousTrustStatementSigningStatus": previous_trust_statement_signing_status,
            "appServicesDependencyGraphStatus": app_services_dependency_graph_status,
            "previousAppServicesDependencyGraphStatus": previous_app_services_dependency_graph_status,
            "appServicesGrantBundlesStatus": app_services_grant_bundles_status,
            "previousAppServicesGrantBundlesStatus": previous_app_services_grant_bundles_status,
            "appServicesGrantExpiryStatus": app_services_grant_expiry_status,
            "previousAppServicesGrantExpiryStatus": previous_app_services_grant_expiry_status,
            "appServicesProviderRevalidationStatus": app_services_provider_revalidation_status,
            "previousAppServicesProviderRevalidationStatus": (
                previous_app_services_provider_revalidation_status
            ),
            "socialInboxServiceDependencyStatus": social_inbox_service_dependency_status,
            "previousSocialInboxServiceDependencyStatus": (
                previous_social_inbox_service_dependency_status
            ),
            "appServicesDependencyRedactionStatus": app_services_dependency_redaction_status,
            "previousAppServicesDependencyRedactionStatus": (
                previous_app_services_dependency_redaction_status
            ),
            "profilePublisherAppId": profile_details.get("appId"),
            "feedReaderAppId": feed_reader_details.get("appId"),
            "trustGraphAppId": trust_graph_details.get("appId"),
            "socialInboxAppId": social_inbox_details.get("appId"),
        }
    )
    return gate_from_issues(
        "ecosystem.reference-content-apps",
        "Reference content, profile, feed, trust, and social inbox app evidence passed.",
        failures,
        warnings,
        gate_details,
    )

def evaluate_legacy_retirement_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> GateResult:
    failures: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {}
    for evidence_id in (
        "legacy.retirement",
        "legacy-admin.removal-wave-1",
        "legacy-admin.removal-wave-2",
        "legacy-admin.removal-wave-3",
        "legacy-admin.removal-wave-4",
        "legacy-admin.removal-wave-5",
        "legacy-admin.final-admin-surface",
        "legacy-admin.browse-retained",
        "legacy-admin.emergency-fallback-retained",
    ):
        status = evidence_status(current.get(evidence_id))
        previous_status = evidence_status(previous.get(evidence_id))
        details[evidence_id] = {"currentStatus": status, "previousStatus": previous_status}
        if status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is not passing")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
        elif status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            add_evidence_issue(details, "warningEvidenceIds", evidence_id)
        if previous_status == "pass" and status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} regressed from pass to {status}")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
    for evidence_id in (
        "legacy-admin.removal-wave-1",
        "legacy-admin.removal-wave-2",
        "legacy-admin.removal-wave-3",
        "legacy-admin.removal-wave-4",
        "legacy-admin.removal-wave-5",
    ):
        current_wave = evidence_details(current.get(evidence_id))
        previous_wave = evidence_details(previous.get(evidence_id))
        current_routes = set(sorted_strings(current_wave.get("removedByDefaultRouteIds")))
        previous_routes = set(sorted_strings(previous_wave.get("removedByDefaultRouteIds")))
        details[f"{evidence_id}.removedByDefaultRouteCounts"] = {
            "current": len(current_routes),
            "previous": len(previous_routes),
        }
        if previous_routes and current_routes != previous_routes:
            if current_wave.get("docsDescribeWave") or current_wave.get("updateNote"):
                warnings.append(f"{evidence_id} route set changed with documentation evidence")
                add_evidence_issue(details, "warningEvidenceIds", evidence_id)
            else:
                warnings.append(f"{evidence_id} route set changed without doc/update note metadata")
                add_evidence_issue(details, "warningEvidenceIds", evidence_id)
        safety = current_wave.get("retainedBrowseSafety") or current_wave.get("retainedScope")
        if isinstance(safety, dict) and any(value is False for value in safety.values()):
            failures.append(f"{evidence_id} retained browse safety evidence failed")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
    return gate_from_issues(
        "ecosystem.legacy-retirement",
        "Legacy retirement and removal-wave evidence passed.",
        failures,
        warnings,
        details,
    )

def evaluate_waiver_validation_gate(context: WaiverContext, mode: str) -> GateResult | None:
    if not context.errors:
        return None
    status = "fail" if mode == "release-candidate" else "warn"
    return GateResult(
        "ecosystem.waivers",
        status,
        status == "fail",
        "Structured waiver files contain validation errors.",
        {"errors": context.errors, "issueIds": ["ecosystem.waivers.validation"]},
    )

def unique_ids(values: Any) -> list[str]:
    return sorted(dict.fromkeys(str(value) for value in values if str(value).strip()))

def detail_waiver_ids(details: dict[str, Any]) -> list[str]:
    waiver_ids: list[Any] = []
    existing_ids = details.get("waiverIds", [])
    if isinstance(existing_ids, list):
        waiver_ids.extend(existing_ids)
    elif existing_ids:
        waiver_ids.append(existing_ids)
    direct_waiver_id = details.get("waiverId")
    if direct_waiver_id:
        waiver_ids.append(direct_waiver_id)
    return unique_ids(waiver_ids)

def evidence_detail_waiver_id(entry: dict[str, Any] | None) -> str:
    details = evidence_details(entry)
    waiver_id = details.get("waiverId")
    return str(waiver_id) if waiver_id else ""

def gate_detail_waiver_id(gate: GateResult | None) -> str:
    if gate is None:
        return ""
    waiver_id = gate.details.get("waiverId")
    return str(waiver_id) if waiver_id else ""

def gate_waiver_ids(gate: GateResult | None) -> list[str]:
    if gate is None:
        return []
    return detail_waiver_ids(gate.details)

def ecosystem_matrix_row_ids_for_evidence(evidence_id: str) -> list[str]:
    return unique_ids(
        spec.id for spec in ecosystem_matrix_row_specs() if evidence_id in spec.evidence_ids()
    )

def active_waiver_for_ecosystem_rc_evidence(
    context: WaiverContext, evidence_id: str, mode: str
) -> WaiverRecord | None:
    issue_ids = [
        f"evidence.{evidence_id}",
        *ecosystem_matrix_row_ids_for_evidence(evidence_id),
    ]
    return active_waiver_for(context, evidence_id, issue_ids, mode)

def ecosystem_rc_evidence_waiver_id(
    entry: dict[str, Any] | None,
    context: WaiverContext,
    evidence_id: str,
    mode: str,
) -> str:
    if evidence_entry_has_unwaivable_redaction_findings(entry):
        return ""
    waiver_id = evidence_detail_waiver_id(entry)
    if waiver_id:
        return waiver_id
    waiver = active_waiver_for_ecosystem_rc_evidence(context, evidence_id, mode)
    return waiver.id if waiver is not None else ""

def ecosystem_rc_evidence_satisfied(
    entries: dict[str, dict[str, Any]],
    context: WaiverContext,
    evidence_id: str,
    mode: str,
) -> bool:
    entry = entries.get(evidence_id)
    status = evidence_status(entry)
    if status not in {"fail", "missing", "skip"}:
        return True
    return bool(ecosystem_rc_evidence_waiver_id(entry, context, evidence_id, mode))

def conditional_ecosystem_rc_required_evidence_ids(settings: Settings) -> list[str]:
    evidence_ids = list(ECOSYSTEM_RC_REQUIRED_EVIDENCE_IDS)
    if settings.live_network_beta_required:
        evidence_ids.extend(LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS)
    return unique_ids(evidence_ids)

def conditional_ecosystem_rc_required_gate_ids(
    settings: Settings, gate_entries: dict[str, GateResult]
) -> list[str]:
    gate_ids = list(ECOSYSTEM_RC_REQUIRED_GATE_IDS)
    if settings.live_network_beta_required:
        gate_ids.append("ecosystem.live-network-beta")
    if "ecosystem.waivers" in gate_entries:
        gate_ids.append("ecosystem.waivers")
    return unique_ids(gate_ids)

def evaluate_ecosystem_rc_certification_gate(
    settings: Settings,
    current_evidence: list[EvidenceItem],
    child_gates: list[GateResult],
    history_comparison: dict[str, Any],
    waiver_context: WaiverContext,
) -> GateResult:
    current = evidence_map_from_items(current_evidence)
    gate_entries = {gate.id: gate for gate in child_gates}
    required_evidence_ids = conditional_ecosystem_rc_required_evidence_ids(settings)
    required_gate_ids = conditional_ecosystem_rc_required_gate_ids(settings, gate_entries)
    optional_gate_ids = [] if settings.live_network_beta_required else ["ecosystem.live-network-beta"]
    failed_evidence_ids: list[str] = []
    warning_evidence_ids: list[str] = []
    missing_evidence_ids: list[str] = []
    skipped_evidence_ids: list[str] = []
    waived_evidence_ids: list[str] = []
    waived_gate_ids: list[str] = []
    waiver_ids: list[str] = []
    redaction_failure_ids: list[str] = []

    for evidence_id in required_evidence_ids:
        entry = current.get(evidence_id)
        status = evidence_status(entry)
        if evidence_entry_has_unwaivable_redaction_findings(entry):
            redaction_failure_ids.append(evidence_id)
            failed_evidence_ids.append(evidence_id)
            continue
        waiver_id = (
            ecosystem_rc_evidence_waiver_id(entry, waiver_context, evidence_id, settings.mode)
            if status in {"fail", "missing", "skip", "warn"}
            else evidence_detail_waiver_id(entry)
        )
        if waiver_id:
            waived_evidence_ids.append(evidence_id)
            waiver_ids.append(waiver_id)
        if status == "fail":
            if waiver_id:
                warning_evidence_ids.append(evidence_id)
            else:
                failed_evidence_ids.append(evidence_id)
        elif status == "missing":
            if waiver_id:
                warning_evidence_ids.append(evidence_id)
            else:
                missing_evidence_ids.append(evidence_id)
        elif status == "skip":
            if waiver_id:
                warning_evidence_ids.append(evidence_id)
            elif settings.mode == "release-candidate":
                skipped_evidence_ids.append(evidence_id)
            else:
                warning_evidence_ids.append(evidence_id)
        elif status == "warn":
            warning_evidence_ids.append(evidence_id)

    blocking_gate_ids: list[str] = []
    warning_gate_ids: list[str] = []
    for gate_id in required_gate_ids:
        gate = gate_entries.get(gate_id)
        if gate is None:
            blocking_gate_ids.append(gate_id)
            continue
        waiver_id = gate_detail_waiver_id(gate)
        if waiver_id:
            waived_gate_ids.append(gate_id)
            waiver_ids.append(waiver_id)
        if gate.status == "fail" and gate.release_blocker:
            blocking_gate_ids.append(gate_id)
        elif gate.status in {"warn", "fail", "missing"}:
            warning_gate_ids.append(gate_id)
    for gate_id in optional_gate_ids:
        gate = gate_entries.get(gate_id)
        if gate is not None and gate.status in {"warn", "fail", "missing"}:
            warning_gate_ids.append(gate_id)

    history_status = normalize_evidence_status(str(history_comparison.get("status", "missing")))
    if history_status == "fail":
        blocking_gate_ids.append("history-comparison")
    elif history_status in {"warn", "missing"}:
        warning_gate_ids.append("history-comparison")

    matrix_entry = current.get("release-certification.ecosystem-matrix")
    matrix_coverage = evidence_details(matrix_entry).get("coverage", {})
    matrix_redaction_passed = (
        bool(matrix_coverage.get("redactionPassed", True))
        if isinstance(matrix_coverage, dict)
        else True
    )
    redaction_evidence_passed = True
    for evidence_id in ECOSYSTEM_RC_REDACTION_EVIDENCE_IDS:
        entry = current.get(evidence_id)
        status = evidence_status(entry)
        has_redaction_findings = evidence_entry_has_unwaivable_redaction_findings(entry)
        if (
            evidence_id == "live-network-beta.redaction"
            and not settings.live_network_beta_required
            and status in {"missing", "skip"}
            and not has_redaction_findings
        ):
            continue
        if has_redaction_findings:
            redaction_evidence_passed = False
            if evidence_id not in redaction_failure_ids:
                redaction_failure_ids.append(evidence_id)
    redaction_passed = matrix_redaction_passed and redaction_evidence_passed

    live_required = settings.live_network_beta_required
    live_network_satisfied = (not live_required) or all(
        ecosystem_rc_evidence_satisfied(
            current,
            waiver_context,
            evidence_id,
            settings.mode,
        )
        for evidence_id in LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS
    )
    network_scale_soak_satisfied = ecosystem_rc_evidence_satisfied(
        current,
        waiver_context,
        NETWORK_SCALE_SOAK_EVIDENCE_ID,
        settings.mode,
    )
    multi_node_beta_satisfied = all(
        ecosystem_rc_evidence_satisfied(
            current,
            waiver_context,
            evidence_id,
            settings.mode,
        )
        for evidence_id in MULTI_NODE_BETA_EVIDENCE_IDS
    )
    first_party_gate = gate_entries.get("ecosystem.first-party-apps")
    first_party_apps_covered = first_party_gate is not None and first_party_gate.status in {"pass", "warn"}

    failed_evidence_ids = unique_ids(failed_evidence_ids)
    warning_evidence_ids = unique_ids(warning_evidence_ids)
    missing_evidence_ids = unique_ids(missing_evidence_ids)
    skipped_evidence_ids = unique_ids(skipped_evidence_ids)
    blocking_gate_ids = unique_ids(blocking_gate_ids)
    warning_gate_ids = unique_ids(warning_gate_ids)
    waived_evidence_ids = unique_ids(waived_evidence_ids)
    waived_gate_ids = unique_ids(waived_gate_ids)
    waiver_ids = unique_ids(waiver_ids)
    redaction_failure_ids = unique_ids(redaction_failure_ids)

    has_blockers = bool(
        failed_evidence_ids
        or missing_evidence_ids
        or (settings.mode == "release-candidate" and skipped_evidence_ids)
        or blocking_gate_ids
        or not redaction_passed
        or not network_scale_soak_satisfied
        or not multi_node_beta_satisfied
        or not live_network_satisfied
    )
    has_warnings = bool(
        warning_evidence_ids
        or skipped_evidence_ids
        or warning_gate_ids
        or waiver_ids
        or history_status in {"warn", "missing"}
    )
    release_blocker = has_blockers and (settings.mode == "release-candidate" or not redaction_passed)
    status = "fail" if release_blocker else ("warn" if has_blockers or has_warnings else "pass")
    promotion_ready = not release_blocker
    details = {
        "phase": "phase-9",
        "requiredEvidenceIds": required_evidence_ids,
        "requiredGateIds": required_gate_ids,
        "optionalGateIds": optional_gate_ids,
        "failedEvidenceIds": failed_evidence_ids,
        "warningEvidenceIds": warning_evidence_ids,
        "missingEvidenceIds": missing_evidence_ids,
        "skippedEvidenceIds": skipped_evidence_ids,
        "blockingGateIds": blocking_gate_ids,
        "warningGateIds": warning_gate_ids,
        "waiverIds": waiver_ids,
        "waivedEvidenceIds": waived_evidence_ids,
        "waivedGateIds": waived_gate_ids,
        "historyComparisonStatus": history_status,
        "liveNetworkRequired": live_required,
        "liveNetworkSatisfied": live_network_satisfied,
        "networkScaleSoakSatisfied": network_scale_soak_satisfied,
        "multiNodeBetaSatisfied": multi_node_beta_satisfied,
        "redactionPassed": redaction_passed,
        "redactionFailureEvidenceIds": redaction_failure_ids,
        "firstPartyAppsCovered": first_party_apps_covered,
        "promotionReady": promotion_ready,
    }
    if failed_evidence_ids or missing_evidence_ids or skipped_evidence_ids:
        details["failureEvidenceIds"] = unique_ids(
            failed_evidence_ids + missing_evidence_ids + skipped_evidence_ids
        )
    if redaction_failure_ids:
        details["unwaivableFailureEvidenceIds"] = redaction_failure_ids
    if warning_evidence_ids:
        details["warningEvidenceIds"] = warning_evidence_ids
    summary = (
        "Ecosystem RC certification is ready for promotion."
        if status == "pass"
        else (
            "Ecosystem RC certification has warnings or waived blockers."
            if status == "warn"
            else "Ecosystem RC certification has release-blocking failures."
        )
    )
    return GateResult(ECOSYSTEM_RC_GATE_ID, status, release_blocker, summary, details)

def evaluate_ecosystem_gates(
    settings: Settings,
    current_evidence: list[EvidenceItem],
    previous_summary: dict[str, Any] | None,
    history_comparison: dict[str, Any],
    metadata: dict[str, Any],
    waiver_context: WaiverContext,
) -> list[GateResult]:
    current = evidence_map_from_items(current_evidence)
    previous = evidence_map_from_summary(previous_summary)
    diffs = history_comparison.get("evidenceDiffs", [])
    if not isinstance(diffs, list):
        diffs = []
    child_gates = [
        evaluate_required_evidence_regressions([diff for diff in diffs if isinstance(diff, dict)]),
        evaluate_platform_api_gate(current, previous, settings.mode, settings.require_history),
        evaluate_first_party_apps_gate(current, previous),
        evaluate_app_ui_quality_gate(current, previous),
        evaluate_app_review_trust_gate(current, previous, metadata, settings.mode),
        evaluate_app_update_rollback_gate(current, previous),
        evaluate_operator_rc_recovery_gate(current, previous),
        evaluate_ecosystem_security_advisory_revocation_gate(current, previous),
        evaluate_live_network_beta_gate(current, settings),
        evaluate_multi_node_beta_gate(current, settings),
        evaluate_app_vault_gate(current, previous),
        evaluate_sandbox_provider_gate(current, previous, settings.mode, metadata),
        evaluate_reference_content_gate(current, previous),
        evaluate_legacy_retirement_gate(current, previous),
    ]
    waiver_gate = evaluate_waiver_validation_gate(waiver_context, settings.mode)
    if waiver_gate is not None:
        child_gates.append(waiver_gate)
    waived_child_gates = [
        apply_waiver_to_gate(gate, waiver_context, settings.mode) for gate in child_gates
    ]
    final_gate = evaluate_ecosystem_rc_certification_gate(
        settings,
        current_evidence,
        waived_child_gates,
        history_comparison,
        waiver_context,
    )
    return [
        *waived_child_gates,
        apply_waiver_to_gate(final_gate, waiver_context, settings.mode),
    ]

def history_status_affects_decision(status: str) -> bool:
    return status in {"warn", "fail", "missing"}

def determine_certification_status(
    mode: str,
    evidence: list[EvidenceItem],
    history_comparison: dict[str, Any],
    ecosystem_gates: list[GateResult],
    waiver_context: WaiverContext,
) -> tuple[str, bool]:
    evidence_status_value, evidence_release_passed = determine_overall_status(
        mode, evidence, waiver_context
    )
    history_status = normalize_evidence_status(str(history_comparison.get("status", "missing")))
    gate_failures = [gate for gate in ecosystem_gates if gate.status == "fail" and gate.release_blocker]
    gate_warnings = [gate for gate in ecosystem_gates if gate.status in {"warn", "fail", "missing"}]
    history_warning = history_status_affects_decision(history_status)
    release_candidate_passed = evidence_release_passed and not gate_failures and history_status != "fail"
    if mode == "release-candidate":
        if evidence_status_value == "fail" or gate_failures or history_status == "fail":
            return "fail", False
        if evidence_status_value == "warn" or gate_warnings or history_warning:
            return "warn", release_candidate_passed
        return "pass", True
    if mode == "nightly":
        if evidence_status_value == "fail" or gate_failures:
            return "fail", False
        if evidence_status_value == "warn" or gate_warnings or history_warning:
            return "warn", release_candidate_passed
        return "pass", True
    if evidence_status_value == "warn" or gate_warnings or history_warning:
        return "warn", release_candidate_passed
    return "pass", release_candidate_passed

def promotion_decision(status: str, release_candidate_passed: bool = True) -> str:
    if not release_candidate_passed:
        return "FAIL"
    if status == "pass":
        return "PASS"
    if status == "warn":
        return "PASS WITH WARNINGS"
    return "FAIL"

def report_status_label(status: Any) -> str:
    normalized = normalize_evidence_status(str(status))
    if normalized in {"skip", "missing"}:
        return "NOT AVAILABLE"
    return normalized.upper()

def aggregate_gate_status(gates: list[GateResult]) -> str:
    if any(gate.status == "fail" for gate in gates):
        return "fail"
    if any(gate.status == "warn" for gate in gates):
        return "warn"
    return "pass"

def ecosystem_rc_gate_summary(gates: list[GateResult]) -> dict[str, Any]:
    gate = next((candidate for candidate in gates if candidate.id == ECOSYSTEM_RC_GATE_ID), None)
    if gate is None:
        return {
            "id": ECOSYSTEM_RC_GATE_ID,
            "status": "missing",
            "releaseBlocker": True,
            "promotionReady": False,
            "failedEvidenceCount": 0,
            "missingEvidenceCount": 0,
            "blockingGateCount": 1,
            "waiverCount": 0,
        }
    details = gate.details
    waiver_ids = gate_waiver_ids(gate)
    return {
        "id": gate.id,
        "status": gate.status,
        "releaseBlocker": gate.release_blocker,
        "promotionReady": bool(details.get("promotionReady", not gate.release_blocker)),
        "failedEvidenceCount": len(details.get("failedEvidenceIds", [])),
        "missingEvidenceCount": len(details.get("missingEvidenceIds", [])),
        "warningEvidenceCount": len(details.get("warningEvidenceIds", [])),
        "blockingGateCount": len(details.get("blockingGateIds", [])),
        "warningGateCount": len(details.get("warningGateIds", [])),
        "waiverCount": len(waiver_ids),
    }

def ecosystem_rc_decision(compact_gate: dict[str, Any]) -> str:
    if compact_gate.get("releaseBlocker") or compact_gate.get("status") in {"fail", "missing"}:
        return "FAIL"
    if compact_gate.get("status") == "warn":
        return "PASS_WITH_WARNINGS"
    return "PASS"

def safe_multi_node_report_text(source_path: Path, settings: Settings, out_dir: Path) -> str | None:
    try:
        report_text = source_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    findings = multi_node_beta_soak.scan_redaction_payload({}, report_text)
    if not findings:
        return scrub_text(report_text, settings.workspace_root, out_dir)
    finding_kinds = sorted({str(finding.get("kind", "redaction-finding")) for finding in findings})
    return (
        "# Multi-node Beta Soak Report Redacted\n\n"
        "The attached multi-node report was not copied because the multi-node redaction "
        "scanner found prohibited content. Use the compact JSON summary for release evidence.\n\n"
        f"- findingCount: {len(findings)}\n"
        f"- findingKinds: {', '.join(finding_kinds)}\n"
    )

def collect_source_artifacts(settings: Settings, out_dir: Path) -> list[str]:
    artifacts_dir = out_dir / "artifacts"
    if artifacts_dir.exists():
        shutil.rmtree(artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    source_map = {
        "interop-smoke-summary.json": settings.interop_smoke_summary,
        "interop-extended-summary.json": settings.interop_extended_summary,
        "performance-smoke-summary.json": settings.perf_smoke_summary,
        "app-platform-smoke-summary.json": settings.app_platform_summary,
        "security-drills-summary.json": settings.security_drills_summary
        or settings.workspace_root / "build/security-drills/security-drills-summary.json",
        "interop-smoke-report.md": settings.interop_smoke_summary.parent / "artifacts" / "interop-report.md",
        "interop-extended-report.md": settings.interop_extended_summary.parent / "artifacts" / "interop-report.md",
        "performance-smoke-report.md": settings.perf_smoke_summary.parent / "artifacts" / "perf-report.md",
        "app-platform-smoke-report.md": settings.app_platform_summary.parent / "app-platform-smoke-report.md",
        "network-scale-soak-summary.json": settings.network_scale_soak_summary,
        "multi-node-beta-soak-summary.json": settings.multi_node_soak_summary,
        "multi-node-beta-soak-report.md": settings.multi_node_soak_summary.parent
        / multi_node_beta_soak.REPORT_FILE_NAME,
    }
    if settings.live_network_beta_enabled or settings.live_network_beta_required:
        source_map.update(
            {
                "live-network-beta-smoke-summary.json": settings.live_network_summary,
                "live-network-beta-smoke-report.md": settings.live_network_summary.parent
                / "live-network-beta-smoke-report.md",
            }
        )
    copied: list[str] = []
    for target_name, source_path in source_map.items():
        if not source_path.is_file():
            continue
        if any(name in str(source_path) for name in PRIVATE_ARTIFACT_NAMES):
            continue
        target_path = artifacts_dir / target_name
        if target_name.endswith(".json"):
            value = read_json(source_path)
            if value is None:
                continue
            if target_name == "network-scale-soak-summary.json":
                safe_value, _ = allowlisted_network_scale_soak_summary(value)
            elif target_name == "multi-node-beta-soak-summary.json":
                safe_value = sanitize_compact_multi_node_summary(value, settings.workspace_root, out_dir)
            else:
                safe_value = sanitize_value(value, settings.workspace_root, out_dir)
            write_json(target_path, safe_value)
        elif target_name == "multi-node-beta-soak-report.md":
            safe_text = safe_multi_node_report_text(source_path, settings, out_dir)
            if safe_text is None:
                continue
            target_path.write_text(safe_text, encoding="utf-8")
        else:
            target_path.write_text(
                scrub_text(source_path.read_text(encoding="utf-8"), settings.workspace_root, out_dir),
                encoding="utf-8",
            )
        copied.append(display_path(target_path, settings.workspace_root, out_dir))
    return copied

def sanitize_compact_multi_node_summary(
    value: dict[str, Any],
    workspace_root: Path,
    out_dir: Path,
) -> dict[str, Any]:
    compact = multi_node_beta_soak.compact_for_release(value)
    safe_value = sanitize_value(compact, workspace_root, out_dir)
    if not isinstance(safe_value, dict):
        return {}
    safe_redaction = safe_value.get("redaction")
    compact_redaction = compact.get("redaction")
    if not isinstance(safe_redaction, dict) or not isinstance(compact_redaction, dict):
        return safe_value
    safe_checks = safe_redaction.get("checks")
    compact_checks = compact_redaction.get("checks")
    if not isinstance(safe_checks, dict) or not isinstance(compact_checks, dict):
        return safe_value
    for key in multi_node_beta_soak.REDACTION_KEYS:
        value = compact_checks.get(key)
        if isinstance(value, bool):
            safe_checks[key] = value
    return safe_value

def collect_metadata(settings: Settings) -> dict[str, Any]:
    metadata = {}
    metadata.update(collect_git_metadata(settings))
    metadata.update(collect_ci_metadata(os.environ))
    metadata.update(settings.metadata)
    return dict(sanitize_value(metadata, settings.workspace_root, settings.out_dir))

def sanitized_cli_waivers(settings: Settings) -> dict[str, str]:
    return {
        scrub_text(str(waiver_id), settings.workspace_root, settings.out_dir): scrub_text(
            reason, settings.workspace_root, settings.out_dir
        )
        for waiver_id, reason in settings.waivers.items()
    }
