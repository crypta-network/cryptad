"""Implementation segment for the contracts portion of ``app_platform_smoke.py``."""

from __future__ import annotations

def stable_capability_names(capabilities: list[Any]) -> list[str]:
    names: list[str] = []
    for entry in capabilities:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("stability", "unknown")).lower() != "stable":
            continue
        name = str(entry.get("name") or entry.get("id") or "").strip()
        if name and name not in names:
            names.append(name)
    return sorted(names)

def stable_endpoint_identities(endpoints: list[Any]) -> list[str]:
    identities: list[str] = []
    for entry in endpoints:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("stability", "unknown")).lower() != "stable":
            continue
        route = str(entry.get("routeTemplate") or entry.get("path") or entry.get("route") or "").strip()
        if not route:
            continue
        method = str(entry.get("method", "")).strip().upper()
        identity = f"{method} {route}" if method else route
        if identity not in identities:
            identities.append(identity)
    return sorted(identities)

def endpoint_identity(entry: dict[str, Any]) -> str:
    route = str(entry.get("routeTemplate") or entry.get("path") or entry.get("route") or "").strip()
    if not route:
        return ""
    method = str(entry.get("method", "")).strip().upper()
    return f"{method} {route}" if method else route

def string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        text = str(item).strip()
        if text and text not in result:
            result.append(text)
    return sorted(result)

def stable_endpoint_required_capabilities(
    endpoints: list[Any], baseline_endpoint_identities: list[str]
) -> dict[str, list[str]]:
    baseline = set(baseline_endpoint_identities)
    capability_sets: dict[str, list[str]] = {}
    for entry in endpoints:
        if not isinstance(entry, dict):
            continue
        identity = endpoint_identity(entry)
        if not identity:
            continue
        if baseline:
            if identity not in baseline:
                continue
        elif str(entry.get("stability", "unknown")).lower() != "stable":
            continue
        capability_sets[identity] = string_list(entry.get("requiredCapabilities"))
    for identity in sorted(baseline):
        capability_sets.setdefault(identity, [])
    return {identity: capability_sets[identity] for identity in sorted(capability_sets)}

def boolean_field(value: Any) -> bool:
    return value if isinstance(value, bool) else False

def plain_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)

def stable_endpoint_app_access(
    endpoints: list[Any], baseline_endpoint_identities: list[str]
) -> dict[str, dict[str, bool]]:
    baseline = set(baseline_endpoint_identities)
    access_by_endpoint: dict[str, dict[str, bool]] = {}
    for entry in endpoints:
        if not isinstance(entry, dict):
            continue
        identity = endpoint_identity(entry)
        if not identity:
            continue
        if baseline:
            if identity not in baseline:
                continue
        elif str(entry.get("stability", "unknown")).lower() != "stable":
            continue
        access_by_endpoint[identity] = {
            "appProcessPrincipalsAllowed": boolean_field(entry.get("appProcessPrincipalsAllowed")),
            "appBrowserPrincipalsAllowed": boolean_field(entry.get("appBrowserPrincipalsAllowed")),
        }
    for identity in sorted(baseline):
        access_by_endpoint.setdefault(
            identity,
            {
                "appProcessPrincipalsAllowed": False,
                "appBrowserPrincipalsAllowed": False,
            },
        )
    return {identity: access_by_endpoint[identity] for identity in sorted(access_by_endpoint)}

def stable_endpoint_action_labels(
    endpoints: list[Any], baseline_endpoint_identities: list[str]
) -> dict[str, str]:
    baseline = set(baseline_endpoint_identities)
    labels_by_endpoint: dict[str, str] = {}
    for entry in endpoints:
        if not isinstance(entry, dict):
            continue
        identity = endpoint_identity(entry)
        if not identity:
            continue
        if baseline:
            if identity not in baseline:
                continue
        elif str(entry.get("stability", "unknown")).lower() != "stable":
            continue
        label = str(entry.get("actionLabel") or "").strip()
        if label:
            labels_by_endpoint[identity] = label
    return {identity: labels_by_endpoint[identity] for identity in sorted(labels_by_endpoint)}

def stable_descriptor_deprecation_entry(
    kind: str, identity: str, entry: dict[str, Any]
) -> dict[str, Any] | None:
    stability = str(entry.get("stability", "unknown")).strip().lower()
    deprecation = entry.get("deprecation")
    has_deprecation_metadata = isinstance(deprecation, dict)
    if stability not in PLATFORM_API_DEPRECATION_STABILITY_VALUES and not has_deprecation_metadata:
        return None
    descriptor: dict[str, Any] = {
        "kind": kind,
        "identity": identity,
        "stability": stability,
        "hasDeprecationMetadata": has_deprecation_metadata,
    }
    if has_deprecation_metadata:
        descriptor[FIELD_DEPRECATED_SINCE_CONTRACT_VERSION] = deprecation.get(
            FIELD_DEPRECATED_SINCE_CONTRACT_VERSION
        )
        if FIELD_REMOVAL_CONTRACT_VERSION in deprecation:
            descriptor[FIELD_REMOVAL_CONTRACT_VERSION] = deprecation.get(
                FIELD_REMOVAL_CONTRACT_VERSION
            )
    return descriptor

def stable_descriptor_deprecations(
    capabilities: list[Any],
    endpoints: list[Any],
    baseline_capabilities: list[str],
    baseline_endpoints: list[str],
) -> list[dict[str, Any]]:
    baseline_capability_names = set(baseline_capabilities)
    baseline_endpoint_identities = set(baseline_endpoints)
    deprecations: list[dict[str, Any]] = []
    for entry in capabilities:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or entry.get("id") or "").strip()
        if not name or name not in baseline_capability_names:
            continue
        descriptor = stable_descriptor_deprecation_entry("capability", name, entry)
        if descriptor:
            deprecations.append(descriptor)
    for entry in endpoints:
        if not isinstance(entry, dict):
            continue
        identity = endpoint_identity(entry)
        if not identity or identity not in baseline_endpoint_identities:
            continue
        descriptor = stable_descriptor_deprecation_entry("endpoint", identity, entry)
        if descriptor:
            deprecations.append(descriptor)
    return sorted(deprecations, key=lambda value: (value["kind"], value["identity"]))

def stable_deprecation_label(descriptor: dict[str, Any]) -> str:
    kind = str(descriptor.get("kind") or "descriptor").strip()
    identity = str(descriptor.get("identity") or "<unknown>").strip()
    return f"stable {kind} {identity}"

def stable_deprecation_version_errors(
    descriptor: dict[str, Any],
    current_contract_version: int,
    minimum_deprecation_window: int,
    minimum_scheduled_removal_window: int,
) -> list[str]:
    label = stable_deprecation_label(descriptor)
    stability = str(descriptor.get("stability") or "unknown").strip().lower()
    deprecated_since = descriptor.get(FIELD_DEPRECATED_SINCE_CONTRACT_VERSION)
    if not plain_int(deprecated_since):
        return [f"{label} is {stability} without deprecatedSinceContractVersion metadata"]
    if deprecated_since > current_contract_version:
        return [
            f"{label} deprecatedSinceContractVersion {deprecated_since} is after current "
            f"contractVersion {current_contract_version}"
        ]
    removal_version = descriptor.get(FIELD_REMOVAL_CONTRACT_VERSION)
    if stability == "deprecated" and removal_version is None:
        return []
    if not plain_int(removal_version):
        return [f"{label} is scheduled for removal without removalContractVersion metadata"]
    errors: list[str] = []
    if removal_version <= deprecated_since:
        errors.append(
            f"{label} removalContractVersion must be greater than "
            "deprecatedSinceContractVersion"
        )
    if removal_version - deprecated_since < minimum_deprecation_window:
        errors.append(
            f"{label} deprecation window is shorter than "
            f"{minimum_deprecation_window} contract versions"
        )
    if removal_version - current_contract_version < minimum_scheduled_removal_window:
        errors.append(
            f"{label} scheduled-removal runway is shorter than "
            f"{minimum_scheduled_removal_window} contract versions"
        )
    return errors

def stable_deprecation_policy_findings(
    contract_details: dict[str, Any], compatibility_window: dict[str, Any]
) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    current_contract_version = contract_details.get("contractVersion")
    minimum_deprecation_window = compatibility_window.get(
        "minimumDeprecationWindowContractVersions"
    )
    minimum_scheduled_removal_window = compatibility_window.get(
        "minimumScheduledRemovalWindowContractVersions"
    )
    if not plain_int(current_contract_version):
        errors.append("contractVersion must be an integer for stable deprecation policy checks")
    if not plain_int(minimum_deprecation_window):
        errors.append("minimum deprecation window must be an integer")
    if not plain_int(minimum_scheduled_removal_window):
        errors.append("minimum scheduled-removal window must be an integer")
    descriptors = contract_details.get("stableDescriptorDeprecations")
    if not isinstance(descriptors, list):
        errors.append("stable descriptor deprecation metadata is missing")
        descriptors = []
    if errors:
        return errors, warnings
    for descriptor in descriptors:
        if not isinstance(descriptor, dict):
            errors.append("stable descriptor deprecation entry is malformed")
            continue
        stability = str(descriptor.get("stability") or "unknown").strip().lower()
        label = stable_deprecation_label(descriptor)
        if stability not in PLATFORM_API_DEPRECATION_STABILITY_VALUES:
            warnings.append(f"{label} has deprecation metadata but stability is {stability}")
            continue
        descriptor_errors = stable_deprecation_version_errors(
            descriptor,
            current_contract_version,
            minimum_deprecation_window,
            minimum_scheduled_removal_window,
        )
        if descriptor_errors:
            errors.extend(descriptor_errors)
        elif descriptor.get(FIELD_REMOVAL_CONTRACT_VERSION) is None:
            warnings.append(
                f"{label} is deprecated since contract "
                f"{descriptor.get(FIELD_DEPRECATED_SINCE_CONTRACT_VERSION)}"
            )
        else:
            warnings.append(
                f"{label} is scheduled for removal in contract "
                f"{descriptor.get(FIELD_REMOVAL_CONTRACT_VERSION)}"
            )
    return errors, warnings

def capability_names(capabilities: list[Any]) -> list[str]:
    names: list[str] = []
    for entry in capabilities:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or entry.get("id") or "").strip()
        if name and name not in names:
            names.append(name)
    return sorted(names)

def endpoint_identities(endpoints: list[Any]) -> list[str]:
    identities: list[str] = []
    for entry in endpoints:
        if not isinstance(entry, dict):
            continue
        route = str(entry.get("routeTemplate") or entry.get("path") or entry.get("route") or "").strip()
        if not route:
            continue
        method = str(entry.get("method", "")).strip().upper()
        identity = f"{method} {route}" if method else route
        if identity not in identities:
            identities.append(identity)
    return sorted(identities)

def collect_platform_api_contract_evidence(
    settings: Settings, cli: Path | None, sample_paths: dict[str, Path]
) -> EvidenceItem:
    source = summary_source(settings)
    artifact = settings.out_dir / "artifacts" / "platform-api-contract.json"
    details: dict[str, Any] = {"artifactPath": display_path(artifact, settings.workspace_root, settings.out_dir)}
    if cli is None or not cli.is_file():
        return EvidenceItem(
            "platform-api.contract",
            root_consequence(settings, "missing"),
            True,
            "crypta-app CLI is unavailable for Platform API contract evidence.",
            source,
            details,
        )

    snapshot_result = run_cli(
        cli,
        ["api", "snapshot", "--output", str(artifact)],
        settings,
        "crypta-app-api-snapshot",
    )
    details["snapshotCommand"] = command_details(snapshot_result, settings)
    errors: list[str] = []
    if snapshot_result.exit_code != 0:
        errors.append("contract snapshot generation failed")
    if not artifact.is_file():
        errors.append("contract snapshot file was not written")

    contract: dict[str, Any] = {}
    if artifact.is_file():
        try:
            payload = json.loads(artifact.read_text(encoding="utf-8"))
            contract = payload.get("contract", payload) if isinstance(payload, dict) else {}
        except (json.JSONDecodeError, OSError) as exc:
            errors.append(f"contract snapshot is not valid JSON: {exc}")

    capabilities = contract.get("capabilities", []) if isinstance(contract, dict) else []
    endpoints = contract.get("endpoints", []) if isinstance(contract, dict) else []
    if not isinstance(capabilities, list):
        errors.append("contract capabilities must be a list")
        capabilities = []
    if not isinstance(endpoints, list):
        errors.append("contract endpoints must be a list")
        endpoints = []
    stability_counts: dict[str, int] = {}
    flagged: list[str] = []
    for collection_name, entries in (("capability", capabilities), ("endpoint", endpoints)):
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            stability = str(entry.get("stability", "unknown"))
            stability_counts[stability] = stability_counts.get(stability, 0) + 1
            if stability != "stable":
                flagged.append(f"{collection_name}:{entry.get('name') or entry.get('routeTemplate')}:{stability}")
    contract_version = contract.get("contractVersion") if isinstance(contract, dict) else None
    api_version = contract.get("apiVersion") if isinstance(contract, dict) else None
    details["contractVersion"] = contract_version
    details["apiVersion"] = api_version
    details["capabilityCount"] = len(capabilities)
    details["endpointCount"] = len(endpoints)
    stable_capabilities = stable_capability_names(capabilities)
    stable_endpoints = stable_endpoint_identities(endpoints)
    stable_baseline = contract.get("stableBaseline") if isinstance(contract, dict) else None
    compatibility_window = (
        contract.get("compatibilityWindow") if isinstance(contract, dict) else None
    )
    if isinstance(stable_baseline, dict):
        baseline_capabilities = stable_baseline.get("capabilities", [])
        baseline_endpoints = stable_baseline.get("endpoints", [])
        details["stableBaseline"] = stable_baseline
        details["stableBaselineCapabilities"] = (
            sorted(str(value) for value in baseline_capabilities)
            if isinstance(baseline_capabilities, list)
            else []
        )
        details["stableBaselineEndpoints"] = (
            sorted(str(value) for value in baseline_endpoints)
            if isinstance(baseline_endpoints, list)
            else []
        )
    else:
        details["stableBaseline"] = None
        details["stableBaselineCapabilities"] = stable_capabilities
        details["stableBaselineEndpoints"] = stable_endpoints
    details["compatibilityWindow"] = (
        compatibility_window if isinstance(compatibility_window, dict) else None
    )
    details["stableCapabilities"] = stable_capabilities
    details["stableEndpoints"] = stable_endpoints
    details["stableEndpointRequiredCapabilities"] = stable_endpoint_required_capabilities(
        endpoints, details["stableBaselineEndpoints"]
    )
    details["stableEndpointAppAccess"] = stable_endpoint_app_access(
        endpoints, details["stableBaselineEndpoints"]
    )
    details["stableEndpointActionLabels"] = stable_endpoint_action_labels(
        endpoints, details["stableBaselineEndpoints"]
    )
    details["stableDescriptorDeprecations"] = stable_descriptor_deprecations(
        capabilities,
        endpoints,
        details["stableBaselineCapabilities"],
        details["stableBaselineEndpoints"],
    )
    details["stableCapabilityCount"] = len(details["stableCapabilities"])
    details["stableEndpointCount"] = len(details["stableEndpoints"])
    details["stableBaselineCapabilityCount"] = len(details["stableBaselineCapabilities"])
    details["stableBaselineEndpointCount"] = len(details["stableBaselineEndpoints"])
    details["stabilityCounts"] = stability_counts
    details["flaggedStability"] = flagged
    required_app_data_capabilities = {"app.data.read", "app.data.write"}
    required_app_data_endpoints = {
        "GET /app-data/status",
        "GET /app-data/namespaces",
        "GET /app-data/namespaces/{namespace}",
        "POST /app-data/namespaces/{namespace}/schema",
        "DELETE /app-data/namespaces/{namespace}",
        "GET /app-data/records",
        "GET /app-data/records/{namespace}/{key}",
        "POST /app-data/records",
        "DELETE /app-data/records/{namespace}/{key}",
        "GET /app-data/export",
        "POST /app-data/import",
    }
    required_trust_exchange_capabilities = {"content.fetch", "trust.read", "trust.write"}
    required_trust_exchange_endpoints = {
        "GET /trust-graph/audit",
        "POST /trust-graph/import-uri",
    }
    required_social_message_capabilities = {
        "vault.identities.read",
        "vault.identities.use",
    }
    required_social_message_endpoints = {
        "POST /app-vault/identities/{identityId}/social-message",
    }
    required_app_service_capabilities = {
        "app.services.read",
        "app.services.call",
    }
    required_app_service_endpoints = {
        "GET /app-services",
        "GET /app-services/audit",
        "GET /app-services/dependencies",
        "GET /app-services/dependencies/consumers/{consumerAppId}",
        "GET /app-services/grant-bundles",
        "GET /app-services/grants",
        "POST /app-services/grant-bundles",
        "POST /app-services/grant-bundles/{bundleId}/approve",
        "POST /app-services/grant-bundles/{bundleId}/reject",
        "POST /app-services/grant-bundles/{bundleId}/renew",
        "POST /app-services/grants",
        "POST /app-services/grants/{grantId}/approve",
        "POST /app-services/grants/{grantId}/revoke",
        "GET /app-services/{providerAppId}/services",
        "GET /app-services/{providerAppId}/services/{serviceId}",
        "POST /app-services/{providerAppId}/services/{serviceId}/invoke",
    }
    stable_baseline_capabilities = set(details["stableBaselineCapabilities"])
    stable_baseline_endpoints = set(details["stableBaselineEndpoints"])
    contract_capabilities = set(capability_names(capabilities))
    contract_endpoints = set(endpoint_identities(endpoints))
    missing_app_data_capabilities = sorted(
        required_app_data_capabilities - stable_baseline_capabilities
    )
    missing_app_data_endpoints = sorted(required_app_data_endpoints - stable_baseline_endpoints)
    missing_trust_exchange_capabilities = sorted(
        required_trust_exchange_capabilities - contract_capabilities
    )
    missing_trust_exchange_endpoints = sorted(
        required_trust_exchange_endpoints - contract_endpoints
    )
    missing_social_message_capabilities = sorted(
        required_social_message_capabilities - contract_capabilities
    )
    missing_social_message_endpoints = sorted(
        required_social_message_endpoints - contract_endpoints
    )
    missing_app_service_capabilities = sorted(
        required_app_service_capabilities - contract_capabilities
    )
    missing_app_service_endpoints = sorted(required_app_service_endpoints - contract_endpoints)
    details["appDataContract"] = {
        "capabilities": sorted(required_app_data_capabilities),
        "endpoints": sorted(required_app_data_endpoints),
        "missingCapabilities": missing_app_data_capabilities,
        "missingEndpoints": missing_app_data_endpoints,
    }
    details["trustGraphExchangeContract"] = {
        "capabilities": sorted(required_trust_exchange_capabilities),
        "endpoints": sorted(required_trust_exchange_endpoints),
        "missingCapabilities": missing_trust_exchange_capabilities,
        "missingEndpoints": missing_trust_exchange_endpoints,
    }
    details["socialMessageContract"] = {
        "capabilities": sorted(required_social_message_capabilities),
        "endpoints": sorted(required_social_message_endpoints),
        "missingCapabilities": missing_social_message_capabilities,
        "missingEndpoints": missing_social_message_endpoints,
    }
    details["appServicesContract"] = {
        "capabilities": sorted(required_app_service_capabilities),
        "endpoints": sorted(required_app_service_endpoints),
        "missingCapabilities": missing_app_service_capabilities,
        "missingEndpoints": missing_app_service_endpoints,
    }
    if contract:
        if not isinstance(contract_version, int) or isinstance(contract_version, bool) or contract_version <= 0:
            errors.append("contractVersion must be a positive integer")
        if not isinstance(api_version, str) or not api_version.strip():
            errors.append("apiVersion must be a non-empty string")
        if contract_version != CURRENT_PLATFORM_API_CONTRACT_VERSION:
            errors.append(
                "contractVersion must be "
                f"{CURRENT_PLATFORM_API_CONTRACT_VERSION} for app-service dependency bundle support"
            )
        if not isinstance(stable_baseline, dict):
            errors.append("contract stableBaseline metadata is missing")
        else:
            if stable_baseline.get("name") != "1.0":
                errors.append("stableBaseline.name must be 1.0")
            if (
                stable_baseline.get("contractVersion")
                != CURRENT_PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION
            ):
                errors.append(
                    "stableBaseline.contractVersion must match the Platform API 1.0 baseline"
                    " contract version"
                )
            if (
                stable_baseline.get("capabilityCount")
                != details["stableBaselineCapabilityCount"]
            ):
                errors.append("stableBaseline.capabilityCount does not match capabilities")
            if stable_baseline.get("endpointCount") != details["stableBaselineEndpointCount"]:
                errors.append("stableBaseline.endpointCount does not match endpoints")
        if not isinstance(compatibility_window, dict):
            errors.append("contract compatibilityWindow metadata is missing")
        else:
            if compatibility_window.get("schemaVersion") != 1:
                errors.append("compatibilityWindow.schemaVersion must be 1")
            if compatibility_window.get("baselineName") != "1.0":
                errors.append("compatibilityWindow.baselineName must be 1.0")
            if (
                compatibility_window.get("baselineContractVersion")
                != CURRENT_PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION
            ):
                errors.append(
                    "compatibilityWindow.baselineContractVersion must match the Platform API"
                    " 1.0 baseline contract version"
                )
            if compatibility_window.get("currentContractVersion") != contract_version:
                errors.append(
                    "compatibilityWindow.currentContractVersion must match contractVersion"
                )
            if compatibility_window.get("supportPhase") != "beta":
                errors.append("compatibilityWindow.supportPhase must be beta")
            deprecation_window = compatibility_window.get(
                "minimumDeprecationWindowContractVersions"
            )
            if (
                not isinstance(deprecation_window, int)
                or isinstance(deprecation_window, bool)
                or deprecation_window
                < PLATFORM_API_MINIMUM_DEPRECATION_WINDOW_CONTRACT_VERSIONS
            ):
                errors.append("compatibilityWindow deprecation window is below policy minimum")
            removal_window = compatibility_window.get(
                "minimumScheduledRemovalWindowContractVersions"
            )
            if (
                not isinstance(removal_window, int)
                or isinstance(removal_window, bool)
                or removal_window
                < PLATFORM_API_MINIMUM_SCHEDULED_REMOVAL_WINDOW_CONTRACT_VERSIONS
            ):
                errors.append(
                    "compatibilityWindow scheduled-removal window is below policy minimum"
                )
            if compatibility_window.get("stableRemovalRequiresNewBaseline") is not True:
                errors.append("compatibilityWindow must require a future stable baseline")
            if compatibility_window.get("stableRemovalRequiresPreviousSnapshot") is not True:
                errors.append("compatibilityWindow must require previous snapshot history")
            if compatibility_window.get("stableRemovalRequiresExplicitWaiver") is not True:
                errors.append("compatibilityWindow must require explicit waiver metadata")
            if compatibility_window.get("criticalStableRemovalWaiverAllowed") is not False:
                errors.append("critical stable removals must not be waiverable")
            if (
                compatibility_window.get("experimentalGraduationRequiresReview")
                is not True
            ):
                errors.append("experimental graduation must require review evidence")
            if (
                compatibility_window.get(
                    "experimentalGraduationRequiresStableReferenceUpdate"
                )
                is not True
            ):
                errors.append(
                    "experimental graduation must require stable reference documentation"
                )
            if (
                compatibility_window.get("previousSnapshotRequiredInProductionBeta")
                is not True
            ):
                errors.append(
                    "production beta must require previous Platform API contract history"
                )
            if (
                compatibility_window.get("policyDocument")
                != "docs/platform-api-compatibility-support-window.md"
            ):
                errors.append("compatibilityWindow.policyDocument is not canonical")
    if not capabilities:
        errors.append("contract has no capability descriptors")
    if not endpoints:
        errors.append("contract has no endpoint descriptors")
    if missing_app_data_capabilities:
        errors.append("contract is missing app-data capability descriptors")
    if missing_app_data_endpoints:
        errors.append("contract is missing app-data endpoint descriptors")
    if missing_trust_exchange_capabilities:
        errors.append("contract is missing trust graph exchange capability descriptors")
    if missing_trust_exchange_endpoints:
        errors.append("contract is missing trust graph exchange endpoint descriptors")
    if missing_social_message_capabilities:
        errors.append("contract is missing social message capability descriptors")
    if missing_social_message_endpoints:
        errors.append("contract is missing social message endpoint descriptors")
    if missing_app_service_capabilities:
        errors.append("contract is missing app-service capability descriptors")
    if missing_app_service_endpoints:
        errors.append("contract is missing app-service endpoint descriptors")

    verifier_args = ["compat", "verify"]
    if settings.mode == "release-candidate":
        verifier_args.append("--strict")
    verifier_args.extend(["--contract", str(artifact)])
    verification: dict[str, Any] = {}
    for spec in first_party_app_specs(settings):
        staged_dir = spec["stagedDir"]
        if staged_dir.is_dir():
            result = run_cli(
                cli,
                [*verifier_args, "--bundle-dir", str(staged_dir)],
                settings,
                f"crypta-app-compat-{spec['appId']}",
            )
            verification[spec["appId"]] = command_details(result, settings)
            if result.exit_code != 0:
                errors.append(f"compat verify failed for {spec['appId']}")
        else:
            verification[spec["appId"]] = {"skipped": True, "reason": "staged app directory missing"}
    sample_dir = sample_paths.get("bundleDir")
    if sample_dir is not None and sample_dir.is_dir():
        result = run_cli(
            cli,
            [*verifier_args, "--bundle-dir", str(sample_dir)],
            settings,
            "crypta-app-compat-sample",
        )
        verification["cert-smoke"] = command_details(result, settings)
        if result.exit_code != 0:
            errors.append("compat verify failed for cert-smoke")
    details["verifier"] = verification

    if errors:
        return EvidenceItem(
            "platform-api.contract",
            root_consequence(settings, "fail"),
            True,
            "Platform API contract evidence found compatibility risks.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "platform-api.contract",
        "pass",
        True,
        "Platform API contract snapshot and offline compatibility checks passed.",
        source,
        details,
    )

def collect_platform_api_stable_freeze_evidence(
    settings: Settings, contract_item: EvidenceItem
) -> list[EvidenceItem]:
    source = summary_source(settings)
    contract_details = contract_item.details
    stable_baseline = contract_details.get("stableBaseline")
    stable_errors: list[str] = []
    if not isinstance(stable_baseline, dict):
        stable_errors.append("stableBaseline metadata is missing")
    else:
        if stable_baseline.get("name") != "1.0":
            stable_errors.append("stableBaseline.name must be 1.0")
        if not stable_baseline.get("capabilities"):
            stable_errors.append("stableBaseline.capabilities is empty")
        if not stable_baseline.get("endpoints"):
            stable_errors.append("stableBaseline.endpoints is empty")
    stable_endpoint_capabilities = contract_details.get("stableEndpointRequiredCapabilities")
    if not isinstance(stable_endpoint_capabilities, dict) or not stable_endpoint_capabilities:
        stable_errors.append("stable endpoint required-capability metadata is missing")
    stable_endpoint_access = contract_details.get("stableEndpointAppAccess")
    if not isinstance(stable_endpoint_access, dict) or not stable_endpoint_access:
        stable_errors.append("stable endpoint app-principal access metadata is missing")
    stable_baseline_item = EvidenceItem(
        "platform-api.stable-baseline",
        root_consequence(settings, "fail") if stable_errors else "pass",
        True,
        (
            "Platform API stable baseline metadata is incomplete."
            if stable_errors
            else "Platform API 1.0 stable baseline metadata is present."
        ),
        source,
        {"errors": stable_errors, "stableBaseline": stable_baseline},
    )

    breaking_check_details = {
        "currentContractVersion": contract_details.get("contractVersion"),
        "stableCapabilityCount": contract_details.get("stableBaselineCapabilityCount"),
        "stableEndpointCount": contract_details.get("stableBaselineEndpointCount"),
        "stableBaselineCapabilityCount": contract_details.get("stableBaselineCapabilityCount"),
        "stableBaselineEndpointCount": contract_details.get("stableBaselineEndpointCount"),
        "stableEndpointRequiredCapabilities": stable_endpoint_capabilities,
        "stableEndpointAppAccess": stable_endpoint_access,
        "stableEndpointActionLabels": contract_details.get("stableEndpointActionLabels", {}),
        "historyGate": "certify.py release-certification compares previous stable baseline summaries",
        "productionMode": "requires previous release summary through release certification history",
    }
    stable_breaking_item = EvidenceItem(
        "platform-api.stable-breaking-change-check",
        "pass" if not stable_errors else root_consequence(settings, "fail"),
        True,
        (
            "Stable Platform API breaking-change check is wired through release certification."
            if not stable_errors
            else "Stable Platform API breaking-change check is missing usable baseline input."
        ),
        source,
        {"errors": stable_errors, **breaking_check_details},
    )

    compatibility_window = contract_details.get("compatibilityWindow")
    window_errors: list[str] = []
    if not isinstance(compatibility_window, dict):
        window_errors.append("compatibilityWindow metadata is missing")
        compatibility_window = {}
    else:
        expected_window_values = {
            "schemaVersion": 1,
            "baselineName": "1.0",
            "baselineContractVersion": CURRENT_PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION,
            "currentContractVersion": contract_details.get("contractVersion"),
            "supportPhase": "beta",
            "stableRemovalRequiresNewBaseline": True,
            "stableRemovalRequiresPreviousSnapshot": True,
            "stableRemovalRequiresExplicitWaiver": True,
            "criticalStableRemovalWaiverAllowed": False,
            "experimentalGraduationRequiresReview": True,
            "experimentalGraduationRequiresStableReferenceUpdate": True,
            "previousSnapshotRequiredInProductionBeta": True,
            "policyDocument": "docs/platform-api-compatibility-support-window.md",
        }
        for key, expected in expected_window_values.items():
            if compatibility_window.get(key) != expected:
                window_errors.append(f"compatibilityWindow.{key} must be {expected!r}")
        if (
            compatibility_window.get("minimumDeprecationWindowContractVersions")
            != PLATFORM_API_MINIMUM_DEPRECATION_WINDOW_CONTRACT_VERSIONS
        ):
            window_errors.append("compatibilityWindow deprecation window policy mismatch")
        if (
            compatibility_window.get("minimumScheduledRemovalWindowContractVersions")
            != PLATFORM_API_MINIMUM_SCHEDULED_REMOVAL_WINDOW_CONTRACT_VERSIONS
        ):
            window_errors.append("compatibilityWindow scheduled-removal policy mismatch")
        if not compatibility_window.get("supportWindowStartedRelease"):
            window_errors.append("compatibilityWindow.supportWindowStartedRelease is missing")
    compatibility_window_item = EvidenceItem(
        "platform-api.compatibility-window",
        root_consequence(settings, "fail") if window_errors else "pass",
        True,
        (
            "Platform API compatibility-window metadata is incomplete."
            if window_errors
            else "Platform API 1.0 compatibility-window metadata is present."
        ),
        source,
        {
            "errors": window_errors,
            "compatibilityWindow": compatibility_window,
        },
    )

    previous_snapshot_errors: list[str] = []
    if compatibility_window.get("previousSnapshotRequiredInProductionBeta") is not True:
        previous_snapshot_errors.append("production beta previous snapshot policy is disabled")
    if compatibility_window.get("stableRemovalRequiresPreviousSnapshot") is not True:
        previous_snapshot_errors.append("stable removal previous snapshot policy is disabled")
    previous_snapshot_item = EvidenceItem(
        "platform-api.previous-contract-snapshot",
        root_consequence(settings, "fail") if previous_snapshot_errors else "pass",
        True,
        (
            "Previous Platform API contract snapshot policy is incomplete."
            if previous_snapshot_errors
            else "Previous Platform API contract snapshot history is enforced by release certification."
        ),
        source,
        {
            "errors": previous_snapshot_errors,
            "canonicalLocations": [
                "docs/platform-api/contracts/platform-api-1.0-baseline.json",
                "docs/platform-api/contracts/previous-production-beta-contract.json",
                "build/production-beta-release/evidence/platform-api-contract-current.json",
                "build/production-beta-release/evidence/platform-api-contract-previous.json",
                "build/production-beta-release/evidence/platform-api-stable-diff.json",
            ],
            "productionMode": "certify.py release-certification fails closed without previous contract history",
        },
    )

    deprecation_policy_errors: list[str] = []
    if (
        compatibility_window.get("minimumDeprecationWindowContractVersions")
        != PLATFORM_API_MINIMUM_DEPRECATION_WINDOW_CONTRACT_VERSIONS
    ):
        deprecation_policy_errors.append("minimum deprecation window mismatch")
    if (
        compatibility_window.get("minimumScheduledRemovalWindowContractVersions")
        != PLATFORM_API_MINIMUM_SCHEDULED_REMOVAL_WINDOW_CONTRACT_VERSIONS
    ):
        deprecation_policy_errors.append("minimum scheduled-removal window mismatch")
    if compatibility_window.get("stableRemovalRequiresNewBaseline") is not True:
        deprecation_policy_errors.append("stable removals must require a future baseline")
    if compatibility_window.get("criticalStableRemovalWaiverAllowed") is not False:
        deprecation_policy_errors.append("critical stable removal waiver must be rejected")
    descriptor_policy_errors, descriptor_policy_warnings = stable_deprecation_policy_findings(
        contract_details, compatibility_window
    )
    deprecation_policy_errors.extend(descriptor_policy_errors)
    deprecation_policy_item = EvidenceItem(
        "platform-api.deprecation-window-policy",
        root_consequence(settings, "fail") if deprecation_policy_errors else "pass",
        True,
        (
            "Stable Platform API deprecation/removal policy is incomplete."
            if deprecation_policy_errors
            else "Stable Platform API deprecation/removal windows are policy-backed."
        ),
        source,
        {
            "errors": deprecation_policy_errors,
            "minimumDeprecationWindowContractVersions": compatibility_window.get(
                "minimumDeprecationWindowContractVersions"
            ),
            "minimumScheduledRemovalWindowContractVersions": compatibility_window.get(
                "minimumScheduledRemovalWindowContractVersions"
            ),
            "criticalStableRemovalWaiverAllowed": compatibility_window.get(
                "criticalStableRemovalWaiverAllowed"
            ),
            "stableDescriptorDeprecations": contract_details.get(
                "stableDescriptorDeprecations", []
            ),
            "descriptorErrors": descriptor_policy_errors,
            "descriptorWarnings": descriptor_policy_warnings,
        },
    )

    support_window_doc = (
        settings.workspace_root / "docs/platform-api-compatibility-support-window.md"
    )
    stable_reference_doc = settings.workspace_root / "docs/platform-api-1.0-stable-reference.md"
    verifier_test = (
        settings.workspace_root
        / "platform-api/src/test/java/network/crypta/platform/api/PlatformApiContractVerifierTest.java"
    )
    support_window_text = read_source(support_window_doc)
    stable_reference_text_for_graduation = read_source(stable_reference_doc)
    verifier_test_text = read_source(verifier_test)
    graduation_checks = {
        "reviewRequired": compatibility_window.get("experimentalGraduationRequiresReview")
        is True,
        "stableReferenceUpdateRequired": compatibility_window.get(
            "experimentalGraduationRequiresStableReferenceUpdate"
        )
        is True,
        "supportWindowDocExplainsGraduation": "experimental-to-stable graduation"
        in support_window_text,
        "stableReferenceDocNamesFrozenBaseline": "Platform API 1.0 stable baseline"
        in stable_reference_text_for_graduation,
        "verifierTestsCoverStableIdentity": "compareStableBaseline_whenStableEndpointIdentityChanges"
        in verifier_test_text,
    }
    graduation_errors = [name for name, passed in graduation_checks.items() if not passed]
    graduation_policy_item = EvidenceItem(
        "platform-api.experimental-graduation-policy",
        root_consequence(settings, "fail") if graduation_errors else "pass",
        True,
        (
            "Experimental-to-stable graduation policy evidence is incomplete."
            if graduation_errors
            else "Experimental-to-stable graduation requires review, docs, and verifier coverage."
        ),
        source,
        {
            "errors": graduation_errors,
            "checks": graduation_checks,
            "sources": {
                "supportWindow": display_path(support_window_doc, settings.workspace_root),
                "stableReference": display_path(stable_reference_doc, settings.workspace_root),
                "verifierTest": display_path(verifier_test, settings.workspace_root),
            },
        },
    )

    manifest_sources = {
        "metadataModel": settings.workspace_root
        / "platform-appdist/src/main/java/network/crypta/platform/appdist/AppApiCompatibilityMetadata.java",
        "manifestParser": settings.workspace_root
        / "platform-appdist/src/main/java/network/crypta/platform/appdist/AppBundleManifestParser.java",
        "catalogParser": settings.workspace_root
        / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog/AppCatalogParser.java",
        "catalogWriter": settings.workspace_root
        / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog/AppCatalogWriter.java",
        "cliGenerator": settings.workspace_root
        / "platform-devtools/src/main/java/network/crypta/platform/devtools/CatalogEntryDescriptorGenerator.java",
    }
    manifest_checks = {
        name: "api.targetStability" in read_source(path)
        for name, path in manifest_sources.items()
    }
    manifest_errors = [name for name, passed in manifest_checks.items() if not passed]
    manifest_item = EvidenceItem(
        "platform-api.manifest-target-stability",
        root_consequence(settings, "fail") if manifest_errors else "pass",
        True,
        (
            "Manifest/catalog target-stability support is incomplete."
            if manifest_errors
            else "Manifest, catalog, and CLI metadata preserve api.targetStability."
        ),
        source,
        {
            "errors": manifest_errors,
            "checks": manifest_checks,
            "sources": {
                name: display_path(path, settings.workspace_root)
                for name, path in manifest_sources.items()
            },
        },
    )

    declaration_errors: list[str] = []
    declarations: dict[str, Any] = {}
    for spec in first_party_app_specs(settings):
        template = spec["sourceDir"] / "cryptad-app.properties.template"
        manifest = parse_properties(template) if template.is_file() else {}
        declarations[spec["appId"]] = {
            "apiTargetStability": manifest.get("api.targetStability"),
            "experimentalCapabilitiesAccepted": manifest.get(
                "api.experimentalCapabilitiesAccepted"
            ),
        }
        if manifest.get("api.targetStability") != spec.get("apiTargetStability"):
            declaration_errors.append(f"{spec['appId']}: api.targetStability mismatch")
        expected_experimental = (
            "true" if spec.get("experimentalCapabilitiesAccepted") else "false"
        )
        if manifest.get("api.experimentalCapabilitiesAccepted") != expected_experimental:
            declaration_errors.append(
                f"{spec['appId']}: api.experimentalCapabilitiesAccepted mismatch"
            )
    first_party_item = EvidenceItem(
        "platform-api.first-party-stability-declarations",
        root_consequence(settings, "fail") if declaration_errors else "pass",
        True,
        (
            "First-party app stability declarations are incomplete."
            if declaration_errors
            else "First-party app manifests declare stable or experimental API targets."
        ),
        source,
        {"errors": declaration_errors, "apps": declarations},
    )

    stable_reference = settings.workspace_root / "docs/platform-api-1.0-stable-reference.md"
    contract_doc = settings.workspace_root / "docs/platform-api-contract.md"
    support_window_doc = (
        settings.workspace_root / "docs/platform-api-compatibility-support-window.md"
    )
    stable_reference_text = read_source(stable_reference)
    contract_doc_text = read_source(contract_doc)
    support_window_text = read_source(support_window_doc)
    support_window_lower = support_window_text.lower()
    docs_checks = {
        "stableReferenceDocExists": stable_reference.is_file(),
        "stableReferenceNamesBaseline": "Platform API 1.0 stable baseline" in stable_reference_text,
        "contractDocMentionsTargetStability": "api.targetStability" in contract_doc_text,
        "contractDocMentionsOperatorOnly": "operator-only" in contract_doc_text,
        "supportWindowDocMentionsPreviousSnapshots": "previous contract snapshot"
        in support_window_lower,
        "supportWindowDocMentionsWaivers": "waiver" in support_window_lower,
    }
    docs_errors = [name for name, passed in docs_checks.items() if not passed]
    docs_item = EvidenceItem(
        "platform-api.stable-reference-docs",
        root_consequence(settings, "fail") if docs_errors else "pass",
        True,
        (
            "Platform API stable reference docs are incomplete."
            if docs_errors
            else "Platform API 1.0 stable reference docs are present."
        ),
        source,
        {
            "errors": docs_errors,
            "checks": docs_checks,
            "sources": {
                "stableReference": display_path(stable_reference, settings.workspace_root),
                "contractDoc": display_path(contract_doc, settings.workspace_root),
                "supportWindowDoc": display_path(support_window_doc, settings.workspace_root),
            },
        },
    )
    return [
        stable_baseline_item,
        stable_breaking_item,
        compatibility_window_item,
        previous_snapshot_item,
        deprecation_policy_item,
        graduation_policy_item,
        manifest_item,
        first_party_item,
        docs_item,
    ]

def collect_app_services_evidence(settings: Settings) -> list[EvidenceItem]:
    source = summary_source(settings)
    workspace = settings.workspace_root
    api_dir = workspace / "platform-api/src/main/java/network/crypta/platform/api"
    appservices_dir = api_dir / "appservices"
    api_tests_dir = workspace / "platform-api/src/test/java/network/crypta/platform/api"
    appservices_tests_dir = api_tests_dir / "appservices"
    trust_manifest_path = workspace / "apps/trust-graph/src/staged/cryptad-app.properties.template"
    social_manifest_path = workspace / "apps/social-inbox/src/staged/cryptad-app.properties.template"
    if not trust_manifest_path.is_file():
        trust_manifest_path = (
            workspace / "apps/trust-graph/build/cryptad-app/trust-graph/cryptad-app.properties"
        )
    if not social_manifest_path.is_file():
        social_manifest_path = (
            workspace / "apps/social-inbox/build/cryptad-app/social-inbox/cryptad-app.properties"
        )
    try:
        trust_manifest = parse_properties(trust_manifest_path) if trust_manifest_path.is_file() else {}
    except ValueError:
        trust_manifest = {}
    try:
        social_manifest = parse_properties(social_manifest_path) if social_manifest_path.is_file() else {}
    except ValueError:
        social_manifest = {}
    social_permissions = parse_permission_set(social_manifest.get("app.permissions", ""))
    contract_text = read_source(api_dir / "PlatformApiContract.java")
    capabilities_text = read_source(api_dir / "PlatformApiCapabilities.java")
    router_text = read_source(api_dir / "PlatformApiRouter.java")
    route_text = read_source(api_dir / "PlatformApiAppServiceRoutes.java")
    shared_services_text = read_source(api_dir / "PlatformApiSharedAppServices.java")
    runtime_text = read_source(
        workspace
        / "bridge-http-runtime/src/main/java/network/crypta/clients/http/bridge/CoreHttpShellRuntimeSupport.java"
    )
    coordinator_text = read_source(appservices_dir / "AppServiceCoordinator.java")
    parser_text = read_source(appservices_dir / "AppServiceManifestParser.java")
    descriptor_text = read_source(appservices_dir / "AppServiceDescriptor.java")
    request_descriptor_text = read_source(appservices_dir / "AppServiceRequestDescriptor.java")
    grant_text = read_source(appservices_dir / "AppServiceGrant.java")
    status_text = read_source(appservices_dir / "AppServiceGrantStatus.java")
    audit_text = read_source(appservices_dir / "AppServiceAuditEvent.java")
    audit_text_normalized = re.sub(r"\s+", " ", re.sub(r"(?m)^\s*\*\s?", " ", audit_text))
    store_text = "\n".join(
        read_source(appservices_dir / name)
        for name in (
            "AppServiceGrantStore.java",
            "FileAppServiceGrantStore.java",
            "InMemoryAppServiceGrantStore.java",
        )
    )
    appservices_model_text = "\n".join(
        read_source(path) for path in sorted(appservices_dir.glob("*.java"))
    )
    adapter_text = read_source(appservices_dir / "TrustGraphScoreAppServiceAdapter.java")
    tests_text = "\n".join(
        read_source(path)
        for path in (
            appservices_tests_dir / "AppServiceManifestParserTest.java",
            appservices_tests_dir / "AppServiceGrantStoreTest.java",
            appservices_tests_dir / "AppServiceCoordinatorTest.java",
            appservices_tests_dir / "TrustGraphScoreAppServiceAdapterTest.java",
            api_tests_dir / "PlatformApiAppServicesRouterTest.java",
        )
    )
    sdk_text = read_source(
        workspace
        / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    )
    shell_text = read_source(
        workspace
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    )
    social_app_js = read_source(workspace / "apps/social-inbox/src/staged/static/app.js")
    social_index = read_source(workspace / "apps/social-inbox/src/staged/static/index.html")
    trust_index = read_source(workspace / "apps/trust-graph/src/staged/static/index.html")
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/app-service-discovery-and-grants.md",
            "docs/platform-api-contract.md",
            "docs/platform-sdk-js.md",
            "docs/social-inbox-reference-app.md",
            "docs/trust-graph-preview.md",
            "docs/release-certification.md",
            "tools/release-certification/README.md",
        )
    )

    def item(
        evidence_id: str,
        pass_summary: str,
        fail_summary: str,
        checks: dict[str, bool],
        details: dict[str, Any] | None = None,
    ) -> EvidenceItem:
        errors = [name for name, passed in checks.items() if passed is not True]
        payload: dict[str, Any] = {
            "checks": checks,
            "sources": {
                "contract": display_path(api_dir / "PlatformApiContract.java", workspace),
                "routes": display_path(api_dir / "PlatformApiAppServiceRoutes.java", workspace),
                "coordinator": display_path(appservices_dir / "AppServiceCoordinator.java", workspace),
                "socialManifest": display_path(social_manifest_path, workspace),
                "trustManifest": display_path(trust_manifest_path, workspace),
            },
        }
        if details:
            payload.update(details)
        if errors:
            return EvidenceItem(
                evidence_id,
                root_consequence(settings, "fail"),
                True,
                fail_summary,
                source,
                {"errors": errors, **payload},
            )
        return EvidenceItem(evidence_id, "pass", True, pass_summary, source, payload)

    registry_checks = {
        "contractV12AndCapabilitiesPresent": (
            "CURRENT_CONTRACT_VERSION = 24" in contract_text
            and "APP_SERVICES_CONTRACT_VERSION = 12" in contract_text
            and "APP_SERVICE_DEPENDENCY_BUNDLES_CONTRACT_VERSION = 16" in contract_text
            and "APP_SERVICES_READ" in capabilities_text
            and "APP_SERVICES_CALL" in capabilities_text
            and "app.services.read" in capabilities_text
            and "app.services.call" in capabilities_text
        ),
        "routeFamilyPresent": (
            "PlatformApiAppServiceRoutes" in router_text
            and 'case "app-services"' in router_text
            and "Routes local app-service discovery" in route_text
            and "service.listServices()" in route_text
        ),
        "descriptorParserPresent": (
            "record AppServiceDescriptor" in descriptor_text
            and "record AppServiceRequestDescriptor" in request_descriptor_text
            and "app.services.provides" in parser_text
            and "app.service-request." in parser_text
        ),
        "runtimeWiresSharedCoordinator": (
            "AppServiceCoordinator appServiceCoordinator" in shared_services_text
            and "new AppServiceCoordinator" in runtime_text
            and 'resolve("app-services")' in runtime_text
            and "TrustGraphScoreAppServiceAdapter" in runtime_text
        ),
        "sdkHelpersPresent": (
            "services: Object.freeze" in sdk_text
            and "listAppServices" in sdk_text
            and "requestAppServiceGrant" in sdk_text
            and "requestAppServiceBundle" in sdk_text
            and "listAppServiceDependencies" in sdk_text
            and "invokeAppService" in sdk_text
        ),
        "testsCoverManifestAndRouter": (
            "AppServiceManifestParserTest" in tests_text
            and "PlatformApiAppServicesRouterTest" in tests_text
        ),
    }
    grants_checks = {
        "grantModelHasRequiredFields": all(
            fragment in grant_text
            for fragment in (
                "grantId",
                "consumerAppId",
                "providerAppId",
                "serviceId",
                "scopes",
                "contexts",
                "purpose",
                "approvedAt",
                "revokedAt",
                "lastUsedAt",
                "useCount",
                "tokenFingerprint",
                "bundleId",
                "expiresAt",
                "compatibilityFingerprint",
                "providerServiceVersionAtApproval",
            )
        ),
        "grantStatusesPresent": all(
            status in status_text
            for status in (
                "PENDING",
                "ACTIVE",
                "REVOKED",
                "INACTIVE",
                "EXPIRED",
                "REVALIDATION_REQUIRED",
            )
        ),
        "storesAreFileBackedAndInMemory": (
            "class FileAppServiceGrantStore" in store_text
            and "class InMemoryAppServiceGrantStore" in store_text
            and "ATOMIC_MOVE" in store_text
            and '"grants"' in store_text
            and '"bundles"' in store_text
            and '"audit"' in store_text
        ),
        "coordinatorEnforcesApprovalRevocation": (
            "requestGrant" in coordinator_text
            and "approveGrant" in coordinator_text
            and "revokeGrant" in coordinator_text
            and "App principals cannot approve app-service grants." in coordinator_text
            and "active app-service grant" in coordinator_text
        ),
        "testsCoverGrantLifecycle": all(
            fragment in tests_text
            for fragment in (
                "grantLifecycle_whenApprovedThenRevoked_expectInvocationBoundary",
                "invoke_whenConsumerManifestDropsCallPermission_expectDenied",
                "requestGrant_whenProviderNotInstalled_expectProviderMissing",
                "fileStore_whenGrantsReload_expectDeterministicOrderingAndRedactedJson",
                "fileStore_whenBundleAndGrantLifecycleFieldsReload_expectDeterministicRecords",
                "fileStore_whenAuditEventsReload_expectNewestFirstAndRedactedSubjectHash",
            )
        ),
    }
    dependency_checks = {
        "dependencyModelsPresent": all(
            fragment in appservices_model_text
            for fragment in (
                "record AppServiceDependencyDescriptor",
                "enum AppServiceDependencyKind",
                "enum AppServiceDegradeBehavior",
                "record AppServiceVersionRange",
            )
        ),
        "dependencyParserStrictFieldsPresent": (
            'dependencyPrefix + "minServiceVersion"' in parser_text
            and 'dependencyPrefix + "maxServiceVersion"' in parser_text
            and 'dependencyPrefix + "grantExpiresAfter"' in parser_text
            and "duplicate alias" in parser_text
            and "Field value must not contain local filesystem paths" in parser_text
        ),
        "dependencyRoutesPresent": (
            '"/app-services/dependencies"' in contract_text
            and "service.dependencyGraph" in route_text
            and "dependencyGraph(" in coordinator_text
        ),
        "dependencyTestsPresent": all(
            fragment in tests_text
            for fragment in (
                "parseServiceRequests_whenOptionalDependencyFieldsPresent_expectDependencyDescriptor",
                "parseServiceRequests_whenRequiredDependencyFieldsPresent_expectRequiredDescriptor",
                "dependencyGraph_whenProviderAvailable_expectSocialInboxTrustGraphEdge",
                "dependencyGraph_whenAppReadsOtherConsumer_expectForbidden",
            )
        ),
    }
    bundle_checks = {
        "bundleModelsAndStorePresent": all(
            fragment in appservices_model_text
            for fragment in (
                "record AppServiceGrantBundle",
                "enum AppServiceGrantBundleStatus",
                "listBundles",
                "writeBundle",
            )
        ),
        "bundleRoutesPresent": (
            '"/app-services/grant-bundles"' in contract_text
            and "approveBundle" in route_text
            and "rejectBundle" in route_text
            and "renewBundle" in route_text
        ),
        "bundleCoordinatorHostOnly": (
            "App principals cannot approve app-service grant bundles." in coordinator_text
            and "App principals cannot reject app-service grant bundles." in coordinator_text
            and "App principals cannot renew app-service grant bundles." in coordinator_text
        ),
        "bundleTestsPresent": all(
            fragment in tests_text
            for fragment in (
                "grantBundleLifecycle_whenApprovedExpiredAndRenewed_expectInvocationBoundary",
                "approveBundle_whenRejected_expectNoActiveGrantCreated",
                "route_whenAppUsesDependencyAndBundleRoutes_expectScopedReviewFlow",
            )
        ),
    }
    expiry_checks = {
        "grantExpiryFieldsPresent": (
            "expiresAt" in grant_text
            and "renewedAt" in grant_text
            and "isExpired" in coordinator_text
            and "MAX_BUNDLE_GRANT_DURATION" in coordinator_text
        ),
        "expiredGrantsFailClosed": (
            "effectiveStatus(grant) == AppServiceGrantStatus.ACTIVE" in coordinator_text
            and "AppServiceGrantStatus.EXPIRED" in coordinator_text
            and "grantBundleLifecycle_whenApprovedExpiredAndRenewed_expectInvocationBoundary"
            in tests_text
        ),
        "renewalRevalidates": (
            "renewBundle" in coordinator_text
            and "approveOrRenewBundle" in coordinator_text
            and "ensureDescriptorSupported" in coordinator_text
            and "descriptor.compatibilityFingerprint()" in coordinator_text
        ),
    }
    revalidation_checks = {
        "compatibilityFingerprintPresent": (
            "compatibilityFingerprint" in descriptor_text
            and "providerServiceVersionAtApproval" in grant_text
            and "approvalMetadataStillMatches" in coordinator_text
        ),
        "descriptorDriftNonAuthorizing": (
            "REVALIDATION_REQUIRED" in status_text
            and "revalidation-required" in status_text
            and "invoke_whenProviderDescriptorDriftsAfterBundleApproval_expectRevalidationRequired"
            in tests_text
        ),
        "descriptorMatchingChecksVersionScopeContextKindAdapter": (
            "satisfiesVersionRange" in descriptor_text
            and "hasUnsupportedScopes" in descriptor_text
            and "supportsContext" in descriptor_text
            and "SUPPORTED_SERVICE_KIND" in coordinator_text
            and "adapters.containsKey" in coordinator_text
        ),
    }
    provider_checks = {
        "trustGraphManifestAdvertisesService": (
            trust_manifest.get("app.services.provides") == "trust-score"
            and trust_manifest.get("app.service.trust-score.id") == "trust.score"
            and trust_manifest.get("app.service.trust-score.kind") == "platform-adapter"
            and trust_manifest.get("app.service.trust-score.adapter") == "trust-graph.score"
            and "score.read" in parse_permission_set(
                trust_manifest.get("app.service.trust-score.scopes", "")
            )
        ),
        "adapterIsBoundedNotProxy": (
            'ADAPTER_ID = "trust-graph.score"' in adapter_text
            and "trustGraphApiHandler.score" in adapter_text
            and "not a proxy" in adapter_text
            and "subjectUriHash" in adapter_text
            and 'json.put("subjectUri",' not in adapter_text
        ),
        "providerDocsAndUiDescribePreviewGrantBoundary": (
            "Trust Score Service" in trust_index
            and "operator-approved app-service grants" in trust_index
            and "trust.score" in docs_text
            and "not complete WoT" in docs_text
        ),
        "adapterTestsCoverRedaction": (
            "TrustGraphScoreAppServiceAdapterTest" in tests_text
            and "invoke_whenScoreRequested_expectRedactedScoreSummary" in tests_text
            and "subjectUriHash" in tests_text
        ),
    }
    social_checks = {
        "socialManifestRequestsServiceGrant": (
            social_manifest.get("app.services.requests") == "trust-score"
            and social_manifest.get("app.service-request.trust-score.provider") == "trust-graph"
            and social_manifest.get("app.service-request.trust-score.service") == "trust.score"
            and social_manifest.get("app.service-request.trust-score.scopes") == "score.read"
            and social_manifest.get("app.service-request.trust-score.contexts") == "message-author"
        ),
        "socialManifestUsesAppServiceCapabilities": (
            {"app.services.read", "app.services.call"}.issubset(social_permissions)
            and "trust.read" not in social_permissions
            and social_manifest.get("api.minimumVersion") == "16"
            and social_manifest.get("api.maximumTestedVersion")
            == str(FIRST_PARTY_CERTIFIED_MAX_CONTRACT_VERSION)
        ),
        "socialUsesSdkServicesNamespace": (
            "CryptaPlatform.services.get" in social_app_js
            and "CryptaPlatform.services.grants.list" in social_app_js
            and "CryptaPlatform.services.bundles.request" in social_app_js
            and "CryptaPlatform.services.invoke" in social_app_js
            and "CryptaPlatform.trust.score" not in social_app_js
        ),
        "socialUiShowsGrantStates": (
            "Request trust grant" in social_index
            and "trust-service-status" in social_index
            and "Trust score unavailable / grant required" in social_app_js
            and "Trust score unavailable / grant expired." in social_app_js
            and "Trust score unavailable / grant requires operator revalidation." in social_app_js
        ),
        "socialDocsDescribeRevocation": (
            "Trust Score Service grant" in docs_text
            and "revoked" in docs_text
            and "must not fall back to\n`CryptaPlatform.trust.score`" in docs_text
        ),
    }
    web_shell_checks = {
        "webShellLoadsAppServiceData": (
            'apiUrl("app-services")' in shell_text
            and 'apiUrl("app-services/grants")' in shell_text
            and 'apiUrl("app-services/dependencies")' in shell_text
            and 'apiUrl("app-services/grant-bundles")' in shell_text
            and 'apiUrl("app-services/audit?limit=12")' in shell_text
        ),
        "webShellRendersGrantActions": (
            "App-service grants" in shell_text
            and "Approve" in shell_text
            and "Revoke" in shell_text
            and "Renew bundle" in shell_text
            and "renderAppServiceDependencyGraph" in shell_text
            and "renderAppServiceBundleCard" in shell_text
            and "appServiceGrantPath" in shell_text
        ),
        "webShellOmitsPrivateMaterial": (
            "tokenFingerprint" not in shell_text
            and "CRYPTAD_APP_TOKEN" not in shell_text
            and "privateInsertUri" not in shell_text
        ),
        "webShellTestsPresent": "App-service grants" in read_source(
            workspace
            / "platform-web-shell/src/test/java/network/crypta/platform/webshell/WebShellResourcesTest.java"
        ),
    }
    redaction_checks = {
        "auditModelIsRedacted": (
            "subjectUriHash" in audit_text
            and "raw subject URIs" in audit_text_normalized
            and "raw tokens" in audit_text_normalized
            and "local paths" in audit_text_normalized
        ),
        "invocationReturnsHashNotRawSubject": (
            "subjectUriHash" in adapter_text
            and 'json.put("subjectUri",' not in adapter_text
            and "completeWot" in adapter_text
        ),
        "grantJsonContainsOnlyFingerprint": (
            "tokenFingerprint" in grant_text
            and "PR-243 does not issue raw service tokens" in grant_text
            and "rawToken" not in grant_text
        ),
        "docsStateNoGenericProxyOrLocalhostTrust": (
            "not a localhost proxy" in docs_text
            and "not generic RPC" in docs_text
            and "raw service tokens" in docs_text
            and "ambient access" in docs_text
            and "raw request bodies" in docs_text
        ),
        "evidenceIdsDocumented": all(
            evidence_id in docs_text
            for evidence_id in (
                "app-services.registry",
                "app-services.grants",
                "app-services.trust-score-provider",
                "reference-app.social-inbox-service-grant",
                "app-services.web-shell",
                "app-services.redaction",
                "app-services.dependency-graph",
                "app-services.grant-bundles",
                "app-services.grant-expiry-renewal",
                "app-services.provider-revalidation",
                "reference-app.social-inbox-service-dependency",
                "app-services.dependency-redaction",
            )
        ),
    }
    social_dependency_checks = {
        "socialManifestDeclaresOptionalDependency": (
            social_manifest.get("app.service-request.trust-score.dependency.kind") == "optional"
            and social_manifest.get("app.service-request.trust-score.dependency.required") == "false"
            and social_manifest.get("app.service-request.trust-score.dependency.featureId")
            == "trust-score-annotations"
            and social_manifest.get("app.service-request.trust-score.dependency.grantBundle")
            == "trust-annotations"
        ),
        "socialDegradesSafely": (
            "markTrustScoresUnavailable" in social_app_js
            and "Trust score unavailable / grant expired." in social_app_js
            and "Trust score unavailable / grant requires operator revalidation." in social_app_js
            and "CryptaPlatform.trust.score" not in social_app_js
        ),
        "socialDependencyDocsPresent": (
            "Trust score annotations" in docs_text
            and "trust-annotations" in docs_text
            and "optional" in docs_text
        ),
    }
    bundle_source = read_source(appservices_dir / "AppServiceGrantBundle.java")
    dependency_redaction_checks = {
        "dependencyJsonPathFreeByConstruction": (
            "dependencyJson" in coordinator_text
            and "providerServiceVersion" in coordinator_text
            and "subjectUri" not in request_descriptor_text
            and "request bodies" in appservices_model_text
        ),
        "bundlePublicJsonFieldsSafe": (
            "AppServiceGrantBundle" in appservices_model_text
            and app_service_bundle_public_fields_are_safe(bundle_source)
        ),
        "uiAndEvidenceAvoidRawSensitiveValues": (
            "subjectUriHash" in shell_text
            and '"subjectUri"' not in shell_text
            and "subjectUri:" not in shell_text
            and "privateInsertUri" not in shell_text
            and "CRYPTAD_APP_TOKEN" not in shell_text
        ),
    }
    return [
        item(
            "app-services.registry",
            "App-service registry and descriptor evidence passed deterministic checks.",
            "App-service registry evidence is incomplete.",
            registry_checks,
        ),
        item(
            "app-services.grants",
            "App-service grant lifecycle evidence passed deterministic checks.",
            "App-service grant lifecycle evidence is incomplete.",
            grants_checks,
        ),
        item(
            "app-services.dependency-graph",
            "App-service dependency graph evidence passed deterministic checks.",
            "App-service dependency graph evidence is incomplete.",
            dependency_checks,
        ),
        item(
            "app-services.grant-bundles",
            "App-service grant-bundle evidence passed deterministic checks.",
            "App-service grant-bundle evidence is incomplete.",
            bundle_checks,
        ),
        item(
            "app-services.grant-expiry-renewal",
            "App-service grant expiry and renewal evidence passed deterministic checks.",
            "App-service grant expiry and renewal evidence is incomplete.",
            expiry_checks,
        ),
        item(
            "app-services.provider-revalidation",
            "App-service provider descriptor revalidation evidence passed deterministic checks.",
            "App-service provider descriptor revalidation evidence is incomplete.",
            revalidation_checks,
        ),
        item(
            "app-services.trust-score-provider",
            "Trust Graph trust.score provider evidence passed deterministic checks.",
            "Trust Graph trust.score provider evidence is incomplete.",
            provider_checks,
        ),
        item(
            "reference-app.social-inbox-service-grant",
            "Social Inbox app-service grant evidence passed deterministic checks.",
            "Social Inbox app-service grant evidence is incomplete.",
            social_checks,
        ),
        item(
            "reference-app.social-inbox-service-dependency",
            "Social Inbox service dependency evidence passed deterministic checks.",
            "Social Inbox service dependency evidence is incomplete.",
            social_dependency_checks,
        ),
        item(
            "app-services.web-shell",
            "Web Shell app-service grant UI evidence passed deterministic checks.",
            "Web Shell app-service grant UI evidence is incomplete.",
            web_shell_checks,
        ),
        item(
            "app-services.redaction",
            "App-service redaction and boundary evidence passed deterministic checks.",
            "App-service redaction and boundary evidence is incomplete.",
            redaction_checks,
            {
                "redaction": {
                    "rawTokensExcluded": True,
                    "rawSubjectUrisExcluded": True,
                    "privateInsertUrisExcluded": True,
                    "absolutePathsExcluded": True,
                    "genericProxyExcluded": True,
                }
            },
        ),
        item(
            "app-services.dependency-redaction",
            "App-service dependency and bundle redaction evidence passed deterministic checks.",
            "App-service dependency and bundle redaction evidence is incomplete.",
            dependency_redaction_checks,
        ),
    ]
