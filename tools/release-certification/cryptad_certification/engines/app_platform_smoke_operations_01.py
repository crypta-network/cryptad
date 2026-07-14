"""Implementation segment for the operations portion of ``app_platform_smoke.py``."""

from __future__ import annotations

def legacy_counts_from_registry_text(text: str) -> dict[str, int]:
    start = text.index("List.of(")
    end = text.index("private static final Map", start)
    block = text[start:end]
    return {
        "PRIMARY_REPLACED": len(
            re.findall(
                r"\n\s+(?:diagnosticFallbackReplacement|diagnosticWave4Redirect|securityLevelsWave3Redirect|replaced|wave\d+Redirect)\(",
                block,
            )
        ),
        "PENDING": len(re.findall(r"\n\s+pendingWizard\(", block)) + len(re.findall(r"\n\s+pending\(", block)),
        "RETAINED": len(re.findall(r"\n\s+retained\(", block)),
        "INFRASTRUCTURE": len(re.findall(r"\n\s+infrastructure\(", block)),
    }

def java_method_body(text: str, method_name: str) -> str:
    pattern = re.compile(
        r"\b(?:public|private)\s+static\s+[\w<>, ?]+\s+"
        + re.escape(method_name)
        + r"\s*\([^)]*\)\s*\{",
        re.DOTALL,
    )
    match = pattern.search(text)
    if match is None:
        return ""
    open_brace = match.end() - 1
    depth = 0
    for offset in range(open_brace, len(text)):
        char = text[offset]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace + 1 : offset]
    return ""

def web_shell_toadlet_sources_security_fallback_path(text: str) -> bool:
    """Return true when Web Shell bootstrap security fallback comes from the registry.

    The source formatter may wrap the final `WebShellBootstrap.nodeManagement(...)`
    call across lines, so this proof follows the small adapter chain instead of
    depending on one contiguous substring.
    """
    return (
        'LegacyAdminRetirementRegistry.require("security-levels").legacyPath()' in text
        and bool(
            re.search(
                r"\bcreateNodeManagementBootstrap\(\s*legacySecurityLevelsPath\(\)\s*,",
                text,
                re.DOTALL,
            )
        )
        and bool(
            re.search(
                r"\bWebShellBootstrap\.nodeManagement\(\s*legacySecurityLevelsPath\s*,",
                text,
                re.DOTALL,
            )
        )
    )

def legacy_fallback_link_checks(text: str) -> dict[str, bool]:
    fallback_body = java_method_body(text, "webShellFallbackSurfaces")
    replaced_body = (
        java_method_body(text, "diagnosticWave4Redirect")
        or java_method_body(text, "diagnosticFallbackReplacement")
        or java_method_body(text, "replaced")
    )
    navigation_body = java_method_body(text, "shouldPromoteInLegacyNavigation")
    replaced_marks_no_fallback = (
        "FALLBACK_POLICY_RENDER_LEGACY" in replaced_body
        or "FALLBACK_POLICY_SUPPORT_EMERGENCY" in replaced_body
    ) and bool(re.search(r",\s*true\s*,\s*false\s*\)\s*;", replaced_body, re.DOTALL))
    fallback_filters_include_flag = bool(
        re.search(r"\.filter\s*\(\s*LegacyAdminSurface::includeInWebShellFallbackLinks\s*\)", fallback_body)
    )
    fallback_filters_primary_state = bool(
        re.search(r"state\(\)\s*!=\s*LegacyAdminRetirementState\.PRIMARY_REPLACED", fallback_body)
    )
    navigation_excludes_primary = bool(
        re.search(r"state\(\)\s*!=\s*LegacyAdminRetirementState\.PRIMARY_REPLACED", navigation_body)
    )
    primary_replaced_excluded = fallback_filters_primary_state or (
        fallback_filters_include_flag and replaced_marks_no_fallback
    )
    return {
        "fallbackMethodFound": bool(fallback_body),
        "replacedHelperFound": bool(replaced_body),
        "replacedHelperDisablesFallbackLinks": replaced_marks_no_fallback,
        "fallbackFiltersIncludeFlag": fallback_filters_include_flag,
        "fallbackFiltersPrimaryState": fallback_filters_primary_state,
        "primaryReplacedExcludedFromFallbackLinks": primary_replaced_excluded,
        "primaryReplacedAbsentFromPrimaryNavigation": navigation_excludes_primary,
    }

def collect_legacy_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    registry = settings.workspace_root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRetirementRegistry.java"
    docs = settings.workspace_root / "docs/legacy-retirement-plan.md"
    errors: list[str] = []
    details: dict[str, Any] = {}
    if not registry.is_file():
        errors.append("LegacyAdminRetirementRegistry.java is missing")
    else:
        registry_text = registry.read_text(encoding="utf-8")
        counts = legacy_counts_from_registry_text(registry_text)
        fallback_checks = legacy_fallback_link_checks(registry_text)
        details["stateCounts"] = counts
        details["totalRegisteredSurfaces"] = sum(counts.values())
        details["primaryReplacedSurfaces"] = counts["PRIMARY_REPLACED"]
        details["pendingSurfaces"] = counts["PENDING"]
        details["retainedSurfaces"] = counts["RETAINED"]
        details["fallbackLinkChecks"] = fallback_checks
        details["primaryReplacedAbsentFromFallbackLinks"] = fallback_checks[
            "primaryReplacedExcludedFromFallbackLinks"
        ]
        details["primaryReplacedAbsentFromPrimaryNavigation"] = fallback_checks[
            "primaryReplacedAbsentFromPrimaryNavigation"
        ]
        docs_text = re.sub(r"\s+", " ", docs.read_text(encoding="utf-8")) if docs.is_file() else ""
        details["retainedPendingRoutesDocumented"] = (
            "retained and pending legacy routes remain reachable" in docs_text.lower()
        )
        if counts["PRIMARY_REPLACED"] < 1:
            errors.append("No PRIMARY_REPLACED surfaces were found")
        if not details["primaryReplacedAbsentFromFallbackLinks"]:
            errors.append("PRIMARY_REPLACED surfaces may still appear in Web Shell fallback links")
        if not details["primaryReplacedAbsentFromPrimaryNavigation"]:
            errors.append("PRIMARY_REPLACED surfaces may still appear in primary legacy navigation")
        if not details["retainedPendingRoutesDocumented"]:
            errors.append("Retained/pending legacy route behavior is not documented")
    if errors:
        return EvidenceItem("legacy.retirement", "fail", True, "Legacy-admin retirement evidence is incomplete.", source, {"errors": errors, **details})
    return EvidenceItem("legacy.retirement", "pass", True, "Legacy-admin retirement map is visible and stable.", source, details)

def legacy_removal_wave_one_ids(registry_text: str) -> list[str]:
    return re.findall(r"\n\s+wave1Redirect\(\s*\"([^\"]+)\"", registry_text)

def legacy_removal_wave_two_ids(registry_text: str) -> list[str]:
    return re.findall(r"\n\s+wave2Redirect\(\s*\"([^\"]+)\"", registry_text)

def legacy_removal_wave_three_ids(registry_text: str) -> list[str]:
    ids = re.findall(r"\n\s+wave3Redirect\(\s*\"([^\"]+)\"", registry_text)
    if re.search(r"\n\s+securityLevelsWave3Redirect\(\s*\)", registry_text):
        ids.insert(0, "security-levels")
    return ids

def legacy_removal_wave_four_ids(registry_text: str) -> list[str]:
    ids = re.findall(r"\n\s+wave4Redirect\(\s*\"([^\"]+)\"", registry_text)
    if re.search(r"\n\s+diagnosticWave4Redirect\(\s*\)", registry_text):
        ids.insert(0, "diagnostic")
    return ids

def legacy_removal_wave_five_ids(registry_text: str) -> list[str]:
    return re.findall(r"\n\s+wave5(?:Redirect|Removed)\(\s*\"([^\"]+)\"", registry_text)

def legacy_final_surface_category_ids(registry_text: str, category: str) -> list[str]:
    block = java_method_body(registry_text, "buildFinalSurfacePolicy")
    if not block:
        return []
    helper_names = r"(?:surfaceFinalSurface|retainedBrowseFinalSurface)"
    pattern = (
        r"\n\s+surfaceFinalSurface\(\s*\"([^\"]+)\""
        r"(?:(?!\n\s+"
        + helper_names
        + r"\().)*?"
        + re.escape(f"FinalSurfaceCategory.{category}")
    )
    ids = re.findall(pattern, block, re.DOTALL)
    if category == "RETAINED_BROWSE_SURFACE":
        ids.extend(
            re.findall(r"\n\s+retainedBrowseFinalSurface\(\s*\"([^\"]+)\"", block)
        )
    return ids

def legacy_scope_expansion_wave_two_ids(registry_text: str) -> list[str]:
    try:
        start = registry_text.index("List.of(")
        end = registry_text.index("private static final Map", start)
    except ValueError:
        return []
    block = registry_text[start:end]
    matches = re.findall(
        r"\n\s+(?:wave1Redirect|wave2Redirect)\(\s*\"([^\"]+)\"(?:(?!\n\s+(?:wave1Redirect|wave2Redirect|replaced|pending|retained|infrastructure)\().)*?REMOVAL_WAVE_2",
        block,
        re.DOTALL,
    )
    return matches

def collect_legacy_removal_wave_one_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    root = settings.workspace_root
    files = {
        "registry": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRetirementRegistry.java",
        "policy": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRemovalPolicy.java",
        "response": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminReplacementResponse.java",
        "recorder": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminUsageRecorder.java",
        "usageDto": root / "runtime-spi/src/main/java/network/crypta/runtime/spi/LegacyAdminSurfaceUsage.java",
        "diagnostics": root / "platform-api/src/main/java/network/crypta/platform/api/diagnostics/DiagnosticsApiHandler.java",
        "docs": root / "docs/legacy-retirement-plan.md",
    }
    text: dict[str, str] = {}
    missing = []
    for key, path in files.items():
        if not path.is_file():
            missing.append(key)
            text[key] = ""
        else:
            text[key] = path.read_text(encoding="utf-8")

    wave_ids = legacy_removal_wave_one_ids(text["registry"])
    checks = {
        "waveOneIdsMatch": wave_ids == list(LEGACY_REMOVAL_WAVE_ONE_IDS),
        "redirectModeDeclared": "LegacyAdminRemovalMode.REDIRECT_TO_REPLACEMENT" in text["registry"],
        "canonicalOnlyPolicy": "matchesCanonicalPageOrSlashlessAlias" in text["policy"],
        "safeReadRedirects": "GET" in text["policy"] and "HEAD" in text["policy"] and "redirect(" in text["policy"],
        "mutatingRequestsBlocked": "BLOCKED_MUTATING_REQUEST" in text["policy"] or "blockedMutation" in text["policy"],
        "replacementAvailabilityGate": "replacementAvailable" in text["policy"]
        and "isStaticAppUiAvailable" in text["policy"]
        and "primaryUiRoot" in text["policy"],
        "replacementResponsesRecorded": "REPLACEMENT_RESPONSE" in text["recorder"] or "REPLACEMENT_RESPONSE" in text["policy"],
        "diagnosticsCarriesReplacementCounter": "replacementResponseCount" in text["diagnostics"] and "replacementResponseCount" in text["usageDto"],
        "diagnosticsCarriesBlockedCounter": "blockedMutatingRequestCount" in text["diagnostics"] and "blockedMutatingRequestCount" in text["usageDto"],
        "diagnosticsCarriesFallbackCounter": "fallbackRenderCount" in text["diagnostics"] and "fallbackRenderCount" in text["usageDto"],
        "docsDescribeWave": "legacy-admin.removal-wave-1" in text["docs"],
        "docsDescribeAvailabilityFallback": "replacement is reachable" in text["docs"]
        or "replacement is unavailable" in text["docs"],
        "docsRetainBrowse": "FProxy browse remains retained" in text["docs"],
        "liveNodeNotRequired": True,
    }
    redaction = {
        "queryStringsExcluded": True,
        "requestBodiesExcluded": True,
        "formPasswordsExcluded": True,
        "remoteAddressesExcluded": True,
        "tokensExcluded": True,
        "privateUrisExcluded": True,
        "localPathsExcluded": True,
    }
    details = {
        "removedByDefaultRouteIds": wave_ids,
        "expectedRouteIds": list(LEGACY_REMOVAL_WAVE_ONE_IDS),
        "replacementUrls": {
            "queue-downloads": "/apps/queue-manager/",
            "queue-uploads": "/apps/queue-manager/",
            "file-insert": "/apps/publisher/",
            "local-file-insert": "/apps/publisher/",
            "friends": "/app/node/#peers",
            "add-friend": "/app/node/#peers",
            "strangers": "/app/node/#peers",
            "connectivity": "/app/node/#connectivity",
        },
        "statusBehavior": {
            "safeRead": "303 See Other when replacement is available; legacy fallback when unavailable",
            "mutating": "410 Gone when replacement is available; legacy fallback when unavailable",
        },
        "liveNodeRequired": False,
        "checks": checks,
        "redaction": redaction,
        "missingSources": missing,
    }
    errors = [name for name, passed in checks.items() if not passed]
    errors.extend(f"missing {name}" for name in missing)
    if errors:
        return EvidenceItem(
            "legacy-admin.removal-wave-1",
            "fail",
            True,
            "Legacy-admin removal wave 1 evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "legacy-admin.removal-wave-1",
        "pass",
        True,
        "Legacy-admin removal wave 1 replacement behavior is documented and observable.",
        source,
        details,
    )

def collect_legacy_removal_wave_two_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    root = settings.workspace_root
    files = {
        "registry": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRetirementRegistry.java",
        "policy": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRemovalPolicy.java",
        "response": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminReplacementResponse.java",
        "recorder": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminUsageRecorder.java",
        "usageDto": root / "runtime-spi/src/main/java/network/crypta/runtime/spi/LegacyAdminSurfaceUsage.java",
        "diagnostics": root / "platform-api/src/main/java/network/crypta/platform/api/diagnostics/DiagnosticsApiHandler.java",
        "docs": root / "docs/legacy-retirement-plan.md",
    }
    text: dict[str, str] = {}
    missing = []
    for key, path in files.items():
        if not path.is_file():
            missing.append(key)
            text[key] = ""
        else:
            text[key] = path.read_text(encoding="utf-8")

    wave_ids = legacy_removal_wave_two_ids(text["registry"])
    scope_expansion_ids = legacy_scope_expansion_wave_two_ids(text["registry"])
    docs_lower = text["docs"].lower()
    checks = {
        "waveTwoIdsMatch": wave_ids == list(LEGACY_REMOVAL_WAVE_TWO_IDS),
        "waveOneIdsStable": legacy_removal_wave_one_ids(text["registry"]) == list(LEGACY_REMOVAL_WAVE_ONE_IDS),
        "scopeExpansionIdsMatch": scope_expansion_ids == list(LEGACY_REMOVAL_WAVE_TWO_SCOPE_EXPANSION_IDS),
        "redirectModeDeclared": "LegacyAdminRemovalMode.REDIRECT_TO_REPLACEMENT" in text["registry"],
        "routeScopeDeclared": "LegacyAdminRemovalScope" in text["registry"] and "matchesRemovalScope" in text["policy"],
        "explicitChildrenDeclared": "EXPLICIT_CHILDREN" in text["registry"] and "explicitRemovalChildPaths" in text["policy"],
        "prefixFamilyDeclared": "PREFIX_FAMILY" in text["registry"],
        "safeReadReplacementResponses": "GET" in text["policy"]
        and "HEAD" in text["policy"]
        and ("redirect(" in text["policy"] or "gone(" in text["policy"]),
        "partialMutationFallbackDocumented": "blockMutatingRequests" in text["policy"]
        and "mutating legacy alert" in text["docs"].lower()
        and "installer and package-store" in text["docs"].lower(),
        "mutatingRequestsBlockedWhereCovered": "BLOCKED_MUTATING_REQUEST" in text["policy"]
        or "blockedMutation" in text["policy"],
        "replacementAvailabilityGate": "replacementAvailable" in text["policy"]
        and "isStaticAppUiAvailable" in text["policy"]
        and "primaryUiRoot" in text["policy"],
        "diagnosticsCarriesReplacementCounter": "replacementResponseCount" in text["diagnostics"] and "replacementResponseCount" in text["usageDto"],
        "diagnosticsCarriesBlockedCounter": "blockedMutatingRequestCount" in text["diagnostics"] and "blockedMutatingRequestCount" in text["usageDto"],
        "diagnosticsCarriesFallbackCounter": "fallbackRenderCount" in text["diagnostics"] and "fallbackRenderCount" in text["usageDto"],
        "diagnosticsCarriesScopeMetadata": "removalScope" in text["diagnostics"]
        and "scopeExpandedInWave" in text["diagnostics"]
        and "removalScope" in text["usageDto"]
        and "scopeExpandedInWave" in text["usageDto"],
        "docsDescribeWave": "legacy-admin.removal-wave-2" in text["docs"],
        "docsDescribeAvailabilityFallback": "replacement is reachable" in text["docs"]
        or "replacement is unavailable" in text["docs"],
        "docsRetainBrowse": "FProxy browse remains retained" in text["docs"],
        "docsRetainDiagnosticExport": (
            "raw diagnostic export remains retained" in docs_lower
            or "raw diagnostic export remained retained" in docs_lower
        ),
        "liveNodeNotRequired": True,
    }
    retained_browse_safety = {
        "fproxyBrowseRootOutOfScope": "/" not in wave_ids,
        "contentFilterOutOfScope": "content-filter" not in wave_ids,
        "wizardOutOfScope": "first-time-wizard" not in wave_ids,
        "nodeToNodeMessageOutOfScope": "node-to-node-message" not in wave_ids,
        "diagnosticPlainTextRetained": "diagnostic" not in wave_ids,
    }
    redaction = {
        "queryStringsExcluded": True,
        "requestBodiesExcluded": True,
        "formPasswordsExcluded": True,
        "remoteAddressesExcluded": True,
        "tokensExcluded": True,
        "privateUrisExcluded": True,
        "localPathsExcluded": True,
    }
    details = {
        "removedByDefaultRouteIds": wave_ids,
        "expectedRouteIds": list(LEGACY_REMOVAL_WAVE_TWO_IDS),
        "scopeExpandedRouteIds": scope_expansion_ids,
        "expectedScopeExpandedRouteIds": list(LEGACY_REMOVAL_WAVE_TWO_SCOPE_EXPANSION_IDS),
        "replacementUrls": {
            "alerts": "/app/node/#alerts",
            "config": "/app/node/#config",
            "core-update": "/app/node/#updates",
            "statistics": "/app/node/#diagnostics",
            "queue-downloads": "/apps/queue-manager/",
            "queue-uploads": "/apps/queue-manager/",
        },
        "statusBehavior": {
            "safeRead": "303 See Other when replacement is available; legacy fallback when unavailable",
            "mutating": "410 Gone only for covered mutations when replacement is available; partial legacy actions remain fallback",
        },
        "actionCoverage": {
            "alerts": "safe reads redirect; legacy POST fallback remains for bulk dismiss and node-message deletion",
            "config": "safe reads and config POST mutations are removed by default when Web Shell config is available",
            "core-update": "safe reads redirect; legacy POST fallback remains for installer and package-store actions",
            "statistics": "safe reads redirect for overview and requesters HTML; raw diagnostic export is retained",
            "queue": "canonical routes plus reviewed count and key-list helpers redirect when Queue Manager is available",
        },
        "retainedBrowseSafety": retained_browse_safety,
        "liveNodeRequired": False,
        "checks": checks,
        "redaction": redaction,
        "missingSources": missing,
    }
    errors = [name for name, passed in checks.items() if not passed]
    errors.extend(f"retainedBrowseSafety.{name}" for name, passed in retained_browse_safety.items() if not passed)
    errors.extend(f"missing {name}" for name in missing)
    if errors:
        return EvidenceItem(
            "legacy-admin.removal-wave-2",
            "fail",
            True,
            "Legacy-admin removal wave 2 evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "legacy-admin.removal-wave-2",
        "pass",
        True,
        "Legacy-admin removal wave 2 replacement behavior is documented and observable.",
        source,
        details,
    )

def collect_legacy_removal_wave_three_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    root = settings.workspace_root
    files = {
        "registry": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRetirementRegistry.java",
        "policy": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRemovalPolicy.java",
        "response": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminReplacementResponse.java",
        "webshellToadlet": root
        / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/WebShellToadlet.java",
        "bootstrap": root
        / "platform-web-shell/src/main/java/network/crypta/platform/webshell/bootstrap/WebShellBootstrap.java",
        "bootstrapJson": root
        / "platform-web-shell/src/main/java/network/crypta/platform/webshell/bootstrap/WebShellBootstrapJson.java",
        "webshell": root
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js",
        "webshellIndex": root
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/index.html",
        "docs": root / "docs/legacy-retirement-plan.md",
    }
    text: dict[str, str] = {}
    missing = []
    for key, path in files.items():
        if not path.is_file():
            missing.append(key)
            text[key] = ""
        else:
            text[key] = path.read_text(encoding="utf-8")

    wave_ids = legacy_removal_wave_three_ids(text["registry"])
    docs_lower = text["docs"].lower()
    checks = {
        "waveThreeIdsMatch": wave_ids == list(LEGACY_REMOVAL_WAVE_THREE_IDS),
        "waveOneIdsStable": legacy_removal_wave_one_ids(text["registry"]) == list(LEGACY_REMOVAL_WAVE_ONE_IDS),
        "waveTwoIdsStable": legacy_removal_wave_two_ids(text["registry"]) == list(LEGACY_REMOVAL_WAVE_TWO_IDS),
        "waveThreeConstantPresent": "REMOVAL_WAVE_3" in text["registry"],
        "removedSinceMarkerPresent": "phase-8-pr-244" in text["registry"],
        "securityReplacementUrl": (
            "SHELL_SECURITY_URL" in text["registry"]
            or "/app/node/#security" in text["registry"]
        )
        and "/app/node/#security" in text["docs"],
        "securityMutatingFallbackDeclared": "security-levels" in text["registry"]
        and (
            "canonicalMutationFallback()" in text["registry"]
            or "mutating-legacy-fallback" in text["registry"]
        ),
        "securityLegacyFallbackMarkerDeclared": "legacyFallback=security-levels" in text["policy"]
        and "legacyFallback=security-levels" in text["webshell"]
        and "Open the legacy security page" in text["webshell"],
        "securityFallbackLinkDiscoverable": "function renderSecurityLegacyFallbackAction()" in text["webshell"]
        and "sections.security.append(renderSecurityLegacyFallbackAction())" in text["webshell"]
        and "Open legacy password and recovery forms" in text["webshell"]
        and "Security panel" in text["docs"],
        "securityFallbackPathFromBootstrap": "bootstrap.legacySecurityLevelsPath" in text["webshell"]
        and 'legacySecurityLevelsPath + "?legacyFallback=security-levels"' in text["webshell"]
        and "legacySecurityLevelsPath" in text["bootstrap"]
        and '"legacySecurityLevelsPath"' in text["bootstrapJson"],
        "securityFallbackAllowsSlashlessPath": "normalizeLocalPath(" in text["webshell"]
        and "bootstrap.legacySecurityLevelsPath" in text["webshell"]
        and (
            "requireLegacySecurityLevelsPath(legacySecurityLevelsPath" in text["bootstrap"]
            or 'requireLegacyLocalPath(legacySecurityLevelsPath, "legacySecurityLevelsPath")'
            in text["bootstrap"]
        ),
        "securityFallbackPathFromRegistry": web_shell_toadlet_sources_security_fallback_path(
            text["webshellToadlet"]
        ),
        "securityFallbackPathNotHardCoded": '"/seclevels/?legacyFallback=security-levels"'
        not in text["webshell"],
        "securityCanonicalScopeOnly": "CANONICAL_AND_SLASHLESS_ALIAS" in text["registry"]
        and "prefix-family matching" in docs_lower,
        "policyRoutesSecurityThroughWebShell": '"security-levels"' in text["policy"]
        and "webShellReplacementAvailable" in text["policy"],
        "safeReadReplacementResponses": "GET" in text["policy"]
        and "HEAD" in text["policy"]
        and "redirect(" in text["policy"],
        "mutatingFallbackDocumented": "master-password" in docs_lower
        and "high physical security" in docs_lower
        and "recovery" in docs_lower
        and "legacy fallback remains" in docs_lower,
        "safeReadFallbackDocumented": "bootstrap-resolved explicit fallback link" in docs_lower
        and "arbitrary query strings still receive" in docs_lower,
        "docsDescribeWave": "legacy-admin.removal-wave-3" in text["docs"],
        "docsRetainBrowse": "FProxy browse" in text["docs"]
        and "content rendering" in text["docs"],
        "docsRetainContentFilter": "Content filter" in text["docs"]
        or "content filter" in docs_lower,
        "docsRetainDiagnosticExport": "raw diagnostic export" in docs_lower,
        "docsRetainStartupWizard": "Startup wizard" in text["docs"]
        and "emergency fallback" in docs_lower,
        "docsLeaveNodeToNodePending": "Node-to-node messages" in text["docs"],
        "liveNodeNotRequired": True,
    }
    retained_browse_safety = {
        "fproxyBrowseRootOutOfScope": "/" not in wave_ids,
        "contentFilterOutOfScope": "content-filter" not in wave_ids,
        "wizardOutOfScope": "first-time-wizard" not in wave_ids,
        "nodeToNodeMessageOutOfScope": "node-to-node-message" not in wave_ids,
        "diagnosticPlainTextRetained": "diagnostic" not in wave_ids,
    }
    redaction = {
        "queryStringsExcluded": True,
        "formPasswordsExcluded": True,
        "tokensExcluded": True,
        "privateUrisExcluded": True,
        "requestBodiesExcluded": True,
        "rawFetchedBodiesExcluded": True,
        "rawSignaturesExcluded": True,
        "localPathsExcluded": True,
    }
    details = {
        "removedByDefaultRouteIds": wave_ids,
        "expectedRouteIds": list(LEGACY_REMOVAL_WAVE_THREE_IDS),
        "replacementUrls": {"security-levels": "/app/node/#security"},
        "fallbackUrlSource": "Web Shell bootstrap legacySecurityLevelsPath from the registry security-levels legacy path",
        "statusBehavior": {
            "safeRead": "303 See Other when Web Shell security is available; legacy fallback when unavailable",
            "mutating": "legacy fallback remains for partial master-password, recovery, and high-physical-security flows",
        },
        "retainedBrowseSafety": retained_browse_safety,
        "liveNodeRequired": False,
        "checks": checks,
        "redaction": redaction,
        "missingSources": missing,
    }
    errors = [name for name, passed in checks.items() if not passed]
    errors.extend(f"retainedBrowseSafety.{name}" for name, passed in retained_browse_safety.items() if not passed)
    errors.extend(f"missing {name}" for name in missing)
    if errors:
        return EvidenceItem(
            "legacy-admin.removal-wave-3",
            "fail",
            True,
            "Legacy-admin removal wave 3 evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "legacy-admin.removal-wave-3",
        "pass",
        True,
        "Legacy-admin removal wave 3 replacement behavior is documented and observable.",
        source,
        details,
    )

def collect_legacy_removal_wave_four_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    root = settings.workspace_root
    files = {
        "registry": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRetirementRegistry.java",
        "policy": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRemovalPolicy.java",
        "webshellToadlet": root
        / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/WebShellToadlet.java",
        "bootstrap": root
        / "platform-web-shell/src/main/java/network/crypta/platform/webshell/bootstrap/WebShellBootstrap.java",
        "bootstrapJson": root
        / "platform-web-shell/src/main/java/network/crypta/platform/webshell/bootstrap/WebShellBootstrapJson.java",
        "webshell": root
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js",
        "webshellIndex": root
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/index.html",
        "docs": root / "docs/legacy-retirement-plan.md",
        "policyTest": root
        / "adapter-http-legacy-admin/src/test/java/network/crypta/clients/http/LegacyAdminRemovalPolicyTest.java",
        "registryTest": root
        / "adapter-http-legacy-admin/src/test/java/network/crypta/clients/http/LegacyAdminRetirementRegistryTest.java",
        "bootstrapTest": root
        / "platform-web-shell/src/test/java/network/crypta/platform/webshell/WebShellBootstrapTest.java",
        "resourcesTest": root
        / "platform-web-shell/src/test/java/network/crypta/platform/webshell/WebShellResourcesTest.java",
        "toadletBootstrapTest": root
        / "adapter-http-legacy-admin/src/test/java/network/crypta/clients/http/WebShellToadletBootstrapTest.java",
    }
    text: dict[str, str] = {}
    missing = []
    for key, path in files.items():
        if not path.is_file():
            missing.append(key)
            text[key] = ""
        else:
            text[key] = path.read_text(encoding="utf-8")

    wave_ids = legacy_removal_wave_four_ids(text["registry"])
    diagnostic_body = java_method_body(text["registry"], "diagnosticWave4Redirect")
    tests_text = "\n".join(
        text[key]
        for key in (
            "policyTest",
            "registryTest",
            "bootstrapTest",
            "resourcesTest",
            "toadletBootstrapTest",
        )
    )
    docs_lower = text["docs"].lower()
    webshell_lower = text["webshell"].lower()
    retained_scope = {
        "fproxyBrowseRootOutOfScope": "/" not in wave_ids,
        "contentRenderingOutOfScope": "browse" not in wave_ids and "content" not in wave_ids,
        "contentFilterOutOfScope": "content-filter" not in wave_ids,
        "firstTimeWizardOutOfScope": "first-time-wizard" not in wave_ids
        and "first-time-wizard-js" not in wave_ids,
        "securityRecoveryFallbackOutOfScope": "security-levels" not in wave_ids,
        "chatOutOfScope": "chat" not in wave_ids,
        "translationOutOfScope": "translation" not in wave_ids,
        "helpOutOfScope": "help" not in wave_ids,
        "nodeToNodeMessageOutOfScope": "node-to-node-message" not in wave_ids,
    }
    checks = {
        "waveFourIdsMatch": wave_ids == list(LEGACY_REMOVAL_WAVE_FOUR_IDS),
        "waveOneIdsStable": legacy_removal_wave_one_ids(text["registry"]) == list(LEGACY_REMOVAL_WAVE_ONE_IDS),
        "waveTwoIdsStable": legacy_removal_wave_two_ids(text["registry"]) == list(LEGACY_REMOVAL_WAVE_TWO_IDS),
        "waveThreeIdsStable": legacy_removal_wave_three_ids(text["registry"]) == list(LEGACY_REMOVAL_WAVE_THREE_IDS),
        "waveFourConstantPresent": "REMOVAL_WAVE_4" in text["registry"],
        "waveFourMarkerPresent": "phase-9-pr-254" in text["registry"],
        "diagnosticRedirectModeDeclared": "diagnostic" in diagnostic_body
        and "LegacyAdminRemovalMode.REDIRECT_TO_REPLACEMENT" in diagnostic_body
        and "REMOVAL_WAVE_4" in diagnostic_body
        and "REMOVED_BY_DEFAULT_SINCE_WAVE_4" in diagnostic_body,
        "diagnosticReplacementUrl": (
            "/app/node/#diagnostics" in text["registry"]
            or "SHELL_DIAGNOSTICS_URL" in text["registry"]
        )
        and "/app/node/#diagnostics" in text["docs"],
        "diagnosticFallbackMarkerPolicyExact": "legacyFallback=diagnostic-export" in text["policy"]
        and "diagnostic" in text["policy"]
        and "getRawQuery()" in text["policy"]
        and "isMutatingRequestMethod" in text["policy"],
        "diagnosticFallbackSafeReadOnly": "GET" in text["policy"]
        and "HEAD" in text["policy"]
        and "legacyFallback=diagnostic-export" in text["policy"],
        "diagnosticReplacementAvailableThroughWebShell": '"diagnostic"' in text["policy"]
        and "webShellReplacementAvailable" in text["policy"],
        "safeReadReplacementResponses": "GET" in text["policy"]
        and "HEAD" in text["policy"]
        and "redirect(" in text["policy"],
        "bootstrapDiagnosticPathValidated": "legacyDiagnosticPath" in text["bootstrap"]
        and (
            "requireLegacyDiagnosticPath" in text["bootstrap"]
            or "requireLegacyLocalPath" in text["bootstrap"]
            or "requireLocalPath" in text["bootstrap"]
        )
        and "getRawQuery()" in text["bootstrap"]
        and "getRawFragment()" in text["bootstrap"],
        "bootstrapDiagnosticPathSerialized": '"legacyDiagnosticPath"' in text["bootstrapJson"],
        "diagnosticPathFromRegistry": 'LegacyAdminRetirementRegistry.require("diagnostic").legacyPath()'
        in text["webshellToadlet"]
        and "legacyDiagnosticPath" in text["webshellToadlet"]
        and '"/diagnostic/"' not in text["webshellToadlet"],
        "webShellUsesBootstrapDiagnosticPath": "bootstrap.legacyDiagnosticPath" in text["webshell"]
        and "normalizeLocalPath" in text["webshell"]
        and 'legacyDiagnosticPath + "?legacyFallback=diagnostic-export"' in text["webshell"],
        "webShellDiagnosticFallbackAction": (
            "Open legacy plaintext diagnostic export" in text["webshell"]
            or "Open legacy plaintext diagnostic export" in text["webshellIndex"]
        )
        and (
            "emergency" in webshell_lower
            or "support fallback" in webshell_lower
            or "emergency" in text["webshellIndex"].lower()
            or "support fallback" in text["webshellIndex"].lower()
        ),
        "webShellDoesNotHardcodeRawFallbackPath": '"/diagnostic/?legacyFallback=diagnostic-export"'
        not in text["webshell"]
        and "'/diagnostic/?legacyFallback=diagnostic-export'" not in text["webshell"],
        "webShellDoesNotStoreDiagnosticExport": not re.search(
            r"(?:localStorage|sessionStorage|indexedDB)[^\n;]*(?:legacyDiagnostic|diagnostic-export|diagnostic export)",
            text["webshell"],
            re.IGNORECASE,
        ),
        "testsCoverDiagnosticFallbackMarker": "legacyFallback=diagnostic-export" in tests_text,
        "testsCoverNonExactDiagnosticQuery": "diagnostic-export&" in tests_text
        or "token=secret" in tests_text,
        "testsCoverSlashlessDiagnosticAlias": '"/diagnostic"' in tests_text
        or "slashless" in tests_text.lower(),
        "testsCoverDiagnosticSubpathOutOfScope": "/diagnostic/requesters" in tests_text
        or "subpath" in tests_text.lower(),
        "testsCoverDiagnosticOnlyWaveFour": "REMOVAL_WAVE_4" in tests_text
        or "wave 4" in tests_text.lower()
        or "waveFour" in tests_text,
        "docsDescribeWave": "legacy-admin.removal-wave-4" in text["docs"],
        "docsPrimaryWebShellDiagnostics": "web shell diagnostics" in docs_lower
        and "/app/node/#diagnostics" in text["docs"],
        "docsFallbackSupportEmergency": "plain-text" in docs_lower
        and ("support" in docs_lower or "emergency" in docs_lower),
        "docsRetainFproxyBrowse": "fproxy browse" in docs_lower
        and "content rendering" in docs_lower,
        "docsRetainContentFilter": "content filter" in docs_lower,
        "docsRetainStartupWizard": "startup wizard" in docs_lower
        or "first-time wizard" in docs_lower,
        "docsRetainSecurityFallback": "legacyFallback=security-levels" in text["docs"]
        or "security fallback" in docs_lower,
        "securityFallbackBehaviorUnchanged": "legacyFallback=security-levels" in text["policy"]
        and "legacyFallback=security-levels" in text["webshell"],
        "liveNodeNotRequired": True,
    }
    redaction = {
        "queryStringsExcluded": True,
        "requestBodiesExcluded": True,
        "formPasswordsExcluded": True,
        "tokensExcluded": True,
        "privateInsertUrisExcluded": True,
        "rawDiagnosticOutputExcluded": True,
        "rawFetchedBodiesExcluded": True,
        "rawAppDataExcluded": True,
        "rawSignaturesExcluded": True,
        "absoluteLocalPathsExcluded": True,
    }
    details = {
        "removedByDefaultRouteIds": wave_ids,
        "expectedRouteIds": list(LEGACY_REMOVAL_WAVE_FOUR_IDS),
        "replacementUrls": {"diagnostic": "/app/node/#diagnostics"},
        "fallbackUrlSource": "Web Shell bootstrap legacyDiagnosticPath from the registry diagnostic legacy path",
        "statusBehavior": {
            "safeRead": "303 See Other when Web Shell diagnostics are available",
            "explicitFallback": "legacy plaintext diagnostic export remains support-only for exact safe-read fallback marker",
            "mutating": "blocked before the removed legacy diagnostic route can execute",
            "subpaths": "diagnostic subpaths remain outside removal scope unless separately registered",
        },
        "retainedScope": retained_scope,
        "liveNodeRequired": False,
        "checks": checks,
        "redaction": redaction,
        "missingSources": missing,
    }
    errors = [name for name, passed in checks.items() if not passed]
    errors.extend(f"retainedScope.{name}" for name, passed in retained_scope.items() if not passed)
    errors.extend(f"missing {name}" for name in missing)
    if errors:
        return EvidenceItem(
            "legacy-admin.removal-wave-4",
            "fail",
            True,
            "Legacy-admin removal wave 4 evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "legacy-admin.removal-wave-4",
        "pass",
        True,
        "Legacy-admin removal wave 4 diagnostic replacement behavior is documented and observable.",
        source,
        details,
    )

def collect_legacy_removal_wave_five_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    root = settings.workspace_root
    files = {
        "registry": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRetirementRegistry.java",
        "policy": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRemovalPolicy.java",
        "docs": root / "docs/legacy-retirement-plan.md",
        "policyTest": root
        / "adapter-http-legacy-admin/src/test/java/network/crypta/clients/http/LegacyAdminRemovalPolicyTest.java",
        "registryTest": root
        / "adapter-http-legacy-admin/src/test/java/network/crypta/clients/http/LegacyAdminRetirementRegistryTest.java",
        "browseRegistrarTest": root
        / "adapter-http-legacy-browse/src/test/java/network/crypta/clients/http/LegacyFProxyBrowseRouteRegistrarTest.java",
    }
    text: dict[str, str] = {}
    missing = []
    for key, path in files.items():
        if not path.is_file():
            missing.append(key)
            text[key] = ""
        else:
            text[key] = path.read_text(encoding="utf-8")

    wave_ids = legacy_removal_wave_five_ids(text["registry"])
    docs_lower = text["docs"].lower()
    retained_scope = {
        "fproxyBrowseRootOutOfScope": "/" not in wave_ids,
        "contentRenderingOutOfScope": "fproxy-key-content-rendering" not in wave_ids,
        "contentFilterOutOfScope": "content-filter" not in wave_ids,
        "firstTimeWizardOutOfScope": "first-time-wizard" not in wave_ids
        and "first-time-wizard-js" not in wave_ids,
        "securityRecoveryFallbackOutOfScope": "security-levels" not in wave_ids,
        "diagnosticExportFallbackOutOfScope": "diagnostic" not in wave_ids,
        "chatOutOfScope": "chat" not in wave_ids,
        "translationOutOfScope": "translation" not in wave_ids,
        "helpOutOfScope": "help" not in wave_ids,
        "nodeToNodeMessageOutOfScope": "node-to-node-message" not in wave_ids,
        "platformApiOutOfScope": "platform-api" not in wave_ids,
        "webShellOutOfScope": "web-shell" not in wave_ids,
        "appUiOutOfScope": "app-ui" not in wave_ids,
    }
    checks = {
        "waveFiveIdsMatch": wave_ids == list(LEGACY_REMOVAL_WAVE_FIVE_IDS),
        "waveOneIdsStable": legacy_removal_wave_one_ids(text["registry"]) == list(LEGACY_REMOVAL_WAVE_ONE_IDS),
        "waveTwoIdsStable": legacy_removal_wave_two_ids(text["registry"]) == list(LEGACY_REMOVAL_WAVE_TWO_IDS),
        "waveThreeIdsStable": legacy_removal_wave_three_ids(text["registry"]) == list(LEGACY_REMOVAL_WAVE_THREE_IDS),
        "waveFourIdsStable": legacy_removal_wave_four_ids(text["registry"]) == list(LEGACY_REMOVAL_WAVE_FOUR_IDS),
        "waveFiveConstantPresent": "REMOVAL_WAVE_5" in text["registry"],
        "waveFiveMarkerPresent": "phase-10-pr-265" in text["registry"],
        "finalSurfacePolicyPresent": "FinalSurfacePolicy" in text["registry"]
        and "buildFinalSurfacePolicy" in text["registry"],
        "noUnprovenWaveFivePromotionTest": "removalWaveSurfaces_whenWaveFiveRequested_expectNoUnprovenRoutePromotions"
        in text["registryTest"],
        "retainedRouteNoDecisionTest": "waveFiveRetainedInfrastructureAndFallbackRoutes"
        in text["policyTest"],
        "browseRegistrarEvidencePresent": "ContentFilterToadlet" in text["browseRegistrarTest"]
        and "LegacyHttpBrowseRouteRegistrar.Phase.QUEUE_FILTER_ROUTES" in text["browseRegistrarTest"],
        "docsDescribeWave": "legacy-admin.removal-wave-5" in text["docs"],
        "docsMaintenanceOnly": "maintenance-only" in docs_lower,
        "docsRetainBrowse": "fproxy browse" in docs_lower and "content rendering" in docs_lower,
        "docsRetainContentFilter": "content filter" in docs_lower,
        "docsRetainStartupRecovery": "startup" in docs_lower and "recovery" in docs_lower,
        "docsNoNewLegacyAdmin": "no new legacy admin surfaces" in docs_lower,
        "liveNodeNotRequired": True,
    }
    redaction = {
        "queryStringsExcluded": True,
        "requestBodiesExcluded": True,
        "formPasswordsExcluded": True,
        "tokensExcluded": True,
        "privateInsertUrisExcluded": True,
        "rawDiagnosticOutputExcluded": True,
        "rawFetchedBodiesExcluded": True,
        "rawAppDataExcluded": True,
        "absoluteLocalPathsExcluded": True,
    }
    details = {
        "removedByDefaultRouteIds": wave_ids,
        "expectedRouteIds": list(LEGACY_REMOVAL_WAVE_FIVE_IDS),
        "waveFivePromotedRouteIds": wave_ids,
        "since": "phase-10-pr-265",
        "statusBehavior": {
            "safeRead": "no additional safe-read legacy route is promoted in Wave 5",
            "mutating": "no additional mutating legacy route is promoted in Wave 5; prior covered mutations remain blocked",
            "finalSurface": "remaining routes are explicitly retained, pending, support fallback, startup/recovery fallback, browse, or infrastructure",
        },
        "retainedScope": retained_scope,
        "liveNodeRequired": False,
        "checks": checks,
        "redaction": redaction,
        "missingSources": missing,
    }
    errors = [name for name, passed in checks.items() if not passed]
    errors.extend(f"retainedScope.{name}" for name, passed in retained_scope.items() if not passed)
    errors.extend(f"missing {name}" for name in missing)
    if errors:
        return EvidenceItem(
            "legacy-admin.removal-wave-5",
            "fail",
            True,
            "Legacy-admin removal wave 5 final-surface readiness evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "legacy-admin.removal-wave-5",
        "pass",
        True,
        "Legacy-admin removal wave 5 final-surface readiness is documented and observable.",
        source,
        details,
    )

def collect_legacy_final_admin_surface_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    root = settings.workspace_root
    files = {
        "registry": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRetirementRegistry.java",
        "policy": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRemovalPolicy.java",
        "docs": root / "docs/legacy-retirement-plan.md",
        "policyTest": root
        / "adapter-http-legacy-admin/src/test/java/network/crypta/clients/http/LegacyAdminRemovalPolicyTest.java",
        "registryTest": root
        / "adapter-http-legacy-admin/src/test/java/network/crypta/clients/http/LegacyAdminRetirementRegistryTest.java",
    }
    text: dict[str, str] = {}
    missing = []
    for key, path in files.items():
        if not path.is_file():
            missing.append(key)
            text[key] = ""
        else:
            text[key] = path.read_text(encoding="utf-8")

    categories = {
        "removedByDefaultAdmin": legacy_final_surface_category_ids(
            text["registry"], "REMOVED_BY_DEFAULT_ADMIN"
        ),
        "retainedBrowse": legacy_final_surface_category_ids(
            text["registry"], "RETAINED_BROWSE_SURFACE"
        ),
        "retainedBrowseSafety": legacy_final_surface_category_ids(
            text["registry"], "RETAINED_BROWSE_SAFETY"
        ),
        "supportEmergencyFallback": legacy_final_surface_category_ids(
            text["registry"], "SUPPORT_EMERGENCY_FALLBACK"
        ),
        "startupRecoveryFallback": legacy_final_surface_category_ids(
            text["registry"], "STARTUP_RECOVERY_FALLBACK"
        ),
        "pendingMigrationGap": legacy_final_surface_category_ids(
            text["registry"], "PENDING_MIGRATION_GAP"
        ),
        "retainedNonAdminSupport": legacy_final_surface_category_ids(
            text["registry"], "RETAINED_NON_ADMIN_SUPPORT"
        ),
        "infrastructure": legacy_final_surface_category_ids(text["registry"], "INFRASTRUCTURE"),
    }
    docs_lower = text["docs"].lower()
    checks = {
        "policyEvidenceIdPresent": "legacy-admin.final-admin-surface" in text["registry"],
        "waveFiveMarkerPresent": "phase-10-pr-265" in text["registry"],
        "removedByDefaultAdminIdsMatch": categories["removedByDefaultAdmin"]
        == list(LEGACY_FINAL_ADMIN_REMOVED_IDS),
        "retainedBrowseIdsMatch": categories["retainedBrowse"]
        == list(LEGACY_FINAL_RETAINED_BROWSE_IDS),
        "retainedBrowseSafetyIdsMatch": categories["retainedBrowseSafety"]
        == list(LEGACY_FINAL_RETAINED_BROWSE_SAFETY_IDS),
        "supportEmergencyIdsMatch": categories["supportEmergencyFallback"]
        == list(LEGACY_FINAL_SUPPORT_EMERGENCY_IDS),
        "startupRecoveryIdsMatch": categories["startupRecoveryFallback"]
        == list(LEGACY_FINAL_STARTUP_RECOVERY_IDS),
        "pendingGapIdsMatch": categories["pendingMigrationGap"]
        == list(LEGACY_FINAL_PENDING_GAP_IDS),
        "retainedSupportIdsMatch": categories["retainedNonAdminSupport"]
        == list(LEGACY_FINAL_RETAINED_NON_ADMIN_SUPPORT_IDS),
        "infrastructureIdsMatch": categories["infrastructure"]
        == list(LEGACY_FINAL_INFRASTRUCTURE_IDS),
        "testsCoverFinalSurfacePolicy": "finalSurfacePolicy_whenRemovedAdminRequested" in text["registryTest"]
        and "finalSurfacePolicy_whenFallbacksRequested" in text["registryTest"],
        "testsCoverRetainedNoDecision": "waveFiveRetainedInfrastructureAndFallbackRoutes"
        in text["policyTest"],
        "docsFinalSurface": "final admin surface" in docs_lower,
        "docsMaintenanceOnly": "maintenance-only" in docs_lower,
        "docsNoNewLegacyAdmin": "no new legacy admin surfaces" in docs_lower,
        "docsRedactionBoundary": "query strings" in docs_lower and "request bodies" in docs_lower,
        "liveNodeNotRequired": True,
    }
    redaction = {
        "routeIdsOnly": True,
        "queryStringsExcluded": True,
        "requestBodiesExcluded": True,
        "formPasswordsExcluded": True,
        "tokensExcluded": True,
        "privateInsertUrisExcluded": True,
        "rawDiagnosticOutputExcluded": True,
        "rawFetchedBodiesExcluded": True,
        "rawAppDataExcluded": True,
        "absoluteLocalPathsExcluded": True,
    }
    details = {
        "since": "phase-10-pr-265",
        "categories": categories,
        "waveFivePromotedRouteIds": legacy_removal_wave_five_ids(text["registry"]),
        "liveNodeRequired": False,
        "checks": checks,
        "redaction": redaction,
        "missingSources": missing,
    }
    errors = [name for name, passed in checks.items() if not passed]
    errors.extend(f"missing {name}" for name in missing)
    if errors:
        return EvidenceItem(
            "legacy-admin.final-admin-surface",
            "fail",
            True,
            "Legacy-admin final-surface policy evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "legacy-admin.final-admin-surface",
        "pass",
        True,
        "Legacy-admin final-surface policy is deterministic and machine-checkable.",
        source,
        details,
    )

def collect_legacy_browse_retained_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    root = settings.workspace_root
    files = {
        "registry": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRetirementRegistry.java",
        "registryTest": root
        / "adapter-http-legacy-admin/src/test/java/network/crypta/clients/http/LegacyAdminRetirementRegistryTest.java",
        "policyTest": root
        / "adapter-http-legacy-admin/src/test/java/network/crypta/clients/http/LegacyAdminRemovalPolicyTest.java",
        "browseTest": root
        / "adapter-http-legacy-browse/src/test/java/network/crypta/clients/http/LegacyFProxyBrowseRouteRegistrarTest.java",
        "docs": root / "docs/legacy-retirement-plan.md",
    }
    text: dict[str, str] = {}
    missing = []
    for key, path in files.items():
        if not path.is_file():
            missing.append(key)
            text[key] = ""
        else:
            text[key] = path.read_text(encoding="utf-8")

    retained_browse_ids = legacy_final_surface_category_ids(
        text["registry"], "RETAINED_BROWSE_SURFACE"
    )
    retained_safety_ids = legacy_final_surface_category_ids(
        text["registry"], "RETAINED_BROWSE_SAFETY"
    )
    docs_lower = text["docs"].lower()
    checks = {
        "retainedBrowseIdsMatch": retained_browse_ids
        == list(LEGACY_FINAL_RETAINED_BROWSE_IDS),
        "retainedBrowseSafetyIdsMatch": retained_safety_ids
        == list(LEGACY_FINAL_RETAINED_BROWSE_SAFETY_IDS),
        "browseRootNotRetirementSurface": "findByLegacyPath_whenFProxyBrowseRouteRequested_expectNoRetirementSurface"
        in text["registryTest"],
        "policyTestsBrowseNoDecision": "/CHK@abc" in text["policyTest"]
        and "/SSK@abc" in text["policyTest"]
        and "/USK@abc" in text["policyTest"]
        and "/filterfile/" in text["policyTest"]
        and "/filter-browse/" in text["policyTest"],
        "browseRegistrarRegistersRootAndFilter": '"/"' in text["browseTest"]
        and "ContentFilterToadlet" in text["browseTest"]
        and "LocalFileFilterToadlet" in text["browseTest"],
        "docsRetainBrowse": "fproxy browse remains retained" in docs_lower
        and "content rendering" in docs_lower,
        "docsRetainContentFilter": "content filter remains retained" in docs_lower,
        "liveNodeNotRequired": True,
    }
    details = {
        "retainedBrowseRouteIds": retained_browse_ids,
        "retainedBrowseSafetyRouteIds": retained_safety_ids,
        "retainedRoutePatterns": ["/", "/{CHK,SSK,USK,KSK}@...", "/filterfile/"],
        "liveNodeRequired": False,
        "checks": checks,
        "redaction": {
            "rawFetchedContentExcluded": True,
            "privateInsertUrisExcluded": True,
            "queryStringsExcluded": True,
            "requestBodiesExcluded": True,
            "absoluteLocalPathsExcluded": True,
        },
        "missingSources": missing,
    }
    errors = [name for name, passed in checks.items() if not passed]
    errors.extend(f"missing {name}" for name in missing)
    if errors:
        return EvidenceItem(
            "legacy-admin.browse-retained",
            "fail",
            True,
            "Legacy browse retention evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "legacy-admin.browse-retained",
        "pass",
        True,
        "FProxy browse, content rendering, and content filter remain explicitly retained.",
        source,
        details,
    )

def collect_legacy_emergency_fallback_retained_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    root = settings.workspace_root
    files = {
        "registry": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRetirementRegistry.java",
        "policy": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRemovalPolicy.java",
        "policyTest": root
        / "adapter-http-legacy-admin/src/test/java/network/crypta/clients/http/LegacyAdminRemovalPolicyTest.java",
        "docs": root / "docs/legacy-retirement-plan.md",
        "operatorDocs": root / "docs/operator-rc-recovery-and-support-workflow.md",
    }
    text: dict[str, str] = {}
    missing = []
    for key, path in files.items():
        if not path.is_file():
            missing.append(key)
            text[key] = ""
        else:
            text[key] = path.read_text(encoding="utf-8")

    support_ids = legacy_final_surface_category_ids(
        text["registry"], "SUPPORT_EMERGENCY_FALLBACK"
    )
    startup_ids = legacy_final_surface_category_ids(
        text["registry"], "STARTUP_RECOVERY_FALLBACK"
    )
    docs_lower = text["docs"].lower()
    operator_docs_lower = text["operatorDocs"].lower()
    checks = {
        "supportEmergencyIdsMatch": support_ids == list(LEGACY_FINAL_SUPPORT_EMERGENCY_IDS),
        "startupRecoveryIdsMatch": startup_ids == list(LEGACY_FINAL_STARTUP_RECOVERY_IDS),
        "diagnosticFallbackMarkerExact": "legacyFallback=diagnostic-export" in text["policy"]
        and "getRawQuery()" in text["policy"],
        "securityFallbackMarkerExact": "legacyFallback=security-levels" in text["policy"]
        and "getRawQuery()" in text["policy"],
        "testsCoverDiagnosticFallback": "legacyFallback=diagnostic-export" in text["policyTest"]
        and "diagnostic-export&" in text["policyTest"],
        "testsCoverSecurityFallback": "legacyFallback=security-levels" in text["policyTest"]
        and "/seclevels/network" in text["policyTest"],
        "testsCoverWizardNoDecision": "/wizard/" in text["policyTest"] and "/wiz/" in text["policyTest"],
        "docsDiagnosticSupportEmergency": "diagnostic" in docs_lower
        and "support" in docs_lower
        and "emergency" in docs_lower,
        "docsStartupRecoveryRetained": "startup" in docs_lower and "recovery" in docs_lower,
        "supportBundleRedactionDocumented": "support bundles" in operator_docs_lower
        and "form passwords" in operator_docs_lower
        and "tokens" in operator_docs_lower,
        "liveNodeNotRequired": True,
    }
    details = {
        "supportEmergencyRouteIds": support_ids,
        "startupRecoveryRouteIds": startup_ids,
        "fallbackMarkers": [
            "legacyFallback=diagnostic-export",
            "legacyFallback=security-levels",
        ],
        "statusBehavior": {
            "diagnostic": "exact safe-read fallback marker retains plaintext export; non-exact queries redirect",
            "security": "exact safe-read fallback marker retains legacy recovery/security forms; child routes are not prefix removed",
            "wizard": "startup wizard routes remain pending fallback and are not Wave 5 removals",
        },
        "liveNodeRequired": False,
        "checks": checks,
        "redaction": {
            "rawDiagnosticOutputExcluded": True,
            "supportBundlePayloadsExcluded": True,
            "requestBodiesExcluded": True,
            "formPasswordsExcluded": True,
            "tokensExcluded": True,
            "privateInsertUrisExcluded": True,
            "absoluteLocalPathsExcluded": True,
        },
        "missingSources": missing,
    }
    errors = [name for name, passed in checks.items() if not passed]
    errors.extend(f"missing {name}" for name in missing)
    if errors:
        return EvidenceItem(
            "legacy-admin.emergency-fallback-retained",
            "fail",
            True,
            "Legacy emergency and support fallback retention evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "legacy-admin.emergency-fallback-retained",
        "pass",
        True,
        "Startup, recovery, diagnostic export, and support fallbacks remain explicit and redacted.",
        source,
        details,
    )

def collect_sandbox_provider_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    sandbox_dir = settings.workspace_root / "platform-apphost/src/main/java/network/crypta/platform/apphost/sandbox"
    sandbox_test_dir = settings.workspace_root / "platform-apphost/src/test/java/network/crypta/platform/apphost/sandbox"
    expected_files = {
        "providerSource": sandbox_dir / "BubblewrapSandboxProvider.java",
        "commandBuilderSource": sandbox_dir / "BubblewrapCommandBuilder.java",
        "availabilitySource": sandbox_dir / "BubblewrapAvailability.java",
        "registrySource": sandbox_dir / "AppSandboxProviders.java",
        "providerTest": sandbox_test_dir / "BubblewrapSandboxProviderTest.java",
    }
    checks: dict[str, Any] = {}
    errors: list[str] = []
    for key, path in expected_files.items():
        exists = path.is_file()
        checks[key] = {
            "present": exists,
            "path": display_path(path, settings.workspace_root),
        }
        if not exists:
            errors.append(f"{key} is missing")
    provider_text = expected_files["providerSource"].read_text(encoding="utf-8") if expected_files["providerSource"].is_file() else ""
    builder_text = expected_files["commandBuilderSource"].read_text(encoding="utf-8") if expected_files["commandBuilderSource"].is_file() else ""
    registry_text = expected_files["registrySource"].read_text(encoding="utf-8") if expected_files["registrySource"].is_file() else ""
    test_text = expected_files["providerTest"].read_text(encoding="utf-8") if expected_files["providerTest"].is_file() else ""
    checks["enforcedSupportLevel"] = "AppSandboxSupportLevel.ENFORCED" in provider_text
    checks["bubblewrapProviderName"] = 'PROVIDER_NAME = "bubblewrap"' in provider_text
    checks["restrictedProcessRegistry"] = "BubblewrapSandboxProvider" in registry_text
    checks["environmentPassThrough"] = "checkedContext.environment()" in provider_text
    checks["noSetenvCommand"] = 'command.add("--setenv")' not in provider_text + builder_text
    checks["offlineProviderTests"] = "BubblewrapSandboxProviderTest" in test_text
    for key in (
        "enforcedSupportLevel",
        "bubblewrapProviderName",
        "restrictedProcessRegistry",
        "environmentPassThrough",
        "noSetenvCommand",
        "offlineProviderTests",
    ):
        if not checks[key]:
            errors.append(f"{key} check failed")
    gradle_result = gradle_command(
        settings,
        [
            ":platform-apphost:test",
            "--tests",
            "*BubblewrapSandboxProviderTest",
            "--tests",
            "*AppSandboxProvidersTest",
        ],
        "gradle-apphost-sandbox-provider",
    )
    details: dict[str, Any] = {
        "mode": "restricted-process",
        "provider": "bubblewrap",
        "supportLevel": "enforced",
        "liveBubblewrapRequired": False,
        "hostBubblewrapProbe": {"enabled": False},
        "checks": checks,
        "contractTestsCommand": command_details(gradle_result, settings),
    }
    if gradle_result is not None and gradle_result.exit_code != 0:
        errors.append("platform-apphost sandbox provider tests failed")
    if gradle_result is None and settings.mode == "release-candidate":
        errors.append("platform-apphost sandbox provider tests were skipped")
    if errors:
        return EvidenceItem(
            "apphost.sandbox-provider",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "AppHost sandbox provider evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "apphost.sandbox-provider",
        "pass",
        True,
        "AppHost sandbox provider contract passed using deterministic offline evidence.",
        source,
        details,
    )

def read_source(path: Path) -> str:
    if path.is_file():
        return path.read_text(encoding="utf-8", errors="replace")
    return ""

def read_engine_source(workspace: Path, engine_name: str) -> str:
    engine_dir = workspace / "tools/release-certification/cryptad_certification/engines"
    return "\n".join(
        segment.read_text(encoding="utf-8", errors="replace")
        for segment in sorted(engine_dir.glob(f"{engine_name}*.py"))
    )

def java_source_without_comments(source: str) -> str:
    """Return Java source with line and block comments removed.

    Certification source checks often need to prove that serialized field names
    are safe. Redaction policy comments may legitimately mention tokens, paths,
    or other forbidden payloads, so callers should strip comments before checking
    Java identifiers or JSON keys.
    """
    result: list[str] = []
    index = 0
    in_string = False
    in_char = False
    escaped = False
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if in_string or in_char:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif in_string and char == '"':
                in_string = False
            elif in_char and char == "'":
                in_char = False
            index += 1
            continue
        if char == '"':
            in_string = True
            result.append(char)
            index += 1
            continue
        if char == "'":
            in_char = True
            result.append(char)
            index += 1
            continue
        if char == "/" and next_char == "/":
            index += 2
            while index < len(source) and source[index] not in "\r\n":
                index += 1
            result.append("\n")
            continue
        if char == "/" and next_char == "*":
            index += 2
            while index + 1 < len(source) and not (
                source[index] == "*" and source[index + 1] == "/"
            ):
                if source[index] in "\r\n":
                    result.append("\n")
                index += 1
            index = min(index + 2, len(source))
            continue
        result.append(char)
        index += 1
    return "".join(result)

def split_java_top_level_commas(source: str) -> list[str]:
    parts: list[str] = []
    start = 0
    angle_depth = 0
    paren_depth = 0
    bracket_depth = 0
    for index, char in enumerate(source):
        if char == "<":
            angle_depth += 1
        elif char == ">" and angle_depth > 0:
            angle_depth -= 1
        elif char == "(":
            paren_depth += 1
        elif char == ")" and paren_depth > 0:
            paren_depth -= 1
        elif char == "[":
            bracket_depth += 1
        elif char == "]" and bracket_depth > 0:
            bracket_depth -= 1
        elif char == "," and angle_depth == 0 and paren_depth == 0 and bracket_depth == 0:
            parts.append(source[start:index].strip())
            start = index + 1
    parts.append(source[start:].strip())
    return [part for part in parts if part]

def java_record_component_names(source: str, record_name: str) -> set[str]:
    source_without_comments = java_source_without_comments(source)
    match = re.search(
        rf"\brecord\s+{re.escape(record_name)}\s*\((?P<components>.*?)\)\s*\{{",
        source_without_comments,
        re.DOTALL,
    )
    if not match:
        return set()
    names: set[str] = set()
    for component in split_java_top_level_commas(match.group("components")):
        name_match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*$", component)
        if name_match:
            names.add(name_match.group(1))
    return names

def java_json_field_names(source: str) -> set[str]:
    source_without_comments = java_source_without_comments(source)
    return set(re.findall(r'\bjson\.put\(\s*"([^"]+)"', source_without_comments))

def app_service_bundle_public_fields_are_safe(bundle_source: str) -> bool:
    public_fields = java_record_component_names(bundle_source, "AppServiceGrantBundle")
    public_fields.update(java_json_field_names(bundle_source))
    forbidden_fragments = (
        "token",
        "path",
        "privateinserturi",
        "privatekey",
        "subjecturi",
        "requestbody",
        "rawbody",
        "providerstate",
        "processstate",
        "appdatabackup",
    )
    return bool(public_fields) and not any(
        fragment in field_name.lower()
        for field_name in public_fields
        for fragment in forbidden_fragments
    )

def source_contains_markup_fixture(source: str, fixture: str) -> bool:
    return fixture in source or fixture.replace('"', '\\"') in source

def public_beta_security_item(
    settings: Settings,
    evidence_id: str,
    pass_summary: str,
    checks: dict[str, bool],
    details: dict[str, Any],
) -> EvidenceItem:
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            evidence_id,
            root_consequence(settings, "fail"),
            True,
            f"{evidence_id} evidence is incomplete.",
            summary_source(settings),
            {"errors": errors, **details},
        )
    return EvidenceItem(evidence_id, "pass", True, pass_summary, summary_source(settings), details)

def public_beta_redaction_fuzz_checks(settings: Settings) -> dict[str, Any]:
    raw = {
        "auditEvent": PUBLIC_BETA_SECURITY_SENSITIVE_FIXTURES,
        "transparencyLog": {
            "recordCount": 2,
            "latestHash": "sha256:0123456789abcdef",
            "reviewerKeyId": "reviewer-local-public",
            "policyId": "crypta-app-review-v1",
            "rawSignatureValue": "MEUCIQD...",
            "localEvidencePath": "/home/alice/.crypta/reviews/evidence.json",
        },
        "webShellSummary": (
            "Authorization: Bearer host-or-app-secret\n"
            "raw fetched body: <script>alert(1)</script>\n"
            "raw trust statement body: signed-trust-document\n"
            "raw message body: private-social-body"
        ),
    }
    redacted = sanitize_value(raw, settings.workspace_root, "releaseEvidence")
    encoded = json.dumps(redacted, sort_keys=True)
    fixture_leaks = [
        value for value in PUBLIC_BETA_SECURITY_SENSITIVE_FIXTURES if value and value in encoded
    ]
    high_risk_leaks = [
        value
        for value in (
            "browser-session-secret",
            "form-secret",
            "host-or-app-secret",
            "PRIVATE-INSERT-URI",
            "BEGIN PRIVATE KEY",
            "BEGIN OPENSSH PRIVATE KEY",
            "pem-private-key-body",
            "truncated-pem-private-key-body",
            "END PRIVATE KEY",
            "private-document",
            "signed-trust-document",
            "private-social-body",
            "/home/alice/.crypta",
            r"C:\Users\Alice",
            "<script>alert(1)</script>",
            "MEUCIQD",
        )
        if value in encoded
    ]
    return {
        "redacted": redacted,
        "encoded": encoded,
        "fixtureLeaks": fixture_leaks,
        "highRiskLeaks": high_risk_leaks,
        "placeholdersPresent": "<redacted>" in encoded or "<redacted-uri>" in encoded,
        "publicMetadataRetained": "reviewer-local-public" in encoded
        and "sha256:0123456789abcdef" in encoded,
    }

def collect_public_beta_security_evidence(settings: Settings) -> list[EvidenceItem]:
    workspace = settings.workspace_root
    app_ui_headers = read_source(
        workspace
        / "platform-app-ui/src/main/java/network/crypta/platform/appui/AppUiSecurityHeaders.java"
    )
    app_ui_headers_test = read_source(
        workspace
        / "platform-app-ui/src/test/java/network/crypta/platform/appui/AppUiSecurityHeadersTest.java"
    )
    web_shell = read_source(
        workspace
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    )
    web_shell_test = read_source(
        workspace
        / "platform-web-shell/src/test/java/network/crypta/platform/webshell/WebShellResourcesTest.java"
    )
    content_policy = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/ContentFetchPolicy.java"
    )
    content_handler = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/ContentApiHandler.java"
    )
    content_tests = "\n".join(
        read_source(path)
        for path in sorted((workspace / "platform-api/src/test/java").rglob("*Content*.java"))
    )
    feed_app = read_source(workspace / "apps/feed-reader/src/staged/static/app.js")
    feed_tests = "\n".join(
        read_source(path)
        for path in sorted((workspace / "apps/feed-reader/src/test/java").rglob("*.java"))
    )
    social_app = read_source(workspace / "apps/social-inbox/src/staged/static/app.js")
    social_tests = "\n".join(
        read_source(path)
        for path in sorted((workspace / "apps/social-inbox/src/test/java").rglob("*.java"))
    )
    profile_app = read_source(workspace / "apps/profile-publisher/src/staged/static/app.js")
    profile_tests = "\n".join(
        read_source(path)
        for path in sorted((workspace / "apps/profile-publisher/src/test/java").rglob("*.java"))
    )
    trust_sources = "\n".join(
        read_source(path)
        for path in (
            workspace
            / "platform-trustgraph/src/main/java/network/crypta/platform/trustgraph/TrustStatementParser.java",
            workspace
            / "platform-trustgraph/src/main/java/network/crypta/platform/trustgraph/TrustStatementValidator.java",
            workspace
            / "platform-trustgraph/src/main/java/network/crypta/platform/trustgraph/TrustGraphStoreSanitizer.java",
            workspace
            / "platform-trustgraph/src/main/java/network/crypta/platform/trustgraph/TrustStatementPayload.java",
            workspace
            / "platform-api/src/main/java/network/crypta/platform/api/trust/TrustGraphApiHandler.java",
            workspace
            / "platform-api/src/main/java/network/crypta/platform/api/appvault/TrustStatementRequest.java",
        )
    )
    trust_tests = "\n".join(
        read_source(path)
        for path in (
            workspace
            / "platform-trustgraph/src/test/java/network/crypta/platform/trustgraph/TrustStatementParserTest.java",
            workspace
            / "platform-api/src/test/java/network/crypta/platform/api/TrustGraphApiRouterTest.java",
            workspace / "platform-api/src/test/java/network/crypta/platform/api/AppVaultApiRouterTest.java",
        )
    )
    apphost_source = read_source(
        workspace
        / "platform-apphost/src/main/java/network/crypta/platform/apphost/runtime/LocalProcessAppHost.java"
    )
    apphost_tests = read_source(
        workspace
        / "platform-apphost/src/test/java/network/crypta/platform/apphost/runtime/LocalProcessAppHostTest.java"
    )
    sandbox_sources = "\n".join(
        read_source(path)
        for path in sorted(
            (
                workspace
                / "platform-apphost/src/main/java/network/crypta/platform/apphost/sandbox"
            ).glob("*.java")
        )
    )
    sandbox_tests = "\n".join(
        read_source(path)
        for path in sorted(
            (
                workspace
                / "platform-apphost/src/test/java/network/crypta/platform/apphost/sandbox"
            ).glob("*.java")
        )
    )
    appreview_source = "\n".join(
        read_source(path)
        for path in sorted(
            (workspace / "platform-appcatalog/src/main/java").rglob("*Review*.java")
        )
    )
    appreview_tests = "\n".join(
        read_source(path)
        for path in sorted(
            (workspace / "platform-appcatalog/src/test/java").rglob("*Review*.java")
        )
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/SECURITY.md",
            "docs/app-owned-ui.md",
            "docs/app-ui-design-system.md",
            "docs/app-permissions-and-audit.md",
            "docs/feed-reader-reference-app.md",
            "docs/social-inbox-reference-app.md",
            "docs/trust-graph-preview.md",
            "docs/apphost-runtime-hardening.md",
            "docs/app-platform-beta-known-limitations.md",
            "docs/release-certification.md",
        )
    )
    redaction_checks = public_beta_redaction_fuzz_checks(settings)
    return [
        public_beta_security_item(
            settings,
            "public-beta-security.app-ui-csp",
            "Static app UI CSP and defensive header evidence passed.",
            {
                "defaultNone": "default-src " in app_ui_headers and "'none'" in app_ui_headers,
                "localScriptStyleConnect": all(
                    marker in app_ui_headers for marker in ("script-src", "style-src", "connect-src")
                ),
                "blockedDangerousDirectives": all(
                    marker in app_ui_headers
                    for marker in ("object-src", "base-uri", "worker-src", "frame-src", "manifest-src")
                ),
                "defensiveHeaders": all(
                    marker in app_ui_headers
                    for marker in (
                        "permissions-policy",
                        "cross-origin-resource-policy",
                        "nosniff",
                        "no-referrer",
                    )
                ),
                "safeOriginTests": all(
                    marker in app_ui_headers_test
                    for marker in ("admin.example", "0.0.0.0", "127.0.0.1.attacker.example", "user:pass@", "ftp://")
                ),
                "docsUpdated": "default-src 'none'" in docs_text
                and "CSP is a browser mitigation" in docs_text,
            },
            {"sources": ["platform-app-ui", "docs/app-owned-ui.md"]},
        ),
        public_beta_security_item(
            settings,
            "public-beta-security.app-origin-policy",
            "Web Shell app-origin launch policy evidence passed.",
            {
                "registeredLoopbackOrigin": "function registeredAppUiOrigin(app)" in web_shell
                and "127.0.0.1" in web_shell,
                "rejectsCredentials": "url.username" in web_shell and "url.password" in web_shell,
                "rejectsSearchHash": "url.search !== \"\"" in web_shell
                and "url.hash !== \"\"" in web_shell,
                "sameOriginFallbackOnly": "safeSameOriginAppUiHref" in web_shell and "/apps/" in web_shell,
                "probeCorsSafe": "credentials: \"omit\"" in web_shell and "mode: \"cors\"" in web_shell,
                "sourceTests": "assertAppUiOriginHardeningMarkersPresent" in web_shell_test,
            },
            {"sources": ["platform-web-shell"]},
        ),
        public_beta_security_item(
            settings,
            "public-beta-security.content-fetch-bounds",
            "Content fetch bound and URI-family evidence passed.",
            {
                "sharedPolicy": "class ContentFetchPolicy" in content_policy,
                "contentKeyFamiliesOnly": all(
                    marker in content_policy for marker in ("CHK@", "SSK@", "USK@", "KSK@", "crypta:")
                ),
                "rejectsExternalSources": all(
                    marker in content_tests
                    for marker in ("http://", "https://", "file://", "//example.invalid", "C:\\\\Users")
                ),
                "hardBounds": "HARD_APP_FETCH_MAX_BYTES" in content_policy
                and "HARD_APP_FETCH_TIMEOUT_MILLIS" in content_policy,
                "strictUtf8": "CodingErrorAction.REPORT" in content_handler
                and "unsupported_content_encoding" in content_handler,
                "redactedErrors": "content_fetch_failed" in content_handler and "SECRET" in content_tests,
            },
            {"sources": ["platform-api", "runtime-spi"]},
        ),
        public_beta_security_item(
            settings,
            "public-beta-security.feed-sanitization",
            "Feed Reader sanitization evidence passed.",
            {
                "textRendering": "textContent" in feed_app,
                "noHtmlInjection": "innerHTML" not in feed_app and "insertAdjacentHTML" not in feed_app,
                "activeMarkupNeutralized": all(
                    marker in feed_app for marker in ("srcdoc", "iframe", "base", "svg")
                ),
                "cryptaUriValidation": "normalizedCryptaContentUri" in feed_app,
                "adversarialFixtures": all(
                    source_contains_markup_fixture(feed_tests, marker)
                    for marker in PUBLIC_BETA_SECURITY_MARKUP_FIXTURES
                ),
            },
            {"sources": ["apps/feed-reader"]},
        ),
        public_beta_security_item(
            settings,
            "public-beta-security.social-inbox-sanitization",
            "Social Inbox sanitization evidence passed.",
            {
                "textRendering": "textContent" in social_app,
                "noHtmlInjection": "innerHTML" not in social_app and "insertAdjacentHTML" not in social_app,
                "cryptaUriValidation": "normalizedCryptaContentUri" in social_app,
                "boundedFields": all(
                    marker in social_app
                    for marker in (
                        "maxDraftBodyLength",
                        "maxImportedSubjectLength",
                        "maxAuthorLabelLength",
                        "maxImportedMessages",
                    )
                )
                and ("maxImportedBodyPreviewLength" in social_app),
                "adversarialFixtures": all(
                    source_contains_markup_fixture(social_tests, marker)
                    for marker in PUBLIC_BETA_SECURITY_MARKUP_FIXTURES
                ),
            },
            {"sources": ["apps/social-inbox"]},
        ),
        public_beta_security_item(
            settings,
            "public-beta-security.profile-sanitization",
            "Profile Publisher sanitization evidence passed.",
            {
                "textRendering": "textContent" in profile_app,
                "noHtmlInjection": "innerHTML" not in profile_app and "insertAdjacentHTML" not in profile_app,
                "activeMarkupNeutralized": all(
                    marker in profile_app for marker in ("srcdoc", "iframe", "base", "svg")
                ),
                "bounds": all(
                    marker in profile_app
                    for marker in (
                        "maxProfileTextLength",
                        "maxProfileBioLength",
                        "maxContentUriLength",
                        "maxRecentActions",
                    )
                ),
                "websiteTextPreserved": "optionalProfileWebsite" in profile_app
                and "website.length > maxContentUriLength" in profile_app
                and "website: optionalProfileWebsite" in profile_app,
                "privateMaterialExcluded": all(
                    marker not in profile_app for marker in ("privateKey", "seedPhrase", "rawSignature")
                ),
                "sourceTests": "textContent" in profile_tests and "innerHTML" in profile_tests,
            },
            {"sources": ["apps/profile-publisher"]},
        ),
        public_beta_security_item(
            settings,
            "public-beta-security.trust-statement-hardening",
            "Trust statement parser, signing, and audit hardening evidence passed.",
            {
                "byteCap": "MAX_DOCUMENT_BYTES" in trust_sources,
                "unknownFields": "rejectUnknown" in trust_sources,
                "isoControlRejected": "Character.isISOControl" in trust_sources,
                "rangeChecks": "requireScore" in trust_sources and "requireConfidence" in trust_sources,
                "expiresAfterIssued": "expiresAt.isAfter(issuedAt)" in trust_sources,
                "unsupportedSigningParameters": "SUPPORTED_PARAMETERS" in trust_sources,
                "redactedRejectedAudit": "redactedRejectedUriSummary" in trust_sources
                and "uri:redacted" in trust_tests,
                "maliciousTests": all(
                    marker in trust_tests for marker in ("\\u0000", "\\u0085", "50.5", "token=secret")
                ),
            },
            {"sources": ["platform-trustgraph", "platform-api"]},
        ),
        public_beta_security_item(
            settings,
            "public-beta-security.apphost-env-minimization",
            "AppHost launch environment minimization evidence passed.",
            {
                "clearsEnvironment": "environment.clear()" in apphost_source,
                "documentedAppVariables": all(
                    marker in apphost_source
                    for marker in (
                        "CRYPTAD_APP_ID",
                        "CRYPTAD_APP_TOKEN",
                        "CRYPTAD_APP_PERMISSIONS",
                        "CRYPTAD_APP_UI_MODE",
                    )
                ),
                "deterministicUnixPath": "safeUnixPath" in apphost_source
                and "BASE_UNIX_PATH_ENTRIES" in apphost_source,
                "secretEnvTests": all(
                    marker in apphost_tests
                    for marker in (
                        "JAVA_TOOL_OPTIONS",
                        "LD_PRELOAD",
                        "AWS_SECRET_ACCESS_KEY",
                        "OPENAI_API_KEY",
                        "SSH_AUTH_SOCK",
                        "PRIVATE_KEY",
                        "CRYPTAD_APPHOST_BWRAP",
                    )
                ),
                "docsBoundary": "Public-beta certification treats the environment allow-list"
                in docs_text,
            },
            {"sources": ["platform-apphost"]},
        ),
        public_beta_security_item(
            settings,
            "public-beta-security.sandbox-host-checks",
            "Sandbox provider host-check and fail-closed evidence passed.",
            {
                "pathFreeAvailability": "path-free" in sandbox_sources.lower(),
                "failClosedRequired": "RequiredRestrictedProcess" in sandbox_tests
                and "expectFailClosed" in sandbox_tests,
                "preflightFailure": "PreflightFails" in sandbox_tests,
                "commandContainmentFlags": all(
                    marker in sandbox_tests
                    for marker in (
                        "--die-with-parent",
                        "--new-session",
                        "--unshare-pid",
                        "--unshare-ipc",
                        "--ro-bind",
                        "--bind",
                    )
                ),
                "tokenNotInCommand": "CRYPTAD_APP_TOKEN" in sandbox_tests
                and "assertFalse(commandText.contains" in sandbox_tests,
                "noOverclaim": "network isolation" in docs_text
                and "does not enforce CPU, memory, or network isolation" in docs_text,
            },
            {"sources": ["platform-apphost/src/main/java/network/crypta/platform/apphost/sandbox"]},
        ),
        public_beta_security_item(
            settings,
            "public-beta-security.audit-redaction-fuzz",
            "Audit and release evidence redaction fuzz fixtures passed.",
            {
                "noFixtureLeaks": not redaction_checks["fixtureLeaks"],
                "noHighRiskLeaks": not redaction_checks["highRiskLeaks"],
                "placeholdersPresent": bool(redaction_checks["placeholdersPresent"]),
                "publicMetadataRetained": bool(redaction_checks["publicMetadataRetained"]),
                "docsBoundary": "Public-beta release evidence is redacted evidence" in docs_text,
            },
            {"redaction": {k: v for k, v in redaction_checks.items() if k != "encoded"}},
        ),
        public_beta_security_item(
            settings,
            "public-beta-security.transparency-log-privacy",
            "App-review governance and transparency-log privacy evidence passed.",
            {
                "sourcePresent": "Transparency" in appreview_source,
                "privacyTests": "raw public key" in appreview_tests.lower()
                or "rawPublicKey" in appreview_tests,
                "redactedSummaries": all(
                    marker in docs_text
                    for marker in (
                        "record counts",
                        "latest hashes",
                        "raw receipt signatures",
                        "catalog scratch paths",
                    )
                ),
                "localLogScoped": "local transparency log" in docs_text
                and "not a global public log" in docs_text,
                "noKnownPrivateFixtures": not redaction_checks["highRiskLeaks"],
            },
            {"sources": ["platform-appcatalog", "docs/SECURITY.md", "docs/release-certification.md"]},
        ),
    ]

def ecosystem_security_item(
    settings: Settings,
    evidence_id: str,
    pass_summary: str,
    checks: dict[str, bool],
    details: dict[str, Any],
) -> EvidenceItem:
    errors = [key for key, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            evidence_id,
            root_consequence(settings, "fail"),
            True,
            f"{evidence_id} evidence is incomplete.",
            summary_source(settings),
            {"errors": errors, **details},
        )
    return EvidenceItem(evidence_id, "pass", True, pass_summary, summary_source(settings), details)

def ecosystem_security_redaction_checks(settings: Settings) -> dict[str, Any]:
    raw = {
        "advisoryId": "CRYPTA-2026-0001",
        "appId": "social-inbox",
        "version": "0.1.0",
        "receiptFingerprintSha256": "a" * 64,
        "reviewerKeyId": "crypta-first-party-review-2026q2",
        "rawSignatureValue": "MEUCIQD-secret-signature",
        "rawPublicKeyBytes": "public-key-der-secret",
        "rawReviewReceipt": "review.receipt.signature.value.base64=MEUCIQD",
        "reviewReceiptContent": "raw receipt content",
        "privateInsertUri": "USK@PRIVATE-INSERT-URI",
        "catalogScratchPath": "/home/alice/.crypta/catalog-scratch/current",
        "stagedBundlePath": "/home/alice/.crypta/apps/social-inbox/staged/bundle.zip",
        "rawRequestBody": "{\"token\":\"secret\"}",
        "rawFetchedBody": "<script>alert(1)</script>",
        "appDataBackupPayload": "base64-private-backup",
    }
    redacted = sanitize_value(raw, settings.workspace_root, "ecosystemSecurity")
    encoded = json.dumps(redacted, sort_keys=True)
    leaks = [
        value
        for value in (
            "MEUCIQD-secret-signature",
            "public-key-der-secret",
            "review.receipt.signature.value.base64",
            "raw receipt content",
            "PRIVATE-INSERT-URI",
            "/home/alice/.crypta",
            "bundle.zip",
            "secret",
            "<script>alert(1)</script>",
            "base64-private-backup",
        )
        if value in encoded
    ]
    return {
        "redacted": redacted,
        "encoded": encoded,
        "leaks": leaks,
        "publicMetadataRetained": all(
            value in encoded
            for value in (
                "CRYPTA-2026-0001",
                "social-inbox",
                "0.1.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "crypta-first-party-review-2026q2",
            )
        ),
    }

def collect_ecosystem_security_advisory_revocation_evidence(
    settings: Settings,
) -> list[EvidenceItem]:
    workspace = settings.workspace_root
    appcatalog_dir = workspace / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog"
    appcatalog_tests = workspace / "platform-appcatalog/src/test/java/network/crypta/platform/appcatalog"
    api_catalogs = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandler.java"
    )
    api_updates = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateService.java"
    )
    api_update_candidate = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateCandidate.java"
    )
    api_update_handler = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdatesApiHandler.java"
    )
    api_update_tests = (
        workspace / "platform-api/src/test/java/network/crypta/platform/api/appupdates/AppUpdateServiceTest.java"
    )
    api_catalog_tests = (
        workspace
        / "platform-api/src/test/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandlerTest.java"
    )
    devtools = workspace / "platform-devtools/src/main/java/network/crypta/platform/devtools/CryptaAppCli.java"
    shell = workspace / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    shell_tests = workspace / "platform-web-shell/src/test/java/network/crypta/platform/webshell/WebShellResourcesTest.java"
    docs = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/ecosystem-security-advisories.md",
            "docs/app-catalogs.md",
            "docs/production-first-party-catalog-channels.md",
            "docs/app-review-governance.md",
            "docs/app-update-lifecycle.md",
            "docs/SECURITY.md",
            "docs/release-certification.md",
            "tools/release-certification/README.md",
        )
    )
    docs_lower = docs.lower()
    catalog_text = read_source(appcatalog_dir / "AppCatalog.java")
    parser_text = read_source(appcatalog_dir / "AppCatalogParser.java")
    writer_text = read_source(appcatalog_dir / "AppCatalogWriter.java")
    policy_text = read_source(appcatalog_dir / "AppCatalogSecurityPolicy.java")
    decision_text = read_source(appcatalog_dir / "AppCatalogSecurityDecision.java")
    advisory_text = read_source(appcatalog_dir / "AppCatalogSecurityAdvisoryRecord.java")
    denylist_text = read_source(appcatalog_dir / "AppCatalogVersionDenylistEntry.java")
    receipt_text = read_source(appcatalog_dir / "AppReviewReceipt.java")
    keys_text = read_source(appcatalog_dir / "TrustedReviewerKeys.java")
    verifier_text = read_source(appcatalog_dir / "AppReviewReceiptVerifier.java")
    status_text = read_source(appcatalog_dir / "AppReviewTrustStatus.java")
    review_policy_text = read_source(appcatalog_dir / "AppReviewPolicy.java")
    registry_summary_text = read_source(appcatalog_dir / "TrustedReviewerRegistrySummary.java")
    review_tests = read_source(appcatalog_tests / "AppReviewReceiptTest.java")
    catalog_tests_text = "\n".join(
        read_source(path) for path in sorted(appcatalog_tests.glob("*.java"))
    )
    catalog_api_text = read_source(api_catalogs)
    update_text = read_source(api_updates)
    candidate_text = read_source(api_update_candidate)
    update_handler_text = read_source(api_update_handler)
    update_tests = read_source(api_update_tests)
    catalog_api_tests_text = read_source(api_catalog_tests)
    devtools_text = read_source(devtools)
    shell_text = read_source(shell)
    shell_test_text = read_source(shell_tests)
    redaction_checks = ecosystem_security_redaction_checks(settings)
    common_sources = {
        "catalog": display_path(appcatalog_dir, workspace),
        "catalogTests": display_path(appcatalog_tests, workspace),
        "catalogApi": display_path(api_catalogs, workspace),
        "updateService": display_path(api_updates, workspace),
        "webShell": display_path(shell, workspace),
        "docs": "docs/ecosystem-security-advisories.md",
    }
    return [
        ecosystem_security_item(
            settings,
            "catalog.security-advisories",
            "Catalog v4 security advisory records passed deterministic evidence checks.",
            {
                "schemaVersionFour": "VERSION_SECURITY_POLICY = 4" in catalog_text,
                "catalogLevelRecords": (
                    "record AppCatalogSecurityAdvisoryRecord" in advisory_text
                    and "AppCatalogSecuritySeverity" in advisory_text
                    and "AppCatalogSecurityStatus" in advisory_text
                    and "AppCatalogSecurityAction" in advisory_text
                ),
                "parserAcceptsV4Fields": (
                    "catalog.securityAdvisories" in parser_text
                    and "catalog.securityAdvisory." in parser_text
                    and "parseCatalogSecurityPolicy" in parser_text
                ),
                "olderVersionsFailClosed": (
                    "version < AppCatalog.VERSION_SECURITY_POLICY" in parser_text
                    and "version < VERSION_SECURITY_POLICY" in catalog_text
                ),
                "boundedStrictValidation": (
                    "duplicate catalog security advisory id" in policy_text
                    and "safeUninstallGuidance" in advisory_text
                    and "single-line" in advisory_text.lower()
                    and "Instant.parse" in parser_text
                ),
                "writerDeterministic": (
                    "appendSecurityPolicy" in writer_text
                    and "catalog.securityAdvisories" in writer_text
                    and "catalog.securityAdvisory." in writer_text
                ),
                "testsCoverStrictSchema": all(
                    marker in catalog_tests_text
                    for marker in (
                        "parse_whenCatalogHasSecurityPolicy_expectDecisionDenylisted",
                        "parse_whenVersionThreeCatalogDeclaresSecurityPolicy_expectInvalidCatalogEntry",
                        "parse_whenSecurityPolicyHasDuplicateAdvisoryId_expectInvalidCatalogEntry",
                        "serialize_whenCatalogHasSecurityPolicy_expectVersionFourDeterministicOutput",
                    )
                ),
            },
            {"sources": common_sources},
        ),
        ecosystem_security_item(
            settings,
            "catalog.version-denylist",
            "Exact app-version denylist records passed deterministic evidence checks.",
            {
                "denylistModel": (
                    "record AppCatalogVersionDenylistEntry" in denylist_text
                    and "matches(String candidateAppId, String candidateVersion)" in denylist_text
                ),
                "denylistParserWriter": (
                    "catalog.securityDenylist" in parser_text
                    and "catalog.securityDenylist" in writer_text
                    and "denylist entry references unknown advisory" in policy_text
                ),
                "denylistDecision": (
                    "decisionForInstalledVersion" in policy_text
                    and "AppCatalogSecurityDecisionStatus.DENYLISTED" in policy_text
                    and "DENYLIST" in policy_text
                ),
                "redactedDecisionShape": all(
                    marker in decision_text
                    for marker in (
                        "blocksInstall",
                        "blocksUpdate",
                        "blocksAutomaticApply",
                        "safeUninstallGuidance",
                        "replacementAppId",
                    )
                ),
                "installedVersionVisibility": (
                    "installedSecurityDecision" in catalog_api_text
                    and "installedSecurityDecision" in update_text
                    and "installedSecurityDecisionForCatalogApp" in shell_text
                ),
                "testsCoverUnknownAdvisory": (
                    "parse_whenSecurityPolicyDenylistReferencesUnknownAdvisory_expectInvalidCatalogEntry"
                    in catalog_tests_text
                ),
            },
            {"sources": common_sources},
        ),
        ecosystem_security_item(
            settings,
            "app-review.receipt-revocation",
            "Review receipt revocation evidence passed deterministic source checks.",
            {
                "stableFingerprint": (
                    "fingerprintSha256()" in receipt_text
                    and "payloadSha256()" in receipt_text
                    and "canonicalPayloadBytes" in receipt_text
                ),
                "registryV3Revocations": (
                    "version >= 3 ? readReceiptRevocations(properties) : List.of()" in keys_text
                    and "review.revocations" in keys_text
                    and "receiptFingerprintSha256" in keys_text
                ),
                "verifierFailsClosed": (
                    "AppReviewTrustStatus.REVOKED_RECEIPT" in verifier_text
                    and "findReceiptRevocation(receipt)" in verifier_text
                    and "false" in verifier_text
                ),
                "trustStatusAndPolicy": (
                    'REVOKED_RECEIPT("revoked_receipt")' in status_text
                    and "REVOKED_RECEIPT" in review_policy_text
                ),
                "redactedSummaryCount": "receiptRevocationCount" in registry_summary_text,
                "testsCoverRevocation": all(
                    marker in review_tests
                    for marker in (
                        "fingerprintSha256_whenReceiptRoundTrips_expectStableFingerprint",
                        "evaluate_whenReceiptFingerprintIsRevoked_expectRevokedReceiptNotTrusted",
                        "trustedReviewerKeysLoad_whenV3ReceiptRevocationConfigured_expectParsesRevocation",
                        "trustedReviewerKeysLoad_whenV2RegistryContainsReceiptRevocation_expectInvalidCatalogEntry",
                    )
                ),
            },
            {"sources": common_sources},
        ),
        ecosystem_security_item(
            settings,
            "app-review.reviewer-key-compromise-flow",
            "Reviewer-key compromise flow evidence passed deterministic source checks.",
            {
                "revokedReviewerStatus": (
                    "REVOKED_REVIEWER" in verifier_text and "REVOKED_REVIEWER" in review_policy_text
                ),
                "lifecycleMetadata": (
                    "revoked.at" in keys_text
                    and "revocation.reason" in keys_text
                    and "revocation metadata requires status=revoked" in read_source(
                        appcatalog_dir / "TrustedReviewerKeyLifecycle.java"
                    )
                ),
                "governanceUiWarns": (
                    "Review governance" in shell_text
                    and "revoked" in shell_text.lower()
                    and "reviewerKeyStatus" in shell_text
                ),
                "cliInspectCounts": (
                    "Receipt revocations:" in devtools_text
                    and "receiptRevocations=" in devtools_text
                    and "review fingerprint" in devtools_text.lower()
                ),
                "docsCompromiseProcess": (
                    "compromise" in docs_lower
                    and "status=revoked" in docs
                    and "revoked_reviewer" in docs
                ),
            },
            {"sources": common_sources | {"devtools": display_path(devtools, workspace)}},
        ),
        ecosystem_security_item(
            settings,
            "app-update.security-denylist-gates",
            "Install, update, stage, apply, and automatic-policy security gates passed.",
            {
                "catalogInstallUpdateGates": (
                    "PARAM_SECURITY_ACKNOWLEDGED" in catalog_api_text
                    and "ERROR_APP_SECURITY_DENYLISTED" in catalog_api_text
                    and "requireSecurityGate" in catalog_api_text
                    and "securityAcknowledgementStillApplies" in catalog_api_text
                ),
                "updateCandidateCarriesDecision": (
                    '"securityDecision"' in candidate_text
                    and "blocksAutomaticApply" in candidate_text
                    and "eligibleForAutomaticApply" in candidate_text
                ),
                "stageAndApplyRevalidation": (
                    "PARAM_SECURITY_ACKNOWLEDGED" in update_handler_text
                    and "requireCurrentStagedSecurityDecision" in update_text
                    and "targetSecurityDecision(staged.candidate().catalogId(), staged.entry())"
                    in update_text
                    and "targetSecurityDecision(plan.catalogId(), entry).toJsonValue()"
                    in update_text
                    and "AppCatalogSecurityDecision.combine" in update_text
                    and "installedSecurityDecision(entry.appId(), entry.version())" in update_text
                    and "requireSecurityGate(" in update_text
                    and "ERROR_APP_SECURITY_DENYLISTED" in update_text
                ),
                "automationSkip": (
                    "securityGateRequiresOperator" in update_text
                    and "automaticSecurityGateFailureCode" in update_text
                    and "security_denylist_blocked" in update_text
                ),
                "ackDoesNotBypassBlock": (
                    "stage_whenSecurityDecisionIsDenylisted_expectStableSecurityError" in update_tests
                    and "install_whenCatalogSecurityDecisionIsDenylisted_expectStableSecurityError"
                    in catalog_api_tests_text
                ),
                "warningRequiresAck": (
                    "stage_whenSecurityWarningIsNotAcknowledged_expectStableSecurityAckError"
                    in update_tests
                    and "install_whenCatalogSecurityDecisionWarnsWithoutAcknowledgement_expectSecurityAckError"
                    in catalog_api_tests_text
                ),
            },
            {"sources": common_sources | {"candidate": display_path(api_update_candidate, workspace)}},
        ),
        ecosystem_security_item(
            settings,
            "web-shell.security-advisory-trust-warnings",
            "Web Shell security advisory and trust-warning evidence passed.",
            {
                "catalogWarningUi": (
                    "securityDecisionNoticeNode" in shell_text
                    and "catalogSecurityDetailsNode" in shell_text
                    and "Safe uninstall guidance" in shell_text
                ),
                "denylistedActionsHidden": (
                    "securityDecisionActionReason" in shell_text
                    and "Installed version vulnerable" in shell_text
                    and "app-card-actions" in shell_text
                ),
                "warningAcknowledgement": (
                    "appendSecurityAcknowledgement" in shell_text
                    and 'input.name = "securityAcknowledged"' in shell_text
                    and "security-acknowledgement" in shell_text
                ),
                "safeDomMarkers": (
                    "definitionList" in shell_text
                    and "text(" in shell_text
                    and "safeUninstallGuidance" in shell_text
                ),
                "testsCoverUiMarkers": (
                    "function appendSecurityAcknowledgement(form, securityDecision, action)"
                    in shell_test_text
                    and "securityAcknowledged" in shell_test_text
                ),
            },
            {"sources": common_sources | {"webShellTests": display_path(shell_tests, workspace)}},
        ),
        ecosystem_security_item(
            settings,
            "ecosystem-security.advisory-revocation-redaction",
            "Ecosystem security advisory and revocation redaction evidence passed.",
            {
                "noForbiddenFixtureLeaks": not redaction_checks["leaks"],
                "publicMetadataRetained": bool(redaction_checks["publicMetadataRetained"]),
                "docsDescribeRedaction": all(
                    fragment in docs_lower
                    for fragment in (
                        "raw signatures",
                        "raw public keys",
                        "private insert uris",
                        "local filesystem paths",
                    )
                ),
                "releaseDocsListEvidence": all(
                    evidence_id in docs for evidence_id in ECOSYSTEM_SECURITY_EVIDENCE_IDS
                ),
            },
            {
                "redaction": {k: v for k, v in redaction_checks.items() if k != "encoded"},
                "sources": common_sources,
            },
        ),
    ]

def production_security_redaction_findings(text: str, workspace: Path) -> list[str]:
    findings: list[str] = []
    if scrub_text(text, workspace) != text:
        findings.append("credential-or-path marker")
    if PRODUCTION_SECURITY_AUTH_SCHEME_RE.search(text):
        findings.append("authorization scheme marker")
    if PRODUCTION_SECURITY_RAW_APP_DATA_RE.search(text):
        findings.append("raw app data marker")
    if PRODUCTION_SECURITY_RAW_FETCHED_CONTENT_RE.search(text):
        findings.append("raw fetched content marker")
    return findings

def production_security_should_redact_json_key(key_hint: str, value: Any | None = None) -> bool:
    normalized = normalize_key_name(key_hint)
    if not normalized:
        return False
    if "rawappdata" in normalized:
        return not (
            isinstance(value, bool)
            and normalized in PRODUCTION_SECURITY_SAFE_RAW_APP_DATA_BOOLEAN_METADATA_KEYS
        )
    sensitive = (
        normalized in PRODUCTION_SECURITY_SENSITIVE_JSON_KEY_NAMES
        or any(fragment in normalized for fragment in PRODUCTION_SECURITY_SENSITIVE_JSON_KEY_FRAGMENTS)
        or any(normalized.endswith(suffix) for suffix in PRODUCTION_SECURITY_SENSITIVE_JSON_KEY_SUFFIXES)
    )
    if not sensitive:
        return False
    return not (
        isinstance(value, bool)
        and normalized.endswith(PRODUCTION_SECURITY_SAFE_BOOLEAN_METADATA_SUFFIXES)
    )

def sensitive_json_key_findings(value: Any) -> list[str]:
    findings: list[str] = []

    def visit(current: Any) -> None:
        if isinstance(current, dict):
            for key, child in current.items():
                if production_security_should_redact_json_key(str(key), child):
                    findings.append("sensitive JSON key marker")
                visit(child)
        elif isinstance(current, (list, tuple)):
            for child in current:
                visit(child)

    visit(value)
    return list(dict.fromkeys(findings))

def json_string_values(value: Any) -> list[str]:
    values: list[str] = []

    def visit(current: Any) -> None:
        if isinstance(current, str):
            values.append(current)
        elif isinstance(current, dict):
            for child in current.values():
                visit(child)
        elif isinstance(current, (list, tuple)):
            for child in current:
                visit(child)

    visit(value)
    return values

def collect_production_security_response_runbook_evidence(settings: Settings) -> EvidenceItem:
    workspace = settings.workspace_root
    runbook_path = workspace / "docs/production-security-response-runbook.md"
    model_path = workspace / "tools/release-certification/production-security-response-runbook.json"
    template_path = workspace / "docs/templates/security-release-notes.md"
    verifier_path = workspace / "tools/release-certification/certify.py"
    verifier_source_path = (
        workspace
        / "tools/release-certification/cryptad_certification/engines/security_response_runbook_impl.py"
    )
    status_path = (
        workspace
        / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog/AppCatalogSecurityStatus.java"
    )
    catalog_tests_path = (
        workspace
        / "platform-appcatalog/src/test/java/network/crypta/platform/appcatalog/AppCatalogParserTest.java"
    )
    catalog_api_path = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandler.java"
    )
    dashboard_path = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/operator/OperatorBetaDashboardService.java"
    )
    support_redactor_path = (
        workspace / "platform-api/src/main/java/network/crypta/platform/api/operator/OperatorSupportRedactor.java"
    )
    support_redactor_tests_path = (
        workspace
        / "platform-api/src/test/java/network/crypta/platform/api/operator/OperatorSupportRedactorTest.java"
    )
    shell_path = (
        workspace
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    )
    shell_tests_path = (
        workspace
        / "platform-web-shell/src/test/java/network/crypta/platform/webshell/WebShellResourcesTest.java"
    )
    required_docs = (
        "docs/SECURITY.md",
        "docs/ecosystem-security-advisories.md",
        "docs/app-catalogs.md",
        "docs/app-review-governance.md",
        "docs/operator-rc-recovery-and-support-workflow.md",
        "docs/production-beta-release-pipeline.md",
        "docs/release-certification.md",
        "tools/release-certification/README.md",
        "docs/cryptad-release-workflow-and-runbook.md",
    )
    runbook_text = read_source(runbook_path)
    template_text = read_source(template_path)
    verifier_text = read_source(verifier_source_path)
    status_text = read_source(status_path)
    catalog_tests_text = "\n".join(
        read_source(path) for path in sorted(catalog_tests_path.parent.glob("*.java"))
    )
    catalog_api_text = read_source(catalog_api_path)
    dashboard_text = read_source(dashboard_path)
    support_redactor_text = read_source(support_redactor_path)
    support_redactor_tests = read_source(support_redactor_tests_path)
    shell_text = read_source(shell_path)
    shell_tests_text = read_source(shell_tests_path)
    docs_text = "\n".join(read_source(workspace / path) for path in required_docs)
    model_text = read_source(model_path)
    model_is_object = False
    try:
        model = json.loads(model_text)
        model_is_object = isinstance(model, dict)
    except json.JSONDecodeError:
        model = {}
    drills = model.get("drills") if model_is_object else None
    seen_drill_ids: set[str] = set()
    duplicate_drill_ids: set[str] = set()
    drill_by_id = {}
    for drill in drills or []:
        if not isinstance(drill, dict) or not isinstance(drill.get("id"), str):
            continue
        drill_id = drill["id"]
        if drill_id in seen_drill_ids:
            duplicate_drill_ids.add(drill_id)
        seen_drill_ids.add(drill_id)
        drill_by_id[drill_id] = drill
    drill_ids = sorted(drill_by_id)
    duplicate_drill_ids_sorted = sorted(duplicate_drill_ids)
    required_drills_present = all(
        drill_id in drill_by_id for drill_id in PRODUCTION_SECURITY_REQUIRED_DRILLS
    )
    required_fields_present = all(
        all(field in drill_by_id.get(drill_id, {}) for field in PRODUCTION_SECURITY_REQUIRED_DRILL_FIELDS)
        for drill_id in PRODUCTION_SECURITY_REQUIRED_DRILLS
    )
    array_fields_bounded = all(
        isinstance(drill_by_id.get(drill_id, {}).get(field), list)
        and 0 < len(drill_by_id[drill_id][field]) <= 6
        and all(isinstance(item, str) and 0 < len(item) <= 160 for item in drill_by_id[drill_id][field])
        for drill_id in PRODUCTION_SECURITY_REQUIRED_DRILLS
        for field in PRODUCTION_SECURITY_ARRAY_DRILL_FIELDS
    )
    scalar_fields_bounded = all(
        isinstance(drill_by_id.get(drill_id, {}).get(field), str)
        and 0 < len(drill_by_id[drill_id][field]) <= 160
        for drill_id in PRODUCTION_SECURITY_REQUIRED_DRILLS
        for field in PRODUCTION_SECURITY_SCALAR_DRILL_FIELDS
    )
    combined_sensitive_text = "\n".join(
        (
            runbook_text,
            template_text,
            "\n".join(json_string_values(model)) if model_is_object else model_text,
        )
    )
    runbook_lower = runbook_text.lower()
    production_security_findings = production_security_redaction_findings(
        combined_sensitive_text,
        workspace,
    )
    if model_is_object:
        production_security_findings.extend(sensitive_json_key_findings(model))
        production_security_findings = list(dict.fromkeys(production_security_findings))
    production_security_redaction_clean = not production_security_findings
    checks = {
        "runbookDocExists": runbook_path.is_file(),
        "modelExists": model_path.is_file(),
        "templateExists": template_path.is_file(),
        "verifierScriptExists": verifier_path.is_file(),
        "requiredIncidentTypesDocumented": all(
            marker in runbook_text
            for marker in (
                "Vulnerable app version",
                "Malicious or compromised app version",
                "App signing key compromise",
                "Reviewer key compromise",
                "Review receipt revocation",
                "Catalog signing key compromise or rotation",
                "Malicious catalog entry or catalog metadata compromise",
                "Emergency replacement app publication",
                "Safe uninstall/update guidance",
                "Support bundle intake and redaction handling",
            )
        ),
        "runbookModelValid": (
            model_is_object
            and model.get("schemaVersion") == 1
            and model.get("kind") == "cryptad-production-security-response-runbook"
            and required_drills_present
            and required_fields_present
            and array_fields_bounded
            and scalar_fields_bounded
            and not duplicate_drill_ids_sorted
        ),
        "advisoryLifecycleTestable": all(
            marker in status_text
            for marker in ("DRAFT", "DETECTED", "PUBLISHED", "SUPERSEDED", "RETRACTED", "enforcesAdvisoryAction")
        )
        and all(
            marker in catalog_tests_text
            for marker in (
                "parse_whenSecurityAdvisoryLifecycleIsPublished_expectEntryAdvisoryEnforced",
                "parse_whenSecurityAdvisoryLifecycleIsNonEnforcing_expectEntryAdvisoryNotApplied",
            )
        ),
        "reviewerKeyCompromiseDrill": "reviewer-key-compromise" in drill_by_id
        and "revoked reviewer" in runbook_text.lower(),
        "catalogKeyRotationDrill": "catalog-signing-key-rotation" in drill_by_id
        and all(
            marker in runbook_lower
            for marker in ("unknown", "untrusted", "compromised")
        )
        and ("catalog key" in runbook_lower or "catalog signing key" in runbook_lower),
        "appSigningKeyCompromiseDrill": "app-signing-key-compromise" in drill_by_id
        and "App signing key compromise" in runbook_text,
        "emergencyCatalogUpdateDrill": "emergency-replacement-app" in drill_by_id
        and "Emergency catalog update workflow" in runbook_text,
        "supportRedactionDrill": "support-bundle-intake-redaction" in drill_by_id
        and "redact_whenSecurityIncidentArtifactContainsIntakeSecrets" in support_redactor_tests
        and all(
            marker in support_redactor_text
            for marker in ("authorizationheader", "cisecretvalue", "rawappdata")
        ),
        "releaseNotesTemplate": all(
            marker in template_text
            for marker in (
                "Advisory id",
                "Affected apps and versions",
                "Severity",
                "Containment",
                "Safe uninstall guidance",
                "Support bundle guidance",
                "Redaction note",
                "Credits",
            )
        ),
        "toolingCommands": all(
            marker in verifier_text
            for marker in (
                "drill_create",
                "drill_verify",
                "advisory_template",
                "verify_runbook",
                "cryptad-security-response-drill",
            )
        ),
        "operatorApiSummary": "securityResponseSummary()" in catalog_api_text
        and '"securityResponse"' in dashboard_text,
        "webShellSummary": all(
            marker in shell_text
            for marker in (
                "renderSecurityResponseSummary",
                "Production security response",
                "Denylisted app versions",
                "Support handling",
            )
        )
        and "function renderSecurityResponseSummary(response)" in shell_tests_text,
        "docsCrossLinked": all("production-security-response-runbook.md" in read_source(workspace / path) for path in required_docs),
        "sensitiveMarkersAbsent": production_security_redaction_clean,
    }
    errors = [name for name, passed in checks.items() if not passed]
    details = {
        "checks": checks,
        "drillIds": drill_ids,
        "duplicateDrillIds": duplicate_drill_ids_sorted,
        "sources": {
            "runbook": display_path(runbook_path, workspace),
            "model": display_path(model_path, workspace),
            "template": display_path(template_path, workspace),
            "verifier": display_path(verifier_path, workspace),
            "operatorApi": display_path(catalog_api_path, workspace),
            "webShell": display_path(shell_path, workspace),
            "supportRedactionTests": display_path(support_redactor_tests_path, workspace),
        },
    }
    if production_security_findings:
        details["redactionFindings"] = production_security_findings
    if errors:
        return EvidenceItem(
            "production-security.response-runbook",
            root_consequence(settings, "fail"),
            True,
            "Production security response runbook evidence is incomplete.",
            summary_source(settings),
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "production-security.response-runbook",
        "pass",
        True,
        "Production security response runbook evidence passed deterministic checks.",
        summary_source(settings),
        details,
    )

def collect_user_consent_flow_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    consent_dir = workspace / "platform-api/src/main/java/network/crypta/platform/api/consent"
    consent_text = "\n".join(read_source(path) for path in sorted(consent_dir.glob("*.java")))
    router_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiRouter.java"
    )
    app_routes_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiAppRoutes.java"
    )
    contract_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java"
    )
    toadlet_text = read_source(
        workspace / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/PlatformApiToadlet.java"
    )
    service_routes_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiAppServiceRoutes.java"
    )
    update_candidate_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateCandidate.java"
    )
    update_service_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateService.java"
    )
    web_shell_text = read_source(
        workspace
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    )
    web_shell_test_text = read_source(
        workspace
        / "platform-web-shell/src/test/java/network/crypta/platform/webshell/WebShellResourcesTest.java"
    )
    consent_test_text = read_source(
        workspace
        / "platform-api/src/test/java/network/crypta/platform/api/consent/ConsentServiceTest.java"
    )
    candidate_test_text = read_source(
        workspace
        / "platform-api/src/test/java/network/crypta/platform/api/appupdates/AppUpdateCandidateTest.java"
    )
    update_service_test_text = read_source(
        workspace
        / "platform-api/src/test/java/network/crypta/platform/api/appupdates/AppUpdateServiceTest.java"
    )
    app_services_router_test_text = read_source(
        workspace / "platform-api/src/test/java/network/crypta/platform/api/PlatformApiAppServicesRouterTest.java"
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/user-consent-and-permission-upgrade-ux.md",
            "docs/app-platform-developer-portal.md",
            "docs/app-dev-cli.md",
            "docs/app-catalogs.md",
            "docs/app-service-discovery-and-grants.md",
            "docs/app-data-store.md",
            "docs/production-beta-release-pipeline.md",
            "docs/release-certification.md",
            "tools/release-certification/README.md",
        )
    )
    checks = {
        "consentModelsPresent": all(
            marker in consent_text
            for marker in (
                "enum ConsentActionType",
                "enum ConsentRiskLevel",
                "enum ConsentDecisionStatus",
                "record ConsentSnapshot",
                "final class ConsentSnapshotDigest",
                "record ConsentRequest",
                "record ConsentDecision",
                "record ConsentAuditEvent",
                "interface ConsentAuditStore",
                "final class FileConsentAuditStore",
                "final class ConsentPolicy",
                "final class ConsentService",
            )
        ),
        "previewRoutesPresent": all(
            marker in consent_text + router_text
            for marker in (
                'case "consent" -> appRoutes.routeConsentRequest',
                'case "install-preview"',
                'case "catalog-update-preview"',
                'case "update-preview"',
                'case "service-grant-preview"',
                'case "approve"',
                'case "reject"',
                'case "audit"',
            )
        ),
        "contractConsentDescriptorsPresent": all(
            marker in contract_text
            for marker in (
                "CURRENT_CONTRACT_VERSION = 23",
                "CONSENT_CONTRACT_VERSION = 21",
                "ROUTE_FAMILY_CONSENT",
                "consentEndpoints",
                "consentEndpoint",
                "PlatformApiStabilityLevel.OPERATOR_ONLY",
                "/consent/install-preview",
                "/consent/update-preview",
                "/consent/catalog-update-preview",
                "/consent/service-grant-preview",
                "/consent/approve",
                "/consent/reject",
                "/consent/defer",
                "/consent/audit",
            )
        ),
        "installPreviewCoversMaterialTrustAndPermissions": all(
            marker in consent_text
            for marker in (
                "buildInstallSnapshot",
                "installIdentitySection",
                "catalogTrustSection",
                "reviewSection",
                "securitySection",
                "installPermissionsSection",
                "apiStabilitySection",
                "appDataAndBackupSection",
                "serviceGrantPlaceholderSection",
            )
        ),
        "updatePreviewCoversMaterialDeltas": all(
            marker in consent_text
            for marker in (
                "buildUpdateSnapshot",
                "permissionDeltaSection",
                "updateApiStabilitySection",
                "updateReviewSection",
                "updateCatalogSection",
                "updateSecuritySection",
                "updateMigrationSection",
                "updateBackupSection",
                "updateServiceGrantDeltaSection",
            )
        ),
        "serviceGrantConsentIntegrated": (
            "buildServiceGrantSnapshot" in consent_text
            and "serviceGrantDependenciesSection" in consent_text
            and "requireApprovedServiceGrantIfRequired" in service_routes_text
            and "recordServiceGrantRejection" in service_routes_text
        ),
        "migrationAndBackupConsentIntegrated": (
            "app-data migration" in consent_text.lower()
            and "backup_before_update" in consent_text
            and "migrationRisk" in consent_text
            and "operatorReviewRequired" in update_candidate_text
            and "previewForConsent(String appId, boolean refreshCatalogs)" in update_service_text
            and "candidateWithConsentMigrationPlan" in update_service_text
        ),
        "automaticUpdateGatingPresent": (
            "materialConsentAllowsAutomaticStage" in update_candidate_text
            and "materialConsentBlocksAutomaticStage" in update_candidate_text
            and "permissionDeltaAllowsAutomaticStage" in update_candidate_text
            and "apiStabilityAllowsAutomaticStage" in update_candidate_text
            and "securityAdvisoriesAllowAutomaticStage" in update_candidate_text
            and "security_advisory" in update_candidate_text
            and "dataMigrationAllowsAutomaticStage" in update_candidate_text
            and "app_data_migration" in update_candidate_text
            and "statusValue instanceof String status" in update_candidate_text
            and "blocksAutoUpdate" in update_candidate_text
            and "preview(String appId, boolean refreshCatalogs)" in update_service_text
            and "ERROR_CONSENT_REQUIRED" in update_service_text
            and "appendMaterialConsentHistory" in update_service_text
            and "consent_required" in update_service_text
        ),
        "guardedUpdatePreviewRefresh": (
            "updatePreviewReadOnly" in consent_text
            and "consentService.updatePreview(appId, refreshCatalogs)" in consent_text
            and "requiresConsentFormPassword" in toadlet_text
            and '"update-preview".equals(pathSegments.get(1))' in toadlet_text
        ),
        "snapshotDigestAndStaleApprovalProtection": (
            "ConsentSnapshotDigest.digest(this)" in consent_text
            and "toDigestJson" in consent_text
            and "stale_consent_snapshot" in consent_text
            and "current.snapshotDigest()" in consent_text
            and "consumeConsentRequest" in consent_text
            and "STORED_CONSENT_TTL" in consent_text
            and "MAX_STORED_REQUESTS" in consent_text
            and ("consentRequestId" in app_routes_text or "PARAM_CONSENT_REQUEST_ID" in consent_text)
        ),
        "auditDecisionStoreRedacted": (
            "ConsentRedactor.redact" in consent_text
            and "materialRiskSummary" in consent_text
            and "FileConsentAuditStore" in consent_text
        ),
        "webShellConsentUiPresent": all(
            marker in web_shell_text
            for marker in (
                "function renderConsentPreview",
                "function renderConsentSection",
                "function submitConsentDecision",
                "consent/install-preview",
                "consent/update-preview",
                "consent/service-grant-preview",
                "This approval is stale. Refresh the consent preview.",
                "consentRequestId",
                "snapshotDigest",
                "blocksAutoUpdate",
            )
        ),
        "testsCoverConsentFlow": all(
            marker
            in consent_test_text
            + candidate_test_text
            + update_service_test_text
            + web_shell_test_text
            + app_services_router_test_text
            for marker in (
                "installPreview_whenCatalogEntryHasMaterialMetadata_expectGroupedConsentSections",
                "installPreview_whenSecurityDecisionBlocksInstallOnly_expectBlockingRisk",
                "installPreview_whenReviewTrustBlocksInstallOnly_expectBlockingRisk",
                "requireApprovedUpdate_whenDigestMatches_expectMutationAcknowledgements",
                "requireApprovedUpdate_whenApprovalReused_expectConsentNotApproved",
                "requireApprovedUpdate_whenApprovalExpires_expectConsentNotApprovedAndExpiredAudit",
                "requireApprovedUpdate_whenCandidateDigestChanges_expectStaleApprovalRejected",
                "serviceGrantPreview_whenBundleHasDependencies_expectGrantConsentSections",
                "auditEvent_whenRiskSummaryContainsSensitiveValues_expectRedactedJson",
                "toJsonValue_whenPermissionIsAdded_expectAutomaticUpdateBlockedByConsent",
                "toJsonValue_whenApiCompatibilityStatusUnknown_expectAutomaticUpdateBlockedByConsent",
                "toJsonValue_whenSecurityAdvisoryPresent_expectAutomaticUpdateBlockedByConsent",
                "toJsonValue_whenMigrationRequiresOperatorReview_expectAutomaticUpdateBlockedByConsent",
                "check_whenStagePolicyCandidateAddsPermission_expectConsentRequiredHistory",
                "check_whenStagePolicyCandidateHasSecurityAdvisory_expectConsentRequiredHistory",
                "check_whenStagePolicyMigrationRollbackIncompatible_expectCandidateRequiresOperatorReview",
                "previewForConsent_whenMigrationRollbackIncompatible_expectCandidateRequiresOperatorReview",
                "requireApprovedUpdate_whenMigrationRequiresReview_expectMutationAcknowledgement",
                "updatePreview_whenGetIncludesRefreshCatalogs_expectReadOnlyPreviewWithoutRefresh",
                "updatePreview_whenPostIncludesRefreshCatalogs_expectConsentPreviewRefresh",
                "route_whenBundleRejectFails_expectConsentRejectionAuditNotRecorded",
                "assertConsentUxMarkersPresent",
            )
        ),
        "docsPresent": all(
            marker.casefold() in docs_text.casefold()
            for marker in (
                "app-platform.user-consent-flow",
                "install consent",
                "update consent",
                "permission delta",
                "API stability",
                "review/trust",
                "service grants",
                "app-data migration",
                "backup",
                "security advisory",
                "auto-update",
                "audit",
                "stale consent",
                "non-goals",
            )
        ),
    }
    errors = [name for name, passed in checks.items() if passed is not True]
    details = {
        "checks": checks,
        "redaction": {
            "privateInsertUrisExcluded": True,
            "tokensExcluded": True,
            "rawFetchedContentExcluded": True,
            "rawAppDataExcluded": True,
            "absolutePathsExcluded": True,
        },
        "sources": {
            "consent": display_path(consent_dir, workspace),
            "contract": "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java",
            "router": "platform-api/src/main/java/network/crypta/platform/api/PlatformApiRouter.java",
            "updateCandidate": (
                "platform-api/src/main/java/network/crypta/platform/api/appupdates/"
                "AppUpdateCandidate.java"
            ),
            "webShell": (
                "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/"
                "web-shell.js"
            ),
            "docs": "docs/user-consent-and-permission-upgrade-ux.md",
        },
    }
    if errors:
        return EvidenceItem(
            "app-platform.user-consent-flow",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "User consent and permission-upgrade flow evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.user-consent-flow",
        "pass",
        True,
        "User consent and permission-upgrade flow evidence passed deterministic checks.",
        source,
        details,
    )

def collect_app_update_lifecycle_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    apphost_source = (
        settings.workspace_root
        / "platform-apphost/src/main/java/network/crypta/platform/apphost/runtime/LocalProcessAppHost.java"
    )
    catalog_handler_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandler.java"
    )
    update_service_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateService.java"
    )
    update_handler_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdatesApiHandler.java"
    )
    update_policy_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdatePolicyMode.java"
    )
    update_candidate_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateCandidate.java"
    )
    update_status_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateCandidateStatus.java"
    )
    update_service_test_source = (
        settings.workspace_root
        / "platform-api/src/test/java/network/crypta/platform/api/appupdates/AppUpdateServiceTest.java"
    )
    router_test_source = settings.workspace_root / "src/test/java/network/crypta/platform/api/PlatformApiRouterTest.java"
    lifecycle_doc = settings.workspace_root / "docs/app-update-lifecycle.md"
    apphost_text = read_source(apphost_source)
    catalog_text = read_source(catalog_handler_source)
    update_service_text = read_source(update_service_source)
    update_handler_text = read_source(update_handler_source)
    policy_text = read_source(update_policy_source)
    candidate_text = read_source(update_candidate_source)
    status_text = read_source(update_status_source)
    update_service_test_text = read_source(update_service_test_source)
    router_test_text = read_source(router_test_source)
    doc_text = read_source(lifecycle_doc)
    checks = {
        "apphostUpdateEntryPoint": "updateFromDirectory" in apphost_text,
        "policyModes": (
            'MANUAL("manual")' in policy_text
            and 'STAGE("stage")' in policy_text
            and 'APPLY_WHEN_STOPPED("apply_when_stopped")' in policy_text
        ),
        "managedStageCopyBeforeValidation": (
            "copyDirectoryTree(stagingRoot, temporaryInstallRoot)" in apphost_text
            and "verifyCopiedBundle(temporaryInstallRoot)" in apphost_text
            and "validateCopiedBundle(temporaryInstallRoot)" in apphost_text
        ),
        "matchingAppIdGate": "requireMatchingUpdateTarget(normalizedAppId, manifest)" in apphost_text,
        "hostApplyWhenStoppedGate": (
            "liveRunningProcess(normalizedAppId) != null" in apphost_text
            and "cannot update a running app" in apphost_text
        ),
        "updateApplyRunningConflictTest": (
            "apply_whenAppStartsAfterPrecheck_expectConflictNotServerError"
            in update_service_test_text
            and '"cannot update a running app: " + APP_ID' in update_service_test_text
            and 'assertEquals("app_running", exception.errorCode())' in update_service_test_text
        ),
        "updateApplyRunningConflictRouteTest": (
            "route_whenAppUpdateApplyRequestedWhileRunning_expectConflictJson" in router_test_text
            and 'List.of("apps", APP_ID, "updates", "apply")' in router_test_text
            and "assertEquals(409, response.statusCode())" in router_test_text
            and 'verify(appHost, never()).updateFromDirectory(APP_ID, stagedDir)' in router_test_text
            and "app_running" in router_test_text
        ),
        "catalogVersionComparison": (
            "versionDifferent(" in catalog_text
            and "updateAvailable(" in catalog_text
            and '"versionDifferent"' in catalog_text
            and '"updateAvailable"' in catalog_text
        ),
        "candidateDetectionSemantics": (
            'AVAILABLE("available")' in status_text
            and 'STAGED("staged")' in status_text
            and 'BLOCKED("blocked")' in status_text
            and 'INCOMPATIBLE("incompatible")' in status_text
            and 'AMBIGUOUS("ambiguous")' in status_text
            and 'ROLLBACK_AVAILABLE("rollback_available")' in status_text
        ),
        "candidateReviewMetadata": '"review"' in candidate_text and "reviewSummary" in candidate_text,
        "candidateCompatibilityMetadata": (
            '"apiCompatibility"' in candidate_text and "apiCompatibility" in candidate_text
        ),
        "permissionDeltaReview": (
            "permissionDelta" in candidate_text and '"permissionDelta"' in candidate_text
        ),
        "lifecycleHandlerRoutesStageAndApply": (
            "Map<String, Object> stage(String appId)" in update_handler_text
            and "return updateService.stage(appId)" in update_handler_text
            and (
                "Map<String, Object> apply(String appId, Map<String, List<String>> queryParameters)"
                in update_handler_text
            )
            and (
                "return updateService.apply(appId, applyOptions(queryParameters))"
                in update_handler_text
            )
        ),
        "lifecycleServiceStagesVerifiedPlan": (
            "public synchronized Map<String, Object> stage(String appId)" in update_service_text
            and (
                "catalogManager.prepareInstallPlan(candidate.catalogId(), appId)"
                in update_service_text
            )
            and "planDiffersFromCandidate(candidate, installed, plan)" in update_service_text
        ),
        "lifecycleServiceApplyDelegatesToAppHost": (
            (
                "public synchronized Map<String, Object> apply(String appId, ApplyOptions options)"
                in update_service_text
            )
            and (
                "appHost.updateFromDirectory(normalizedAppId, staged.stagedBundleDirectory())"
                in update_service_text
            )
            and "closeStage(normalizedAppId)" in update_service_text
        ),
        "manualApplyPolicyDocumented": (
            "apply_when_stopped" in doc_text
            and "manual" in doc_text
            and "stage" in doc_text
            and "Silent automatic update is not the default" in doc_text
            and "requires an operator or explicit API caller" in doc_text
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "policy": "manual/stage/apply_when_stopped",
        "silentAutoUpdateDefault": False,
        "liveNodeRequired": False,
        "checks": checks,
        "sources": {
            "apphost": display_path(apphost_source, settings.workspace_root),
            "catalogHandler": display_path(catalog_handler_source, settings.workspace_root),
            "updateService": display_path(update_service_source, settings.workspace_root),
            "updateHandler": display_path(update_handler_source, settings.workspace_root),
            "updatePolicy": display_path(update_policy_source, settings.workspace_root),
            "updateCandidate": display_path(update_candidate_source, settings.workspace_root),
            "updateStatus": display_path(update_status_source, settings.workspace_root),
            "updateServiceTest": display_path(update_service_test_source, settings.workspace_root),
            "routerTest": display_path(router_test_source, settings.workspace_root),
            "lifecycleDoc": display_path(lifecycle_doc, settings.workspace_root),
        },
    }
    if errors:
        return EvidenceItem(
            "app-update.lifecycle",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "App-update lifecycle evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-update.lifecycle",
        "pass",
        True,
        "App-update lifecycle policy passed deterministic offline evidence checks.",
        source,
        details,
    )

def collect_app_update_scheduler_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    scheduler_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateScheduler.java"
    )
    scheduler_config_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateSchedulerConfig.java"
    )
    scheduler_state_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateSchedulerState.java"
    )
    scheduler_store_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/FileAppUpdateSchedulerStore.java"
    )
    update_service_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateService.java"
    )
    scheduler_test_source = (
        settings.workspace_root
        / "platform-api/src/test/java/network/crypta/platform/api/appupdates/AppUpdateSchedulerTest.java"
    )
    scheduler_config_test_source = (
        settings.workspace_root
        / "platform-api/src/test/java/network/crypta/platform/api/appupdates/AppUpdateSchedulerConfigTest.java"
    )
    runtime_source = (
        settings.workspace_root
        / "bridge-http-runtime/src/main/java/network/crypta/clients/http/bridge/CoreHttpShellRuntimeSupport.java"
    )
    web_shell_source = (
        settings.workspace_root
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    )
    lifecycle_doc = settings.workspace_root / "docs/app-update-lifecycle.md"
    scheduler_text = read_source(scheduler_source)
    scheduler_config_text = read_source(scheduler_config_source)
    scheduler_state_text = read_source(scheduler_state_source)
    scheduler_store_text = read_source(scheduler_store_source)
    update_service_text = read_source(update_service_source)
    scheduler_test_text = read_source(scheduler_test_source)
    scheduler_config_test_text = read_source(scheduler_config_test_source)
    runtime_text = read_source(runtime_source)
    web_shell_text = read_source(web_shell_source)
    doc_text = read_source(lifecycle_doc)
    checks = {
        "schedulerSourcePresent": (
            "public final class AppUpdateScheduler" in scheduler_text
            and "AppUpdateSchedulerConfig" in scheduler_text
            and "AppUpdateSchedulerStore" in scheduler_text
        ),
        "schedulerConfigPresent": (
            "CRYPTAD_APPUPDATES_SCHEDULER_ENABLED" in scheduler_config_text
            and "cryptad.appupdates.scheduler.appCheckIntervalSeconds" in scheduler_config_text
            and "defaults()" in scheduler_config_text
            and "true," in scheduler_config_text
            and "from(Map<?, ?> properties, Map<String, String> environment)" in scheduler_config_text
            and "from_whenValuesMalformed_expectDefaultsRetained" in scheduler_config_test_text
        ),
        "schedulerSummaryPublished": (
            'json.put("scheduler", schedulerSummaryProvider.schedulerSummary(appId))'
            in update_service_text
            and '"lastCheckAt"' in scheduler_state_text
            and '"nextCheckAt"' in scheduler_state_text
            and '"failureCount"' in scheduler_state_text
            and '"lastErrorCode"' in scheduler_state_text
            and '"concurrency"' in scheduler_state_text
        ),
        "schedulerCatalogRefresh": (
            "catalogManager.listCatalogs()" in scheduler_text
            and "catalogManager.refresh(catalog.catalogId())" in scheduler_text
            and "MESSAGE_CATALOG_REFRESH_FAILED" in scheduler_text
        ),
        "schedulerDelegatesToUpdateCheck": (
            "updateService.check(state.appId(), false)" in scheduler_text
            and "updateService.stage(" not in scheduler_text
            and "updateService.apply(" not in scheduler_text
            and "appHost.updateFromDirectory(" not in scheduler_text
            and "catalogManager.prepareInstallPlan(" not in scheduler_text
        ),
        "schedulerManualPolicyDoesNotMutate": (
            "tick_whenManualPolicy_expectCheckOnlyAndNoStageOrApply" in scheduler_test_text
            and "verify(catalogManager, never()).prepareInstallPlan" in scheduler_test_text
            and "verify(appHost, never()).updateFromDirectory" in scheduler_test_text
        ),
        "schedulerPolicyDrivenChecks": (
            "tick_whenStagePolicy_expectVerifiedCandidateStagedByServicePolicy"
            in scheduler_test_text
            and "tick_whenApplyWhenStoppedPolicy_expectStoppedAppAppliedByServicePolicy"
            in scheduler_test_text
            and "tick_whenApplyWhenStoppedPolicyAndAppRunning_expectRunningAppNotStoppedOrUpdated"
            in scheduler_test_text
            and "Policy skipped apply because the app is running." in scheduler_test_text
        ),
        "schedulerFailureContained": (
            "tick_whenCheckFails_expectSanitizedFailureAndBackoff" in scheduler_test_text
            and "tick_whenCatalogRefreshFails_expectFailureContainedAndAppsStillChecked"
            in scheduler_test_text
            and "catalog_refresh_failed" in scheduler_text
            and "Scheduler update check failed." in scheduler_text
        ),
        "schedulerDurableStore": (
            "public final class FileAppUpdateSchedulerStore" in scheduler_store_text
            and "ATOMIC_MOVE" in scheduler_store_text
            and "update-scheduler" in runtime_text
            and "layout.dataDir().resolve(\"apps\").resolve(\"update-scheduler\")" in runtime_text
        ),
        "schedulerPerAppSerialized": (
            "AtomicBoolean running" in scheduler_text
            and "alreadyRunning" in scheduler_text
            and "per-app-serialized" in scheduler_state_text
            and "summary_whenSchedulerStatePresent_expectPathFreeSchedulerSummary"
            in scheduler_test_text
        ),
        "schedulerPathAndPrivateDataFree": (
            "summary_whenSchedulerStatePresent_expectPathFreeSchedulerSummary" in scheduler_test_text
            and "secret-token" in scheduler_test_text
            and "contains(tempDir.toString())" in scheduler_test_text
            and "catalog scratch" in scheduler_state_text
            and "staged bundle path" in scheduler_state_text
        ),
        "schedulerRuntimeWiring": (
            "createAppUpdateScheduler(" in runtime_text
            and "appUpdateService.setSchedulerSummaryProvider(appUpdateScheduler::summary)"
            in runtime_text
            and "appUpdateScheduler.start()" in runtime_text
            and "createAppUpdateSchedulerShutdownJob" in runtime_text
        ),
        "schedulerWebShellDisplay": (
            "Scheduler status" in web_shell_text
            and "Scheduler failures" in web_shell_text
            and "Last scheduler error" in web_shell_text
        ),
        "schedulerLifecycleDocumented": (
            "background scheduler" in doc_text.lower()
            and "manual remains the default" in doc_text.lower()
            and "AppUpdateService.check" in doc_text
            and "app-update.scheduler" in doc_text
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "policy": "manual default; policy-driven stage/apply only after explicit selection",
        "silentAutoUpdateDefault": False,
        "liveNodeRequired": False,
        "checks": checks,
        "sources": {
            "scheduler": display_path(scheduler_source, settings.workspace_root),
            "schedulerConfig": display_path(scheduler_config_source, settings.workspace_root),
            "schedulerState": display_path(scheduler_state_source, settings.workspace_root),
            "schedulerStore": display_path(scheduler_store_source, settings.workspace_root),
            "updateService": display_path(update_service_source, settings.workspace_root),
            "schedulerTest": display_path(scheduler_test_source, settings.workspace_root),
            "schedulerConfigTest": display_path(
                scheduler_config_test_source, settings.workspace_root
            ),
            "runtime": display_path(runtime_source, settings.workspace_root),
            "webShell": display_path(web_shell_source, settings.workspace_root),
            "lifecycleDoc": display_path(lifecycle_doc, settings.workspace_root),
        },
    }
    if errors:
        return EvidenceItem(
            "app-update.scheduler",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "App-update scheduler evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-update.scheduler",
        "pass",
        True,
        "App-update background scheduler passed deterministic offline evidence checks.",
        source,
        details,
    )

def collect_app_update_live_catalog_refresh_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    scheduler_source = (
        workspace / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateScheduler.java"
    )
    update_service_source = (
        workspace / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateService.java"
    )
    scheduler_test_source = (
        workspace / "platform-api/src/test/java/network/crypta/platform/api/appupdates/AppUpdateSchedulerTest.java"
    )
    catalog_routes_source = (
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiAppRoutes.java"
    )
    catalog_handler_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandler.java"
    )
    lifecycle_doc = workspace / "docs/app-update-lifecycle.md"
    catalog_doc = workspace / "docs/app-catalogs.md"
    scheduler_text = read_source(scheduler_source)
    update_service_text = read_source(update_service_source)
    scheduler_test_text = read_source(scheduler_test_source)
    catalog_routes_text = read_source(catalog_routes_source)
    catalog_handler_text = read_source(catalog_handler_source)
    docs_text = read_source(lifecycle_doc) + "\n" + read_source(catalog_doc)
    checks = {
        "refreshBeforeCandidateDiscovery": (
            "catalogManager.listCatalogs()" in scheduler_text
            and "catalogManager.refresh(catalog.catalogId())" in scheduler_text
            and "updateService.check(state.appId(), false)" in scheduler_text
            and "inOrder(catalogManager, updateService)" in scheduler_test_text
        ),
        "refreshFailureContained": (
            "MESSAGE_CATALOG_REFRESH_FAILED" in scheduler_text
            and "tick_whenCatalogRefreshFails_expectFailureContainedAndAppsStillChecked"
            in scheduler_test_text
        ),
        "schedulerDoesNotApplyDirectly": (
            "updateService.stage(" not in scheduler_text
            and "updateService.apply(" not in scheduler_text
            and "appHost.updateFromDirectory(" not in scheduler_text
            and "catalogManager.prepareInstallPlan(" not in scheduler_text
        ),
        "manualPolicyStillDefault": (
            "manual remains the default" in scheduler_text.lower()
            and "tick_whenManualPolicy_expectCheckOnlyAndNoStageOrApply" in scheduler_test_text
            and "verify(catalogManager, never()).prepareInstallPlan" in scheduler_test_text
        ),
        "policyDrivenUpdatesStayInService": (
            "check(state.appId(), false)" in scheduler_text
            and "check(" in update_service_text
            and "stage(" in update_service_text
            and "apply(" in update_service_text
        ),
        "manualRefreshRouteExists": (
            '"refresh".equals(action)' in catalog_routes_text
            and '"/app-catalogs/{catalogId}/refresh"' in read_source(
                workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java"
            )
            and "refresh(catalogId)" in catalog_handler_text
        ),
        "schedulerSummaryPrivacyGuard": (
            "summary_whenSchedulerStatePresent_expectPathFreeSchedulerSummary"
            in scheduler_test_text
            and "secret-token" in scheduler_test_text
            and "contains(tempDir.toString())" in scheduler_test_text
        ),
        "docsCoverLiveCatalogRefresh": (
            "live USK catalog" in docs_text
            and "catalog refresh" in docs_text.lower()
            and "last verified" in docs_text.lower()
            and "manual remains the default" in docs_text.lower()
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "liveNodeRequired": False,
        "policy": "manual default; scheduler refreshes catalogs before candidate discovery",
        "silentAutoUpdateDefault": False,
        "checks": checks,
        "sources": {
            "scheduler": display_path(scheduler_source, workspace),
            "updateService": display_path(update_service_source, workspace),
            "schedulerTest": display_path(scheduler_test_source, workspace),
            "catalogRoutes": display_path(catalog_routes_source, workspace),
            "catalogHandler": display_path(catalog_handler_source, workspace),
            "lifecycleDoc": display_path(lifecycle_doc, workspace),
            "catalogDoc": display_path(catalog_doc, workspace),
        },
    }
    if errors:
        return EvidenceItem(
            "app-update.live-catalog-refresh",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "Live catalog refresh scheduler evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-update.live-catalog-refresh",
        "pass",
        True,
        "Live catalog refresh scheduler evidence passed deterministic checks.",
        source,
        details,
    )

def collect_app_update_rollback_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    apphost_source = (
        settings.workspace_root
        / "platform-apphost/src/main/java/network/crypta/platform/apphost/runtime/LocalProcessAppHost.java"
    )
    apphost_test_source = (
        settings.workspace_root
        / "platform-apphost/src/test/java/network/crypta/platform/apphost/runtime/LocalProcessAppHostTest.java"
    )
    lifecycle_doc = settings.workspace_root / "docs/app-update-lifecycle.md"
    apphost_text = read_source(apphost_source)
    apphost_test_text = read_source(apphost_test_source)
    doc_text = read_source(lifecycle_doc)
    checks = {
        "managedBackupAllocated": (
            "TEMP_UPDATE_BACKUP_PREFIX" in apphost_text
            and "temporaryManagedPath(installedAppsDir, TEMP_UPDATE_BACKUP_PREFIX" in apphost_text
        ),
        "durableRollbackRoot": (
            "rollbackRootFor" in apphost_text
            and "ensureRollbackAppsDirectory" in apphost_text
            and "rollbackStatus" in apphost_text
        ),
        "installedBundleRecordedForRollback": (
            "moveIntoPlace(installedRoot, backupRoot)" in apphost_text
            and "moveIntoPlace(backupRoot, rollbackRoot)" in apphost_text
        ),
        "restorePreviousBundleOnReplacementFailure": (
            "restoreInstalledBundle(installedRoot, backupRoot, updateFailure)" in apphost_text
            and "restorePreviousRollback(" in apphost_text
        ),
        "manualRollbackSwapsBundles": (
            "swapInstalledBundleWithRollback" in apphost_text
            and "moveIntoPlace(rollbackRoot, installedRoot)" in apphost_text
            and "moveIntoPlace(currentInstallBackupRoot, rollbackRoot)" in apphost_text
        ),
        "replacementCommitToleratesPreviousRecordCleanupFailure": (
            "deleteBackupAfterSuccessfulReplacement" in apphost_text
            and "simulated backup cleanup failure" in apphost_test_text
            and "cleanupAttempts.incrementAndGet()" in apphost_test_text
            and 'resolve("first").resolve(SAMPLE_APP_ID)' in apphost_test_text
            and "assertEquals(0, cleanupAttempts.get())" in apphost_test_text
            and 'resolve("second").resolve(SAMPLE_APP_ID)' in apphost_test_text
            and "firstUpdate.manifest().appVersion()" in apphost_test_text
            and "assertEquals(1, cleanupAttempts.get())" in apphost_test_text
            and "expectPreviousBundleRecordedForRollback" in apphost_test_text
        ),
        "mutableDirectoriesPreservedByUpdate": (
            "preserve-data.txt" in apphost_test_text
            and "preserve-cache.txt" in apphost_test_text
            and "preserve-run.txt" in apphost_test_text
        ),
        "mutableDirectoriesPreservedByRollback": (
            "rollback-data.txt" in apphost_test_text
            and "rollback-cache.txt" in apphost_test_text
            and "rollback-run.txt" in apphost_test_text
        ),
        "rollbackHealthGate": (
            "cannot rollback a running app" in apphost_text
            and "rollback_whenAppIsRunning_expectFailureAndInstalledBundleUnchanged" in apphost_test_text
        ),
        "rollbackMetadataPathFree": (
            "rollbackStatus_whenRecordExists_expectMetadataOmitsTokensAndHostPaths" in apphost_test_text
        ),
        "rollbackScopeDocumented": (
            "Rollback covers only the immutable installed bundle" in doc_text
            and "Rollback does not roll back" in doc_text
            and "app data directories" in doc_text
            and "app cache directories" in doc_text
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "rollbackScope": "installed-bundle-only",
        "preservesDataCacheRun": True,
        "liveNodeRequired": False,
        "checks": checks,
        "sources": {
            "apphost": display_path(apphost_source, settings.workspace_root),
            "apphostTest": display_path(apphost_test_source, settings.workspace_root),
            "lifecycleDoc": display_path(lifecycle_doc, settings.workspace_root),
        },
    }
    if errors:
        return EvidenceItem(
            "app-update.rollback",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "App-update rollback evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-update.rollback",
        "pass",
        True,
        "App-update rollback scope passed deterministic offline evidence checks.",
        source,
        details,
    )

def collect_app_update_data_migration_contract_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    source_files = {
        "schemaContract": workspace
        / "platform-appdist/src/main/java/network/crypta/platform/appdist/AppDataSchemaContract.java",
        "namespaceSchema": workspace
        / "platform-appdist/src/main/java/network/crypta/platform/appdist/AppDataNamespaceSchema.java",
        "migrationStep": workspace
        / "platform-appdist/src/main/java/network/crypta/platform/appdist/AppDataMigrationStep.java",
        "migrationCommand": workspace
        / "platform-appdist/src/main/java/network/crypta/platform/appdist/AppDataMigrationCommand.java",
        "manifestParser": workspace
        / "platform-appdist/src/main/java/network/crypta/platform/appdist/AppBundleManifestParser.java",
        "structureValidator": workspace
        / "platform-appdist/src/main/java/network/crypta/platform/appdist/AppBundleStructureValidator.java",
        "structureValidatorTest": workspace
        / "platform-appdist/src/test/java/network/crypta/platform/appdist/AppBundleStructureValidatorTest.java",
        "manifestParserTest": workspace
        / "platform-appdist/src/test/java/network/crypta/platform/appdist/AppBundleManifestParserTest.java",
        "appHostManifest": workspace
        / "platform-apphost/src/main/java/network/crypta/platform/apphost/manifest/AppManifest.java",
        "appHostManifestParser": workspace
        / "platform-apphost/src/main/java/network/crypta/platform/apphost/manifest/AppManifestParser.java",
        "appDataService": workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataService.java",
        "appDataSnapshot": workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataUpdateSnapshot.java",
        "appDataServiceTest": workspace
        / "platform-api/src/test/java/network/crypta/platform/api/appdata/AppDataServiceTest.java",
        "migrationPlan": workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppDataMigrationPlan.java",
        "migrationRunner": workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppDataMigrationRunner.java",
        "migrationRunnerTest": workspace
        / "platform-api/src/test/java/network/crypta/platform/api/appupdates/AppDataMigrationRunnerTest.java",
        "updateCandidate": workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateCandidate.java",
        "updateService": workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateService.java",
        "updateHandler": workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdatesApiHandler.java",
        "updateServiceTest": workspace
        / "platform-api/src/test/java/network/crypta/platform/api/appupdates/AppUpdateServiceTest.java",
        "catalogManager": workspace
        / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog/AppCatalogManager.java",
        "catalogManagerTest": workspace
        / "platform-appcatalog/src/test/java/network/crypta/platform/appcatalog/AppCatalogManagerTest.java",
        "webShell": workspace
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js",
        "feedScript": workspace / "apps/feed-reader/src/staged/bin/migrate-feed-data.sh",
        "trustScript": workspace / "apps/trust-graph/src/staged/bin/migrate-preview-data.sh",
    }
    text = {name: read_source(path) for name, path in source_files.items()}
    feed_manifest = read_first_manifest(
        workspace,
        "feed-reader",
        "apps/feed-reader/src/staged/cryptad-app.properties.template",
    )
    trust_manifest = read_first_manifest(
        workspace,
        "trust-graph",
        "apps/trust-graph/src/staged/cryptad-app.properties.template",
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/app-upgrade-data-migrations.md",
            "docs/app-update-lifecycle.md",
            "docs/app-data-store.md",
            "docs/app-distribution.md",
            "docs/app-platform-developer-portal.md",
            "docs/release-certification.md",
            "docs/production-first-party-catalog-channels.md",
            "tools/release-certification/README.md",
        )
    )
    dry_run_index = text["updateService"].find("AppDataMigrationRunner.Mode.DRY_RUN")
    staged_index = text["updateService"].find("new StagedUpdate")
    apply_verify_index = text["updateService"].find("verifyStagedBundleBeforeApply")
    apply_dry_run_index = text["updateService"].find("runApplyDryRunOrReject")
    barrier_index = text["updateService"].find("beginUpdateMigrationWriteBarrier")
    snapshot_index = text["updateService"].find("appDataSnapshot = createUpdateSnapshot")
    replacement_index = text["updateService"].find("appHost.updateFromDirectory")
    checks = {
        "manifestModelsAndParser": (
            "record AppDataSchemaContract" in text["schemaContract"]
            and "record AppDataNamespaceSchema" in text["namespaceSchema"]
            and "record AppDataMigrationStep" in text["migrationStep"]
            and "record AppDataMigrationCommand" in text["migrationCommand"]
            and "app.data.schema.current" in text["manifestParser"]
            and "app.data.migration." in text["manifestParser"]
            and "dataSchemaContract" in text["manifestParser"]
        ),
        "manifestValidationRejectsUnsafeMetadata": (
            "must stay under the app root" in text["migrationCommand"]
            and "WINDOWS_DRIVE_PREFIX_PATTERN" in text["migrationCommand"]
            and "AppDataNamespaceSchema.normalizeNamespace" in text["migrationStep"]
            and "toSchemaVersion <= fromSchemaVersion" in text["migrationStep"]
            and "unsupported app.data manifest property" in text["manifestParser"]
            and "app.data.migrations requires app.data.schema.current or app.data.schema.namespaces"
            in text["manifestParser"]
            and "app.data migration target exceeds declared schema" in text["manifestParser"]
            and "parseContent_whenMigrationDeclaresNoTargetSchema_expectFailure"
            in text["manifestParserTest"]
            and "parseContent_whenGlobalMigrationTargetExceedsSchema_expectFailure"
            in text["manifestParserTest"]
            and "parseContent_whenMigrationCommandEscapesBundle_expectFailure"
            in text["manifestParserTest"]
            and "parseContent_whenMigrationFieldIsUnknown_expectFailure"
            in text["manifestParserTest"]
        ),
        "signedBundleStructureChecksEntrypoints": (
            "step.command().path()" in text["structureValidator"]
            and "Files.isRegularFile" in text["structureValidator"]
            and "Files.isExecutable" not in text["structureValidator"]
            and "NOFOLLOW_LINKS" in text["structureValidator"]
            and "validate_whenMigrationCommandIsRegularNonExecutableFile_expectAccepted"
            in text["structureValidatorTest"]
            and "migration command is not executable" in text["migrationRunner"]
            and "run_whenMigrationCommandIsNotExecutable_expectFailsBeforeCompletion"
            in text["migrationRunnerTest"]
        ),
        "appHostCarriesSignedContract": (
            "dataSchemaContract" in text["appHostManifest"]
            and "manifest.dataSchemaContract()" in text["appHostManifestParser"]
        ),
        "internalSnapshotPrimitives": (
            "record AppDataUpdateSnapshot" in text["appDataSnapshot"]
            and "createUpdateSnapshot" in text["appDataService"]
            and "restoreUpdateSnapshot" in text["appDataService"]
            and "discardUpdateSnapshot" in text["appDataService"]
            and "app_data_snapshot_too_large" in text["appDataService"]
            and "createUpdateSnapshot_whenOtherAppHasData_expectSnapshotIsAppScoped"
            in text["appDataServiceTest"]
            and "restoreUpdateSnapshot_whenDataChangedAfterSnapshot_expectOriginalStateRestored"
            in text["appDataServiceTest"]
        ),
        "migrationRunnerIsShellFreeAndScoped": (
            "ProcessBuilder(commandLine(command))" in text["migrationRunner"]
            and "environment().clear()" in text["migrationRunner"]
            and "CRYPTA_APP_MIGRATION_MODE" in text["migrationRunner"]
            and "CRYPTA_APP_MIGRATION_NAMESPACE" in text["migrationRunner"]
            and "CRYPTA_APP_MIGRATION_INPUT" in text["migrationRunner"]
            and "CRYPTA_APP_MIGRATION_OUTPUT" in text["migrationRunner"]
            and "MigrationDataAccess" in text["migrationRunner"]
            and "importUpdateMigrationPayload" in text["appDataService"]
            and "MAX_CAPTURE_BYTES" in text["migrationRunner"]
            and 'List.of("/bin/sh"' not in text["migrationRunner"]
        ),
        "migrationRunnerFailsClosedWithoutContainment": (
            "ProcessBoundary" in text["migrationRunner"]
            and "new AppEnv()" in text["migrationRunner"]
            and "Process groups alone are not sufficient" in text["migrationRunner"]
            and "return unsupported();" in text["migrationRunner"]
            and "migration process containment is unavailable" in text["migrationRunner"]
            and "OUTPUT_DRAIN_TIMEOUT_MILLIS" in text["migrationRunner"]
            and "terminateProcessGroup" not in text["migrationRunner"]
            and "run_whenOnlyProcessGroupCleanupCouldBeBypassed_expectFailsClosedBeforeCommand"
            in text["migrationRunnerTest"]
            and "run_whenProcessBoundaryUnavailable_expectFailsClosedBeforeCommand"
            in text["migrationRunnerTest"]
        ),
        "updateSummariesExposeSafePlan": (
            '"dataMigration"' in text["updateCandidate"]
            and '"dataMigration"' in text["updateService"]
            and "AppDataMigrationPlan" in text["migrationPlan"]
            and "toJsonValue()" in text["migrationPlan"]
            and '"namespaces"' in text["migrationPlan"]
            and '"blockReason"' in text["migrationPlan"]
            and '"requiresStopped"' in text["migrationPlan"]
            and 'json.put("command"' not in text["migrationPlan"]
        ),
        "dryRunRunsBeforeStagingApply": (
            dry_run_index >= 0
            and staged_index > dry_run_index
            and apply_verify_index >= 0
            and apply_dry_run_index > apply_verify_index
            and "verifyStagedBundleBeforeStageDryRun" in text["updateService"]
            and "verifyStagedBundleAfterApplyDryRun" in text["updateService"]
            and "ERROR_APP_DATA_MIGRATION_DRY_RUN_FAILED" in text["updateService"]
            and "recordMigrationDryRunFailure" in text["updateService"]
            and "catalogManager.verifyInstallPlan" in text["updateService"]
            and "verifyInstallPlan" in text["catalogManager"]
            and "verifyInstallPlan_whenStagedBundleTampered_expectInvalidAppBundle"
            in text["catalogManagerTest"]
            and "stage_whenSchemaIncreaseHasNoMigrationStep_expectBlockedBeforeBundleReplacement"
            in text["updateServiceTest"]
            and "stage_whenStagedMigrationBundleVerificationFails_expectDryRunBlockedBeforeRunner"
            in text["updateServiceTest"]
            and "apply_whenStagedMigrationBundleVerificationFails_expectDryRunBlockedBeforeRunner"
            in text["updateServiceTest"]
            and "apply_whenMigrationDryRunMutatesStagedBundle_expectReverifiedBeforeInstall"
            in text["updateServiceTest"]
        ),
        "dryRunUsesTargetManifestQuota": (
            "targetManifest.dataQuotaBytes()" in text["updateService"]
            and "targetDataQuotaBytes" in text["appDataService"]
            and "ManifestQuotaCheck.targetManifest" in text["appDataService"]
            and "preflightUpdateMigrationDryRunPayloads" in text["appDataService"]
            and "advanceUpdateMigrationDryRunPayload_whenTargetManifestRaisesQuota_expectTargetQuotaUsed"
            in text["appDataServiceTest"]
            and "preflightUpdateMigrationDryRunPayloads_whenCombinedOutputExceedsRecordQuota_expectQuotaError"
            in text["appDataServiceTest"]
            and "stage_whenTargetManifestRaisesDataQuota_expectDryRunUsesTargetQuota"
            in text["updateServiceTest"]
        ),
        "chainedDryRunPreservesNamespaceTotals": (
            "withImportedRecordTotals" in text["appDataService"]
            and "recordCount" in text["appDataService"]
            and "totalBytes" in text["appDataService"]
            and "advanceUpdateMigrationDryRunPayload_whenChainedDryRun_expectNamespaceTotalsMatchRecords"
            in text["appDataServiceTest"]
            and "importedValueBytes" in text["appDataServiceTest"]
        ),
        "missingPathAndRollbackRiskBlock": (
            "STATUS_MISSING_MIGRATION" in text["migrationPlan"]
            and "ERROR_APP_DATA_MIGRATION_MISSING" in text["updateService"]
            and "ERROR_APP_DATA_MIGRATION_REVIEW_REQUIRED" in text["updateService"]
            and "ERROR_APP_DATA_MIGRATION_REQUIRES_STOPPED" in text["updateService"]
            and "ERROR_APP_DATA_MIGRATION_SANDBOX_UNAVAILABLE" in text["updateService"]
            and "targetManifest.sandboxPolicy().required()" in text["updateService"]
            and "isAutomaticPolicyMigrationSkip" in text["updateService"]
            and "bestMigrationPath" in text["updateService"]
            and "migrationAcknowledged" in text["updateHandler"]
            and "stage_whenMigrationRollbackIncompatibleWithoutAcknowledgement_expectReviewRequired"
            in text["updateServiceTest"]
            and "stage_whenStoppedRequiredMigrationAndAppRunning_expectBlockedBeforeDryRun"
            in text["updateServiceTest"]
            and "check_whenStagePolicyMigrationPathMissing_expectCandidateSummaryWithoutCheckFailure"
            in text["updateServiceTest"]
            and "check_whenStagePolicyMigrationDryRunFails_expectCandidateSummaryWithoutCheckFailure"
            in text["updateServiceTest"]
            and "check_whenStagePolicyMigrationDryRunThrows_expectCandidateSummaryWithoutCheckFailure"
            in text["updateServiceTest"]
            and "check_whenApplyWhenStoppedPolicyMigrationDryRunFails_expectCandidateSummaryWithoutApply"
            in text["updateServiceTest"]
            and "stage_whenMigrationBundleRequestsOptionalSandbox_expectDryRunAndStage"
            in text["updateServiceTest"]
            and "check_whenApplyWhenStoppedPolicySandboxMigration_expectCandidateSummaryWithoutApply"
            in text["updateServiceTest"]
            and "stage_whenMigrationHasDeadEndBranch_expectCompletePathSelected"
            in text["updateServiceTest"]
            and "stage_whenCompatibleChainCompetesWithIncompatibleDirectStep_expectCompatiblePathSelected"
            in text["updateServiceTest"]
        ),
        "snapshotBeforeReplacementAndRestoreOnFailure": (
            barrier_index >= 0
            and snapshot_index > barrier_index
            and replacement_index > snapshot_index
            and "closeUpdateMigrationWriteBarrier" in text["updateService"]
            and "shouldHoldApplyMigrationWriteBarrier" in text["updateService"]
            and "targetManifest.dataSchemaContract().declared()" in text["updateService"]
            and "runApplyMigrationOrRollback" in text["updateService"]
            and "rollbackAndRestoreSnapshot" in text["updateService"]
            and "markRollbackFailed" in text["updateService"]
            and "restoreUpdateSnapshot" in text["updateService"]
            and "Migration scratch cleanup is best effort" in text["updateService"]
            and "apply_whenMigrationRequiredAndRunnerPasses_expectSnapshotApplyAndSchemaMetadata"
            in text["updateServiceTest"]
            and "apply_whenChainedMigrationRunner_expectEachStepAppliedBeforeNextStep"
            in text["updateServiceTest"]
            and "apply_whenMigrationContractHasNoExistingDataAndWriteAppearsBeforeReplacement_expectWriteRejected"
            in text["updateServiceTest"]
            and "apply_whenMigrationApplyFailsAndBundleRollbackFails_expectMigrationFailurePreserved"
            in text["updateServiceTest"]
        ),
        "appDataWritesBlockedDuringMigrationApply": (
            "beginUpdateMigrationWriteBarrier" in text["appDataService"]
            and "app_data_migration_in_progress" in text["appDataService"]
            and "rejectIfUpdateMigrationWriteBarrierActive" in text["appDataService"]
            and "appFacingWrites_whenUpdateMigrationWriteBarrierActive_expectMigrationInProgressConflict"
            in text["appDataServiceTest"]
            and "updateMigrationImport_whenWriteBarrierActive_expectInternalMigrationWritesAllowed"
            in text["appDataServiceTest"]
            and "apply_whenAppDataWriteAttemptsDuringMigrationWindow_expectWriteRejectedAndBarrierReleased"
            in text["updateServiceTest"]
            and "apply_whenAppDataWriteAttemptsDuringFinalMigrationDryRun_expectWriteRejected"
            in text["updateServiceTest"]
        ),
        "webShellRendersMigrationStatus": (
            "App-data migration plan" in text["webShell"]
            and "migrationAcknowledged" in text["webShell"]
            and "migration-step-list" in text["webShell"]
            and "App-data migration blocker" in text["webShell"]
        ),
        "feedReaderDeclaresMigrationExample": (
            feed_manifest.get("app.data.schema.current") == "2"
            and feed_manifest.get("app.data.schema.namespace.ui-state.current") == "2"
            and feed_manifest.get("app.data.migration.ui-state-v1-v2.from") == "1"
            and feed_manifest.get("app.data.migration.ui-state-v1-v2.to") == "2"
            and feed_manifest.get("app.data.migration.ui-state-v1-v2.command")
            == "bin/migrate-feed-data.sh"
            and feed_manifest.get("app.data.migration.ui-state-v1-v2.rollbackCompatible")
            == "false"
            and "CRYPTA_APP_MIGRATION_MODE" in text["feedScript"]
            and "CRYPTA_APP_MIGRATION_INPUT" in text["feedScript"]
            and "CRYPTA_APP_MIGRATION_OUTPUT" in text["feedScript"]
            and "ui-state" in text["feedScript"]
            and "dry-run" in text["feedScript"]
            and "apply" in text["feedScript"]
        ),
        "trustGraphDeclaresMigrationExample": (
            trust_manifest.get("app.data.schema.current") == "2"
            and trust_manifest.get("app.data.schema.namespace.ui-state.current") == "2"
            and trust_manifest.get("app.data.migration.ui-state-v1-v2.from") == "1"
            and trust_manifest.get("app.data.migration.ui-state-v1-v2.to") == "2"
            and trust_manifest.get("app.data.migration.ui-state-v1-v2.command")
            == "bin/migrate-preview-data.sh"
            and trust_manifest.get("app.data.migration.ui-state-v1-v2.rollbackCompatible")
            == "false"
            and "CRYPTA_APP_MIGRATION_MODE" in text["trustScript"]
            and "CRYPTA_APP_MIGRATION_INPUT" in text["trustScript"]
            and "CRYPTA_APP_MIGRATION_OUTPUT" in text["trustScript"]
            and "ui-state" in text["trustScript"]
            and "dry-run" in text["trustScript"]
            and "apply" in text["trustScript"]
        ),
        "redactionAndDocsCoverScope": (
            "app-update.data-migration-contract" in docs_text
            and "rollback snapshot" in docs_text.lower()
            and "PR-250" in docs_text
            and "raw app-data values" in docs_text
            and "private insert URIs" in docs_text
            and "channel_policy_blocked" in text["updateService"]
            and "catalog.production-channels" in docs_text
        ),
    }
    details = {
        "checks": checks,
        "referenceApps": {
            "feed-reader": {
                "schema": feed_manifest.get("app.data.schema.current"),
                "migration": feed_manifest.get("app.data.migrations"),
            },
            "trust-graph": {
                "schema": trust_manifest.get("app.data.schema.current"),
                "migration": trust_manifest.get("app.data.migrations"),
            },
        },
        "redaction": {
            "rawAppDataValuesExcluded": True,
            "rawCommandLogsExcluded": True,
            "tokensExcluded": True,
            "privateInsertUrisExcluded": True,
            "stagingPathsExcluded": True,
        },
        "sources": {
            name: display_path(path, workspace) for name, path in source_files.items()
        },
    }
    errors = [key for key, passed in checks.items() if passed is not True]
    if errors:
        return EvidenceItem(
            "app-update.data-migration-contract",
            root_consequence(settings, "fail"),
            True,
            "App-data migration contract evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-update.data-migration-contract",
        "pass",
        True,
        "App-data migration contract evidence passed deterministic checks.",
        source,
        details,
    )

def read_first_manifest(workspace: Path, app_id: str, preferred: str) -> dict[str, str]:
    candidates = (
        workspace / preferred,
        workspace / f"apps/{app_id}/build/cryptad-app/{app_id}/cryptad-app.properties",
    )
    for path in candidates:
        if path.is_file():
            try:
                return parse_properties(path)
            except ValueError:
                return {}
    return {}

OPERATOR_BETA_EVIDENCE_IDS = (
    "operator-beta.dashboard",
    "operator-beta.catalog-health",
    "operator-beta.app-update-recovery",
    "operator-beta.subscription-recovery",
    "operator-beta.trust-review-warnings",
    "operator-beta.app-data-quota-warnings",
    "operator-beta.app-data-backup-restore",
    "operator-beta.support-bundle-redaction",
    "operator-beta.web-shell",
)

OPERATOR_RC_EVIDENCE_IDS = (
    "operator-rc.dashboard",
    "operator-rc.recovery-plan-execute",
    "operator-rc.catalog-repair",
    "operator-rc.app-reinstall-rollback",
    "operator-rc.export-before-uninstall",
    "operator-rc.subscription-recovery",
    "operator-rc.app-service-grant-recovery",
    "operator-rc.trust-graph-recovery",
    "operator-rc.network-budget-visibility",
    "operator-rc.support-bundle-wizard",
    "operator-rc.redaction",
)

PRIVACY_BETA_DIAGNOSTICS_EVIDENCE_ID = "app-platform.privacy-preserving-beta-diagnostics"

SUPPORT_BUNDLE_REDACTION_FIXTURES = (
    "support-bundle-redaction-safe.json",
    "support-bundle-redaction-private-insert-uri.json",
    "support-bundle-redaction-private-insert-uri-text.json",
    "support-bundle-redaction-token.json",
    "support-bundle-redaction-raw-profile.json",
    "support-bundle-redaction-raw-feed.json",
    "support-bundle-redaction-raw-trust-statement.json",
    "support-bundle-redaction-raw-social-message.json",
    "support-bundle-redaction-raw-app-data.json",
    "support-bundle-redaction-local-path.json",
    "support-bundle-redaction-private-key.json",
    "support-bundle-redaction-app-service-body.json",
    "support-bundle-redaction-nested-backup.json",
)

SUPPORT_BUNDLE_SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "cookie",
        "token",
        "privateinserturi",
        "privatekey",
        "identitymaterial",
        "vaultidentitymaterial",
        "rawprofiledocument",
        "rawfeedsnapshot",
        "rawtruststatement",
        "rawsocialmessage",
        "rawappdata",
        "rawappdatavalue",
        "appserviceinvocationbody",
        "backuppayload",
        "backuppayloadbase64",
        "payloadbase64",
        "localpath",
        "path",
    }
)

SUPPORT_BUNDLE_CONTENT_URI_RE = re.compile(r"(?i)\b(?:crypta:)?(?:CHK|SSK|USK|KSK)@[^\s\"'<>)}\]]+")

SUPPORT_BUNDLE_BEARER_TOKEN_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~-]+")

SUPPORT_BUNDLE_LOCAL_PATH_RE = re.compile(r"(?i)(?:/work/|/home/|/Users/|C:\\\\|file:/)[^\s\"'<>)}\]]*")

def operator_beta_evidence_item(
    settings: Settings,
    evidence_id: str,
    checks: dict[str, bool],
    pass_summary: str,
    details: dict[str, Any],
) -> EvidenceItem:
    errors = [key for key, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            evidence_id,
            root_consequence(settings, "fail"),
            True,
            f"{evidence_id} evidence is incomplete.",
            summary_source(settings),
            {"errors": errors, **details},
        )
    return EvidenceItem(evidence_id, "pass", True, pass_summary, summary_source(settings), details)
