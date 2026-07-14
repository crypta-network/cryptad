"""Implementation segment for the operations portion of ``app_platform_smoke.py``."""

from __future__ import annotations

def collect_operator_beta_evidence(settings: Settings) -> list[EvidenceItem]:
    workspace = settings.workspace_root
    service_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/operator/OperatorBetaDashboardService.java"
    )
    routes_source = workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiOperatorRoutes.java"
    router_source = workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiRouter.java"
    redactor_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/operator/OperatorSupportRedactor.java"
    )
    recovery_service_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/operator/recovery/OperatorRecoveryService.java"
    )
    recovery_action_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/operator/recovery/OperatorRecoveryActionId.java"
    )
    recovery_target_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/operator/recovery/OperatorRecoveryTarget.java"
    )
    subscription_service_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionService.java"
    )
    subscription_record_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/ContentSubscription.java"
    )
    operator_routes_test_source = (
        workspace
        / "platform-api/src/test/java/network/crypta/platform/api/PlatformApiOperatorRoutesTest.java"
    )
    recovery_service_test_source = (
        workspace
        / "platform-api/src/test/java/network/crypta/platform/api/operator/recovery/OperatorRecoveryServiceTest.java"
    )
    redactor_test_source = (
        workspace
        / "platform-api/src/test/java/network/crypta/platform/api/operator/OperatorSupportRedactorTest.java"
    )
    toadlet_source = (
        workspace / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/PlatformApiToadlet.java"
    )
    toadlet_test_source = workspace / "src/test/java/network/crypta/clients/http/PlatformApiToadletTest.java"
    web_shell_source = (
        workspace
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    )
    web_shell_index_source = (
        workspace
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/index.html"
    )
    web_shell_test_source = (
        workspace
        / "platform-web-shell/src/test/java/network/crypta/platform/webshell/WebShellResourcesTest.java"
    )
    docs_source = workspace / "docs/operator-beta-dashboard.md"
    rc_docs_source = workspace / "docs/operator-rc-recovery-and-support-workflow.md"
    beta_program_doc = workspace / "docs/app-platform-beta-program.md"
    limitations_doc = workspace / "docs/app-platform-beta-known-limitations.md"
    api_surface_doc = workspace / "docs/platform-api-surface.md"

    service_text = read_source(service_source)
    routes_text = read_source(routes_source)
    router_text = read_source(router_source)
    redactor_text = read_source(redactor_source)
    recovery_service_text = read_source(recovery_service_source)
    recovery_action_text = read_source(recovery_action_source)
    recovery_target_text = read_source(recovery_target_source)
    subscription_service_text = read_source(subscription_service_source)
    subscription_record_text = read_source(subscription_record_source)
    operator_routes_test_text = read_source(operator_routes_test_source)
    recovery_service_test_text = read_source(recovery_service_test_source)
    redactor_test_text = read_source(redactor_test_source)
    toadlet_text = read_source(toadlet_source)
    toadlet_test_text = read_source(toadlet_test_source)
    web_shell_text = read_source(web_shell_source)
    web_shell_index_text = read_source(web_shell_index_source)
    web_shell_test_text = read_source(web_shell_test_source)
    docs_text = read_source(docs_source)
    rc_docs_text = read_source(rc_docs_source)
    beta_program_text = read_source(beta_program_doc)
    limitations_text = read_source(limitations_doc)
    api_surface_text = read_source(api_surface_doc)
    operator_docs_text = docs_text + "\n" + rc_docs_text
    recovery_service_compact_text = compact_source_text(recovery_service_text)
    web_shell_test_search_text = java_string_search_text(web_shell_test_text)
    form_password_redaction_test = (
        "FORM_FIELD_ASSIGNMENT" in operator_routes_test_text
        and '"form" + "Pass" + "word=secret-value"' in operator_routes_test_text
        and "contains(FORM_FIELD_ASSIGNMENT)" in operator_routes_test_text
    )
    shared_details = {
        "liveNodeRequired": False,
        "hostOperatorOnly": True,
        "operatorRoutesExcludedFromAppContract": True,
        "sources": {
            "service": display_path(service_source, workspace),
            "routes": display_path(routes_source, workspace),
            "router": display_path(router_source, workspace),
            "redactor": display_path(redactor_source, workspace),
            "recoveryService": display_path(recovery_service_source, workspace),
            "recoveryActions": display_path(recovery_action_source, workspace),
            "subscriptionService": display_path(subscription_service_source, workspace),
            "subscriptionRecord": display_path(subscription_record_source, workspace),
            "operatorRoutesTest": display_path(operator_routes_test_source, workspace),
            "recoveryServiceTest": display_path(recovery_service_test_source, workspace),
            "redactorTest": display_path(redactor_test_source, workspace),
            "toadlet": display_path(toadlet_source, workspace),
            "toadletTest": display_path(toadlet_test_source, workspace),
            "webShell": display_path(web_shell_source, workspace),
            "webShellIndex": display_path(web_shell_index_source, workspace),
            "webShellTest": display_path(web_shell_test_source, workspace),
            "docs": display_path(docs_source, workspace),
            "rcDocs": display_path(rc_docs_source, workspace),
        },
    }

    evidence_specs = [
        (
            "operator-beta.dashboard",
            {
                "dashboardRoute": (
                    '"beta-dashboard".equals(resource)' in routes_text
                    and "dashboardService.dashboard()" in routes_text
                    and 'case "operator" -> operatorRoutes.route(segments, request);' in router_text
                ),
                "hostOperatorOnly": (
                    "requireHostOperator(request)" in routes_text
                    and "host_operator_required" in routes_text
                    and "route_whenAppPrincipalRequestsOperatorDashboard_expectForbiddenBeforeDispatch"
                    in operator_routes_test_text
                ),
                "dashboardSections": all(
                    fragment in service_text
                    for fragment in (
                        '"overallStatus"',
                        '"summary"',
                        '"catalogs"',
                        '"apps"',
                        '"subscriptions"',
                        '"trustGraph"',
                        '"appServices"',
                        '"legacyAdmin"',
                        '"diagnostics"',
                        '"recoveryActions"',
                    )
                ),
                "docs": "operator-beta.dashboard" in docs_text and "host/operator-only" in docs_text,
            },
            "Operator beta dashboard route, auth, and section evidence passed.",
        ),
        (
            "operator-beta.catalog-health",
            {
                "catalogSummary": (
                    "catalogSummary(Map<String, Object> catalog)" in service_text
                    and '"trustedCatalogKeyStatus"' in service_text
                    and '"lastFetchStatus"' in service_text
                    and '"recommendedFirstPartyPresent"' in service_text
                    and "safeSourceDisplay(source, sourceKind)" in service_text
                ),
                "catalogRecoveryAction": (
                    '"refresh-catalog"' in service_text
                    and '"app-catalogs/" + encodePathSegment(catalogId) + "/refresh"' in service_text
                ),
                "catalogUi": "function renderBetaCatalogs(catalogs)" in web_shell_text,
                "docs": "operator-beta.catalog-health" in docs_text,
            },
            "Operator beta catalog health evidence passed.",
        ),
        (
            "operator-beta.app-update-recovery",
            {
                "appRecoveryActions": all(
                    fragment in service_text
                    for fragment in (
                        '"check-app-update"',
                        '"stage-app-update"',
                        '"apply-app-update"',
                        '"rollback-app"',
                        '"open-app-logs"',
                    )
                ),
                "noPreserveUninstallInUi": (
                    "operatorRecoveryActionVisible(action)" in web_shell_text
                    and 'actionId !== "preserve-data-uninstall"' in web_shell_text
                ),
                "appRecoveryUi": "function renderBetaApps(apps)" in web_shell_text,
                "docs": "operator-beta.app-update-recovery" in docs_text,
            },
            "Operator beta app-update recovery evidence passed.",
        ),
        (
            "operator-beta.subscription-recovery",
            {
                "operatorList": "listAllForOperator()" in subscription_service_text,
                "subscriptionRoutes": all(
                    fragment in routes_text for fragment in ('case "refresh"', 'case "pause"', 'case "resume"')
                ),
                "subscriptionActions": all(
                    fragment in service_text
                    for fragment in (
                        '"refresh-subscription"',
                        '"pause-subscription"',
                        '"resume-subscription"',
                        '"operator/subscriptions/"',
                    )
                ),
                "formPasswordGuard": (
                    "requiresOperatorFormPassword" in toadlet_text
                    and "/operator/subscriptions/feed-reader/sub-123/refresh" in toadlet_test_text
                ),
                "appPrincipalDenied": (
                    "route_whenAppPrincipalUsesOperatorSubscriptionWrapper_expectForbidden"
                    in operator_routes_test_text
                ),
                "docs": "operator-beta.subscription-recovery" in docs_text,
            },
            "Operator beta subscription recovery evidence passed.",
        ),
        (
            "operator-beta.trust-review-warnings",
            {
                "trustPreviewWarning": (
                    "Trust Graph Local RC is local operator-curated state only"
                    in service_text
                    and '"previewOnly"' in service_text
                    and '"completeWot"' in service_text
                    and '"scope"' in service_text
                    and '"statementLifecycle"' in service_text
                ),
                "appReviewSurface": (
                    '"reviewTrust"' in service_text
                    and "renderBetaTrustAndServices(trustGraph, appServices)" in web_shell_text
                    and "Trust Graph Local RC" in web_shell_text
                ),
                "docs": (
                    "operator-beta.trust-review-warnings" in docs_text
                    and "not global truth" in docs_text
                ),
            },
            "Operator beta trust and review-warning evidence passed.",
        ),
        (
            "operator-beta.app-data-quota-warnings",
            {
                "appDataSummary": "appDataSummary(appId)" in service_text and '"appData"' in service_text,
                "quotaWarnings": (
                    "app_data_quota_unavailable" in service_text
                    and "apphost_quota_over_limit" in service_text
                    and '"quotaWarningCount"' in service_text
                ),
                "quotaUi": (
                    '"Quota warnings"' in web_shell_text
                    and '"Data quota"' in web_shell_text
                    and "quota.dataOverLimit || quota.cacheOverLimit" in web_shell_text
                ),
                "docs": "operator-beta.app-data-quota-warnings" in docs_text,
            },
            "Operator beta app-data and quota-warning evidence passed.",
        ),
        (
            "operator-beta.app-data-backup-restore",
            {
                "backupRestoreRoutes": (
                    "routeAppDataBackup" in routes_text
                    and "methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE)" in routes_text
                    and "routeAppDataRestoreCommit" in routes_text
                    and "routeAppDataRestore(" in routes_text
                    and "app_data_service_unavailable" in routes_text
                    and "requireHostOperator(request)" in routes_text
                ),
                "formPasswordGuard": (
                    "requiresOperatorFormPassword" in toadlet_text
                    and "/operator/app-data/backups" in toadlet_test_text
                    and "/operator/app-data/restore/plan" in toadlet_test_text
                    and "/operator/app-data/restore" in toadlet_test_text
                ),
                "appPrincipalDenied": (
                    "route_whenAppPrincipalRequestsAppDataBackupRestore_expectForbidden"
                    in operator_routes_test_text
                ),
                "webShellControls": (
                    "downloadAllAppDataBackup()" in web_shell_text
                    and "submitAppDataRestoreForm(" in web_shell_text
                    and "setBetaDashboardStatus" in web_shell_text
                    and "Export backup before delete" in web_shell_text
                    and 'id="all-app-data-backup-button"' in web_shell_index_text
                    and 'id="operator-app-data-restore-form"' in web_shell_index_text
                ),
                "resourceTests": (
                    "assertAppDataBackupRestoreMarkersPresent(script)" in web_shell_test_text
                ),
                "docs": (
                    "operator-beta.app-data-backup-restore" in docs_text
                    and "app-data.backup-restore-portability" in docs_text
                ),
            },
            "Operator beta app-data backup/restore evidence passed.",
        ),
        (
            "operator-beta.support-bundle-redaction",
            {
                "supportBundleRoute": (
                    '"support-bundle".equals(resource)' in routes_text
                    and "supportBundle()" in routes_text
                ),
                "redactorApplied": (
                    "OperatorSupportRedactor.redact(dashboard)" in service_text
                    and "OperatorSupportRedactor.redact(diagnostics)" in service_text
                    and "OperatorSupportRedactor.redact(recentAudit)" in service_text
                ),
                "sensitiveFieldsOmitted": all(
                    fragment in redactor_text
                    for fragment in (
                        '"formpassword"',
                        '"browsersession"',
                        '"requestbody"',
                        '"rawbody"',
                        '"sourcepath"',
                        '"rollbackpath"',
                    )
                ),
                "redactionTests": (
                    "route_whenSupportBundleIncludesSensitiveDiagnostics_expectRedactedOutput"
                    in operator_routes_test_text
                    and "/work/private/catalog" in operator_routes_test_text
                    and form_password_redaction_test
                    and "redact_whenNestedSecretsPathsAndContentUrisPresent_expectUnsafeValuesRemoved"
                    in redactor_test_text
                    and "/work/cryptad/private.txt" in redactor_test_text
                    and "query-secret" in redactor_test_text
                ),
                "docs": (
                    "operator-beta.support-bundle-redaction" in docs_text
                    and "reviewed by the operator before sharing" in docs_text
                    and "raw request bodies" in limitations_text
                ),
            },
            "Operator beta support-bundle redaction evidence passed.",
        ),
        (
            "operator-beta.web-shell",
            {
                "panelMarkup": (
                    'id="beta-dashboard"' in web_shell_index_text
                    and 'id="beta-dashboard-body"' in web_shell_index_text
                    and 'id="support-bundle-download-button"' in web_shell_index_text
                ),
                "loadsOperatorEndpoints": (
                    'loadJson(apiUrl("operator/beta-dashboard"))' in web_shell_text
                    and 'loadJson(apiUrl("operator/support-bundle"))' in web_shell_text
                ),
                "supportControls": all(
                    fragment in web_shell_text
                    for fragment in (
                        "downloadSupportBundle()",
                        "copySupportSummary()",
                        "supportBundleSnapshot",
                    )
                ),
                "recoverySubmitHandler": (
                    "submitOperatorRecoveryAction(form)" in web_shell_text
                    and 'sections.betaDashboard.addEventListener("submit"' in web_shell_text
                ),
                "resourceTests": (
                    "assertBetaDashboardMarkersPresent(script)" in web_shell_test_text
                    and "assertBetaDashboardLoadSequencing(script)" in web_shell_test_text
                ),
                "docs": (
                    "operator-beta.web-shell" in docs_text
                    and "Operator beta dashboard" in beta_program_text
                    and "Operator" in api_surface_text
                ),
            },
            "Operator beta Web Shell evidence passed.",
        ),
        (
            "operator-rc.dashboard",
            {
                "rcDashboardRoute": (
                    '"rc-dashboard".equals(resource)' in routes_text
                    and '"operator-rc-recovery-dashboard"' in routes_text
                    and '"operatorRcRecovery"' in routes_text
                ),
                "hostOperatorOnly": (
                    "requireHostOperator(request)" in routes_text
                    and "route_whenAppPrincipalRequestsOperatorRcRecovery_expectForbiddenBeforeDispatch"
                    in operator_routes_test_text
                ),
                "webShellRcFirst": (
                    'loadJson(apiUrl("operator/rc-dashboard"))' in web_shell_text
                    and "rcCompatibilityFallback" in web_shell_text
                    and "Operator RC Recovery" in web_shell_index_text
                ),
                "docs": "operator-rc.dashboard" in operator_docs_text,
            },
            "Operator RC dashboard evidence passed.",
        ),
        (
            "operator-rc.recovery-plan-execute",
            {
                "typedModels": (
                    "enum OperatorRecoveryActionId" in recovery_action_text
                    and "fromJsonValue" in recovery_action_text
                    and "OperatorRecoveryPlan" in recovery_service_text
                    and "OperatorRecoveryResult" in recovery_service_text
                ),
                "closedDispatch": (
                    "executePlanned(OperatorRecoveryPlan plan)" in recovery_service_text
                    and "switch (action)" in recovery_service_text
                    and '"unknown_recovery_action"' in recovery_service_text
                    and "some/arbitrary/path" in operator_routes_test_text
                    and "execute_whenSupportPreviewIncludesArbitraryPathParameter_expectIgnored"
                    in recovery_service_test_text
                ),
                "routes": (
                    'case "actions"' in routes_text
                    and 'case "plan"' in routes_text
                    and 'case "execute"' in routes_text
                ),
                "confirmation": (
                    "recovery_confirmation_required" in recovery_service_text
                    and "route_whenRecoveryExecuteMissingConfirmationForDestructiveAction_expectConflict"
                    in operator_routes_test_text
                ),
                "planTokenRequired": (
                    "PARAM_PLAN_TOKEN" in recovery_service_text
                    and "issuePlanToken" in recovery_service_text
                    and "requireIssuedPlanToken" in recovery_service_text
                    and "recovery_plan_required" in recovery_service_text
                    and "recovery_plan_mismatch" in recovery_service_text
                    and 'operatorRcSubmitButton("Plan", "plan", false)' in web_shell_text
                    and 'operatorRcSubmitButton("Execute", "execute", action.destructive === true)'
                    in web_shell_text
                    and "planTokenInput.name = \"planToken\"" in web_shell_text
                    and "execute_whenPlanTokenMissing_expectConflictBeforeDispatch"
                    in recovery_service_test_text
                    and "route_whenRecoveryExecuteMissingPlanToken_expectConflict"
                    in operator_routes_test_text
                ),
                "formPasswordGuard": (
                    "/operator/recovery/plan" in toadlet_test_text
                    and "/operator/recovery/execute" in toadlet_test_text
                ),
                "docs": "operator-rc.recovery-plan-execute" in operator_docs_text,
            },
            "Operator RC recovery plan/execute evidence passed.",
        ),
        (
            "operator-rc.catalog-repair",
            {
                "actionIds": all(
                    fragment in recovery_action_text
                    for fragment in (
                        '"catalog.refresh"',
                        '"catalog.reverify"',
                        '"catalog.repair-first-party-source"',
                    )
                ),
                "usesCatalogGates": (
                    "appCatalogsApiHandler.refresh(target.catalogId())" in recovery_service_text
                    and "appCatalogsApiHandler.addRecommended(target.catalogId())"
                    in recovery_service_text
                    and "reverifiedCatalog(target.catalogId())" in recovery_service_text
                ),
                "docs": "operator-rc.catalog-repair" in operator_docs_text,
            },
            "Operator RC catalog repair evidence passed.",
        ),
        (
            "operator-rc.app-reinstall-rollback",
            {
                "actionIds": all(
                    fragment in recovery_action_text
                    for fragment in (
                        '"app.rollback"',
                        '"app.reinstall-from-catalog"',
                        '"app.check-update"',
                        '"app.stage-update"',
                        '"app.apply-update"',
                    )
                ),
                "rollbackUsesUpdateService": "appUpdateService.rollback(target.appId(), false)"
                in recovery_service_text,
                "reinstallBlockedUntilSafeApi": (
                    "A dedicated verified catalog reinstall API is not available."
                    in recovery_service_text
                ),
                "runningGuardVisible": "App must be stopped before rollback." in recovery_service_text,
                "startPlanMetadata": (
                    "actionId == OperatorRecoveryActionId.APP_START" in recovery_service_text
                    and "plan_whenAppStartRequested_expectStoppedAppRequirementReported"
                    in recovery_service_test_text
                ),
                "docs": "operator-rc.app-reinstall-rollback" in operator_docs_text,
            },
            "Operator RC app rollback/reinstall evidence passed.",
        ),
        (
            "operator-rc.export-before-uninstall",
            {
                "actionId": '"app.export-before-uninstall"' in recovery_action_text,
                "backupThenUninstall": (
                    "appDataService.exportBackup" in recovery_service_text
                    and "currentCryptaVersion.get()" in recovery_service_text
                    and "appsApiHandler.uninstall(target.appId(), false, true)"
                    in recovery_service_text
                    and "clearAppStateAfterRecoveryUninstall(target.appId())"
                    in recovery_service_text
                    and "appRoutes::clearAppStateAfterUninstall" in routes_text
                    and "execute_whenExportBeforeUninstallSucceeds_expectRelatedAppStateCleared"
                    in recovery_service_test_text
                    and "uninstallFailure" in recovery_service_text
                    and "execute_whenExportBeforeUninstallFailsAfterBackup_expectPartialResultWithSensitiveBackup"
                    in recovery_service_test_text
                    and "partialExportBeforeUninstallResult" in recovery_service_text
                    and "execute_whenExportBeforeUninstallCleanupFails_expectPartialResultWithSensitiveBackup"
                    in recovery_service_test_text
                    and "sourceCryptaVersion()" in recovery_service_test_text
                    and '"sensitiveBackup"' in read_source(
                        workspace
                        / "platform-api/src/main/java/network/crypta/platform/api/operator/recovery/OperatorRecoveryResult.java"
                    )
                ),
                "supportBundleExcludesPayload": (
                    "payloadBase64" in redactor_test_text
                    and "route_whenSupportBundlePreviewRequested_expectRedactionMetadataAndRecoveryContext"
                    in operator_routes_test_text
                ),
                "docs": "operator-rc.export-before-uninstall" in operator_docs_text,
            },
            "Operator RC export-before-uninstall evidence passed.",
        ),
        (
            "operator-rc.subscription-recovery",
            {
                "actionIds": all(
                    fragment in recovery_action_text
                    for fragment in (
                        '"subscription.refresh"',
                        '"subscription.pause"',
                        '"subscription.resume"',
                        '"subscription.reset-backoff"',
                        '"subscription.reschedule-now"',
                        '"subscription.delete"',
                    )
                ),
                "metadataOnlyMutations": (
                    "resetBackoff(String appId, String subscriptionId)" in subscription_service_text
                    and "rescheduleNow(String appId, String subscriptionId)"
                    in subscription_service_text
                    and "withBackoffReset" in subscription_record_text
                    and "withRescheduledNow" in subscription_record_text
                ),
                "tests": (
                    "resetBackoff_whenSubscriptionFailed_expectMetadataClearedWithoutFetch"
                    in read_source(
                        workspace
                        / "platform-api/src/test/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionServiceTest.java"
                    )
                    and "route_whenOperatorResetsSubscriptionBackoff_expectNoFetchAndRedactedSummary"
                    in operator_routes_test_text
                ),
                "docs": "operator-rc.subscription-recovery" in operator_docs_text,
            },
            "Operator RC subscription recovery evidence passed.",
        ),
        (
            "operator-rc.app-service-grant-recovery",
            {
                "actionIds": all(
                    fragment in recovery_action_text
                    for fragment in (
                        '"app-service.grant-revoke"',
                        '"app-service.bundle-renew"',
                        '"app-service.bundle-revalidate"',
                        '"app-service.bundle-reject"',
                    )
                ),
                "usesCoordinator": (
                    "appServiceCoordinator.revokeGrant" in recovery_service_text
                    and "appServiceCoordinator.renewBundle" in recovery_service_text
                    and "appServiceCoordinator.rejectBundle" in recovery_service_text
                ),
                "docs": "operator-rc.app-service-grant-recovery" in operator_docs_text,
            },
            "Operator RC app-service grant recovery evidence passed.",
        ),
        (
            "operator-rc.trust-graph-recovery",
            {
                "actionIds": all(
                    fragment in recovery_action_text
                    for fragment in (
                        '"trust-graph.export-summary"',
                        '"trust-graph.reset-local-state"',
                        '"trust-graph.clear-audit"',
                        '"trust-graph.recompute-summary"',
                    )
                ),
                "metadataOnlyExport": (
                    "trustGraphExportSummary()" in recovery_service_text
                    and '"metadataOnly"' in recovery_service_text
                    and "trustGraphApiHandler.statements(Map.of())" in recovery_service_text
                    and "catch (TrustGraphException exception)" in recovery_service_text
                    and "mappedTrustGraphException(exception)" in recovery_service_text
                    and "execute_whenTrustGraphStoreUnavailable_expectFailedResultInsteadOfThrownException"
                    in recovery_service_test_text
                ),
                "resetUnavailable": (
                    "Trust Graph stores do not expose a tested local-state reset API."
                    in recovery_service_text
                    and "plan_whenTrustGraphResetRequested_expectUnavailableInsteadOfFakeSuccess"
                    in recovery_service_test_text
                ),
                "docs": "operator-rc.trust-graph-recovery" in operator_docs_text,
            },
            "Operator RC Trust Graph recovery evidence passed.",
        ),
        (
            "operator-rc.network-budget-visibility",
            {
                "route": (
                    '"network-budgets".equals(resource)' in routes_text
                    and "recoveryService.networkBudgets()" in routes_text
                ),
                "snapshots": (
                    "networkBudgetService.snapshots()" in recovery_service_text
                    and "AppNetworkBudgetSnapshot::toJson" in recovery_service_text
                    and "route_whenOperatorRequestsNetworkBudgets_expectSafeSnapshotsOnly"
                    in operator_routes_test_text
                ),
                "docs": "operator-rc.network-budget-visibility" in operator_docs_text,
            },
            "Operator RC network budget visibility evidence passed.",
        ),
        (
            "operator-rc.support-bundle-wizard",
            {
                "previewRoute": (
                    '"support-bundle".equals(segments.get(1)) && "preview".equals(segments.get(2))'
                    in routes_text
                    and "supportBundlePreview" in recovery_service_text
                ),
                "recoveryActionArtifacts": (
                    "supportBundleSupplier.get()" in recovery_service_text
                    and "recoverySupportBundle()" in recovery_service_text
                    and 'redactedDetails("supportBundlePreview",supportBundlePreview(recoverySupportBundle()))'
                    in recovery_service_compact_text
                    and 'redactedDetails("supportBundle",recoverySupportBundle())'
                    in recovery_service_compact_text
                    and "execute_whenSupportBundlePreviewRequested_expectRealPreviewArtifactBuilt"
                    in recovery_service_test_text
                    and "execute_whenSupportBundleExportRequested_expectRedactedBundleArtifactReturned"
                    in recovery_service_test_text
                ),
                "webShellPreview": (
                    (
                        'loadJson(apiUrl("operator/support-bundle/preview"))' in web_shell_text
                        or 'apiUrl("operator/support-bundle/preview")' in web_shell_text
                    )
                    and "supportBundlePreviewSnapshot" in web_shell_text
                    and "appendOperatorRcSupportBundleArtifact(container, result)"
                    in web_shell_text
                    and "downloadJsonBlob(supportBundle, supportBundleFileName(supportBundle))"
                    in web_shell_text
                    and "operatorRcResultPreservesVisibleArtifact(result)" in web_shell_text
                ),
                "resourceTests": (
                    (
                        'loadJson(apiUrl("operator/support-bundle/preview"))'
                        in web_shell_test_search_text
                        or 'apiUrl("operator/support-bundle/preview")'
                        in web_shell_test_search_text
                    )
                    and "Operator RC recovery actions unavailable in read-only mode."
                    in web_shell_test_text
                ),
                "docs": "operator-rc.support-bundle-wizard" in operator_docs_text,
            },
            "Operator RC support-bundle wizard evidence passed.",
        ),
        (
            "operator-rc.redaction",
            {
                "supportContext": "recoveryContext" in routes_text and "supportContext()" in recovery_service_text,
                "auditTargetRedaction": (
                    "safeAuditTargetId(target)" in recovery_service_text
                    and "redactedMap(json)" in recovery_service_text
                    and "safeIdentifier(value.trim())" in recovery_target_text
                    and "OperatorSupportRedactor.redact(value).value()" in recovery_target_text
                    and "safePrimaryId()" in recovery_target_text
                    and "fingerprintSource()" in recovery_target_text
                    and "target.fingerprintSource()" in recovery_service_text
                    and "target.safePrimaryId()" in recovery_service_text
                    and "planResultAndSupportContext_whenUnsafeTargetIdSupplied_expectTargetIdRedacted"
                    in recovery_service_test_text
                    and "plan_whenDestructiveUnsafeTargetIdSupplied_expectConfirmationPhraseRedacted"
                    in recovery_service_test_text
                    and '"plantoken"' in redactor_text
                ),
                "redactorTest": (
                    "redact_whenOperatorRcRecoveryContextContainsSecrets_expectUnsafeValuesRemoved"
                    in redactor_test_text
                    and "rawTrustStatementBody" in redactor_test_text
                    and "payloadBase64" in redactor_test_text
                    and "stagedBundlePath" in redactor_test_text
                ),
                "ordinaryPanelsNoRawJsonDump": (
                    "renderOperatorRcPlan(container, plan)" in web_shell_text
                    and "renderOperatorRcResult(container, result)" in web_shell_text
                    and "appendOperatorRcResultSteps(container, result.steps)" in web_shell_text
                    and "appendOperatorRcResultDetails(container, result.details)" in web_shell_text
                    and "appendOperatorRcSupportBundleArtifact(container, result)"
                    in web_shell_text
                    and "operatorRcBoundedScalar(value)" in web_shell_text
                    and "operatorRcResultPreservesVisibleArtifact(result)" in web_shell_text
                    and "!operatorRcResultPreservesVisibleArtifact(result)" in web_shell_text
                    and "JSON.stringify(response" not in web_shell_text
                ),
                "docs": "operator-rc.redaction" in operator_docs_text,
            },
            "Operator RC redaction evidence passed.",
        ),
    ]

    return [
        operator_beta_evidence_item(
            settings,
            evidence_id,
            checks,
            pass_summary,
            {**shared_details, "checks": checks},
        )
        for evidence_id, checks, pass_summary in evidence_specs
    ]

def support_bundle_fixture_findings(value: Any, path: str = "$") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for raw_key, child in value.items():
            key = str(raw_key)
            normalized = re.sub(r"[^A-Za-z0-9]", "", key).lower()
            child_path = f"{path}.{key}"
            if normalized in SUPPORT_BUNDLE_SENSITIVE_KEYS:
                findings.append("sensitive-key")
            findings.extend(support_bundle_fixture_findings(child, child_path))
        return findings
    if isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(support_bundle_fixture_findings(child, f"{path}[{index}]"))
        return findings
    if isinstance(value, str):
        if re.search(r"(?i)\b(?:crypta:)?(?:CHK|SSK|USK|KSK)@", value):
            findings.append("content-uri")
        if re.search(r"(?i)\bBearer\s+[A-Za-z0-9._~-]+", value):
            findings.append("bearer-token")
        if "-----BEGIN PRIVATE KEY-----" in value or "-----BEGIN OPENSSH PRIVATE KEY-----" in value:
            findings.append("private-key")
        if re.search(r"(?i)(?:/work/|/home/|/Users/|C:\\\\|file:/)", value):
            findings.append("local-path")
        if "crypta-app-data-backup" in value:
            findings.append("app-data-backup")
    return findings

def java_string_literal(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)

def support_bundle_java_literal(value: Any) -> str:
    if isinstance(value, dict):
        entries: list[str] = []
        for raw_key, child in value.items():
            entries.append(java_string_literal(str(raw_key)))
            entries.append(support_bundle_java_literal(child))
        return f"map({', '.join(entries)})"
    if isinstance(value, list):
        return f"list({', '.join(support_bundle_java_literal(child) for child in value)})"
    if isinstance(value, str):
        return java_string_literal(value)
    if isinstance(value, bool):
        return "Boolean.TRUE" if value else "Boolean.FALSE"
    if value is None:
        return "null"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    return java_string_literal(str(value))

def support_bundle_java_string_set_literal(values: frozenset[str] | set[str]) -> str:
    return "Set.of(" + ", ".join(java_string_literal(value) for value in sorted(values)) + ")"

def support_bundle_redactor_fixture_runner_source(
    fixture_values: dict[str, dict[str, Any]],
) -> str:
    fixture_entries = []
    for fixture_name in SUPPORT_BUNDLE_REDACTION_FIXTURES:
        if fixture_name not in fixture_values:
            continue
        fixture_entries.append(
            "    fixtures.add(new Fixture("
            + java_string_literal(fixture_name)
            + ", "
            + ("true" if fixture_name.endswith("-safe.json") else "false")
            + ", "
            + support_bundle_java_literal(fixture_values[fixture_name])
            + "));"
        )
    return (
        """
package network.crypta.platform.api.operator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

final class SupportBundleRedactorFixtureRunner {
  private static final Set<String> SENSITIVE_KEYS = """
        + support_bundle_java_string_set_literal(SUPPORT_BUNDLE_SENSITIVE_KEYS)
        + """;
  private static final Pattern CONTENT_URI =
      Pattern.compile("(?i)\\\\b(?:crypta:)?(?:CHK|SSK|USK|KSK)@");
  private static final Pattern BEARER_TOKEN =
      Pattern.compile("(?i)\\\\bBearer\\\\s+[A-Za-z0-9._~-]+");
  private static final Pattern LOCAL_PATH =
      Pattern.compile("(?i)(?:/work/|/home/|/Users/|C:\\\\\\\\|file:/)");

  public static void main(String[] args) {
    List<Fixture> fixtures = new ArrayList<>();
"""
        + "\n".join(fixture_entries)
        + """
    boolean passed = true;
    for (Fixture fixture : fixtures) {
      List<String> rawFindings = findings(fixture.value());
      OperatorSupportRedactor.RedactionResult result =
          OperatorSupportRedactor.redact(fixture.value());
      List<String> redactedFindings = findings(result.value());
      boolean fixturePassed =
          fixture.expectedSafe()
              ? rawFindings.isEmpty() && redactedFindings.isEmpty()
              : !rawFindings.isEmpty() && redactedFindings.isEmpty();
      if (!fixturePassed) {
        passed = false;
      }
      System.out.println(
          String.join(
              "\\t",
              "RESULT",
              fixture.name(),
              fixturePassed ? "pass" : "fail",
              Boolean.toString(fixture.expectedSafe()),
              Integer.toString(rawFindings.size()),
              Integer.toString(redactedFindings.size()),
              Integer.toString(result.omittedFields().size()),
              String.join("|", rawFindings),
              String.join("|", redactedFindings)));
    }
    if (!passed) {
      System.exit(1);
    }
  }

  private static List<String> findings(Object value) {
    List<String> findings = new ArrayList<>();
    appendFindings(value, findings);
    return findings;
  }

  private static void appendFindings(Object value, List<String> findings) {
    if (value instanceof Map<?, ?> map) {
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        String key = String.valueOf(entry.getKey());
        if (SENSITIVE_KEYS.contains(normalize(key))) {
          findings.add("sensitive-key");
        }
        appendFindings(entry.getValue(), findings);
      }
      return;
    }
    if (value instanceof List<?> list) {
      for (Object child : list) {
        appendFindings(child, findings);
      }
      return;
    }
    if (value instanceof String text) {
      if (CONTENT_URI.matcher(text).find()) {
        findings.add("content-uri");
      }
      if (BEARER_TOKEN.matcher(text).find()) {
        findings.add("bearer-token");
      }
      if (text.contains("-----BEGIN PRIVATE KEY-----")
          || text.contains("-----BEGIN OPENSSH PRIVATE KEY-----")) {
        findings.add("private-key");
      }
      if (LOCAL_PATH.matcher(text).find()) {
        findings.add("local-path");
      }
      if (text.contains("crypta-app-data-backup")) {
        findings.add("app-data-backup");
      }
    }
  }

  private static String normalize(String key) {
    return key.replaceAll("[^A-Za-z0-9]", "").toLowerCase(java.util.Locale.ROOT);
  }

  private static Map<String, Object> map(Object... entries) {
    LinkedHashMap<String, Object> map = new LinkedHashMap<>();
    for (int index = 0; index < entries.length; index += 2) {
      map.put((String) entries[index], entries[index + 1]);
    }
    return map;
  }

  private static List<Object> list(Object... items) {
    return Arrays.asList(items);
  }

  private record Fixture(String name, boolean expectedSafe, Object value) {}
}
"""
    )

def parse_support_bundle_redactor_fixture_output(stdout: str) -> dict[str, dict[str, Any]]:
    entries: dict[str, dict[str, Any]] = {}
    for line in stdout.splitlines():
        if not line.startswith("RESULT\t"):
            continue
        parts = line.split("\t", 8)
        if len(parts) != 9:
            continue
        (
            _marker,
            fixture_name,
            status,
            expected_safe,
            raw_count,
            redacted_count,
            omitted_count,
            findings,
            redacted_findings,
        ) = parts
        entries[fixture_name] = {
            "fixture": fixture_name,
            "status": status,
            "expectedSafe": expected_safe == "true",
            "rawFindingCount": int(raw_count),
            "redactedFindingCount": int(redacted_count),
            "omittedFieldCount": int(omitted_count),
            "findings": [finding for finding in findings.split("|") if finding][:8],
            "redactedFindings": [
                finding for finding in redacted_findings.split("|") if finding
            ][:8],
            "redactor": "OperatorSupportRedactor",
        }
    return entries

def run_support_bundle_redactor_fixture_runner(
    settings: Settings, fixture_values: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    redactor_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/operator/OperatorSupportRedactor.java"
    )
    if not redactor_source.is_file():
        return {
            "passed": False,
            "entriesByFixture": {},
            "error": "OperatorSupportRedactor.java is missing.",
        }
    harness_root = settings.out_dir / "artifacts" / "support-redactor-fixtures"
    if harness_root.exists():
        shutil.rmtree(harness_root)
    source_dir = harness_root / "src/network/crypta/platform/api/operator"
    classes_dir = harness_root / "classes"
    source_dir.mkdir(parents=True, exist_ok=True)
    classes_dir.mkdir(parents=True, exist_ok=True)
    runner_source = source_dir / "SupportBundleRedactorFixtureRunner.java"
    runner_source.write_text(
        support_bundle_redactor_fixture_runner_source(fixture_values),
        encoding="utf-8",
    )
    compile_result = run_command(
        ["javac", "-d", str(classes_dir), str(redactor_source), str(runner_source)],
        settings,
        "support-bundle-redactor-fixtures-javac",
        timeout_seconds=120,
    )
    if compile_result.exit_code != 0:
        return {
            "passed": False,
            "entriesByFixture": {},
            "compileCommand": command_details(compile_result, settings),
            "error": "OperatorSupportRedactor fixture runner did not compile.",
        }
    run_result = run_command(
        [
            "java",
            "-cp",
            str(classes_dir),
            "network.crypta.platform.api.operator.SupportBundleRedactorFixtureRunner",
        ],
        settings,
        "support-bundle-redactor-fixtures-java",
        timeout_seconds=120,
    )
    entries_by_fixture = parse_support_bundle_redactor_fixture_output(run_result.stdout)
    return {
        "passed": run_result.exit_code == 0
        and len(entries_by_fixture) == len(fixture_values)
        and all(entry["status"] == "pass" for entry in entries_by_fixture.values()),
        "entriesByFixture": entries_by_fixture,
        "compileCommand": command_details(compile_result, settings),
        "runCommand": command_details(run_result, settings),
        "runner": display_path(runner_source, settings.workspace_root),
    }

def support_bundle_fixture_report(fixtures_dir: Path, settings: Settings) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    missing: list[str] = []
    fixture_values: dict[str, dict[str, Any]] = {}
    for fixture_name in SUPPORT_BUNDLE_REDACTION_FIXTURES:
        path = fixtures_dir / fixture_name
        value = read_json_file(path)
        if value is None:
            missing.append(fixture_name)
            continue
        fixture_values[fixture_name] = value
    actual_redactor = run_support_bundle_redactor_fixture_runner(settings, fixture_values)
    actual_entries = actual_redactor.get("entriesByFixture", {})
    for fixture_name in SUPPORT_BUNDLE_REDACTION_FIXTURES:
        expected_safe = fixture_name.endswith("-safe.json")
        if fixture_name in missing:
            entries.append(
                {
                    "fixture": fixture_name,
                    "status": "missing",
                    "expectedSafe": expected_safe,
                    "rawFindingCount": 0,
                    "redactedFindingCount": 0,
                    "omittedFieldCount": 0,
                    "findings": [],
                    "redactedFindings": [],
                    "redactor": "OperatorSupportRedactor",
                }
            )
            continue
        entry = actual_entries.get(fixture_name)
        if entry is None:
            value = fixture_values[fixture_name]
            findings = support_bundle_fixture_findings(value)
            entry = {
                "fixture": fixture_name,
                "status": "fail",
                "expectedSafe": expected_safe,
                "rawFindingCount": len(findings),
                "redactedFindingCount": 0,
                "omittedFieldCount": 0,
                "findings": findings[:8],
                "redactedFindings": [],
                "redactor": "OperatorSupportRedactor",
            }
        entries.append(entry)
    return {
        "missing": missing,
        "entries": entries,
        "actualRedactor": {
            key: value for key, value in actual_redactor.items() if key != "entriesByFixture"
        },
        "passed": not missing
        and actual_redactor.get("passed") is True
        and all(entry["status"] == "pass" for entry in entries),
    }

def collect_privacy_preserving_beta_diagnostics_evidence(settings: Settings) -> EvidenceItem:
    workspace = settings.workspace_root
    service_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/operator/OperatorBetaDashboardService.java"
    )
    diagnostics_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/diagnostics/DiagnosticsApiHandler.java"
    )
    routes_source = workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiOperatorRoutes.java"
    redactor_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/operator/OperatorSupportRedactor.java"
    )
    web_shell_source = (
        workspace
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    )
    web_shell_index_source = (
        workspace
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/index.html"
    )
    operator_docs_source = workspace / "docs/privacy-preserving-beta-diagnostics.md"
    operator_routes_test_source = (
        workspace / "platform-api/src/test/java/network/crypta/platform/api/PlatformApiOperatorRoutesTest.java"
    )
    redactor_test_source = (
        workspace
        / "platform-api/src/test/java/network/crypta/platform/api/operator/OperatorSupportRedactorTest.java"
    )
    service_test_source = (
        workspace
        / "platform-api/src/test/java/network/crypta/platform/api/operator/OperatorBetaDashboardServiceTest.java"
    )

    service_text = read_source(service_source)
    diagnostics_text = read_source(diagnostics_source)
    routes_text = read_source(routes_source)
    redactor_text = read_source(redactor_source)
    web_shell_text = read_source(web_shell_source)
    web_shell_index_text = read_source(web_shell_index_source)
    docs_text = read_source(operator_docs_source)
    go_no_go_text = read_engine_source(workspace, "production_beta_go_no_go_dashboard")
    release_cert_text = read_engine_source(workspace, "release_certification")
    production_release_text = read_engine_source(workspace, "production_beta_release")
    operator_routes_test_text = read_source(operator_routes_test_source)
    redactor_test_text = read_source(redactor_test_source)
    service_test_text = read_source(service_test_source)
    fixture_report = support_bundle_fixture_report(
        workspace / "tools/release-certification/fixtures", settings
    )

    lifecycle_sections = (
        '"catalog"',
        '"appUpdates"',
        '"subscriptions"',
        '"appData"',
        '"appServiceGrants"',
        '"consent"',
        '"migrations"',
        '"sandbox"',
        '"contentFormats"',
        '"trustGraph"',
        '"socialInbox"',
        '"recovery"',
        '"diagnostics"',
        '"legacyFallbacks"',
        '"releaseCertification"',
    )
    checks = {
        "schemaV2": (
            "SUPPORT_BUNDLE_SCHEMA_VERSION = 2" in service_text
            and '"cryptad-operator-support-bundle"' in service_text
            and '"supportDigest"' in service_text
            and "supportDigestForPayload(" in service_text
        ),
        "privacyMetadata": all(
            fragment in service_text
            for fragment in (
                '"includesRawContent"',
                '"includesRawAppData"',
                '"includesPrivateInsertUris"',
                '"includesTokens"',
                '"includesIdentityMaterial"',
                '"includesLocalPaths"',
                '"localOnlyUntilExported"',
            )
        ),
        "safeDiagnosticsSummary": (
            "supportSummary()" in diagnostics_text
            and "diagnosticsApiHandler.supportSummary()" in service_text
            and '"plainTextExportAvailable"' in diagnostics_text
            and '"rawDiagnosticBodiesExcluded"' in service_text
            and '"plainTextExportEmbeddedInDefaultBundle"' in service_text
        ),
        "supportRoutes": (
            '"support-bundle".equals(resource)' in routes_text
            and '"support-bundle".equals(segments.get(1)) && "preview".equals(segments.get(2))'
            in routes_text
        ),
        "redactionMetadata": all(
            fragment in service_text
            for fragment in (
                '"omittedFieldNames"',
                '"omittedFieldCount"',
                '"redactionFindings"',
                '"rawSensitiveMaterialExcluded"',
                '"patternsChecked"',
            )
        ),
        "redactionPatterns": all(
            fragment in redactor_text
            for fragment in (
                '"private_insert_uri"',
                '"public_content_uri"',
                '"raw_profile_document"',
                '"raw_feed_snapshot"',
                '"raw_trust_statement"',
                '"raw_social_message"',
                '"app_service_invocation_body"',
                '"vault_identity_material"',
                '"nested_archive_or_base64_backup_payload"',
            )
        ),
        "redactionFixtures": fixture_report["passed"],
        "lifecycleSummaries": all(fragment in service_text for fragment in lifecycle_sections),
        "webShellExportBoundary": all(
            fragment in web_shell_text + "\n" + web_shell_index_text
            for fragment in (
                "This support bundle is generated locally and is not uploaded automatically.",
                "Copy support JSON",
                "supportBundleRedactionStatus",
                "supportBundleDigestShort",
                "Support bundle redaction failed; copy and download are disabled.",
                "Support JSON copied.",
            )
        ),
        "tests": all(
            fragment in operator_routes_test_text + "\n" + redactor_test_text + "\n" + service_test_text
            for fragment in (
                "route_whenSupportBundleIncludesSensitiveDiagnostics_expectRedactedOutput",
                "redact_whenPrivacyPreservingDiagnosticsFieldsPresent_expectUnsafeFieldsOmitted",
                "supportBundle_whenSensitiveDiagnosticsPresent_expectSchemaV2SafeSummariesAndDigest",
                '"plainTextExport"',
                '"redactedLineCount"',
            )
        ),
        "docs": (
            operator_docs_source.is_file()
            and "local-only" in docs_text
            and "raw content" in docs_text
            and "legacy plaintext diagnostics" in docs_text
        ),
        "productionBlockers": (
            PRIVACY_BETA_DIAGNOSTICS_EVIDENCE_ID in go_no_go_text
            and PRIVACY_BETA_DIAGNOSTICS_EVIDENCE_ID in release_cert_text
            and PRIVACY_BETA_DIAGNOSTICS_EVIDENCE_ID in production_release_text
            and "privacy-preserving-diagnostics-risk" in go_no_go_text
            and "privacy-preserving-diagnostics-risk" in release_cert_text
        ),
    }
    details = {
        "checks": checks,
        "fixtures": fixture_report,
        "sources": {
            "service": display_path(service_source, workspace),
            "diagnostics": display_path(diagnostics_source, workspace),
            "routes": display_path(routes_source, workspace),
            "redactor": display_path(redactor_source, workspace),
            "webShell": display_path(web_shell_source, workspace),
            "webShellIndex": display_path(web_shell_index_source, workspace),
            "docs": display_path(operator_docs_source, workspace),
        },
    }
    return operator_beta_evidence_item(
        settings,
        PRIVACY_BETA_DIAGNOSTICS_EVIDENCE_ID,
        checks,
        "Privacy-preserving beta diagnostics evidence passed deterministic checks.",
        details,
    )

def build_http_request(
    method: str, url: str, form_password: str = "", data: dict[str, str] | None = None
) -> urllib.request.Request:
    payload: bytes | None = None
    headers = {"Accept": "application/json"}
    params = data or {}
    if method in {"POST", "DELETE"} and form_password:
        params = {**params, "formPassword": form_password}
    if method in {"POST", "DELETE"} and params:
        payload = urllib.parse.urlencode(params).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif params:
        url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    return urllib.request.Request(url, data=payload, method=method, headers=headers)

def http_request_json(
    method: str, url: str, form_password: str = "", data: dict[str, str] | None = None
) -> tuple[int, Any]:
    request = build_http_request(method, url, form_password, data)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = response.read().decode("utf-8", errors="replace")
            return response.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            value = json.loads(body) if body else {}
        except json.JSONDecodeError:
            value = {"error": {"message": body[:200]}}
        return exc.code, value

def diagnostics_body_summary(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        return {"diagnosticsBodyType": type(body).__name__}
    summary: dict[str, Any] = {}
    section_count = body.get("sectionCount")
    if isinstance(section_count, int):
        summary["sectionCount"] = section_count
    sections = body.get("sections")
    if isinstance(sections, list):
        summary["sectionCount"] = len(sections)
    legacy_admin = body.get("legacyAdmin")
    if isinstance(legacy_admin, dict):
        surfaces = legacy_admin.get("surfaces")
        if isinstance(surfaces, list):
            summary["legacyAdminSurfaceCount"] = len(surfaces)
            counts = [
                surface.get("count")
                for surface in surfaces
                if isinstance(surface, dict) and isinstance(surface.get("count"), int)
            ]
            summary["legacyAdminTotalCount"] = sum(counts)
            for output_key, field_name in (
                ("legacyAdminReplacementResponseTotal", "replacementResponseCount"),
                ("legacyAdminBlockedMutatingRequestTotal", "blockedMutatingRequestCount"),
                ("legacyAdminFallbackRenderTotal", "fallbackRenderCount"),
                ("legacyAdminRetainedOrPendingRenderTotal", "retainedOrPendingRenderCount"),
            ):
                summary[output_key] = sum(
                    surface.get(field_name)
                    for surface in surfaces
                    if isinstance(surface, dict) and isinstance(surface.get(field_name), int)
                )
    if not summary:
        summary["diagnosticsBodyReceived"] = True
    return summary

def live_response_details(path: str, body: Any, workspace_root: Path) -> dict[str, Any]:
    if path == "/diagnostics":
        return {"bodySummary": diagnostics_body_summary(body)}
    return {"body": sanitize_value(body, workspace_root)}

def collect_live_cleanup_steps(root: str, settings: Settings) -> list[dict[str, Any]]:
    cleanup_steps: list[dict[str, Any]] = []
    for method, path in (("POST", "/apps/cert-smoke/stop"), ("DELETE", "/apps/cert-smoke")):
        cleanup_step: dict[str, Any] = {"method": method, "path": path}
        try:
            status, body = http_request_json(method, root + path, settings.live_form_password, {})
            cleanup_step["status"] = status
            cleanup_step.update(live_response_details(path, body, settings.workspace_root))
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            cleanup_step["error"] = scrub_text(str(exc), settings.workspace_root)
        cleanup_steps.append(cleanup_step)
    return cleanup_steps

def failed_live_evidence(
    source: str,
    details: dict[str, Any],
    root: str,
    settings: Settings,
    installed: bool,
    summary: str = "Live AppHost lifecycle smoke failed.",
) -> EvidenceItem:
    if installed:
        details["cleanupSteps"] = collect_live_cleanup_steps(root, settings)
    return EvidenceItem("apphost.live", "fail", False, summary, source, details)

def collect_live_evidence(settings: Settings, sample_paths: dict[str, Path]) -> EvidenceItem:
    source = summary_source(settings)
    if not settings.live:
        return EvidenceItem("apphost.live", "skip", False, "Live AppHost lifecycle smoke was not requested.", source, {"enabled": False})
    details: dict[str, Any] = {"enabled": True, **live_base_url_details(settings.live_base_url)}
    if not settings.live_base_url:
        return EvidenceItem("apphost.live", "fail", False, "Live AppHost smoke was requested without CRYPTAD_CERT_NODE_BASE_URL.", source, details)
    host = urllib.parse.urlparse(settings.live_base_url).hostname or ""
    if not is_local_live_host(host):
        return EvidenceItem("apphost.live", "fail", False, "Live AppHost smoke only records localhost node evidence.", source, details)
    if not settings.live_form_password:
        return EvidenceItem("apphost.live", "fail", False, "Live AppHost smoke was requested without CRYPTAD_CERT_FORM_PASSWORD.", source, details)
    staged_dir = sample_paths.get("bundleDir")
    if not staged_dir or not staged_dir.is_dir():
        return EvidenceItem("apphost.live", "fail", False, "Live AppHost smoke needs the generated sample staged bundle.", source, details)
    root = settings.live_base_url.rstrip("/") + "/api/v1"
    steps: list[dict[str, Any]] = []
    installed = False
    try:
        for method, path, data in (
            ("GET", "/apps", {}),
            ("DELETE", "/apps/cert-smoke", {}),
            ("POST", "/apps/install", {"stagedDir": str(staged_dir.resolve())}),
            ("GET", "/apps/cert-smoke/runtime", {}),
            ("POST", "/apps/cert-smoke/start", {}),
            ("GET", "/apps/cert-smoke/runtime", {}),
            ("POST", "/apps/cert-smoke/stop", {}),
            ("POST", "/apps/cert-smoke/update", {"stagedDir": str(staged_dir.resolve())}),
            ("DELETE", "/apps/cert-smoke", {}),
            ("GET", "/diagnostics", {}),
        ):
            status, body = http_request_json(method, root + path, settings.live_form_password, data)
            step = {"method": method, "path": path, "status": status}
            step.update(live_response_details(path, body, settings.workspace_root))
            steps.append(step)
            if status >= 400 and not (method == "DELETE" and path == "/apps/cert-smoke" and status == 404):
                details["steps"] = steps
                return failed_live_evidence(source, details, root, settings, installed)
            if method == "POST" and path == "/apps/install":
                installed = True
            elif method == "DELETE" and path == "/apps/cert-smoke" and status < 500:
                installed = False
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        details["steps"] = steps
        details["error"] = scrub_text(str(exc), settings.workspace_root)
        return failed_live_evidence(source, details, root, settings, installed)
    details["steps"] = steps
    return EvidenceItem("apphost.live", "pass", False, "Live AppHost install/start/status/stop/update/uninstall smoke passed.", source, details)

def overall_status(mode: str, evidence: list[EvidenceItem]) -> str:
    if any(item.required_for_release_candidate and item.status == "fail" for item in evidence):
        return "fail"
    if mode == "release-candidate" and any(
        item.required_for_release_candidate and item.status in {"missing", "skip"} for item in evidence
    ):
        return "fail"
    if any(
        item.status in {"warn", "missing", "fail"} or (item.required_for_release_candidate and item.status == "skip")
        for item in evidence
    ):
        return "warn"
    return "pass"

def render_report(summary: dict[str, Any]) -> str:
    lines = [
        "# App Platform Smoke Report",
        "",
        f"- Mode: `{summary['mode']}`",
        f"- Status: `{summary['status']}`",
        f"- Generated: `{summary['generatedAt']}`",
        "",
        "| Evidence | Status | Required for RC | Summary |",
        "| --- | --- | --- | --- |",
    ]
    for item in summary["evidence"]:
        summary_text = str(item["summary"]).replace("|", "\\|")
        lines.append(
            f"| `{item['id']}` | `{item['status']}` | "
            f"{'yes' if item['requiredForReleaseCandidate'] else 'no'} | "
            f"{summary_text} |"
        )
    lines.append("")
    return "\n".join(lines)

def build_summary(settings: Settings, evidence: list[EvidenceItem]) -> dict[str, Any]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "mode": settings.mode,
        "status": overall_status(settings.mode, evidence),
        "generatedAt": utc_now(),
        "summaryPath": display_path(settings.out_dir / SUMMARY_FILE_NAME, settings.workspace_root, settings.out_dir),
        "reportPath": display_path(settings.out_dir / REPORT_FILE_NAME, settings.workspace_root, settings.out_dir),
        "evidence": [item.to_json() for item in evidence],
        "redaction": {
            "secretMaterialRedacted": True,
            "formPasswordsRedacted": True,
            "rawFeedBodiesExcluded": True,
            "rawRequestBodiesExcluded": True,
            "privateInsertUrisExcluded": True,
            "appProcessTokensRedacted": True,
            "browserSessionTokensRedacted": True,
            "signatureValuesRedacted": True,
            "reviewerKeyMaterialRedacted": True,
            "reviewTransparencyPathsExcluded": True,
            "rawUpdateRollbackOutputsExcluded": True,
            "rawAppDataBackupsExcluded": True,
            "rawProfileDocumentsExcluded": True,
            "rawFeedSnapshotsExcluded": True,
            "rawTrustStatementsExcluded": True,
            "rawSocialMessagesExcluded": True,
            "appServiceInvocationBodiesExcluded": True,
            "identityMaterialExcluded": True,
            "supportBundleRedactionFailuresBlockProductionBeta": True,
            "absolutePathsSanitized": True,
        },
    }

def run(settings: Settings) -> tuple[dict[str, Any], int]:
    settings.out_dir.mkdir(parents=True, exist_ok=True)
    remove_existing_path(settings.out_dir / "artifacts")
    cli = find_cli(settings)
    cli_item, sample_paths = collect_cli_evidence(settings, cli)
    cli = sample_paths.get("cli") if sample_paths.get("cli") else find_cli(settings)
    platform_api_contract_item = collect_platform_api_contract_evidence(
        settings, cli if isinstance(cli, Path) else None, sample_paths
    )
    evidence = [
        collect_first_party_evidence(settings, cli if isinstance(cli, Path) else None),
        cli_item,
        collect_developer_beta_toolkit_evidence(settings),
        *collect_public_beta_docs_onboarding_evidence(settings),
        platform_api_contract_item,
        *collect_platform_api_stable_freeze_evidence(settings, platform_api_contract_item),
        *collect_app_services_evidence(settings),
        collect_app_vault_evidence(settings),
        collect_identity_profile_publish_evidence(settings),
        collect_generated_document_insert_evidence(settings),
        collect_content_fetch_evidence(settings),
        collect_content_subscription_evidence(settings),
        collect_content_subscription_scheduler_evidence(settings),
        *collect_network_scale_evidence(settings),
        collect_app_data_store_evidence(settings),
        collect_app_data_backup_restore_evidence(settings),
        collect_trust_graph_preview_evidence(settings),
        collect_trust_graph_rc_scope_and_safety_evidence(settings),
        collect_trust_graph_durable_store_evidence(settings),
        collect_trust_graph_exchange_evidence(settings),
        collect_trust_statement_signing_evidence(settings),
        collect_social_message_signing_evidence(settings),
        collect_signed_bundle_evidence(settings, sample_paths),
        collect_catalog_evidence(settings, sample_paths),
        collect_live_usk_catalog_publication_evidence(settings, sample_paths),
        collect_first_party_beta_catalog_evidence(settings),
        collect_production_catalog_channels_evidence(settings),
        collect_catalog_operations_and_mirrors_evidence(settings),
        collect_first_party_maintenance_policy_evidence(settings),
        collect_first_party_beta_quality_evidence(settings),
        collect_live_usk_source_verification_evidence(settings),
        collect_app_review_receipt_evidence(settings),
        *collect_app_store_submission_workflow_evidence(settings),
        *collect_third_party_intake_evidence(settings),
        *collect_third_party_developer_beta_program_evidence(settings),
        collect_app_review_policy_evidence(settings),
        collect_app_review_governance_evidence(settings),
        collect_app_review_reviewer_key_lifecycle_evidence(settings),
        collect_app_review_transparency_log_evidence(settings),
        collect_app_review_history_api_evidence(settings),
        collect_app_review_first_party_catalog_evidence(settings, sample_paths),
        collect_app_review_first_party_chain_evidence(settings),
        collect_app_ui_design_system_evidence(settings),
        collect_app_ui_lint_evidence(settings, cli if isinstance(cli, Path) else None),
        collect_app_ui_first_party_adoption_evidence(settings),
        collect_app_ui_evidence(settings),
        collect_reference_content_app_evidence(settings),
        collect_profile_publisher_reference_app_evidence(settings),
        collect_profile_publisher_app_data_evidence(settings),
        collect_social_inbox_reference_app_evidence(settings),
        collect_social_inbox_signed_message_evidence(settings),
        collect_social_inbox_subscriptions_evidence(settings),
        collect_social_inbox_app_data_evidence(settings),
        collect_social_inbox_trust_annotation_evidence(settings),
        collect_social_inbox_rc_threading_evidence(settings),
        collect_trust_social_beta_hardening_evidence(settings),
        collect_trust_social_content_format_profiles_evidence(settings),
        collect_social_mail_migration_preview_evidence(settings),
        collect_legacy_plugin_migration_evidence(settings),
        collect_legacy_plugin_social_inbox_spike_evidence(settings),
        collect_legacy_plugin_freeze_policy_evidence(settings),
        collect_legacy_plugin_migration_finalization_evidence(settings),
        collect_feed_reader_reference_app_evidence(settings),
        collect_feed_reader_subscription_evidence(settings),
        collect_feed_reader_app_data_evidence(settings),
        collect_trust_graph_reference_app_evidence(settings),
        collect_trust_graph_durable_exchange_reference_app_evidence(settings),
        collect_trust_graph_app_data_preview_evidence(settings),
        collect_legacy_evidence(settings),
        collect_legacy_removal_wave_one_evidence(settings),
        collect_legacy_removal_wave_two_evidence(settings),
        collect_legacy_removal_wave_three_evidence(settings),
        collect_legacy_removal_wave_four_evidence(settings),
        collect_legacy_removal_wave_five_evidence(settings),
        collect_legacy_final_admin_surface_evidence(settings),
        collect_legacy_browse_retained_evidence(settings),
        collect_legacy_emergency_fallback_retained_evidence(settings),
        collect_sandbox_provider_evidence(settings),
        *collect_public_beta_security_evidence(settings),
        *collect_ecosystem_security_advisory_revocation_evidence(settings),
        collect_production_security_response_runbook_evidence(settings),
        collect_user_consent_flow_evidence(settings),
        collect_app_update_lifecycle_evidence(settings),
        collect_app_update_scheduler_evidence(settings),
        collect_app_update_live_catalog_refresh_evidence(settings),
        collect_app_update_rollback_evidence(settings),
        collect_app_update_data_migration_contract_evidence(settings),
        *collect_operator_beta_evidence(settings),
        collect_privacy_preserving_beta_diagnostics_evidence(settings),
        collect_live_evidence(settings, sample_paths),
    ]
    sanitized_evidence = [
        EvidenceItem(
            item.id,
            item.status,
            item.required_for_release_candidate,
            scrub_text(item.summary, settings.workspace_root),
            item.source,
            dict(sanitize_value(item.details, settings.workspace_root)),
        )
        for item in evidence
    ]
    summary = build_summary(settings, sanitized_evidence)
    write_json(settings.out_dir / SUMMARY_FILE_NAME, summary)
    write_text(settings.out_dir / REPORT_FILE_NAME, render_report(summary))
    exit_code = 1 if settings.mode == "release-candidate" and summary["status"] == "fail" else 0
    return summary, exit_code

def settings_from_args(args: argparse.Namespace) -> Settings:
    workspace = args.workspace_root.resolve()
    out_dir = (workspace / args.out_dir).resolve() if not args.out_dir.is_absolute() else args.out_dir.resolve()
    mode = args.mode or os.environ.get("CRYPTAD_CERT_MODE", "pr")
    if mode not in MODES:
        raise SystemExit(f"--mode must be one of {', '.join(MODES)}")
    live = args.live or os.environ.get("CRYPTAD_CERT_APP_SMOKE_LIVE") == "1"
    cli_path = args.cli_path.resolve() if args.cli_path else None
    return Settings(
        workspace_root=workspace,
        out_dir=out_dir,
        mode=mode,
        skip_gradle=args.skip_gradle,
        cli_path=cli_path,
        live=live,
        live_base_url=args.node_base_url or os.environ.get("CRYPTAD_CERT_NODE_BASE_URL", ""),
        live_form_password=os.environ.get("CRYPTAD_CERT_FORM_PASSWORD", ""),
        timeout_seconds=args.timeout_seconds,
    )

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run offline deterministic self-tests.")
    parser.add_argument("--workspace-root", type=Path, default=Path.cwd())
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--mode", choices=MODES, default=None)
    parser.add_argument("--skip-gradle", action="store_true", help="Do not invoke Gradle tasks.")
    parser.add_argument("--cli-path", type=Path, help="Path to an installed crypta-app launcher.")
    parser.add_argument("--live", action="store_true", help="Run optional live-node AppHost lifecycle smoke.")
    parser.add_argument("--node-base-url", default="", help="Live-node base URL for optional AppHost smoke.")
    parser.add_argument("--timeout-seconds", type=int, default=900)
    return parser
