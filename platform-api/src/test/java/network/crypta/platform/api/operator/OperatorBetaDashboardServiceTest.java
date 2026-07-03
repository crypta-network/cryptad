package network.crypta.platform.api.operator;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.platform.api.appcatalogs.AppCatalogsApiHandler;
import network.crypta.platform.api.appdata.AppDataService;
import network.crypta.platform.api.apps.AppsApiHandler;
import network.crypta.platform.api.appservices.AppServiceCoordinator;
import network.crypta.platform.api.appupdates.AppUpdateService;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionService;
import network.crypta.platform.api.diagnostics.DiagnosticsApiHandler;
import network.crypta.platform.api.trust.TrustGraphApiHandler;
import network.crypta.runtime.spi.DiagnosticReportSnapshot;
import network.crypta.runtime.spi.DiagnosticSectionSnapshot;
import network.crypta.runtime.spi.LegacyAdminSurfaceUsage;
import network.crypta.runtime.spi.LegacyAdminUsageSnapshot;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings({"java:S100", "unchecked"})
class OperatorBetaDashboardServiceTest {
  private static final String APP_ID = "feed-reader";
  private static final String APP_NEEDS_REVIEW_WARNING =
      "App " + APP_ID + " needs operator review.";
  private static final String APP_UPDATES_SECTION = "appUpdates";
  private static final String APP_UPDATE_UNAVAILABLE =
      "App-update lifecycle service is unavailable.";
  private static final String APP_UPDATE_UNAVAILABLE_DASHBOARD_WARNING =
      "App " + APP_ID + " update state is unavailable.";
  private static final String APPLY_APP_UPDATE_ACTION = "apply-app-update";
  private static final String AVAILABLE = "available";
  private static final String BLOCKED_UPDATE_COUNT_FIELD = "blockedUpdateCount";
  private static final String CONSENT_SECTION = "consent";
  private static final String ERROR = "error";
  private static final String MANUAL_SOURCE_KIND = "manual";
  private static final String MIGRATIONS_SECTION = "migrations";
  private static final String PENDING = "pending";
  private static final String PENDING_UPDATE_COUNT_FIELD = "pendingUpdateCount";
  private static final String QUOTA_FIELD = "quota";
  private static final String ROLLBACK_APP_ACTION = "rollback-app";
  private static final String SOURCE_KIND_FIELD = "sourceKind";
  private static final String STAGE_APP_UPDATE_ACTION = "stage-app-update";
  private static final String STAGED_UPDATE_COUNT_FIELD = "stagedUpdateCount";
  private static final String SUMMARY_FIELD = "summary";
  private static final String SOCIAL_INBOX_APP_ID = "social-inbox";
  private static final String SOCIAL_INBOX_SECTION = "socialInbox";
  private static final String UNAVAILABLE = "unavailable";
  private static final String UPPERCASE_FILE_CATALOG_SOURCE =
      "FILE:///home/operator/private/cryptad-app-catalog.properties";
  private static final String WARNINGS_FIELD = "warnings";
  private static final String WARNING = "warning";
  private static final Clock CLOCK =
      Clock.fixed(Instant.parse("2026-05-24T12:00:00Z"), ZoneOffset.UTC);

  @Test
  void dashboard_whenUpdateCandidateAvailable_expectPendingCountAndStageActionAvailable() {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(APP_ID)).thenReturn(updateSummary(availableCandidate()));

    Map<String, Object> dashboard = service(appsHandler(), updateService).dashboard();

    Map<String, Object> summary = mapValue(dashboard.get(SUMMARY_FIELD));
    List<Map<String, Object>> actions = recoveryActionsForFirstApp(dashboard);
    assertEquals(1L, summary.get(PENDING_UPDATE_COUNT_FIELD));
    assertTrue(actionAvailable(actions, "check-app-update"));
    assertTrue(actionAvailable(actions, STAGE_APP_UPDATE_ACTION));
  }

  @Test
  void dashboard_whenUpdateCandidateRequiresAcknowledgement_expectStageActionUnavailable() {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(APP_ID))
        .thenReturn(updateSummary(availableCandidate(Map.of("requiresAcknowledgement", true))));

    Map<String, Object> dashboard = service(appsHandler(), updateService).dashboard();

    Map<String, Object> summary = mapValue(dashboard.get(SUMMARY_FIELD));
    List<Map<String, Object>> actions = recoveryActionsForFirstApp(dashboard);
    assertEquals(1L, summary.get(PENDING_UPDATE_COUNT_FIELD));
    assertFalse(actionAvailable(actions, STAGE_APP_UPDATE_ACTION));
  }

  @Test
  void dashboard_whenCandidateSecurityAckRequired_expectWarningAndNoStageAction() {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(APP_ID))
        .thenReturn(
            updateSummary(
                availableCandidate(
                    Map.of(), Map.of("requiresAcknowledgement", true, "blocksUpdate", false))));

    Map<String, Object> dashboard = service(appsHandler(), updateService).dashboard();

    Map<String, Object> summary = mapValue(dashboard.get(SUMMARY_FIELD));
    List<Map<String, Object>> actions = recoveryActionsForFirstApp(dashboard);
    assertEquals(1L, summary.get(PENDING_UPDATE_COUNT_FIELD));
    assertFalse(actionAvailable(actions, STAGE_APP_UPDATE_ACTION));
    assertTrue(warningsForFirstApp(dashboard).contains("app_update_security_advisory"));
  }

  @Test
  void dashboard_whenAppRunningWithStagedUpdateAndRollback_expectApplyAndRollbackUnavailable() {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(APP_ID))
        .thenReturn(updateSummary(availableCandidate(), stagedUpdate(), rollbackAvailable()));

    Map<String, Object> dashboard = service(appsHandler(true), updateService).dashboard();

    List<Map<String, Object>> actions = recoveryActionsForFirstApp(dashboard);
    assertFalse(actionAvailable(actions, APPLY_APP_UPDATE_ACTION));
    assertFalse(actionAvailable(actions, ROLLBACK_APP_ACTION));
  }

  @Test
  void dashboard_whenAppStoppedWithStagedUpdateAndRollback_expectApplyAndRollbackAvailable() {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(APP_ID))
        .thenReturn(updateSummary(availableCandidate(), stagedUpdate(), rollbackAvailable()));

    Map<String, Object> dashboard = service(appsHandler(), updateService).dashboard();

    List<Map<String, Object>> actions = recoveryActionsForFirstApp(dashboard);
    assertTrue(actionAvailable(actions, APPLY_APP_UPDATE_ACTION));
    assertTrue(actionAvailable(actions, ROLLBACK_APP_ACTION));
  }

  @Test
  void dashboard_whenStagedUpdateSecurityBlocksUpdate_expectApplyUnavailableAndWarning() {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(APP_ID))
        .thenReturn(
            updateSummary(
                availableCandidate(),
                stagedUpdate(Map.of("blocksUpdate", true)),
                rollbackAvailable()));

    Map<String, Object> dashboard = service(appsHandler(), updateService).dashboard();

    List<Map<String, Object>> actions = recoveryActionsForFirstApp(dashboard);
    assertFalse(actionAvailable(actions, APPLY_APP_UPDATE_ACTION));
    assertTrue(actionAvailable(actions, ROLLBACK_APP_ACTION));
    assertTrue(warningsForFirstApp(dashboard).contains("app_update_security_blocked"));
  }

  @Test
  void dashboard_whenUpdateServiceUnavailable_expectUpdateRecoveryActionsUnavailable() {
    Map<String, Object> dashboard = service(appsHandler(), null).dashboard();

    List<Map<String, Object>> actions = recoveryActionsForFirstApp(dashboard);
    assertFalse(actionAvailable(actions, "check-app-update"));
    assertFalse(actionAvailable(actions, STAGE_APP_UPDATE_ACTION));
    assertFalse(actionAvailable(actions, APPLY_APP_UPDATE_ACTION));
    assertFalse(actionAvailable(actions, ROLLBACK_APP_ACTION));
  }

  @Test
  void dashboard_whenUpdateServiceUnavailableWithOtherServicesAvailable_expectUnavailableWarning() {
    Map<String, Object> dashboard = serviceWithMissingUpdateServiceOnly().dashboard();

    assertEquals(UNAVAILABLE, dashboard.get("overallStatus"));
    assertEquals(
        List.of(APP_UPDATE_UNAVAILABLE_DASHBOARD_WARNING, APP_NEEDS_REVIEW_WARNING),
        stringList(dashboard.get(WARNINGS_FIELD)));
    assertEquals(List.of(APP_UPDATE_UNAVAILABLE), warningsForFirstApp(dashboard));
  }

  @Test
  void dashboard_whenBuildingUninstallRecoveryAction_expectPreserveDataQueryParameter() {
    Map<String, Object> dashboard = service(appsHandler(), null).dashboard();

    Map<String, Object> action =
        action(recoveryActionsForFirstApp(dashboard), "preserve-data-uninstall");
    assertEquals("DELETE", action.get("method"));
    assertEquals("apps/feed-reader?preserveData=true", action.get("path"));
  }

  @Test
  void dashboard_whenCatalogSourceUsesUppercaseFileUri_expectSourceDisplayRedacted() {
    AppCatalogsApiHandler catalogsApiHandler = mock(AppCatalogsApiHandler.class);
    when(catalogsApiHandler.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogsApiHandler.listRecommendedCatalogs()).thenReturn(List.of());
    when(catalogsApiHandler.securityResponseSummary()).thenReturn(clearSecurityResponse());

    Map<String, Object> dashboard = service(appsHandler(), catalogsApiHandler, null).dashboard();

    Map<String, Object> catalog = listOfMaps(dashboard.get("catalogs")).getFirst();
    assertEquals(MANUAL_SOURCE_KIND, catalog.get(SOURCE_KIND_FIELD));
    assertEquals("file:<redacted>", catalog.get("sourceDisplay"));
  }

  @Test
  void dashboard_whenCatalogSourceUsesRemoteUri_expectSourceDisplayRedactedAndDigestRetained() {
    AppCatalogsApiHandler catalogsApiHandler = mock(AppCatalogsApiHandler.class);
    when(catalogsApiHandler.listCatalogs()).thenReturn(List.of(remoteCatalog()));
    when(catalogsApiHandler.listRecommendedCatalogs()).thenReturn(List.of());
    when(catalogsApiHandler.securityResponseSummary()).thenReturn(clearSecurityResponse());

    Map<String, Object> dashboard = service(appsHandler(), catalogsApiHandler, null).dashboard();

    Map<String, Object> catalog = listOfMaps(dashboard.get("catalogs")).getFirst();
    assertEquals(MANUAL_SOURCE_KIND, catalog.get(SOURCE_KIND_FIELD));
    assertEquals("https:<redacted>", catalog.get("sourceDisplay"));
    assertTrue(
        catalog.get("sourceDigest") instanceof String digest && digest.matches("[a-f0-9]{64}"));
  }

  @Test
  void dashboard_whenSecurityResponseHasDenylist_expectSummaryAndWarning() {
    AppCatalogsApiHandler catalogsApiHandler = mock(AppCatalogsApiHandler.class);
    when(catalogsApiHandler.listCatalogs()).thenReturn(List.of());
    when(catalogsApiHandler.listRecommendedCatalogs()).thenReturn(List.of());
    when(catalogsApiHandler.securityResponseSummary()).thenReturn(denylistSecurityResponse());

    Map<String, Object> dashboard = service(appsHandler(), catalogsApiHandler, null).dashboard();

    Map<String, Object> securityResponse = mapValue(dashboard.get("securityResponse"));
    Map<String, Object> securitySummary = mapValue(securityResponse.get(SUMMARY_FIELD));
    assertEquals("denylist_active", securityResponse.get("status"));
    assertEquals(1, securitySummary.get("denylistedVersionCount"));
    assertTrue(
        stringList(dashboard.get(WARNINGS_FIELD))
            .contains("Catalog security response has active denylist entries."));
  }

  @Test
  void dashboard_whenSecurityResponseHasReviewerRevocation_expectSummaryAndWarning() {
    AppCatalogsApiHandler catalogsApiHandler = mock(AppCatalogsApiHandler.class);
    when(catalogsApiHandler.listCatalogs()).thenReturn(List.of());
    when(catalogsApiHandler.listRecommendedCatalogs()).thenReturn(List.of());
    when(catalogsApiHandler.securityResponseSummary())
        .thenReturn(reviewerRevocationSecurityResponse());

    Map<String, Object> dashboard = service(appsHandler(), catalogsApiHandler, null).dashboard();

    Map<String, Object> securityResponse = mapValue(dashboard.get("securityResponse"));
    Map<String, Object> securitySummary = mapValue(securityResponse.get(SUMMARY_FIELD));
    assertEquals("reviewer_revocation_active", securityResponse.get("status"));
    assertEquals(1, securitySummary.get("revokedReviewerKeyCount"));
    assertTrue(
        stringList(dashboard.get(WARNINGS_FIELD))
            .contains("Catalog security response has reviewer revocations."));
  }

  @Test
  void dashboard_whenSecurityResponseInspectionFails_expectUnavailableBlockAndWarning() {
    AppCatalogsApiHandler catalogsApiHandler = mock(AppCatalogsApiHandler.class);
    when(catalogsApiHandler.listCatalogs()).thenReturn(List.of());
    when(catalogsApiHandler.listRecommendedCatalogs()).thenReturn(List.of());
    when(catalogsApiHandler.securityResponseSummary()).thenThrow(new IllegalStateException());

    Map<String, Object> dashboard = service(appsHandler(), catalogsApiHandler, null).dashboard();

    Map<String, Object> securityResponse = mapValue(dashboard.get("securityResponse"));
    assertFalse((Boolean) securityResponse.get(AVAILABLE));
    assertEquals(UNAVAILABLE, securityResponse.get("status"));
    assertEquals(
        List.of("Catalog service is unavailable."),
        stringList(securityResponse.get(WARNINGS_FIELD)));
    assertTrue(
        stringList(dashboard.get(WARNINGS_FIELD))
            .contains("Catalog security response could not be inspected: IllegalStateException"));
  }

  @Test
  void dashboard_whenUpdateBlockedByReviewTrust_expectQuotaWarningCountIgnoresAppWarning() {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(APP_ID))
        .thenReturn(updateSummary(availableCandidate(Map.of("blocksUpdate", true))));

    Map<String, Object> dashboard = service(appsHandler(), updateService).dashboard();

    Map<String, Object> summary = mapValue(dashboard.get(SUMMARY_FIELD));
    assertEquals(0L, summary.get("quotaWarningCount"));
    assertTrue(warningsForFirstApp(dashboard).contains("app_update_blocked"));
  }

  @Test
  void dashboard_whenAppHostQuotaWarningPresent_expectQuotaWarningCountIncludesApp() {
    Map<String, Object> dashboard =
        service(appsHandler(installedAppWithQuotaWarning()), null).dashboard();

    Map<String, Object> summary = mapValue(dashboard.get(SUMMARY_FIELD));
    assertEquals(1L, summary.get("quotaWarningCount"));
  }

  @Test
  void dashboard_whenDiagnosticsOmitLegacyAdminCounters_expectUnavailableWarning() {
    Map<String, Object> dashboard = serviceWithDiagnosticsWithoutLegacyAdmin().dashboard();

    Map<String, Object> legacyAdmin = mapValue(dashboard.get("legacyAdmin"));
    assertEquals(UNAVAILABLE, dashboard.get("overallStatus"));
    assertFalse((Boolean) legacyAdmin.get(AVAILABLE));
    assertEquals(
        List.of("Legacy-admin usage counters are unavailable."),
        stringList(dashboard.get(WARNINGS_FIELD)));
  }

  @Test
  void supportBundle_whenSensitiveDiagnosticsPresent_expectSchemaV2SafeSummariesAndDigest() {
    OperatorBetaDashboardService service = serviceWithSensitiveSupportMaterial();

    Map<String, Object> bundle = service.supportBundle();
    Map<String, Object> secondBundle = service.supportBundle();

    assertEquals("cryptad-operator-support-bundle", bundle.get("kind"));
    assertEquals(2, bundle.get("schemaVersion"));
    assertEquals("2026-05-24T12:00:00Z", bundle.get("generatedAt"));
    assertEquals("2026-05-24T12:00:00Z", bundle.get("createdAt"));
    assertEquals("pass", mapValue(bundle.get("redaction")).get("status"));
    assertEquals(false, mapValue(bundle.get("privacy")).get("includesRawContent"));
    assertEquals(false, mapValue(bundle.get("privacy")).get("includesRawAppData"));
    assertEquals(false, mapValue(bundle.get("privacy")).get("includesPrivateInsertUris"));
    assertEquals(false, mapValue(bundle.get("privacy")).get("includesTokens"));
    assertEquals(false, mapValue(bundle.get("privacy")).get("includesIdentityMaterial"));
    assertEquals(false, mapValue(bundle.get("privacy")).get("includesLocalPaths"));
    assertTrue((Boolean) mapValue(bundle.get("redaction")).get("rawSensitiveMaterialExcluded"));
    assertTrue((Boolean) mapValue(bundle.get("redaction")).get("localOnlyUntilExported"));
    assertTrue(
        stringList(mapValue(bundle.get("redaction")).get("omittedFieldNames"))
            .contains("appServiceInvocationBody"));
    assertSafeDiagnosticsSummary(bundle);
    assertLifecycleSectionsPresent(bundle);
    Map<String, Object> supportDigest = mapValue(bundle.get("supportDigest"));
    Map<String, Object> secondSupportDigest = mapValue(secondBundle.get("supportDigest"));
    assertEquals("SHA-256", supportDigest.get("algorithm"));
    assertTrue(
        supportDigest.get("digest") instanceof String digest && digest.matches("[a-f0-9]{64}"));
    assertEquals(supportDigest.get("digest"), secondSupportDigest.get("digest"));
    String rendered = bundle.toString();
    assertFalse(rendered.contains("/work/private/catalog"));
    assertFalse(rendered.contains("USK@example/private/0"));
    assertFalse(rendered.contains("Bearer diagnostic-secret"));
    assertFalse(rendered.contains("Private App Service Body"));
    assertFalse(rendered.contains("lines="));
  }

  @Test
  void supportBundle_whenOptionalServicesUnavailable_expectLifecycleSectionsUnavailable() {
    Map<String, Object> bundle = serviceWithUnavailableOptionalServices().supportBundle();

    Map<String, Object> sections = mapValue(bundle.get("sections"));
    Map<String, Object> catalog = mapValue(sections.get("catalog"));
    Map<String, Object> appUpdates = mapValue(sections.get(APP_UPDATES_SECTION));
    Map<String, Object> subscriptions = mapValue(sections.get("subscriptions"));
    Map<String, Object> appData = mapValue(sections.get("appData"));
    Map<String, Object> sandbox = mapValue(sections.get("sandbox"));
    Map<String, Object> nodeSummary = mapValue(bundle.get("nodeSummary"));

    assertEquals(UNAVAILABLE, catalog.get("status"));
    assertEquals("Catalog service is unavailable.", catalog.get("lastSafeStatusMessage"));
    assertEquals(0, catalog.get("boundedCount"));
    assertEquals(UNAVAILABLE, appUpdates.get("status"));
    assertEquals(APP_UPDATE_UNAVAILABLE, appUpdates.get("lastSafeStatusMessage"));
    assertEquals(0, appUpdates.get("boundedCount"));
    assertEquals(UNAVAILABLE, subscriptions.get("status"));
    assertEquals(
        "Content subscription service is unavailable.", subscriptions.get("lastSafeStatusMessage"));
    assertEquals(0, subscriptions.get("boundedCount"));
    assertEquals(UNAVAILABLE, appData.get("status"));
    assertEquals("App-data service is unavailable.", appData.get("lastSafeStatusMessage"));
    assertEquals(0, appData.get("boundedCount"));
    assertEquals(UNAVAILABLE, sandbox.get("status"));
    assertEquals("AppHost service is unavailable.", sandbox.get("lastSafeStatusMessage"));
    assertEquals(0, sandbox.get("boundedCount"));
    assertTrue(
        nodeSummary.get("architecture") instanceof String architecture
            && List.of("amd64", "arm64").contains(architecture));
    assertTrue(nodeSummary.get("operatingSystem") instanceof String os && !os.isBlank());
  }

  @Test
  void supportBundle_whenAppHostInspectionFails_expectAppDependentLifecycleUnavailable() {
    Map<String, Object> bundle =
        serviceWithAppHostInspectionFailureAndAvailableStateServices().supportBundle();

    Map<String, Object> sections = mapValue(bundle.get("sections"));
    Map<String, Object> appUpdates = mapValue(sections.get(APP_UPDATES_SECTION));
    Map<String, Object> appData = mapValue(sections.get("appData"));
    Map<String, Object> consent = mapValue(sections.get(CONSENT_SECTION));
    Map<String, Object> migrations = mapValue(sections.get(MIGRATIONS_SECTION));
    String appHostInspectionWarning =
        "Installed apps could not be inspected: IllegalStateException";

    assertUnavailableAppDerivedSection(appUpdates, appHostInspectionWarning);
    assertUnavailableAppDerivedSection(appData, appHostInspectionWarning);
    assertUnavailableAppDerivedSection(consent, appHostInspectionWarning);
    assertUnavailableAppDerivedSection(migrations, appHostInspectionWarning);
  }

  @Test
  void supportBundle_whenUpdateServiceUnavailableAndNoApps_expectUpdateSectionUnavailable() {
    Map<String, Object> bundle = serviceWithNoAppsAndMissingUpdateService().supportBundle();

    Map<String, Object> appUpdates = appUpdatesSection(bundle);
    assertEquals(UNAVAILABLE, appUpdates.get("status"));
    assertEquals(0, appUpdates.get("boundedCount"));
    assertEquals(0L, appUpdates.get(PENDING_UPDATE_COUNT_FIELD));
    assertEquals(0L, appUpdates.get(STAGED_UPDATE_COUNT_FIELD));
    assertEquals(0L, appUpdates.get(BLOCKED_UPDATE_COUNT_FIELD));
    assertEquals(APP_UPDATE_UNAVAILABLE, appUpdates.get("lastSafeStatusMessage"));
  }

  @Test
  void supportBundle_whenUpdateSummaryFails_expectUpdateSectionUnavailable() {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(APP_ID)).thenThrow(new IllegalStateException("backend offline"));

    Map<String, Object> bundle = service(appsHandler(), updateService).supportBundle();

    Map<String, Object> appUpdates = appUpdatesSection(bundle);
    assertEquals(UNAVAILABLE, appUpdates.get("status"));
    assertEquals(1, appUpdates.get("boundedCount"));
    assertEquals(0L, appUpdates.get(PENDING_UPDATE_COUNT_FIELD));
    assertEquals(0L, appUpdates.get(STAGED_UPDATE_COUNT_FIELD));
    assertEquals(0L, appUpdates.get(BLOCKED_UPDATE_COUNT_FIELD));
    assertEquals(
        "App-update state could not be inspected: IllegalStateException",
        appUpdates.get("lastSafeStatusMessage"));
  }

  @Test
  void supportBundle_whenLegacyAdminUsageAvailable_expectLegacyFallbackSurfaceCount() {
    Map<String, Object> bundle = serviceWithLegacyAdminUsage().supportBundle();

    Map<String, Object> legacyFallbacks =
        mapValue(mapValue(bundle.get("sections")).get("legacyFallbacks"));

    assertEquals(1L, legacyFallbacks.get("boundedCount"));
    assertEquals(true, legacyFallbacks.get("legacyFallbackAvailable"));
  }

  @Test
  void supportBundle_whenOnlyAppQuotaWarningPresent_expectAppUpdatesSectionAvailable() {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(APP_ID)).thenReturn(updateSummary(Map.of()));

    Map<String, Object> bundle =
        service(appsHandler(installedAppWithQuotaWarning()), updateService).supportBundle();

    Map<String, Object> appUpdates = appUpdatesSection(bundle);
    Map<String, Object> sandbox = mapValue(mapValue(bundle.get("sections")).get("sandbox"));
    assertEquals(AVAILABLE, appUpdates.get("status"));
    assertEquals(0L, appUpdates.get(PENDING_UPDATE_COUNT_FIELD));
    assertEquals(0L, appUpdates.get(STAGED_UPDATE_COUNT_FIELD));
    assertEquals(0L, appUpdates.get(BLOCKED_UPDATE_COUNT_FIELD));
    assertEquals(AVAILABLE, sandbox.get("status"));
    assertEquals(0L, sandbox.get("warningCount"));
  }

  @Test
  void supportBundle_whenUpdateCandidateAvailable_expectAppUpdatesSectionWarning() {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(APP_ID)).thenReturn(updateSummary(availableCandidate()));

    Map<String, Object> bundle = service(appsHandler(), updateService).supportBundle();

    Map<String, Object> appUpdates = appUpdatesSection(bundle);
    assertEquals(WARNING, appUpdates.get("status"));
    assertEquals(1L, appUpdates.get(PENDING_UPDATE_COUNT_FIELD));
    assertEquals(0L, appUpdates.get(STAGED_UPDATE_COUNT_FIELD));
    assertEquals(0L, appUpdates.get(BLOCKED_UPDATE_COUNT_FIELD));
  }

  @Test
  void supportBundle_whenUpdateStaged_expectAppUpdatesSectionWarning() {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(APP_ID))
        .thenReturn(updateSummary(Map.of(AVAILABLE, false), stagedUpdate(), rollbackAvailable()));

    Map<String, Object> bundle = service(appsHandler(), updateService).supportBundle();

    Map<String, Object> appUpdates = appUpdatesSection(bundle);
    assertEquals(WARNING, appUpdates.get("status"));
    assertEquals(0L, appUpdates.get(PENDING_UPDATE_COUNT_FIELD));
    assertEquals(1L, appUpdates.get(STAGED_UPDATE_COUNT_FIELD));
    assertEquals(0L, appUpdates.get(BLOCKED_UPDATE_COUNT_FIELD));
  }

  @Test
  void supportBundle_whenAppServiceGrantPending_expectAppServiceLifecycleWarning() {
    Map<String, Object> bundle =
        serviceWithAppServiceCoordinator(appServiceCoordinatorWithPendingGrant()).supportBundle();

    Map<String, Object> appServiceGrants =
        mapValue(mapValue(bundle.get("sections")).get("appServiceGrants"));
    assertEquals(WARNING, appServiceGrants.get("status"));
    assertEquals(1L, appServiceGrants.get("pendingGrantCount"));
    assertEquals("pending_app_service_grants", appServiceGrants.get("lastSafeStatusMessage"));
  }

  @Test
  void supportBundle_whenSocialInboxSourcePaused_expectSocialInboxLifecycleWarning() {
    Map<String, Object> bundle =
        serviceWithContentSubscriptions(
                appsHandler(installedSocialInboxApp()),
                contentSubscriptionServiceWithPausedSocialInbox())
            .supportBundle();

    Map<String, Object> socialInbox =
        mapValue(mapValue(bundle.get("sections")).get(SOCIAL_INBOX_SECTION));
    assertEquals(WARNING, socialInbox.get("status"));
    assertEquals(1L, socialInbox.get("sourcePausedCount"));
    assertEquals(0L, socialInbox.get("malformedMessageRejectedCount"));
    assertEquals(List.of(SOCIAL_INBOX_APP_ID), socialInbox.get("safeIds"));
  }

  @Test
  void supportBundle_whenSocialInboxHasAppQuotaWarning_expectSocialInboxLifecycleAvailable() {
    Map<String, Object> bundle =
        serviceWithContentSubscriptions(
                appsHandler(installedSocialInboxAppWithQuotaWarning()),
                emptyContentSubscriptionService())
            .supportBundle();

    Map<String, Object> socialInbox =
        mapValue(mapValue(bundle.get("sections")).get(SOCIAL_INBOX_SECTION));
    assertEquals(AVAILABLE, socialInbox.get("status"));
    assertEquals(0L, socialInbox.get("sourcePausedCount"));
    assertEquals(0L, socialInbox.get("malformedMessageRejectedCount"));
    assertEquals(List.of(SOCIAL_INBOX_APP_ID), socialInbox.get("safeIds"));
  }

  @Test
  void supportBundle_whenSocialInboxSubscriptionServiceUnavailable_expectSocialInboxUnavailable() {
    Map<String, Object> bundle =
        serviceWithContentSubscriptions(appsHandler(installedSocialInboxApp()), null)
            .supportBundle();

    Map<String, Object> socialInbox =
        mapValue(mapValue(bundle.get("sections")).get(SOCIAL_INBOX_SECTION));
    assertEquals(UNAVAILABLE, socialInbox.get("status"));
    assertEquals(
        "Content subscription service is unavailable.", socialInbox.get("lastSafeStatusMessage"));
    assertEquals(0L, socialInbox.get("sourcePausedCount"));
    assertEquals(List.of(SOCIAL_INBOX_APP_ID), socialInbox.get("safeIds"));
  }

  @Test
  void supportBundle_whenUpdateConsentRequired_expectConsentLifecycleWarning() {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(APP_ID)).thenReturn(updateSummary(consentRequiredCandidate()));

    Map<String, Object> bundle = service(appsHandler(), updateService).supportBundle();

    Map<String, Object> consent = mapValue(mapValue(bundle.get("sections")).get(CONSENT_SECTION));
    assertEquals(WARNING, consent.get("status"));
    assertEquals(1L, consent.get("pendingOrRejectedCount"));
    assertEquals(
        "Update consent is pending or rejected for one or more apps.",
        consent.get("lastSafeStatusMessage"));
  }

  @Test
  void supportBundle_whenAppDataServiceUnavailable_expectAppDataSectionUnavailable() {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(APP_ID)).thenReturn(updateSummary(Map.of()));

    Map<String, Object> bundle = service(appsHandler(), updateService).supportBundle();

    Map<String, Object> appData = mapValue(mapValue(bundle.get("sections")).get("appData"));
    assertEquals(UNAVAILABLE, appData.get("status"));
    assertEquals(1L, appData.get("unavailableCount"));
    assertEquals("App-data service is unavailable.", appData.get("lastSafeStatusMessage"));
  }

  @Test
  void supportBundle_whenAppDataServiceUnavailableAndNoApps_expectAppDataSectionUnavailable() {
    Map<String, Object> bundle = serviceWithNoAppsAndMissingAppDataService().supportBundle();

    Map<String, Object> appData = mapValue(mapValue(bundle.get("sections")).get("appData"));
    assertEquals(UNAVAILABLE, appData.get("status"));
    assertEquals(0, appData.get("boundedCount"));
    assertEquals(0L, appData.get("unavailableCount"));
    assertEquals("App-data service is unavailable.", appData.get("lastSafeStatusMessage"));
  }

  @Test
  void supportBundle_whenUpdateDataMigrationBlocked_expectMigrationSectionWarning() {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(APP_ID))
        .thenReturn(
            updateSummary(
                availableCandidateWithDataMigration(
                    Map.of(
                        "status",
                        "missing_migration",
                        "blockReason",
                        "app_data_migration_missing")),
                stagedUpdateWithDataMigration(
                    Map.of(
                        "status",
                        "dry_run_failed",
                        "lastErrorCode",
                        "app_data_migration_dry_run_failed")),
                rollbackAvailable()));

    Map<String, Object> bundle = service(appsHandler(), updateService).supportBundle();

    Map<String, Object> migrations =
        mapValue(mapValue(bundle.get("sections")).get(MIGRATIONS_SECTION));
    assertEquals(WARNING, migrations.get("status"));
    assertEquals(2L, migrations.get("migrationWarningCount"));
    assertEquals("app_data_migration_missing", migrations.get("lastErrorCode"));
    assertEquals("app_data_migration_missing", migrations.get("lastSafeStatusMessage"));
    assertEquals(true, migrations.get("rawAppDataValuesExcluded"));
    assertEquals(List.of(APP_ID), migrations.get("safeIds"));
  }

  @Test
  void supportBundle_whenMigrationRequiresOperatorReview_expectMigrationSectionWarning() {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(APP_ID))
        .thenReturn(
            updateSummary(
                availableCandidateWithDataMigration(
                    Map.of("status", "ready", "operatorReviewRequired", true)),
                Map.of(AVAILABLE, false),
                rollbackAvailable()));

    Map<String, Object> bundle = service(appsHandler(), updateService).supportBundle();

    Map<String, Object> migrations =
        mapValue(mapValue(bundle.get("sections")).get(MIGRATIONS_SECTION));
    assertEquals(WARNING, migrations.get("status"));
    assertEquals(1L, migrations.get("migrationWarningCount"));
    assertEquals("operator_review_required", migrations.get("lastSafeStatusMessage"));
  }

  @Test
  void supportBundle_whenDiagnosticSectionReportsError_expectDiagnosticsLifecycleError() {
    Map<String, Object> bundle =
        serviceWithDiagnosticLines(List.of("Errors: 2", "Warnings: 0")).supportBundle();

    Map<String, Object> diagnostics = mapValue(mapValue(bundle.get("sections")).get("diagnostics"));
    assertEquals(ERROR, diagnostics.get("status"));
    assertEquals(1L, diagnostics.get("diagnosticErrorCount"));
    assertEquals(0L, diagnostics.get("diagnosticWarningCount"));
  }

  @Test
  void supportBundle_whenDiagnosticSectionReportsWarning_expectDiagnosticsLifecycleWarning() {
    Map<String, Object> bundle =
        serviceWithDiagnosticLines(List.of("Errors: 0", "Warnings: 1")).supportBundle();

    Map<String, Object> diagnostics = mapValue(mapValue(bundle.get("sections")).get("diagnostics"));
    assertEquals(WARNING, diagnostics.get("status"));
    assertEquals(0L, diagnostics.get("diagnosticErrorCount"));
    assertEquals(1L, diagnostics.get("diagnosticWarningCount"));
  }

  private static OperatorBetaDashboardService service(
      AppsApiHandler appsApiHandler, AppUpdateService appUpdateService) {
    return service(appsApiHandler, null, appUpdateService);
  }

  private static OperatorBetaDashboardService service(
      AppsApiHandler appsApiHandler,
      AppCatalogsApiHandler appCatalogsApiHandler,
      AppUpdateService appUpdateService) {
    return new OperatorBetaDashboardService(
        new OperatorBetaDashboardService.HandlerSources(
            appsApiHandler, appCatalogsApiHandler, appUpdateService, null),
        new OperatorBetaDashboardService.AppStateSources(null, null, null, null),
        CLOCK);
  }

  private static OperatorBetaDashboardService serviceWithDiagnosticsWithoutLegacyAdmin() {
    DiagnosticsApiHandler diagnosticsApiHandler =
        new DiagnosticsApiHandler(() -> new DiagnosticReportSnapshot(List.of()));
    return new OperatorBetaDashboardService(
        new OperatorBetaDashboardService.HandlerSources(
            emptyAppsHandler(), emptyCatalogsApiHandler(), null, diagnosticsApiHandler),
        new OperatorBetaDashboardService.AppStateSources(
            emptyContentSubscriptionService(),
            null,
            availableTrustGraphApiHandler(),
            emptyAppServiceCoordinator()),
        CLOCK);
  }

  private static OperatorBetaDashboardService serviceWithUnavailableOptionalServices() {
    return new OperatorBetaDashboardService(
        new OperatorBetaDashboardService.HandlerSources(null, null, null, null),
        new OperatorBetaDashboardService.AppStateSources(null, null, null, null),
        CLOCK);
  }

  private static OperatorBetaDashboardService
      serviceWithAppHostInspectionFailureAndAvailableStateServices() {
    return new OperatorBetaDashboardService(
        new OperatorBetaDashboardService.HandlerSources(
            throwingAppsHandler(),
            emptyCatalogsApiHandler(),
            mock(AppUpdateService.class),
            diagnosticsWithLegacyAdmin()),
        new OperatorBetaDashboardService.AppStateSources(
            emptyContentSubscriptionService(),
            availableAppDataService(),
            availableTrustGraphApiHandler(),
            emptyAppServiceCoordinator()),
        CLOCK);
  }

  private static OperatorBetaDashboardService serviceWithLegacyAdminUsage() {
    DiagnosticsApiHandler diagnosticsApiHandler =
        new DiagnosticsApiHandler(
            () -> new DiagnosticReportSnapshot(List.of()),
            () -> new LegacyAdminUsageSnapshot(List.of(legacyAdminSurfaceUsage())));
    return new OperatorBetaDashboardService(
        new OperatorBetaDashboardService.HandlerSources(
            emptyAppsHandler(), emptyCatalogsApiHandler(), null, diagnosticsApiHandler),
        new OperatorBetaDashboardService.AppStateSources(
            emptyContentSubscriptionService(),
            availableAppDataService(),
            availableTrustGraphApiHandler(),
            emptyAppServiceCoordinator()),
        CLOCK);
  }

  private static OperatorBetaDashboardService serviceWithMissingUpdateServiceOnly() {
    return new OperatorBetaDashboardService(
        new OperatorBetaDashboardService.HandlerSources(
            appsHandler(), emptyCatalogsApiHandler(), null, diagnosticsWithLegacyAdmin()),
        new OperatorBetaDashboardService.AppStateSources(
            emptyContentSubscriptionService(),
            availableAppDataService(),
            availableTrustGraphApiHandler(),
            emptyAppServiceCoordinator()),
        CLOCK);
  }

  private static OperatorBetaDashboardService serviceWithNoAppsAndMissingUpdateService() {
    return new OperatorBetaDashboardService(
        new OperatorBetaDashboardService.HandlerSources(
            emptyAppsHandler(), emptyCatalogsApiHandler(), null, diagnosticsWithLegacyAdmin()),
        new OperatorBetaDashboardService.AppStateSources(
            emptyContentSubscriptionService(),
            availableAppDataService(),
            availableTrustGraphApiHandler(),
            emptyAppServiceCoordinator()),
        CLOCK);
  }

  private static OperatorBetaDashboardService serviceWithNoAppsAndMissingAppDataService() {
    return new OperatorBetaDashboardService(
        new OperatorBetaDashboardService.HandlerSources(
            emptyAppsHandler(), emptyCatalogsApiHandler(), null, diagnosticsWithLegacyAdmin()),
        new OperatorBetaDashboardService.AppStateSources(
            emptyContentSubscriptionService(),
            null,
            availableTrustGraphApiHandler(),
            emptyAppServiceCoordinator()),
        CLOCK);
  }

  private static OperatorBetaDashboardService serviceWithAppServiceCoordinator(
      AppServiceCoordinator appServiceCoordinator) {
    return new OperatorBetaDashboardService(
        new OperatorBetaDashboardService.HandlerSources(
            emptyAppsHandler(), emptyCatalogsApiHandler(), null, diagnosticsWithLegacyAdmin()),
        new OperatorBetaDashboardService.AppStateSources(
            emptyContentSubscriptionService(),
            availableAppDataService(),
            availableTrustGraphApiHandler(),
            appServiceCoordinator),
        CLOCK);
  }

  private static OperatorBetaDashboardService serviceWithContentSubscriptions(
      AppsApiHandler appsApiHandler, ContentSubscriptionService contentSubscriptionService) {
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(updateService.summary(SOCIAL_INBOX_APP_ID)).thenReturn(updateSummary(Map.of()));
    return new OperatorBetaDashboardService(
        new OperatorBetaDashboardService.HandlerSources(
            appsApiHandler, emptyCatalogsApiHandler(), updateService, diagnosticsWithLegacyAdmin()),
        new OperatorBetaDashboardService.AppStateSources(
            contentSubscriptionService,
            availableAppDataService(SOCIAL_INBOX_APP_ID),
            availableTrustGraphApiHandler(),
            emptyAppServiceCoordinator()),
        CLOCK);
  }

  private static OperatorBetaDashboardService serviceWithSensitiveSupportMaterial() {
    AppServiceCoordinator appServiceCoordinator = emptyAppServiceCoordinator();
    when(appServiceCoordinator.audit(any(), any()))
        .thenReturn(
            List.of(
                Map.of(
                    "eventId",
                    "audit-1",
                    "appServiceInvocationBody",
                    "{\"request\":\"Private App Service Body\"}")));
    DiagnosticsApiHandler diagnosticsApiHandler =
        new DiagnosticsApiHandler(
            () ->
                new DiagnosticReportSnapshot(
                    List.of(
                        new DiagnosticSectionSnapshot(
                            "Sensitive:",
                            List.of(
                                "path /work/private/catalog",
                                "uri USK@example/private/0",
                                "Authorization: Bearer diagnostic-secret")))),
            () -> new LegacyAdminUsageSnapshot(List.of()));
    return new OperatorBetaDashboardService(
        new OperatorBetaDashboardService.HandlerSources(
            emptyAppsHandler(), emptyCatalogsApiHandler(), null, diagnosticsApiHandler),
        new OperatorBetaDashboardService.AppStateSources(
            emptyContentSubscriptionService(),
            availableAppDataService(),
            availableTrustGraphApiHandler(),
            appServiceCoordinator),
        CLOCK);
  }

  private static OperatorBetaDashboardService serviceWithDiagnosticLines(List<String> lines) {
    DiagnosticsApiHandler diagnosticsApiHandler =
        new DiagnosticsApiHandler(
            () ->
                new DiagnosticReportSnapshot(
                    List.of(new DiagnosticSectionSnapshot("Health:", lines))),
            () -> new LegacyAdminUsageSnapshot(List.of()));
    return new OperatorBetaDashboardService(
        new OperatorBetaDashboardService.HandlerSources(
            emptyAppsHandler(), emptyCatalogsApiHandler(), null, diagnosticsApiHandler),
        new OperatorBetaDashboardService.AppStateSources(
            emptyContentSubscriptionService(),
            availableAppDataService(),
            availableTrustGraphApiHandler(),
            emptyAppServiceCoordinator()),
        CLOCK);
  }

  private static AppCatalogsApiHandler emptyCatalogsApiHandler() {
    AppCatalogsApiHandler catalogsApiHandler = mock(AppCatalogsApiHandler.class);
    when(catalogsApiHandler.listCatalogs()).thenReturn(List.of());
    when(catalogsApiHandler.listRecommendedCatalogs()).thenReturn(List.of());
    when(catalogsApiHandler.securityResponseSummary()).thenReturn(clearSecurityResponse());
    return catalogsApiHandler;
  }

  private static ContentSubscriptionService emptyContentSubscriptionService() {
    ContentSubscriptionService contentSubscriptionService = mock(ContentSubscriptionService.class);
    when(contentSubscriptionService.listAllForOperator()).thenReturn(List.of());
    return contentSubscriptionService;
  }

  private static ContentSubscriptionService contentSubscriptionServiceWithPausedSocialInbox() {
    ContentSubscriptionService contentSubscriptionService = mock(ContentSubscriptionService.class);
    when(contentSubscriptionService.listAllForOperator())
        .thenReturn(List.of(pausedSocialInboxSubscription()));
    return contentSubscriptionService;
  }

  private static TrustGraphApiHandler availableTrustGraphApiHandler() {
    TrustGraphApiHandler trustGraphApiHandler = mock(TrustGraphApiHandler.class);
    when(trustGraphApiHandler.status())
        .thenReturn(
            Map.of(
                AVAILABLE,
                true,
                "mode",
                "local-rc",
                "scoring",
                "direct-local-anchors-confidence-weighted-average",
                "scope",
                Map.of(
                    "localAnchorsOnly",
                    true,
                    "importedStatementsOnly",
                    true,
                    "noCrawling",
                    true,
                    "noGlobalModeration",
                    true,
                    "noBlocking",
                    true,
                    "noRoutingDecisions",
                    true,
                    "noLegacyWoTCompatibility",
                    true),
                "statementLifecycle",
                Map.of(
                    "supportsLocalRevocation",
                    true,
                    "supportsLocalDeprecation",
                    true,
                    "revokedContributes",
                    false,
                    "deprecatedContributes",
                    false),
                "durable",
                false,
                "storeType",
                "memory",
                "anchorCount",
                0,
                "statementCount",
                0,
                "auditCount",
                0));
    return trustGraphApiHandler;
  }

  private static AppServiceCoordinator emptyAppServiceCoordinator() {
    AppServiceCoordinator appServiceCoordinator = mock(AppServiceCoordinator.class);
    when(appServiceCoordinator.listGrants(any())).thenReturn(List.of());
    when(appServiceCoordinator.audit(any(), any())).thenReturn(List.of());
    when(appServiceCoordinator.listServices()).thenReturn(List.of());
    when(appServiceCoordinator.listRequests(any())).thenReturn(List.of());
    return appServiceCoordinator;
  }

  private static AppServiceCoordinator appServiceCoordinatorWithPendingGrant() {
    AppServiceCoordinator appServiceCoordinator = emptyAppServiceCoordinator();
    when(appServiceCoordinator.listGrants(any())).thenReturn(List.of(Map.of("status", PENDING)));
    return appServiceCoordinator;
  }

  private static AppDataService availableAppDataService() {
    return availableAppDataService(APP_ID);
  }

  private static AppDataService availableAppDataService(String appId) {
    AppDataService appDataService = mock(AppDataService.class);
    when(appDataService.status(appId))
        .thenReturn(
            Map.of(QUOTA_FIELD, Map.of("dataQuotaAvailable", true), WARNINGS_FIELD, List.of()));
    return appDataService;
  }

  private static DiagnosticsApiHandler diagnosticsWithLegacyAdmin() {
    return new DiagnosticsApiHandler(
        () -> new DiagnosticReportSnapshot(List.of()),
        () -> new LegacyAdminUsageSnapshot(List.of()));
  }

  private static LegacyAdminSurfaceUsage legacyAdminSurfaceUsage() {
    return new LegacyAdminSurfaceUsage(
        "queue-downloads",
        "Download queue",
        "/downloads/",
        "PRIMARY_REPLACED",
        "/apps/queue-manager/",
        "REDIRECT_TO_REPLACEMENT",
        1,
        "phase-6-pr-8",
        "none",
        "CANONICAL_AND_SLASHLESS_ALIAS",
        0,
        12L,
        4L,
        1L,
        0L,
        0L,
        1_770_000_000_000L);
  }

  private static AppsApiHandler appsHandler() {
    return appsHandler(false);
  }

  private static AppsApiHandler appsHandler(boolean running) {
    return appsHandler(installedApp(running));
  }

  private static AppsApiHandler appsHandler(Map<String, Object> app) {
    AppsApiHandler appsApiHandler = mock(AppsApiHandler.class);
    when(appsApiHandler.list(false)).thenReturn(List.of(app));
    return appsApiHandler;
  }

  private static AppsApiHandler emptyAppsHandler() {
    AppsApiHandler appsApiHandler = mock(AppsApiHandler.class);
    when(appsApiHandler.list(false)).thenReturn(List.of());
    return appsApiHandler;
  }

  private static AppsApiHandler throwingAppsHandler() {
    AppsApiHandler appsApiHandler = mock(AppsApiHandler.class);
    when(appsApiHandler.list(false)).thenThrow(new IllegalStateException("backend offline"));
    return appsApiHandler;
  }

  private static Map<String, Object> installedApp(boolean running) {
    LinkedHashMap<String, Object> app = new LinkedHashMap<>();
    app.put("appId", APP_ID);
    app.put("name", "Feed Reader");
    app.put("version", "1.0.0");
    app.put("running", running);
    app.put(
        QUOTA_FIELD,
        Map.of(WARNINGS_FIELD, List.of(), "dataOverLimit", false, "cacheOverLimit", false));
    app.put("sandbox", Map.of(WARNINGS_FIELD, List.of()));
    app.put("apiCompatibility", Map.of("status", "compatible"));
    return app;
  }

  private static Map<String, Object> installedAppWithQuotaWarning() {
    Map<String, Object> app = installedApp(false);
    app.put(
        QUOTA_FIELD,
        Map.of(
            WARNINGS_FIELD,
            List.of("Cache usage exceeds the configured app limit."),
            "dataOverLimit",
            false,
            "cacheOverLimit",
            false));
    return app;
  }

  private static Map<String, Object> installedSocialInboxApp() {
    Map<String, Object> app = installedApp(false);
    app.put("appId", SOCIAL_INBOX_APP_ID);
    app.put("name", "Social Inbox");
    return app;
  }

  private static Map<String, Object> installedSocialInboxAppWithQuotaWarning() {
    Map<String, Object> app = installedSocialInboxApp();
    app.put(
        QUOTA_FIELD,
        Map.of(
            WARNINGS_FIELD,
            List.of("Cache usage exceeds the configured app limit."),
            "dataOverLimit",
            false,
            "cacheOverLimit",
            false));
    return app;
  }

  private static Map<String, Object> pausedSocialInboxSubscription() {
    LinkedHashMap<String, Object> subscription = new LinkedHashMap<>();
    subscription.put("appId", SOCIAL_INBOX_APP_ID);
    subscription.put("subscriptionId", "social-source-1");
    subscription.put("label", "Social source");
    subscription.put("sourceUri", "crypta:USK@fake-social-source/messages/0");
    subscription.put("normalizedSourceKind", "usk");
    subscription.put("paused", true);
    subscription.put("status", "scheduled");
    subscription.put("failureCount", 0);
    subscription.put("lastErrorCode", null);
    return subscription;
  }

  private static Map<String, Object> catalog() {
    LinkedHashMap<String, Object> catalog = new LinkedHashMap<>();
    catalog.put("catalogId", "local-catalog");
    catalog.put("name", "Local Catalog");
    catalog.put("source", UPPERCASE_FILE_CATALOG_SOURCE);
    catalog.put(SOURCE_KIND_FIELD, "file");
    catalog.put("lastFetchStatus", "success");
    catalog.put("appCount", 0);
    return catalog;
  }

  private static Map<String, Object> remoteCatalog() {
    LinkedHashMap<String, Object> catalog = new LinkedHashMap<>();
    catalog.put("catalogId", "private-beta");
    catalog.put("name", "Private Beta");
    catalog.put("source", "https://staging.example.invalid/private/catalog.json");
    catalog.put(SOURCE_KIND_FIELD, MANUAL_SOURCE_KIND);
    catalog.put("lastFetchStatus", "success");
    catalog.put("appCount", 0);
    return catalog;
  }

  private static Map<String, Object> clearSecurityResponse() {
    return Map.of(
        "status",
        "clear",
        SUMMARY_FIELD,
        Map.of(
            "activeAdvisoryCount",
            0,
            "denylistedVersionCount",
            0,
            "revokedReviewerKeyCount",
            0,
            "revokedReceiptCount",
            0,
            "catalogSigningKeyCount",
            0,
            "catalogKeyRotationStatus",
            "configured",
            "supportRedactionStatus",
            "required"),
        "activeAdvisories",
        List.of(),
        "denylistedVersions",
        List.of(),
        "reviewerGovernance",
        Map.of("counts", Map.of("active", 0, "retired", 0, "revoked", 0)),
        "catalogSigningKeys",
        List.of(),
        "operatorActions",
        List.of(),
        "supportGuidance",
        "Use redacted support bundle preview before sharing evidence.");
  }

  private static Map<String, Object> denylistSecurityResponse() {
    Map<String, Object> response = new LinkedHashMap<>(clearSecurityResponse());
    response.put("status", "denylist_active");
    response.put(
        SUMMARY_FIELD,
        Map.of(
            "activeAdvisoryCount",
            1,
            "denylistedVersionCount",
            1,
            "revokedReviewerKeyCount",
            1,
            "revokedReceiptCount",
            0,
            "catalogSigningKeyCount",
            1,
            "catalogKeyRotationStatus",
            "configured",
            "supportRedactionStatus",
            "required"));
    response.put(
        "denylistedVersions",
        List.of(Map.of("appId", APP_ID, "version", "1.0.0", "advisoryId", "CRYPTA-2026-0001")));
    return response;
  }

  private static Map<String, Object> reviewerRevocationSecurityResponse() {
    Map<String, Object> response = new LinkedHashMap<>(clearSecurityResponse());
    response.put("status", "reviewer_revocation_active");
    response.put(
        SUMMARY_FIELD,
        Map.of(
            "activeAdvisoryCount",
            0,
            "denylistedVersionCount",
            0,
            "revokedReviewerKeyCount",
            1,
            "revokedReceiptCount",
            1,
            "catalogSigningKeyCount",
            1,
            "catalogKeyRotationStatus",
            "configured",
            "supportRedactionStatus",
            "required"));
    return response;
  }

  private static Map<String, Object> updateSummary(Map<String, Object> candidate) {
    return updateSummary(candidate, Map.of(AVAILABLE, false), Map.of(AVAILABLE, false));
  }

  private static Map<String, Object> updateSummary(
      Map<String, Object> candidate, Map<String, Object> staged, Map<String, Object> rollback) {
    return Map.of("candidate", candidate, "staged", staged, "rollback", rollback);
  }

  private static Map<String, Object> availableCandidate() {
    return availableCandidate(Map.of());
  }

  private static Map<String, Object> availableCandidate(Map<String, Object> reviewTrust) {
    return availableCandidate(reviewTrust, Map.of());
  }

  private static Map<String, Object> availableCandidate(
      Map<String, Object> reviewTrust, Map<String, Object> securityDecision) {
    return Map.of(
        "status",
        AVAILABLE,
        "autoStageAllowed",
        true,
        "operatorActionRequired",
        false,
        "reviewTrust",
        reviewTrust,
        "securityDecision",
        securityDecision);
  }

  private static Map<String, Object> consentRequiredCandidate() {
    LinkedHashMap<String, Object> candidate = new LinkedHashMap<>(availableCandidate());
    candidate.put("materialConsentReasons", List.of("new_permission"));
    candidate.put("operatorActionRequired", true);
    return candidate;
  }

  private static Map<String, Object> availableCandidateWithDataMigration(
      Map<String, Object> dataMigration) {
    LinkedHashMap<String, Object> candidate = new LinkedHashMap<>(availableCandidate());
    candidate.put("dataMigration", dataMigration);
    return candidate;
  }

  private static Map<String, Object> stagedUpdate() {
    return stagedUpdate(Map.of());
  }

  private static Map<String, Object> stagedUpdate(Map<String, Object> securityDecision) {
    return Map.of(AVAILABLE, true, "reviewTrust", Map.of(), "securityDecision", securityDecision);
  }

  private static Map<String, Object> stagedUpdateWithDataMigration(
      Map<String, Object> dataMigration) {
    LinkedHashMap<String, Object> staged = new LinkedHashMap<>(stagedUpdate());
    staged.put("dataMigration", dataMigration);
    return staged;
  }

  private static Map<String, Object> rollbackAvailable() {
    return Map.of(AVAILABLE, true);
  }

  private static List<Map<String, Object>> recoveryActionsForFirstApp(
      Map<String, Object> dashboard) {
    return listOfMaps(listOfMaps(dashboard.get("apps")).getFirst().get("recoveryActions"));
  }

  private static List<String> warningsForFirstApp(Map<String, Object> dashboard) {
    return stringList(listOfMaps(dashboard.get("apps")).getFirst().get(WARNINGS_FIELD));
  }

  private static boolean actionAvailable(List<Map<String, Object>> actions, String actionId) {
    return Boolean.TRUE.equals(action(actions, actionId).get(AVAILABLE));
  }

  private static Map<String, Object> appUpdatesSection(Map<String, Object> bundle) {
    return mapValue(mapValue(bundle.get("sections")).get(APP_UPDATES_SECTION));
  }

  private static void assertUnavailableAppDerivedSection(
      Map<String, Object> section, String appHostInspectionWarning) {
    assertEquals(UNAVAILABLE, section.get("status"));
    assertEquals(0, section.get("boundedCount"));
    assertEquals(appHostInspectionWarning, section.get("lastSafeStatusMessage"));
  }

  private static void assertSafeDiagnosticsSummary(Map<String, Object> bundle) {
    Map<String, Object> diagnostics = mapValue(bundle.get("diagnostics"));
    assertEquals(true, diagnostics.get(AVAILABLE));
    assertEquals(1, diagnostics.get("sectionCount"));
    assertEquals(true, diagnostics.get("plainTextExportAvailable"));
    assertFalse(diagnostics.containsKey("plainTextExport"));
    List<Map<String, Object>> sections = listOfMaps(diagnostics.get("sections"));
    Map<String, Object> section = sections.getFirst();
    assertFalse(section.containsKey("lines"));
    assertEquals(3, section.get("lineCount"));
    assertEquals(3L, section.get("redactedLineCount"));
    assertTrue(section.get("digest") instanceof String digest && digest.matches("[a-f0-9]{64}"));
  }

  private static void assertLifecycleSectionsPresent(Map<String, Object> bundle) {
    Map<String, Object> sections = mapValue(bundle.get("sections"));
    List<String> expectedSections =
        List.of(
            "catalog",
            "appUpdates",
            "subscriptions",
            "appData",
            "appServiceGrants",
            CONSENT_SECTION,
            MIGRATIONS_SECTION,
            "sandbox",
            "contentFormats",
            "trustGraph",
            SOCIAL_INBOX_SECTION,
            "recovery",
            "diagnostics",
            "legacyFallbacks",
            "releaseCertification");
    assertTrue(sections.keySet().containsAll(expectedSections));
    assertEquals(
        "app-platform.privacy-preserving-beta-diagnostics",
        mapValue(sections.get("releaseCertification")).get("evidenceId"));
    assertEquals(true, mapValue(sections.get("diagnostics")).get("rawDiagnosticBodiesExcluded"));
    assertEquals(
        false,
        mapValue(sections.get("legacyFallbacks")).get("plainTextExportEmbeddedInDefaultBundle"));
  }

  private static Map<String, Object> action(List<Map<String, Object>> actions, String actionId) {
    return actions.stream()
        .filter(candidate -> actionId.equals(candidate.get("id")))
        .findFirst()
        .orElseThrow();
  }

  private static Map<String, Object> mapValue(Object value) {
    return value instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
  }

  private static List<Map<String, Object>> listOfMaps(Object value) {
    return value instanceof List<?> list ? (List<Map<String, Object>>) list : List.of();
  }

  private static List<String> stringList(Object value) {
    if (value instanceof List<?> list) {
      return list.stream().map(String.class::cast).toList();
    }
    return List.of();
  }
}
