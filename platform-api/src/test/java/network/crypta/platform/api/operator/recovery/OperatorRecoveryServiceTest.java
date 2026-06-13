package network.crypta.platform.api.operator.recovery;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.appdata.AppDataBackupBundle;
import network.crypta.platform.api.appdata.AppDataService;
import network.crypta.platform.api.appdata.AppDataStoreConfig;
import network.crypta.platform.api.appdata.InMemoryAppDataStore;
import network.crypta.platform.api.apps.AppsApiHandler;
import network.crypta.platform.api.operator.OperatorBetaDashboardService;
import network.crypta.platform.api.trust.TrustGraphApiHandler;
import network.crypta.platform.apphost.AppDiskUsageScanner;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class OperatorRecoveryServiceTest {
  private static final Instant NOW = Instant.parse("2026-06-13T00:00:00Z");
  private static final String ACTION_APP_ROLLBACK = "app.rollback";
  private static final String ACTION_CATALOG_REFRESH = "catalog.refresh";
  private static final String ACTION_EXPORT_BEFORE_UNINSTALL = "app.export-before-uninstall";
  private static final String ACTION_SUPPORT_EXPORT = "support-bundle.export";
  private static final String ACTION_SUPPORT_PREVIEW = "support-bundle.preview";
  private static final String ACTION_TRUST_GRAPH_EXPORT = "trust-graph.export-summary";
  private static final String APP_FEED_READER = "feed-reader";
  private static final String PARAM_ACTION_ID = "actionId";
  private static final String PARAM_APP_ID = "appId";
  private static final String PARAM_CATALOG_ID = "catalogId";
  private static final String PARAM_CONFIRM = "confirm";
  private static final String PARAM_CONFIRMATION_PHRASE = "confirmationPhrase";
  private static final String PARAM_PATH = "path";
  private static final String PARAM_PLAN_TOKEN = "planToken";
  private static final String PAYLOAD_BASE64 = "payloadBase64";
  private static final String PROPERTY_RUNNING = "running";
  private static final String SAFE_DIGEST_PREFIX = "sha256:";
  private static final String TEST_CRYPTA_VERSION = "cryptad-rc-test-version";
  private static final String UNSAFE_CONTENT_URI_PREFIX = "USK@example";
  private static final String UNSAFE_PATH_PREFIX =
      String.join("/", "", "work", "cryptad", "private");
  private static final String UNSAFE_ROUTE = "apps/feed-reader/updates/rollback";

  @Test
  void actions_whenListed_expectClosedActionIdsAndNoRouteProxyShape() {
    OperatorRecoveryService service = service();

    List<Map<String, Object>> actions = service.actions();

    assertTrue(
        actions.stream()
            .anyMatch(action -> ACTION_APP_ROLLBACK.equals(action.get(PARAM_ACTION_ID))));
    assertTrue(
        actions.stream()
            .anyMatch(action -> "subscription.reset-backoff".equals(action.get(PARAM_ACTION_ID))));
    assertTrue(
        actions.stream()
            .allMatch(action -> "operator/recovery/plan".equals(action.get("planRoute"))));
    assertTrue(
        actions.stream()
            .allMatch(action -> "operator/recovery/execute".equals(action.get("executeRoute"))));
    assertFalse(actions.toString().contains("\"path\""));
  }

  @Test
  void plan_whenTrustGraphResetRequested_expectUnavailableInsteadOfFakeSuccess() {
    OperatorRecoveryService service = service();

    OperatorRecoveryPlan plan =
        service.plan(Map.of(PARAM_ACTION_ID, List.of("trust-graph.reset-local-state")));

    assertEquals(OperatorRecoveryStatus.UNAVAILABLE, plan.status());
    assertEquals(OperatorRecoveryErrorCode.SERVICE_UNAVAILABLE, plan.reasonCode());
    assertTrue(plan.destructive());
    assertTrue(plan.toJson().toString().contains("RESET TRUST GRAPH"));
  }

  @Test
  void execute_whenDestructiveActionMissingConfirmation_expectConflict() {
    OperatorRecoveryService service = service();
    OperatorRecoveryPlan plan =
        service.plan(
            Map.of(
                PARAM_ACTION_ID,
                List.of(ACTION_APP_ROLLBACK),
                PARAM_APP_ID,
                List.of(APP_FEED_READER)));
    Map<String, List<String>> parameters =
        Map.of(
            PARAM_ACTION_ID,
            List.of(ACTION_APP_ROLLBACK),
            PARAM_APP_ID,
            List.of(APP_FEED_READER),
            PARAM_PLAN_TOKEN,
            List.of(plan.planToken()));

    PlatformApiException failure =
        assertThrows(PlatformApiException.class, () -> service.execute(parameters));

    assertEquals(409, failure.statusCode());
    assertEquals("recovery_confirmation_required", failure.errorCode());
  }

  @Test
  void execute_whenPlanTokenMissing_expectConflictBeforeDispatch() {
    OperatorRecoveryService service = service();
    Map<String, List<String>> parameters = Map.of(PARAM_ACTION_ID, List.of(ACTION_SUPPORT_PREVIEW));

    PlatformApiException failure =
        assertThrows(PlatformApiException.class, () -> service.execute(parameters));

    assertEquals(409, failure.statusCode());
    assertEquals("recovery_plan_required", failure.errorCode());
  }

  @Test
  void execute_whenPlanTokenTargetsDifferentAction_expectConflictBeforeDispatch() {
    OperatorRecoveryService service = service();
    OperatorRecoveryPlan plan =
        service.plan(Map.of(PARAM_ACTION_ID, List.of(ACTION_SUPPORT_PREVIEW)));
    Map<String, List<String>> parameters =
        Map.of(
            PARAM_ACTION_ID,
            List.of(ACTION_CATALOG_REFRESH),
            PARAM_CATALOG_ID,
            List.of("first-party"),
            PARAM_PLAN_TOKEN,
            List.of(plan.planToken()));

    PlatformApiException failure =
        assertThrows(PlatformApiException.class, () -> service.execute(parameters));

    assertEquals(409, failure.statusCode());
    assertEquals("recovery_plan_mismatch", failure.errorCode());
  }

  @Test
  void execute_whenPlanTokenReused_expectConflictAfterFirstUse() {
    OperatorRecoveryService service = service();
    OperatorRecoveryPlan plan =
        service.plan(Map.of(PARAM_ACTION_ID, List.of(ACTION_SUPPORT_PREVIEW)));
    Map<String, List<String>> parameters =
        Map.of(
            PARAM_ACTION_ID,
            List.of(ACTION_SUPPORT_PREVIEW),
            PARAM_PLAN_TOKEN,
            List.of(plan.planToken()));

    OperatorRecoveryResult result = service.execute(parameters);
    PlatformApiException failure =
        assertThrows(PlatformApiException.class, () -> service.execute(parameters));

    assertEquals(OperatorRecoveryStatus.COMPLETED, result.status());
    assertEquals(409, failure.statusCode());
    assertEquals("recovery_plan_mismatch", failure.errorCode());
  }

  @Test
  void execute_whenSupportPreviewIncludesArbitraryPathParameter_expectIgnored() {
    OperatorRecoveryService service = service();
    OperatorRecoveryPlan plan =
        service.plan(
            Map.of(
                PARAM_ACTION_ID,
                List.of(ACTION_SUPPORT_PREVIEW),
                PARAM_PATH,
                List.of(UNSAFE_ROUTE)));

    OperatorRecoveryResult result =
        service.execute(
            Map.of(
                PARAM_ACTION_ID,
                List.of(ACTION_SUPPORT_PREVIEW),
                PARAM_PATH,
                List.of(UNSAFE_ROUTE),
                PARAM_PLAN_TOKEN,
                List.of(plan.planToken())));

    assertEquals(OperatorRecoveryStatus.COMPLETED, result.status());
    assertEquals(OperatorRecoveryErrorCode.NONE, result.reasonCode());
    assertFalse(result.toJson().toString().contains(UNSAFE_ROUTE));
  }

  @Test
  void execute_whenSupportBundlePreviewRequested_expectRealPreviewArtifactBuilt() {
    AtomicInteger supportBundleCalls = new AtomicInteger();
    OperatorRecoveryService service =
        service(
            null,
            null,
            null,
            null,
            () -> "test",
            () -> {
              supportBundleCalls.incrementAndGet();
              return sampleSupportBundle();
            });
    OperatorRecoveryPlan plan =
        service.plan(Map.of(PARAM_ACTION_ID, List.of(ACTION_SUPPORT_PREVIEW)));

    OperatorRecoveryResult result =
        service.execute(
            Map.of(
                PARAM_ACTION_ID,
                List.of(ACTION_SUPPORT_PREVIEW),
                PARAM_PLAN_TOKEN,
                List.of(plan.planToken())));

    String resultJson = result.toJson().toString();
    assertEquals(OperatorRecoveryStatus.COMPLETED, result.status());
    assertEquals(1, supportBundleCalls.get());
    assertTrue(result.details().containsKey("supportBundlePreview"));
    assertTrue(resultJson.contains("crypta-operator-support-bundle-preview"));
    assertTrue(resultJson.contains("includedSections"));
    assertFalse(resultJson.contains("previewAvailable"));
  }

  @Test
  void execute_whenSupportBundleExportRequested_expectRedactedBundleArtifactReturned() {
    AtomicInteger supportBundleCalls = new AtomicInteger();
    OperatorRecoveryService service =
        service(
            null,
            null,
            null,
            null,
            () -> "test",
            () -> {
              supportBundleCalls.incrementAndGet();
              return sampleSupportBundle();
            });
    OperatorRecoveryPlan plan =
        service.plan(Map.of(PARAM_ACTION_ID, List.of(ACTION_SUPPORT_EXPORT)));

    OperatorRecoveryResult result =
        service.execute(
            Map.of(
                PARAM_ACTION_ID,
                List.of(ACTION_SUPPORT_EXPORT),
                PARAM_PLAN_TOKEN,
                List.of(plan.planToken())));

    String resultJson = result.toJson().toString();
    assertEquals(OperatorRecoveryStatus.COMPLETED, result.status());
    assertEquals(1, supportBundleCalls.get());
    assertTrue(result.details().containsKey("supportBundle"));
    assertTrue(resultJson.contains("cryptad-operator-support-bundle"));
    assertTrue(resultJson.contains("recoveryContext"));
    assertTrue(resultJson.contains("supportBundlePayloadPolicy"));
    assertFalse(resultJson.contains("operator/support-bundle"));
    assertFalse(resultJson.contains("secret-form-password"));
  }

  @Test
  void planResultAndSupportContext_whenUnsafeTargetIdSupplied_expectTargetIdRedacted() {
    OperatorRecoveryService service = service();
    String unsafeCatalogId = unsafeTargetId("secret/0/catalog.json");
    OperatorRecoveryPlan plan =
        service.plan(
            Map.of(
                PARAM_ACTION_ID,
                List.of(ACTION_CATALOG_REFRESH),
                PARAM_CATALOG_ID,
                List.of(unsafeCatalogId)));

    OperatorRecoveryResult result =
        service.execute(
            Map.of(
                PARAM_ACTION_ID,
                List.of(ACTION_CATALOG_REFRESH),
                PARAM_CATALOG_ID,
                List.of(unsafeCatalogId),
                PARAM_PLAN_TOKEN,
                List.of(plan.planToken())));

    String planJson = plan.toJson().toString();
    String resultJson = result.toJson().toString();
    String supportJson = service.supportContext().toString();
    assertFalse(planJson.contains(UNSAFE_PATH_PREFIX));
    assertFalse(planJson.contains(UNSAFE_CONTENT_URI_PREFIX));
    assertFalse(resultJson.contains(UNSAFE_PATH_PREFIX));
    assertFalse(resultJson.contains(UNSAFE_CONTENT_URI_PREFIX));
    assertFalse(supportJson.contains(UNSAFE_PATH_PREFIX));
    assertFalse(supportJson.contains(UNSAFE_CONTENT_URI_PREFIX));
    assertTrue(planJson.contains(SAFE_DIGEST_PREFIX));
    assertTrue(resultJson.contains(SAFE_DIGEST_PREFIX));
    assertTrue(supportJson.contains(SAFE_DIGEST_PREFIX));
  }

  @Test
  void plan_whenDestructiveUnsafeTargetIdSupplied_expectConfirmationPhraseRedacted() {
    OperatorRecoveryService service = service();
    String unsafeAppId = unsafeTargetId(APP_FEED_READER);

    OperatorRecoveryPlan plan =
        service.plan(
            Map.of(
                PARAM_ACTION_ID, List.of(ACTION_APP_ROLLBACK), PARAM_APP_ID, List.of(unsafeAppId)));

    String planJson = plan.toJson().toString();
    assertFalse(plan.confirmationPhrase().contains(UNSAFE_PATH_PREFIX));
    assertFalse(plan.confirmationPhrase().contains(UNSAFE_CONTENT_URI_PREFIX));
    assertFalse(planJson.contains(UNSAFE_PATH_PREFIX));
    assertFalse(planJson.contains(UNSAFE_CONTENT_URI_PREFIX));
    assertTrue(plan.confirmationPhrase().contains(SAFE_DIGEST_PREFIX));
  }

  @Test
  void execute_whenExportBeforeUninstallSucceeds_expectRelatedAppStateCleared() {
    AppsApiHandler appsApiHandler = mock(AppsApiHandler.class);
    when(appsApiHandler.get(APP_FEED_READER, false)).thenReturn(Map.of(PROPERTY_RUNNING, false));
    when(appsApiHandler.uninstall(APP_FEED_READER, false, true))
        .thenReturn(Map.of(PARAM_APP_ID, APP_FEED_READER, "installed", false));
    RecordingAppUninstallCleanup cleanup = new RecordingAppUninstallCleanup();
    OperatorRecoveryService service =
        service(appsApiHandler, appDataService(), null, cleanup, () -> TEST_CRYPTA_VERSION);
    OperatorRecoveryPlan plan =
        service.plan(
            Map.of(
                PARAM_ACTION_ID,
                List.of(ACTION_EXPORT_BEFORE_UNINSTALL),
                PARAM_APP_ID,
                List.of(APP_FEED_READER)));

    OperatorRecoveryResult result =
        service.execute(
            Map.of(
                PARAM_ACTION_ID,
                List.of(ACTION_EXPORT_BEFORE_UNINSTALL),
                PARAM_APP_ID,
                List.of(APP_FEED_READER),
                PARAM_CONFIRM,
                List.of("true"),
                PARAM_CONFIRMATION_PHRASE,
                List.of(plan.confirmationPhrase()),
                PARAM_PLAN_TOKEN,
                List.of(plan.planToken())));

    assertEquals(OperatorRecoveryStatus.COMPLETED, result.status());
    assertEquals(APP_FEED_READER, cleanup.appId);
    assertTrue(cleanup.preserveData);
    assertTrue(result.toJson().toString().contains("appPlatformStateCleared=true"));
    assertEquals(
        TEST_CRYPTA_VERSION,
        AppDataBackupBundle.parse(
                Base64.getUrlDecoder()
                    .decode((String) result.sensitiveBackup().get(PAYLOAD_BASE64)))
            .manifest()
            .sourceCryptaVersion());
  }

  @Test
  void execute_whenExportBeforeUninstallFailsAfterBackup_expectPartialResultWithSensitiveBackup() {
    AppsApiHandler appsApiHandler = mock(AppsApiHandler.class);
    when(appsApiHandler.get(APP_FEED_READER, false)).thenReturn(Map.of(PROPERTY_RUNNING, false));
    when(appsApiHandler.uninstall(APP_FEED_READER, false, true))
        .thenThrow(
            new PlatformApiException(
                503, "app_uninstall_incomplete", "App uninstall failed under /work/private."));
    RecordingAppUninstallCleanup cleanup = new RecordingAppUninstallCleanup();
    OperatorRecoveryService service =
        service(appsApiHandler, appDataService(), null, cleanup, () -> TEST_CRYPTA_VERSION);
    OperatorRecoveryPlan plan =
        service.plan(
            Map.of(
                PARAM_ACTION_ID,
                List.of(ACTION_EXPORT_BEFORE_UNINSTALL),
                PARAM_APP_ID,
                List.of(APP_FEED_READER)));

    OperatorRecoveryResult result =
        service.execute(
            Map.of(
                PARAM_ACTION_ID,
                List.of(ACTION_EXPORT_BEFORE_UNINSTALL),
                PARAM_APP_ID,
                List.of(APP_FEED_READER),
                PARAM_CONFIRM,
                List.of("true"),
                PARAM_CONFIRMATION_PHRASE,
                List.of(plan.confirmationPhrase()),
                PARAM_PLAN_TOKEN,
                List.of(plan.planToken())));

    String rendered = result.toJson().toString();
    assertEquals(OperatorRecoveryStatus.PARTIAL, result.status());
    assertEquals(OperatorRecoveryErrorCode.OPERATION_FAILED, result.reasonCode());
    assertTrue(rendered.contains("app_uninstall_incomplete"));
    assertTrue(rendered.contains("appPlatformStateCleared=false"));
    assertFalse(rendered.contains("/work/private"));
    assertNull(cleanup.appId);
    assertEquals(
        TEST_CRYPTA_VERSION,
        AppDataBackupBundle.parse(
                Base64.getUrlDecoder()
                    .decode((String) result.sensitiveBackup().get(PAYLOAD_BASE64)))
            .manifest()
            .sourceCryptaVersion());
  }

  @Test
  void execute_whenExportBeforeUninstallCleanupFails_expectPartialResultWithSensitiveBackup() {
    AppsApiHandler appsApiHandler = mock(AppsApiHandler.class);
    when(appsApiHandler.get(APP_FEED_READER, false)).thenReturn(Map.of(PROPERTY_RUNNING, false));
    when(appsApiHandler.uninstall(APP_FEED_READER, false, true))
        .thenReturn(Map.of(PARAM_APP_ID, APP_FEED_READER, "installed", false));
    OperatorRecoveryService service =
        service(
            appsApiHandler,
            appDataService(),
            null,
            (ignoredAppId, ignoredPreserveData) -> {
              throw new PlatformApiException(
                  503, "app_state_cleanup_unavailable", "App state cleanup is unavailable.");
            },
            () -> TEST_CRYPTA_VERSION);
    OperatorRecoveryPlan plan =
        service.plan(
            Map.of(
                PARAM_ACTION_ID,
                List.of(ACTION_EXPORT_BEFORE_UNINSTALL),
                PARAM_APP_ID,
                List.of(APP_FEED_READER)));

    OperatorRecoveryResult result =
        service.execute(
            Map.of(
                PARAM_ACTION_ID,
                List.of(ACTION_EXPORT_BEFORE_UNINSTALL),
                PARAM_APP_ID,
                List.of(APP_FEED_READER),
                PARAM_CONFIRM,
                List.of("true"),
                PARAM_CONFIRMATION_PHRASE,
                List.of(plan.confirmationPhrase()),
                PARAM_PLAN_TOKEN,
                List.of(plan.planToken())));

    assertEquals(OperatorRecoveryStatus.PARTIAL, result.status());
    assertEquals(OperatorRecoveryErrorCode.OPERATION_FAILED, result.reasonCode());
    assertTrue(result.toJson().toString().contains("appPlatformStateCleared=false"));
    assertTrue(result.toJson().toString().contains("app_state_cleanup_unavailable"));
    assertEquals(
        TEST_CRYPTA_VERSION,
        AppDataBackupBundle.parse(
                Base64.getUrlDecoder()
                    .decode((String) result.sensitiveBackup().get(PAYLOAD_BASE64)))
            .manifest()
            .sourceCryptaVersion());
  }

  @Test
  void plan_whenAppStartRequested_expectStoppedAppRequirementReported() {
    AppsApiHandler appsApiHandler = mock(AppsApiHandler.class);
    when(appsApiHandler.get(APP_FEED_READER, false)).thenReturn(Map.of(PROPERTY_RUNNING, false));
    OperatorRecoveryService service = service(appsApiHandler, null);

    OperatorRecoveryPlan plan =
        service.plan(
            Map.of(PARAM_ACTION_ID, List.of("app.start"), PARAM_APP_ID, List.of(APP_FEED_READER)));

    assertTrue(plan.requiresStoppedApp());
  }

  @Test
  void execute_whenTrustGraphStoreUnavailable_expectFailedResultInsteadOfThrownException() {
    OperatorRecoveryService service = service(null, TrustGraphApiHandler.unavailable());
    OperatorRecoveryPlan plan =
        service.plan(Map.of(PARAM_ACTION_ID, List.of(ACTION_TRUST_GRAPH_EXPORT)));

    OperatorRecoveryResult result =
        service.execute(
            Map.of(
                PARAM_ACTION_ID,
                List.of(ACTION_TRUST_GRAPH_EXPORT),
                PARAM_PLAN_TOKEN,
                List.of(plan.planToken())));

    assertEquals(OperatorRecoveryStatus.FAILED, result.status());
    assertEquals(OperatorRecoveryErrorCode.OPERATION_FAILED, result.reasonCode());
    assertTrue(result.toJson().toString().contains("trust_graph_store_unavailable"));
    assertTrue(result.toJson().toString().contains("statusCode=503"));
  }

  private static OperatorRecoveryService service() {
    return service(null, null, null, null, () -> "test");
  }

  private static OperatorRecoveryService service(
      AppsApiHandler appsApiHandler, TrustGraphApiHandler trustGraphApiHandler) {
    return service(appsApiHandler, null, trustGraphApiHandler, null, () -> "test");
  }

  private static OperatorRecoveryService service(
      AppsApiHandler appsApiHandler,
      AppDataService appDataService,
      TrustGraphApiHandler trustGraphApiHandler,
      OperatorRecoveryService.AppUninstallCleanup appUninstallCleanup,
      Supplier<String> currentCryptaVersion) {
    return service(
        appsApiHandler,
        appDataService,
        trustGraphApiHandler,
        appUninstallCleanup,
        currentCryptaVersion,
        null);
  }

  private static OperatorRecoveryService service(
      AppsApiHandler appsApiHandler,
      AppDataService appDataService,
      TrustGraphApiHandler trustGraphApiHandler,
      OperatorRecoveryService.AppUninstallCleanup appUninstallCleanup,
      Supplier<String> currentCryptaVersion,
      Supplier<Map<String, Object>> supportBundleSupplier) {
    OperatorBetaDashboardService dashboardService =
        new OperatorBetaDashboardService(
            new OperatorBetaDashboardService.HandlerSources(null, null, null, null),
            new OperatorBetaDashboardService.AppStateSources(null, null, null, null));
    return new OperatorRecoveryService(
        new OperatorRecoveryService.Dependencies(
            appsApiHandler,
            null,
            null,
            null,
            appDataService,
            trustGraphApiHandler,
            null,
            null,
            dashboardService,
            appUninstallCleanup,
            currentCryptaVersion,
            supportBundleSupplier),
        Clock.fixed(NOW, ZoneOffset.UTC));
  }

  private static Map<String, Object> sampleSupportBundle() {
    return Map.of(
        "kind",
        "cryptad-operator-support-bundle",
        "generatedAtEpochMillis",
        1781308800000L,
        "schemaVersion",
        1,
        "dashboard",
        Map.of("overallStatus", "warning", "formPassword", "secret-form-password"),
        "diagnostics",
        Map.of("status", "available"),
        "redaction",
        Map.of("status", "pass", "patternsChecked", List.of("formpassword", "localpath")),
        "warnings",
        List.of("Review before sharing."));
  }

  private static AppDataService appDataService() {
    return new AppDataService(
        new InMemoryAppDataStore(),
        null,
        new AppDataStoreConfig(256, 16, 4, 8192, 8192, 8),
        Clock.fixed(NOW, ZoneOffset.UTC),
        new AppDiskUsageScanner());
  }

  private static String unsafeTargetId(String suffix) {
    return UNSAFE_PATH_PREFIX + "/" + UNSAFE_CONTENT_URI_PREFIX + "/" + suffix;
  }

  private static final class RecordingAppUninstallCleanup
      implements OperatorRecoveryService.AppUninstallCleanup {
    private String appId;
    private boolean preserveData;

    @Override
    public void clearAppState(String appId, boolean preserveData) {
      this.appId = appId;
      this.preserveData = preserveData;
    }
  }
}
