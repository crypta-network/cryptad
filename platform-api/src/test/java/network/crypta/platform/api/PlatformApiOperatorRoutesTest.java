package network.crypta.platform.api;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.platform.api.appdata.AppDataRecord;
import network.crypta.platform.api.appdata.AppDataService;
import network.crypta.platform.api.appdata.AppDataStoreConfig;
import network.crypta.platform.api.appdata.InMemoryAppDataStore;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionSchedulerConfig;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionService;
import network.crypta.platform.api.content.subscriptions.InMemoryContentSubscriptionStore;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetConfig;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetOperation;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetService;
import network.crypta.platform.api.networkbudget.InMemoryAppNetworkBudgetStore;
import network.crypta.platform.apphost.AppDiskUsageScanner;
import network.crypta.platform.appui.AppUiOriginRegistry;
import network.crypta.runtime.spi.BoundedContentFetchRequest;
import network.crypta.runtime.spi.BoundedContentFetchResult;
import network.crypta.runtime.spi.ContentFetchPort;
import network.crypta.runtime.spi.DiagnosticReportSnapshot;
import network.crypta.runtime.spi.DiagnosticSectionSnapshot;
import network.crypta.runtime.spi.RuntimePorts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Answers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class PlatformApiOperatorRoutesTest {
  private static final String APP_ID = "feed-reader";
  private static final String BETA_DASHBOARD_SEGMENT = "beta-dashboard";
  private static final String FORM_FIELD_ASSIGNMENT = "form" + "Pass" + "word=secret-value";
  private static final String INTAKE_QUEUE_PROPERTY = "cryptad.appSubmissionIntakeDir";
  private static final String OPERATOR_SEGMENT = "operator";
  private static final String PARAM_PLAN_TOKEN = "planToken";
  private static final String SOURCE = "USK@example/feed/7/feed.json";
  private static final Instant NOW = Instant.parse("2026-05-24T12:00:00Z");
  private static final HexFormat HEX = HexFormat.of();

  @Test
  void route_whenSupportLifecycleRequested_expectReadOnlyFailClosedSnapshot() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());

    PlatformApiResponse response =
        router.route(request("GET", List.of("updates", "support-lifecycle"), Map.of()));
    PlatformApiResponse mutation =
        router.route(request("POST", List.of("updates", "support-lifecycle"), Map.of()));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"known\":false"));
    assertTrue(response.body().contains("\"runningStatus\":null"));
    assertTrue(response.body().contains("\"lifecycle_runtime_snapshot_unavailable\""));
    assertEquals(405, mutation.statusCode());
  }

  @Test
  void route_whenAppPrincipalRequestsSupportLifecycle_expectOperatorOnlyDenial() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());
    List<String> route = List.of("updates", "support-lifecycle");
    List<String> permissions = List.of(PlatformApiCapabilities.UPDATES_READ);

    PlatformApiResponse appProcessResponse =
        router.route(
            request("GET", route, Map.of(), PlatformApiPrincipal.appToken(APP_ID, permissions)));
    PlatformApiResponse appBrowserResponse =
        router.route(
            request(
                "GET",
                route,
                Map.of(),
                PlatformApiPrincipal.appBrowserSession(APP_ID, permissions)));
    PlatformApiResponse appReadableCoreResponse =
        router.route(
            request(
                "GET",
                List.of("updates", "core"),
                Map.of(),
                PlatformApiPrincipal.appToken(APP_ID, permissions)));

    assertEquals(403, appProcessResponse.statusCode());
    assertTrue(appProcessResponse.body().contains("\"code\":\"forbidden\""));
    assertEquals(403, appBrowserResponse.statusCode());
    assertTrue(appBrowserResponse.body().contains("\"code\":\"forbidden\""));
    assertEquals(200, appReadableCoreResponse.statusCode());
    assertFalse(appReadableCoreResponse.body().contains("supportLifecycle"));
  }

  @Test
  void route_whenOperatorDashboardRequested_expectSectionShape() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());

    PlatformApiResponse response =
        router.route(request("GET", List.of(OPERATOR_SEGMENT, BETA_DASHBOARD_SEGMENT), Map.of()));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"overallStatus\""));
    assertTrue(response.body().contains("\"catalogs\""));
    assertTrue(response.body().contains("\"apps\""));
    assertTrue(response.body().contains("\"subscriptions\""));
    assertTrue(response.body().contains("\"trustGraph\""));
    assertTrue(response.body().contains("\"supportWarningCount\""));
    assertTrue(response.body().contains("\"coreSupportLifecycle\""));
    assertTrue(response.body().contains("\"known\":false"));
  }

  @Test
  void route_whenOperatorRcDashboardRequested_expectRecoveryAndBudgetShape() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());

    PlatformApiResponse response =
        router.route(request("GET", List.of(OPERATOR_SEGMENT, "rc-dashboard"), Map.of()));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"dashboardKind\":\"operator-rc-recovery-dashboard\""));
    assertTrue(response.body().contains("\"operatorRcRecovery\""));
    assertTrue(response.body().contains("\"closedActionDispatch\":true"));
    assertTrue(response.body().contains("\"operatorRoutesInAppContract\":false"));
  }

  @Test
  void route_whenAppSubmissionIntakeQueueConfigured_expectSafeOperatorSummary(@TempDir Path tempDir)
      throws Exception {
    Path records = tempDir.resolve("records");
    Files.createDirectories(records);
    Files.writeString(
        records.resolve("sub-hello.json"), intakeRecordJson(), StandardCharsets.UTF_8);
    Files.writeString(
        records.resolve("transparency-log.json"),
        intakeRecordJson("transparency-log", "1".repeat(64)),
        StandardCharsets.UTF_8);
    String previous = System.getProperty(INTAKE_QUEUE_PROPERTY);
    System.setProperty(INTAKE_QUEUE_PROPERTY, tempDir.toString());
    try {
      PlatformApiRouter router = new PlatformApiRouter(runtimePorts());

      PlatformApiResponse list =
          router.route(request("GET", List.of(OPERATOR_SEGMENT, "app-submissions"), Map.of()));
      PlatformApiResponse detail =
          router.route(
              request("GET", List.of(OPERATOR_SEGMENT, "app-submissions", "sub-hello"), Map.of()));
      PlatformApiResponse transparencyLogDetail =
          router.route(
              request(
                  "GET",
                  List.of(OPERATOR_SEGMENT, "app-submissions", "transparency-log"),
                  Map.of()));
      PlatformApiResponse transparencySummary =
          router.route(
              request(
                  "GET",
                  List.of(OPERATOR_SEGMENT, "app-submissions", "transparency", "summary"),
                  Map.of()));

      assertEquals(200, list.statusCode());
      assertTrue(list.body().contains("\"kind\":\"crypta-operator-app-submission-intake\""));
      assertTrue(list.body().contains("\"queueCount\":2"));
      assertTrue(list.body().contains("\"submissionId\":\"sub-hello\""));
      assertTrue(list.body().contains("\"operatorRoutesInAppContract\":false"));
      assertFalse(list.body().contains(tempDir.toString()));
      assertFalse(list.body().contains("raw-submission"));
      assertEquals(200, detail.statusCode());
      assertTrue(detail.body().contains("\"submission\""));
      assertTrue(detail.body().contains("\"appId\":\"hello-stable\""));
      assertFalse(detail.body().contains(tempDir.toString()));
      assertEquals(200, transparencyLogDetail.statusCode());
      assertTrue(transparencyLogDetail.body().contains("\"submission\""));
      assertTrue(transparencyLogDetail.body().contains("\"submissionId\":\"transparency-log\""));
      assertFalse(
          transparencyLogDetail
              .body()
              .contains("crypta-operator-app-submission-transparency-summary"));
      assertEquals(200, transparencySummary.statusCode());
      assertTrue(
          transparencySummary
              .body()
              .contains("\"kind\":\"crypta-operator-app-submission-transparency-summary\""));
      assertTrue(transparencySummary.body().contains("\"recordsWithTransparencyDigest\":1"));
      assertTrue(transparencySummary.body().contains("\"submissionIds\":[\"transparency-log\"]"));
    } finally {
      if (previous == null) {
        System.clearProperty(INTAKE_QUEUE_PROPERTY);
      } else {
        System.setProperty(INTAKE_QUEUE_PROPERTY, previous);
      }
    }
  }

  @Test
  void route_whenAppSubmissionIntakeRecordMalformed_expectUnavailable(@TempDir Path tempDir)
      throws Exception {
    Path records = tempDir.resolve("records");
    Files.createDirectories(records);
    Files.writeString(records.resolve("bad.json"), "{", StandardCharsets.UTF_8);
    String previous = System.getProperty(INTAKE_QUEUE_PROPERTY);
    System.setProperty(INTAKE_QUEUE_PROPERTY, tempDir.toString());
    try {
      PlatformApiRouter router = new PlatformApiRouter(runtimePorts());

      PlatformApiResponse list =
          router.route(request("GET", List.of(OPERATOR_SEGMENT, "app-submissions"), Map.of()));
      PlatformApiResponse transparencySummary =
          router.route(
              request(
                  "GET",
                  List.of(OPERATOR_SEGMENT, "app-submissions", "transparency", "summary"),
                  Map.of()));
      PlatformApiResponse detail =
          router.route(
              request("GET", List.of(OPERATOR_SEGMENT, "app-submissions", "bad"), Map.of()));

      assertEquals(503, list.statusCode());
      assertEquals(503, transparencySummary.statusCode());
      assertEquals(503, detail.statusCode());
      assertTrue(list.body().contains("\"code\":\"app_submission_intake_unavailable\""));
      assertTrue(
          transparencySummary.body().contains("\"code\":\"app_submission_intake_unavailable\""));
      assertTrue(detail.body().contains("\"code\":\"app_submission_intake_unavailable\""));
    } finally {
      if (previous == null) {
        System.clearProperty(INTAKE_QUEUE_PROPERTY);
      } else {
        System.setProperty(INTAKE_QUEUE_PROPERTY, previous);
      }
    }
  }

  @Test
  void route_whenAppPrincipalRequestsOperatorDashboard_expectForbiddenBeforeDispatch() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());

    PlatformApiResponse response =
        router.route(
            request(
                "GET",
                List.of(OPERATOR_SEGMENT, BETA_DASHBOARD_SEGMENT),
                Map.of(),
                PlatformApiPrincipal.appBrowserSession("alpha", List.of("apps.read"))));

    assertEquals(403, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"forbidden\""));
  }

  @Test
  void route_whenAppPrincipalRequestsOperatorRcRecovery_expectForbiddenBeforeDispatch() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());

    PlatformApiResponse plan =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "recovery", "plan"),
                Map.of("actionId", List.of("subscription.reset-backoff")),
                PlatformApiPrincipal.appBrowserSession("alpha", List.of("content.subscribe"))));
    PlatformApiResponse execute =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "recovery", "execute"),
                Map.of("actionId", List.of("subscription.reset-backoff")),
                PlatformApiPrincipal.appBrowserSession("alpha", List.of("content.subscribe"))));

    assertEquals(403, plan.statusCode());
    assertEquals(403, execute.statusCode());
    assertTrue(plan.body().contains("\"code\":\"forbidden\""));
  }

  @Test
  void route_whenSupportBundleIncludesSensitiveDiagnostics_expectRedactedOutput() {
    RuntimePorts runtimePorts = runtimePorts();
    when(runtimePorts.diagnostic())
        .thenReturn(
            () ->
                new DiagnosticReportSnapshot(
                    List.of(
                        new DiagnosticSectionSnapshot(
                            "Sensitive:",
                            List.of(
                                "path /work/private/catalog",
                                "uri USK@example/private/0",
                                FORM_FIELD_ASSIGNMENT)))));
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts);

    PlatformApiResponse response =
        router.route(request("GET", List.of(OPERATOR_SEGMENT, "support-bundle"), Map.of()));

    assertEquals(200, response.statusCode());
    assertFalse(response.body().contains("/work/private/catalog"));
    assertFalse(response.body().contains("USK@example/private/0"));
    assertFalse(response.body().contains(FORM_FIELD_ASSIGNMENT));
    assertFalse(response.body().contains("\"plainTextExport\""));
    assertFalse(response.body().contains("\"lines\""));
    assertTrue(response.body().contains("\"schemaVersion\":2"));
    assertTrue(response.body().contains("\"privacy\""));
    assertTrue(response.body().contains("\"supportDigest\""));
    assertTrue(response.body().contains("\"supportBundleVersion\":2"));
    assertTrue(response.body().contains("\"recoveryContext\""));
    assertTrue(response.body().contains("\"redactedLineCount\":3"));
    assertTrue(response.body().contains("\"redaction\":{\"status\":\"pass\""));
    assertTrue(response.body().contains("\"coreSupportLifecycle\""));
    assertTrue(response.body().contains("\"lifecycle_runtime_snapshot_unavailable\""));
  }

  @Test
  void supportBundleForExport_whenRouteFieldsAdded_expectDigestCoversFinalPayload() {
    LinkedHashMap<String, Object> serviceBundle = new LinkedHashMap<>();
    serviceBundle.put("kind", "cryptad-operator-support-bundle");
    serviceBundle.put("schemaVersion", 2);
    serviceBundle.put("supportDigest", Map.of("algorithm", "SHA-256", "digest", "0".repeat(64)));
    LinkedHashMap<String, Object> recoveryContext = new LinkedHashMap<>();
    recoveryContext.put("kind", "operator-recovery-context");
    recoveryContext.put("supportBundlePayloadPolicy", "metadata-only");

    Map<String, Object> exported =
        PlatformApiOperatorRoutes.supportBundleForExport(serviceBundle, recoveryContext);

    Map<String, Object> supportDigest = mapValue(exported.get("supportDigest"));
    LinkedHashMap<String, Object> digestInput = new LinkedHashMap<>(exported);
    digestInput.remove("supportDigest");
    assertEquals("SHA-256", supportDigest.get("algorithm"));
    assertEquals(2, exported.get("supportBundleVersion"));
    assertEquals(recoveryContext, exported.get("recoveryContext"));
    assertEquals(sha256(PlatformApiJsonWriter.write(digestInput)), supportDigest.get("digest"));
    assertNotEquals("0".repeat(64), supportDigest.get("digest"));
  }

  @Test
  void route_whenSupportBundlePreviewRequested_expectRedactionMetadataAndRecoveryContext() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());

    PlatformApiResponse response =
        router.route(
            request("GET", List.of(OPERATOR_SEGMENT, "support-bundle", "preview"), Map.of()));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("crypta-operator-support-bundle-preview"));
    assertTrue(response.body().contains("\"includedSections\""));
    assertTrue(response.body().contains("\"recoveryContext\""));
    assertFalse(response.body().contains("payloadBase64"));
  }

  @Test
  void route_whenRecoveryActionsRequested_expectClosedActionIdsWithoutPaths() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());

    PlatformApiResponse response =
        router.route(request("GET", List.of(OPERATOR_SEGMENT, "recovery", "actions"), Map.of()));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"actionId\":\"app.rollback\""));
    assertTrue(response.body().contains("\"actionId\":\"subscription.reset-backoff\""));
    assertTrue(response.body().contains("\"planRoute\":\"operator/recovery/plan\""));
    assertFalse(response.body().contains("\"path\""));
  }

  @Test
  void route_whenRecoveryExecuteHasUnknownAction_expectRejected() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "recovery", "execute"),
                Map.of("actionId", List.of("some/arbitrary/path"))));

    assertEquals(400, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"unknown_recovery_action\""));
  }

  @Test
  void route_whenRecoveryExecuteMissingPlanToken_expectConflict() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "recovery", "execute"),
                Map.of("actionId", List.of("support-bundle.preview"))));

    assertEquals(409, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"recovery_plan_required\""));
  }

  @Test
  void route_whenRecoveryExecuteHasArbitraryPathParameter_expectPathIgnored() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());
    Map<String, List<String>> parameters =
        Map.of(
            "actionId",
            List.of("support-bundle.preview"),
            "path",
            List.of("apps/feed-reader/updates/rollback"));
    PlatformApiResponse plan =
        router.route(request("POST", List.of(OPERATOR_SEGMENT, "recovery", "plan"), parameters));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "recovery", "execute"),
                Map.of(
                    "actionId",
                    List.of("support-bundle.preview"),
                    "path",
                    List.of("apps/feed-reader/updates/rollback"),
                    PARAM_PLAN_TOKEN,
                    List.of(planToken(plan.body())))));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"actionId\":\"support-bundle.preview\""));
    assertFalse(response.body().contains("apps/feed-reader/updates/rollback"));
  }

  @Test
  void route_whenRecoveryExecuteMissingConfirmationForDestructiveAction_expectConflict() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());
    Map<String, List<String>> parameters =
        Map.of("actionId", List.of("app.rollback"), "appId", List.of(APP_ID));
    PlatformApiResponse plan =
        router.route(request("POST", List.of(OPERATOR_SEGMENT, "recovery", "plan"), parameters));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "recovery", "execute"),
                Map.of(
                    "actionId",
                    List.of("app.rollback"),
                    "appId",
                    List.of(APP_ID),
                    PARAM_PLAN_TOKEN,
                    List.of(planToken(plan.body())))));

    assertEquals(409, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"recovery_confirmation_required\""));
  }

  @Test
  void route_whenOperatorRefreshesSubscription_expectHostWrapperUsesSharedService() {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    ContentSubscriptionService service = service(fetchPort);
    String subscriptionId = (String) service.create(APP_ID, createParams()).get("subscriptionId");
    PlatformApiRouter router =
        new PlatformApiRouter(
            runtimePorts(),
            null,
            null,
            null,
            AppUiOriginRegistry.sameOriginOnly(),
            PlatformApiSharedAppServices.of(null, null, service));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "subscriptions", APP_ID, subscriptionId, "refresh"),
                Map.of()));

    assertEquals(200, response.statusCode());
    assertEquals(1, fetchPort.calls);
    assertTrue(response.body().contains("\"subscription\""));
    assertTrue(response.body().contains("\"lastSeenEdition\":7"));
    assertTrue(response.body().contains("\"sourceDisplay\":\"crypta:<redacted-content-uri>\""));
    assertTrue(response.body().contains("\"sourceDigest\""));
    assertFalse(response.body().contains("feed body"));
    assertFalse(response.body().contains("sourceUri"));
    assertFalse(response.body().contains("lastSeenResolvedUri"));
    assertFalse(response.body().contains(SOURCE));
  }

  @Test
  void route_whenOperatorResetsSubscriptionBackoff_expectNoFetchAndRedactedSummary() {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    ContentSubscriptionService service = service(fetchPort);
    String subscriptionId = (String) service.create(APP_ID, createParams()).get("subscriptionId");
    service.refresh(APP_ID, subscriptionId);
    PlatformApiRouter router =
        new PlatformApiRouter(
            runtimePorts(),
            null,
            null,
            null,
            AppUiOriginRegistry.sameOriginOnly(),
            PlatformApiSharedAppServices.of(null, null, service));
    Map<String, List<String>> parameters =
        Map.of(
            "actionId",
            List.of("subscription.reset-backoff"),
            "appId",
            List.of(APP_ID),
            "subscriptionId",
            List.of(subscriptionId));
    PlatformApiResponse plan =
        router.route(request("POST", List.of(OPERATOR_SEGMENT, "recovery", "plan"), parameters));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "recovery", "execute"),
                Map.of(
                    "actionId",
                    List.of("subscription.reset-backoff"),
                    "appId",
                    List.of(APP_ID),
                    "subscriptionId",
                    List.of(subscriptionId),
                    PARAM_PLAN_TOKEN,
                    List.of(planToken(plan.body())))));

    assertEquals(200, response.statusCode());
    assertEquals(1, fetchPort.calls);
    assertTrue(response.body().contains("\"status\":\"completed\""));
    assertTrue(response.body().contains("\"rawStatus\":\"scheduled\""));
    assertFalse(response.body().contains(SOURCE));
    assertFalse(response.body().contains("feed body"));
  }

  @Test
  void route_whenOperatorUsesLegacySubscriptionReschedule_expectNoFetch() {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    ContentSubscriptionService service = service(fetchPort);
    String subscriptionId = (String) service.create(APP_ID, createParams()).get("subscriptionId");
    PlatformApiRouter router =
        new PlatformApiRouter(
            runtimePorts(),
            null,
            null,
            null,
            AppUiOriginRegistry.sameOriginOnly(),
            PlatformApiSharedAppServices.of(null, null, service));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of(
                    OPERATOR_SEGMENT, "subscriptions", APP_ID, subscriptionId, "reschedule-now"),
                Map.of()));

    assertEquals(200, response.statusCode());
    assertEquals(0, fetchPort.calls);
    assertTrue(response.body().contains("\"rawStatus\":\"scheduled\""));
    assertFalse(response.body().contains(SOURCE));
  }

  @Test
  void route_whenDashboardHasSubscription_expectOperatorSummaryRedactsSourceAndAddsActions() {
    ContentSubscriptionService service = service(new RecordingFetchPort());
    service.create(APP_ID, createParams());
    PlatformApiRouter router =
        new PlatformApiRouter(
            runtimePorts(),
            null,
            null,
            null,
            AppUiOriginRegistry.sameOriginOnly(),
            PlatformApiSharedAppServices.of(null, null, service));

    PlatformApiResponse response =
        router.route(request("GET", List.of(OPERATOR_SEGMENT, BETA_DASHBOARD_SEGMENT), Map.of()));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"subscriptions\""));
    assertTrue(response.body().contains("\"status\":\"never-fetched\""));
    assertTrue(response.body().contains("\"sourceDisplay\":\"crypta:<redacted-content-uri>\""));
    assertTrue(response.body().contains("\"refresh-subscription\""));
    assertTrue(response.body().contains("\"reset-subscription-backoff\""));
    assertTrue(response.body().contains("\"reschedule-subscription-now\""));
    assertTrue(response.body().contains("\"operator/subscriptions/feed-reader/"));
    assertFalse(response.body().contains(SOURCE));
  }

  @Test
  void route_whenOperatorRequestsNetworkBudgets_expectSafeSnapshotsOnly() {
    AppNetworkBudgetService budgetService = networkBudgetService();
    budgetService
        .acquire(APP_ID, AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH)
        .lease()
        .close();
    PlatformApiRouter router =
        new PlatformApiRouter(
            runtimePorts(),
            null,
            null,
            null,
            AppUiOriginRegistry.sameOriginOnly(),
            PlatformApiSharedAppServices.of(null, null, null, null, null, null, budgetService));

    PlatformApiResponse response =
        router.route(request("GET", List.of(OPERATOR_SEGMENT, "network-budgets"), Map.of()));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"kind\":\"crypta-operator-network-budgets\""));
    assertTrue(response.body().contains("\"operation\":\"foreground_content_fetch\""));
    assertFalse(response.body().contains(SOURCE));
    assertFalse(response.body().contains("/work/"));
  }

  @Test
  void route_whenAppPrincipalUsesOperatorSubscriptionWrapper_expectForbidden() {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    ContentSubscriptionService service = service(fetchPort);
    String subscriptionId = (String) service.create(APP_ID, createParams()).get("subscriptionId");
    PlatformApiRouter router =
        new PlatformApiRouter(
            runtimePorts(),
            null,
            null,
            null,
            AppUiOriginRegistry.sameOriginOnly(),
            PlatformApiSharedAppServices.of(null, null, service));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "subscriptions", APP_ID, subscriptionId, "pause"),
                Map.of(),
                PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("content.subscribe"))));

    assertEquals(403, response.statusCode());
    assertEquals(0, fetchPort.calls);
  }

  @Test
  void route_whenOperatorUsesAppDataBackupRestore_expectSensitiveBackupAndMetadataPlan() {
    AppDataService source = appDataService();
    source.putRecord(APP_ID, appDataRecordParams("private-backup-record-value"));
    String backupPayloadBase64 =
        (String) source.exportBackup(Map.of("appId", List.of(APP_ID)), "test").get("payloadBase64");
    AppDataService target = appDataService();
    target.putRecord(APP_ID, appDataRecordParams("old"));
    PlatformApiRouter router =
        new PlatformApiRouter(
            runtimePorts(),
            null,
            null,
            null,
            AppUiOriginRegistry.sameOriginOnly(),
            PlatformApiSharedAppServices.of(null, null, null, target));

    PlatformApiResponse backupResponse =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "app-data", "backups"),
                Map.of("appId", List.of(APP_ID))));
    PlatformApiResponse planResponse =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "app-data", "restore", "plan"),
                Map.of("payloadBase64", List.of(backupPayloadBase64), "mode", List.of("merge"))));
    PlatformApiResponse restoreResponse =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "app-data", "restore"),
                Map.of("payloadBase64", List.of(backupPayloadBase64), "mode", List.of("merge"))));

    assertEquals(200, backupResponse.statusCode());
    assertTrue(backupResponse.body().contains("crypta-app-data-backup"));
    assertTrue(
        backupResponse
            .body()
            .contains(
                java.util.Base64.getEncoder()
                    .encodeToString("old".getBytes(StandardCharsets.UTF_8))));
    assertEquals(200, planResponse.statusCode());
    assertTrue(planResponse.body().contains("\"restorePlan\""));
    assertTrue(planResponse.body().contains("\"would_merge\""));
    assertFalse(planResponse.body().contains("private-backup-record-value"));
    assertEquals(200, restoreResponse.statusCode());
    assertTrue(restoreResponse.body().contains("\"restoreResult\""));
    assertEquals(
        "private-backup-record-value",
        target.getRecord(APP_ID, "ui-state", "settings").get("valueText"));
  }

  @Test
  void route_whenOperatorUsesGetForAppDataBackup_expectMethodNotAllowedWithoutBackupPayload() {
    AppDataService service = appDataService();
    service.putRecord(APP_ID, appDataRecordParams("private-backup-record-value"));
    PlatformApiRouter router =
        new PlatformApiRouter(
            runtimePorts(),
            null,
            null,
            null,
            AppUiOriginRegistry.sameOriginOnly(),
            PlatformApiSharedAppServices.of(null, null, null, service));

    PlatformApiResponse response =
        router.route(
            request(
                "GET",
                List.of(OPERATOR_SEGMENT, "app-data", "backups"),
                Map.of("scope", List.of("all"))));

    assertEquals(405, response.statusCode());
    assertFalse(response.body().contains("crypta-app-data-backup"));
    assertFalse(response.body().contains("private-backup-record-value"));
  }

  @Test
  void route_whenAppPrincipalRequestsAppDataBackupRestore_expectForbidden() {
    PlatformApiRouter router =
        new PlatformApiRouter(
            runtimePorts(),
            null,
            null,
            null,
            AppUiOriginRegistry.sameOriginOnly(),
            PlatformApiSharedAppServices.of(null, null, null, appDataService()));
    PlatformApiPrincipal appPrincipal =
        PlatformApiPrincipal.appBrowserSession(
            APP_ID,
            List.of(
                AppDataService.CAPABILITY_APP_DATA_READ, AppDataService.CAPABILITY_APP_DATA_WRITE));

    PlatformApiResponse backup =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "app-data", "backups"),
                Map.of("appId", List.of(APP_ID)),
                appPrincipal));
    PlatformApiResponse plan =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "app-data", "restore", "plan"),
                Map.of("payloadBase64", List.of("ignored")),
                appPrincipal));
    PlatformApiResponse restore =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "app-data", "restore"),
                Map.of("payloadBase64", List.of("ignored")),
                appPrincipal));

    assertEquals(403, backup.statusCode());
    assertEquals(403, plan.statusCode());
    assertEquals(403, restore.statusCode());
    assertFalse(backup.body().contains("payloadBase64"));
  }

  @Test
  void route_whenReducedRouterTrustGraphAnchorAdded_expectOperatorDashboardSeesAnchor() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());

    PlatformApiResponse anchorResponse =
        router.route(
            request(
                "POST",
                List.of("trust-graph", "anchors"),
                Map.of(
                    "issuerFingerprint",
                    List.of("fingerprint-operator"),
                    "label",
                    List.of("Operator"),
                    "source",
                    List.of("manual")),
                PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("trust.write"))));
    PlatformApiResponse dashboardResponse =
        router.route(request("GET", List.of(OPERATOR_SEGMENT, BETA_DASHBOARD_SEGMENT), Map.of()));

    assertEquals(201, anchorResponse.statusCode());
    assertEquals(200, dashboardResponse.statusCode());
    assertTrue(dashboardResponse.body().contains("\"trustGraph\""));
    assertTrue(dashboardResponse.body().contains("\"anchorCount\":1"));
  }

  private static PlatformApiRequest request(
      String method, List<String> segments, Map<String, List<String>> params) {
    return request(method, segments, params, PlatformApiPrincipal.hostOperator());
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> mapValue(Object value) {
    return value instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
  }

  private static String sha256(String value) {
    try {
      return HEX.formatHex(
          MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static String planToken(String body) {
    String marker = "\"" + PARAM_PLAN_TOKEN + "\":\"";
    int start = body.indexOf(marker);
    assertTrue(start >= 0, body);
    int valueStart = start + marker.length();
    int end = body.indexOf('"', valueStart);
    assertTrue(end > valueStart, body);
    return body.substring(valueStart, end);
  }

  private static PlatformApiRequest request(
      String method,
      List<String> segments,
      Map<String, List<String>> params,
      PlatformApiPrincipal principal) {
    return new PlatformApiRequest(method, segments, params, principal);
  }

  private static ContentSubscriptionService service(RecordingFetchPort fetchPort) {
    return new ContentSubscriptionService(
        new InMemoryContentSubscriptionStore(),
        fetchPort,
        config(),
        Clock.fixed(NOW, ZoneOffset.UTC),
        new SecureRandom());
  }

  private static Map<String, List<String>> createParams() {
    return Map.of(
        "label",
        List.of("Daily feed"),
        "uri",
        List.of(SOURCE),
        "pollIntervalSeconds",
        List.of("5"),
        "maxBytes",
        List.of("256"),
        "timeoutMillis",
        List.of("1000"));
  }

  private static ContentSubscriptionSchedulerConfig config() {
    return new ContentSubscriptionSchedulerConfig(
        true,
        Duration.ZERO,
        Duration.ofSeconds(1),
        Duration.ofSeconds(10),
        Duration.ofSeconds(5),
        Duration.ofHours(1),
        Duration.ZERO,
        Duration.ofSeconds(5),
        Duration.ofSeconds(30),
        4,
        8,
        2,
        256L,
        1024L,
        Duration.ofSeconds(1),
        Duration.ofSeconds(5));
  }

  private static AppDataService appDataService() {
    return new AppDataService(
        new InMemoryAppDataStore(),
        null,
        new AppDataStoreConfig(256, 16, 4, 8192, 8192, 8),
        Clock.fixed(NOW, ZoneOffset.UTC),
        new AppDiskUsageScanner());
  }

  private static AppNetworkBudgetService networkBudgetService() {
    return new AppNetworkBudgetService(
        new InMemoryAppNetworkBudgetStore(),
        new AppNetworkBudgetConfig(20, 100, 2, 16, 20, 1024, 1, 8, 120, 1024, 1, 8),
        Clock.fixed(NOW, ZoneOffset.UTC));
  }

  private static Map<String, List<String>> appDataRecordParams(String value) {
    return Map.of(
        "namespace",
        List.of("ui-state"),
        "key",
        List.of("settings"),
        "contentType",
        List.of(AppDataRecord.JSON_CONTENT_TYPE),
        "schemaVersion",
        List.of("1"),
        "valueText",
        List.of(value));
  }

  private static String intakeRecordJson() {
    return intakeRecordJson("sub-hello", null);
  }

  private static String intakeRecordJson(String submissionId, String transparencyLogDigest) {
    String sha256 = "0".repeat(64);
    String transparency =
        transparencyLogDigest == null
            ? ""
            : """
              "transparencyLogDigest":"%s",
            """
                .formatted(transparencyLogDigest);
    return """
    {
      "schemaVersion":1,
      "status":"submitted",
      "submissionId":"%s",
      "submissionDigest":"%s",
      "submissionType":"new_app",
      "appId":"hello-stable",
      "appVersion":"1.0.0",
      "bundleDigest":"%s",
      "manifestDigest":"%s",
      "apiTargetStability":"stable",
      "requestedPermissions":["queue.read"],
      "maintainerName":"Example Maintainer",
      "maintainerContactPublic":"https://example.invalid/contact",
      "sourceUrl":"https://example.invalid/source",
      "submittedAt":"2026-06-01T12:00:00Z",
      %s
      "nonProduction":false,
      "redactionStatus":"pass",
      "warnings":[],
      "auditEvents":[]
    }
    """
        .formatted(submissionId, sha256, sha256, sha256, transparency);
  }

  private static RuntimePorts runtimePorts() {
    return mock(
        RuntimePorts.class,
        invocation -> {
          Object defaultValue = Answers.RETURNS_DEFAULTS.answer(invocation);
          if (defaultValue != null || invocation.getMethod().getReturnType().isPrimitive()) {
            return defaultValue;
          }
          Class<?> returnType = invocation.getMethod().getReturnType();
          return returnType.isInterface() ? mock(returnType) : null;
        });
  }

  private static final class RecordingFetchPort implements ContentFetchPort {
    private int calls;

    @Override
    public BoundedContentFetchResult fetchContent(BoundedContentFetchRequest request) {
      calls++;
      return new BoundedContentFetchResult(
          "feed body".getBytes(StandardCharsets.UTF_8), request.uri(), SOURCE, "ok");
    }
  }
}
