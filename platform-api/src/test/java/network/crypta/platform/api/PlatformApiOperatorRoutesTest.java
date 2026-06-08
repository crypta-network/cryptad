package network.crypta.platform.api;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import network.crypta.platform.api.appdata.AppDataRecord;
import network.crypta.platform.api.appdata.AppDataService;
import network.crypta.platform.api.appdata.AppDataStoreConfig;
import network.crypta.platform.api.appdata.InMemoryAppDataStore;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionSchedulerConfig;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionService;
import network.crypta.platform.api.content.subscriptions.InMemoryContentSubscriptionStore;
import network.crypta.platform.apphost.AppDiskUsageScanner;
import network.crypta.platform.appui.AppUiOriginRegistry;
import network.crypta.runtime.spi.BoundedContentFetchRequest;
import network.crypta.runtime.spi.BoundedContentFetchResult;
import network.crypta.runtime.spi.ContentFetchPort;
import network.crypta.runtime.spi.DiagnosticReportSnapshot;
import network.crypta.runtime.spi.DiagnosticSectionSnapshot;
import network.crypta.runtime.spi.RuntimePorts;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class PlatformApiOperatorRoutesTest {
  private static final String APP_ID = "feed-reader";
  private static final String BETA_DASHBOARD_SEGMENT = "beta-dashboard";
  private static final String FORM_FIELD_ASSIGNMENT = "form" + "Pass" + "word=secret-value";
  private static final String OPERATOR_SEGMENT = "operator";
  private static final String SOURCE = "USK@example/feed/7/feed.json";
  private static final Instant NOW = Instant.parse("2026-05-24T12:00:00Z");

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
    assertTrue(response.body().contains("<redacted"));
    assertTrue(response.body().contains("\"redaction\":{\"status\":\"pass\""));
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
    assertTrue(response.body().contains("\"operator/subscriptions/feed-reader/"));
    assertFalse(response.body().contains(SOURCE));
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
