package network.crypta.platform.api;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import network.crypta.platform.api.appdata.AppDataService;
import network.crypta.platform.api.appdata.AppDataStoreConfig;
import network.crypta.platform.api.appdata.InMemoryAppDataStore;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppUninstallOptions;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.runtime.spi.RuntimePorts;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class PlatformApiAppDataRouterTest {
  private static final String APP_ID = "feed-reader";
  private static final Instant NOW = Instant.parse("2026-05-24T12:00:00Z");

  @Test
  void route_whenAppHasAppDataCapabilities_expectRecordLifecycle() {
    AppDataService service = service();
    PlatformApiRouter router = router(service);
    PlatformApiPrincipal principal =
        PlatformApiPrincipal.appBrowserSession(
            APP_ID,
            List.of(
                AppDataService.CAPABILITY_APP_DATA_READ, AppDataService.CAPABILITY_APP_DATA_WRITE));

    PlatformApiResponse write =
        router.route(request("POST", List.of("app-data", "records"), recordParams(), principal));
    PlatformApiResponse list =
        router.route(request("GET", List.of("app-data", "records"), Map.of(), principal));
    PlatformApiResponse read =
        router.route(
            request(
                "GET",
                List.of("app-data", "records", "ui-state", "settings"),
                Map.of(),
                principal));
    PlatformApiResponse status =
        router.route(request("GET", List.of("app-data", "status"), Map.of(), principal));
    PlatformApiResponse delete =
        router.route(
            request(
                "DELETE",
                List.of("app-data", "records", "ui-state", "settings"),
                Map.of(),
                principal));

    assertEquals(201, write.statusCode());
    assertEquals(200, list.statusCode());
    assertEquals(200, read.statusCode());
    assertEquals(200, status.statusCode());
    assertEquals(200, delete.statusCode());
    assertTrue(read.body().contains("\"valueText\":\"{\\\"theme\\\":\\\"dark\\\"}\""));
    assertTrue(list.body().contains("\"records\""));
    assertFalse(list.body().contains("valueText"));
  }

  @Test
  void route_whenAppReadsAnotherAppsRecord_expectNotFound() {
    AppDataService service = service();
    service.putRecord(APP_ID, recordParams());
    PlatformApiRouter router = router(service);
    PlatformApiPrincipal other =
        PlatformApiPrincipal.appBrowserSession(
            "other-app",
            List.of(
                AppDataService.CAPABILITY_APP_DATA_READ, AppDataService.CAPABILITY_APP_DATA_WRITE));

    PlatformApiResponse response =
        router.route(
            request(
                "GET", List.of("app-data", "records", "ui-state", "settings"), Map.of(), other));

    assertEquals(404, response.statusCode());
    assertTrue(response.body().contains("app_data_record_not_found"));
  }

  @Test
  void route_whenCapabilityMissingOrServiceUnavailable_expectDeniedOr503() {
    PlatformApiRouter router = router(service());
    PlatformApiResponse denied =
        router.route(
            request(
                "GET",
                List.of("app-data", "records"),
                Map.of(),
                PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("app.data.write"))));
    PlatformApiResponse unavailable =
        router(null)
            .route(
                request(
                    "GET",
                    List.of("app-data", "records"),
                    Map.of(),
                    PlatformApiPrincipal.appBrowserSession(
                        APP_ID, List.of(AppDataService.CAPABILITY_APP_DATA_READ))));
    PlatformApiResponse host =
        router.route(
            request(
                "GET",
                List.of("app-data", "records"),
                Map.of(),
                PlatformApiPrincipal.hostOperator()));

    assertEquals(403, denied.statusCode());
    assertEquals(503, unavailable.statusCode());
    assertTrue(unavailable.body().contains("app_data_service_unavailable"));
    assertEquals(403, host.statusCode());
  }

  @Test
  void route_whenNamespaceTraverses_expectPathFreeError() {
    PlatformApiRouter router = router(service());

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("app-data", "records"),
                params(
                    "namespace", "../secret",
                    "key", "settings",
                    "schemaVersion", "1",
                    "valueText", "one"),
                PlatformApiPrincipal.appBrowserSession(
                    APP_ID, List.of(AppDataService.CAPABILITY_APP_DATA_WRITE))));

    assertEquals(400, response.statusCode());
    assertTrue(response.body().contains("invalid_app_data_identifier"));
    assertFalse(response.body().contains(".."));
    assertFalse(response.body().contains("/tmp"));
  }

  @Test
  void route_whenAppUninstalledWithoutPreserveData_expectAppDataCleared() throws Exception {
    AppDataService service = service();
    service.putRecord(APP_ID, recordParams());
    AppHost appHost = appHost();
    PlatformApiRouter router = router(appHost, service);

    PlatformApiResponse response =
        router.route(
            request(
                "DELETE", List.of("apps", APP_ID), Map.of(), PlatformApiPrincipal.hostOperator()));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"dataPreserved\":false"));
    assertEquals(0, service.status(APP_ID).get("recordCount"));
    verify(appHost).uninstall(APP_ID, AppUninstallOptions.removeAll());
  }

  @Test
  void route_whenAppUninstalledWithPreserveData_expectAppDataRetained() throws Exception {
    AppDataService service = service();
    service.putRecord(APP_ID, recordParams());
    AppHost appHost = appHost();
    PlatformApiRouter router = router(appHost, service);

    PlatformApiResponse response =
        router.route(
            request(
                "DELETE",
                List.of("apps", APP_ID),
                Map.of("preserveData", List.of("true")),
                PlatformApiPrincipal.hostOperator()));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"dataPreserved\":true"));
    assertEquals(1, service.status(APP_ID).get("recordCount"));
    verify(appHost).uninstall(APP_ID, AppUninstallOptions.preservingData());
  }

  @Test
  void route_whenAppPrincipalRequestsPreserveDataOnUninstall_expectFlagIgnored() throws Exception {
    AppDataService service = service();
    service.putRecord(APP_ID, recordParams());
    AppHost appHost = appHost();
    PlatformApiRouter router = router(appHost, service);

    PlatformApiResponse response =
        router.route(
            request(
                "DELETE",
                List.of("apps", APP_ID),
                Map.of("preserveData", List.of("true")),
                PlatformApiPrincipal.appBrowserSession(
                    APP_ID, List.of(PlatformApiCapabilities.APPS_MANAGE))));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"dataPreserved\":false"));
    assertEquals(0, service.status(APP_ID).get("recordCount"));
    verify(appHost).uninstall(APP_ID, AppUninstallOptions.removeAll());
  }

  private static PlatformApiRouter router(AppDataService service) {
    return router(null, service);
  }

  private static PlatformApiRouter router(AppHost appHost, AppDataService service) {
    return new PlatformApiRouter(
        runtimePorts(),
        appHost,
        null,
        null,
        network.crypta.platform.appui.AppUiOriginRegistry.sameOriginOnly(),
        PlatformApiSharedAppServices.of(null, null, null, service));
  }

  private static AppDataService service() {
    return new AppDataService(
        new InMemoryAppDataStore(),
        null,
        new AppDataStoreConfig(128, 16, 4, 4096, 4096, 8),
        Clock.fixed(NOW, ZoneOffset.UTC),
        new network.crypta.platform.apphost.AppDiskUsageScanner());
  }

  private static PlatformApiRequest request(
      String method,
      List<String> segments,
      Map<String, List<String>> parameters,
      PlatformApiPrincipal principal) {
    return new PlatformApiRequest(method, segments, parameters, principal);
  }

  private static Map<String, List<String>> recordParams() {
    return params(
        "namespace", "ui-state",
        "key", "settings",
        "contentType", "application/json",
        "schemaVersion", "1",
        "valueText", "{\"theme\":\"dark\"}");
  }

  private static Map<String, List<String>> params(String... pairs) {
    java.util.LinkedHashMap<String, List<String>> values = new java.util.LinkedHashMap<>();
    for (int index = 0; index < pairs.length; index += 2) {
      values.put(pairs[index], List.of(pairs[index + 1]));
    }
    return values;
  }

  private static AppHost appHost() throws java.io.IOException {
    AppHost appHost = mock(AppHost.class);
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedApp()));
    when(appHost.inactiveSandboxStatus(any())).thenCallRealMethod();
    return appHost;
  }

  private static InstalledAppSnapshot installedApp() {
    java.nio.file.Path root = java.nio.file.Path.of("build", "test-apphost").toAbsolutePath();
    AppManifest manifest =
        new AppManifest(
            1,
            APP_ID,
            "Feed Reader",
            "1.0.0",
            "bin/launch.sh",
            AppUiMode.NONE,
            null,
            List.of(),
            null,
            null);
    InstalledAppPaths paths =
        new InstalledAppPaths(
            APP_ID,
            root.resolve("installed").resolve(APP_ID),
            root.resolve("data").resolve(APP_ID),
            root.resolve("cache").resolve(APP_ID),
            root.resolve("run").resolve(APP_ID));
    return new InstalledAppSnapshot(manifest, paths);
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
}
