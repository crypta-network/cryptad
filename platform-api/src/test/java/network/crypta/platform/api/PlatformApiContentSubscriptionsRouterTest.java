package network.crypta.platform.api;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionSchedulerConfig;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionService;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionStore;
import network.crypta.platform.api.content.subscriptions.InMemoryContentSubscriptionStore;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.appui.AppUiOriginRegistry;
import network.crypta.runtime.spi.BoundedContentFetchRequest;
import network.crypta.runtime.spi.BoundedContentFetchResult;
import network.crypta.runtime.spi.ContentFetchPort;
import network.crypta.runtime.spi.RuntimePorts;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class PlatformApiContentSubscriptionsRouterTest {
  private static final String APP_ID = "feed-reader";
  private static final Instant NOW = Instant.parse("2026-05-24T12:00:00Z");
  private static final String SOURCE = "USK@example/feed/7/feed.json";
  private static final List<String> BOTH_CAPABILITIES =
      List.of(
          ContentSubscriptionService.CAPABILITY_CONTENT_FETCH,
          ContentSubscriptionService.CAPABILITY_CONTENT_SUBSCRIBE);

  @Test
  void route_whenAppHasSubscriptionCapabilities_expectCreateListRefreshPauseResumeAndDelete() {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    ContentSubscriptionService service = service(fetchPort);
    PlatformApiRouter router = router(service);

    PlatformApiResponse create =
        router.route(
            request(
                "POST",
                List.of("content", "subscriptions"),
                createParams(),
                PlatformApiPrincipal.appBrowserSession(APP_ID, BOTH_CAPABILITIES)));

    assertEquals(201, create.statusCode());
    assertTrue(create.body().contains("\"sourceUri\":\"USK@example/feed/7/feed.json\""));
    assertEquals(0, fetchPort.calls);
    String subscriptionId = (String) service.list(APP_ID).getFirst().get("subscriptionId");

    PlatformApiResponse list =
        router.route(
            request(
                "GET",
                List.of("content", "subscriptions"),
                Map.of(),
                PlatformApiPrincipal.appBrowserSession(APP_ID, BOTH_CAPABILITIES)));
    assertEquals(200, list.statusCode());
    assertTrue(list.body().contains("\"subscriptions\""));

    fetchPort.nextResolvedUri = "USK@example/feed/7/feed.json";
    PlatformApiResponse refresh =
        router.route(
            request(
                "POST",
                List.of("content", "subscriptions", subscriptionId, "refresh"),
                Map.of(),
                PlatformApiPrincipal.appBrowserSession(APP_ID, BOTH_CAPABILITIES)));
    assertEquals(200, refresh.statusCode());
    assertEquals(1, fetchPort.calls);
    assertTrue(refresh.body().contains("\"lastSeenEdition\":7"));
    assertFalse(refresh.body().contains("feed body"));

    assertEquals(
        200,
        router
            .route(
                request(
                    "POST",
                    List.of("content", "subscriptions", subscriptionId, "pause"),
                    Map.of(),
                    PlatformApiPrincipal.appBrowserSession(
                        APP_ID, List.of(ContentSubscriptionService.CAPABILITY_CONTENT_SUBSCRIBE))))
            .statusCode());
    assertEquals(
        200,
        router
            .route(
                request(
                    "POST",
                    List.of("content", "subscriptions", subscriptionId, "resume"),
                    Map.of(),
                    PlatformApiPrincipal.appBrowserSession(
                        APP_ID, List.of(ContentSubscriptionService.CAPABILITY_CONTENT_SUBSCRIBE))))
            .statusCode());
    assertEquals(
        200,
        router
            .route(
                request(
                    "DELETE",
                    List.of("content", "subscriptions", subscriptionId),
                    Map.of(),
                    PlatformApiPrincipal.appBrowserSession(
                        APP_ID, List.of(ContentSubscriptionService.CAPABILITY_CONTENT_SUBSCRIBE))))
            .statusCode());
  }

  @Test
  void route_whenAppLacksContentSubscribe_expectForbidden() {
    PlatformApiRouter router = router(service(new RecordingFetchPort()));

    PlatformApiResponse response =
        router.route(
            request(
                "GET",
                List.of("content", "subscriptions"),
                Map.of(),
                PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("content.fetch"))));

    assertEquals(403, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"forbidden\""));
  }

  @Test
  void route_whenAppLacksContentFetchForCreate_expectForbidden() {
    PlatformApiRouter router = router(service(new RecordingFetchPort()));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("content", "subscriptions"),
                createParams(),
                PlatformApiPrincipal.appBrowserSession(
                    APP_ID, List.of(ContentSubscriptionService.CAPABILITY_CONTENT_SUBSCRIBE))));

    assertEquals(403, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"forbidden\""));
  }

  @Test
  void route_whenHostOperatorUsesSubscriptionRoute_expectForbiddenByAppScope() {
    PlatformApiRouter router = router(service(new RecordingFetchPort()));

    PlatformApiResponse response =
        router.route(
            request(
                "GET",
                List.of("content", "subscriptions"),
                Map.of(),
                PlatformApiPrincipal.hostOperator()));

    assertEquals(403, response.statusCode());
    assertTrue(response.body().contains("requires an app principal"));
  }

  @Test
  void route_whenAppReadsAnotherAppsSubscription_expectNotFound() {
    ContentSubscriptionService service = service(new RecordingFetchPort());
    String subscriptionId = (String) service.create(APP_ID, createParams()).get("subscriptionId");
    PlatformApiRouter router = router(service);

    PlatformApiResponse response =
        router.route(
            request(
                "GET",
                List.of("content", "subscriptions", subscriptionId),
                Map.of(),
                PlatformApiPrincipal.appBrowserSession("other-app", BOTH_CAPABILITIES)));

    assertEquals(404, response.statusCode());
    assertTrue(response.body().contains("content_subscription_not_found"));
  }

  @Test
  void route_whenSubscriptionServiceUnavailable_expectServiceUnavailable() {
    PlatformApiRouter router = router(null);

    PlatformApiResponse response =
        router.route(
            request(
                "GET",
                List.of("content", "subscriptions"),
                Map.of(),
                PlatformApiPrincipal.appBrowserSession(APP_ID, BOTH_CAPABILITIES)));

    assertEquals(503, response.statusCode());
    assertTrue(response.body().contains("content_subscription_service_unavailable"));
  }

  @Test
  void route_whenAppUninstalled_expectContentSubscriptionStateCleared() throws Exception {
    ContentSubscriptionService service = service(new RecordingFetchPort());
    service.create(APP_ID, createParams());
    AppHost appHost = mock(AppHost.class);
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedApp()));
    when(appHost.inactiveSandboxStatus(any())).thenCallRealMethod();
    PlatformApiRouter router = router(appHost, service);

    PlatformApiResponse response =
        router.route(
            request(
                "DELETE", List.of("apps", APP_ID), Map.of(), PlatformApiPrincipal.hostOperator()));

    assertEquals(200, response.statusCode());
    assertTrue(service.list(APP_ID).isEmpty());
    verify(appHost).uninstall(APP_ID);
  }

  @Test
  void route_whenSubscriptionCleanupFailsAfterUninstall_expectSuccessResponsePreserved()
      throws Exception {
    ContentSubscriptionStore store = mock(ContentSubscriptionStore.class);
    doThrow(new IOException("store unavailable below /tmp/private-subscriptions"))
        .when(store)
        .deleteAllForApp(APP_ID);
    ContentSubscriptionService service = service(store);
    AppHost appHost = mock(AppHost.class);
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedApp()));
    when(appHost.inactiveSandboxStatus(any())).thenCallRealMethod();
    PlatformApiRouter router = router(appHost, service);

    PlatformApiResponse response =
        router.route(
            request(
                "DELETE", List.of("apps", APP_ID), Map.of(), PlatformApiPrincipal.hostOperator()));

    assertEquals(200, response.statusCode());
    assertFalse(response.body().contains("content_subscription_store_failed"));
    assertFalse(response.body().contains("private-subscriptions"));
    verify(appHost).uninstall(APP_ID);
    verify(store).deleteAllForApp(APP_ID);
  }

  private static PlatformApiRouter router(ContentSubscriptionService service) {
    return router(null, service);
  }

  private static PlatformApiRouter router(AppHost appHost, ContentSubscriptionService service) {
    return new PlatformApiRouter(
        runtimePorts(),
        appHost,
        null,
        null,
        AppUiOriginRegistry.sameOriginOnly(),
        PlatformApiSharedAppServices.of(null, null, service));
  }

  private static ContentSubscriptionService service(RecordingFetchPort fetchPort) {
    return service(new InMemoryContentSubscriptionStore(), fetchPort);
  }

  private static ContentSubscriptionService service(ContentSubscriptionStore store) {
    return service(store, new RecordingFetchPort());
  }

  private static ContentSubscriptionService service(
      ContentSubscriptionStore store, RecordingFetchPort fetchPort) {
    return new ContentSubscriptionService(
        store, fetchPort, config(), Clock.fixed(NOW, ZoneOffset.UTC), new Random(0));
  }

  private static PlatformApiRequest request(
      String method,
      List<String> segments,
      Map<String, List<String>> parameters,
      PlatformApiPrincipal principal) {
    return new PlatformApiRequest(method, segments, parameters, principal);
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

  private static InstalledAppSnapshot installedApp() {
    Path root = Path.of("build", "test-apphost").toAbsolutePath();
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
    private String nextResolvedUri = SOURCE;

    @Override
    public BoundedContentFetchResult fetchContent(BoundedContentFetchRequest request) {
      calls++;
      return new BoundedContentFetchResult(
          "feed body".getBytes(StandardCharsets.UTF_8), request.uri(), nextResolvedUri, "ok");
    }
  }
}
