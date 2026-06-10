package network.crypta.platform.api;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.platform.api.appservices.AppServiceAdapter;
import network.crypta.platform.api.appservices.AppServiceCoordinator;
import network.crypta.platform.api.appservices.AppServiceDescriptor;
import network.crypta.platform.api.appservices.AppServiceGrant;
import network.crypta.platform.api.appservices.InMemoryAppServiceGrantStore;
import network.crypta.platform.api.appservices.TrustGraphScoreAppServiceAdapter;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.appui.AppUiOriginRegistry;
import network.crypta.runtime.spi.RuntimePorts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Answers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class PlatformApiAppServicesRouterTest {
  private static final Clock CLOCK =
      Clock.fixed(Instant.parse("2026-05-24T12:00:00Z"), ZoneOffset.UTC);

  @TempDir private Path tempDir;

  @Test
  void route_whenAppUsesDiscoveryGrantAndInvocation_expectGrantBoundary() throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    PlatformApiRouter router = router(store, installedProvider(), installedConsumer());
    PlatformApiPrincipal socialInbox =
        PlatformApiPrincipal.appBrowserSession(
            "social-inbox", List.of("app.services.read", "app.services.call"));

    PlatformApiResponse deniedRead =
        router.route(
            request(
                "GET",
                List.of("app-services"),
                Map.of(),
                PlatformApiPrincipal.appBrowserSession("social-inbox", List.of())));
    PlatformApiResponse discovery =
        router.route(request("GET", List.of("app-services"), Map.of(), socialInbox));
    PlatformApiResponse grant =
        router.route(
            request("POST", List.of("app-services", "grants"), grantParams(), socialInbox));

    assertEquals(403, deniedRead.statusCode());
    assertEquals(200, discovery.statusCode());
    assertTrue(discovery.body().contains("trust.score"));
    assertEquals(201, grant.statusCode());
    assertTrue(grant.body().contains("\"status\":\"pending\""));

    String grantId = store.listGrants().getFirst().grantId();
    PlatformApiResponse appApprove =
        router.route(
            request(
                "POST",
                List.of("app-services", "grants", grantId, "approve"),
                Map.of(),
                socialInbox));
    PlatformApiResponse pendingInvoke =
        router.route(
            request(
                "POST",
                List.of("app-services", "trust-graph", "services", "trust.score", "invoke"),
                invokeParams(),
                socialInbox));
    PlatformApiResponse hostApprove =
        router.route(
            request(
                "POST",
                List.of("app-services", "grants", grantId, "approve"),
                Map.of(),
                PlatformApiPrincipal.hostOperator()));
    PlatformApiResponse invocation =
        router.route(
            request(
                "POST",
                List.of("app-services", "trust-graph", "services", "trust.score", "invoke"),
                invokeParams(),
                socialInbox));
    PlatformApiResponse revoke =
        router.route(
            request(
                "POST",
                List.of("app-services", "grants", grantId, "revoke"),
                Map.of(),
                PlatformApiPrincipal.hostOperator()));
    PlatformApiResponse revokedInvoke =
        router.route(
            request(
                "POST",
                List.of("app-services", "trust-graph", "services", "trust.score", "invoke"),
                invokeParams(),
                socialInbox));
    PlatformApiResponse staleApprove =
        router.route(
            request(
                "POST",
                List.of("app-services", "grants", grantId, "approve"),
                Map.of(),
                PlatformApiPrincipal.hostOperator()));

    assertEquals(403, appApprove.statusCode());
    assertEquals(403, pendingInvoke.statusCode());
    assertEquals("app_service_grant_required", errorCode(pendingInvoke));
    assertEquals(200, hostApprove.statusCode());
    assertTrue(hostApprove.body().contains("\"status\":\"active\""));
    assertEquals(200, invocation.statusCode());
    assertTrue(invocation.body().contains("\"serviceCall\""));
    assertTrue(invocation.body().contains("\"providerAppId\":\"trust-graph\""));
    assertEquals(200, revoke.statusCode());
    assertTrue(revoke.body().contains("\"status\":\"revoked\""));
    assertEquals(403, revokedInvoke.statusCode());
    assertEquals("app_service_grant_required", errorCode(revokedInvoke));
    assertEquals(409, staleApprove.statusCode());
    assertEquals("app_service_grant_not_pending", errorCode(staleApprove));
  }

  @Test
  void route_whenCallCapableAppRevokesOwnGrant_expectAllowed() throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    PlatformApiRouter router = router(store, installedProvider(), installedConsumer());
    PlatformApiPrincipal callOnly =
        PlatformApiPrincipal.appBrowserSession("social-inbox", List.of("app.services.call"));

    PlatformApiResponse grant =
        router.route(request("POST", List.of("app-services", "grants"), grantParams(), callOnly));
    String grantId = store.listGrants().getFirst().grantId();
    router.route(
        request(
            "POST",
            List.of("app-services", "grants", grantId, "approve"),
            Map.of(),
            PlatformApiPrincipal.hostOperator()));
    PlatformApiResponse revoke =
        router.route(
            request(
                "POST", List.of("app-services", "grants", grantId, "revoke"), Map.of(), callOnly));

    assertEquals(201, grant.statusCode());
    assertEquals(200, revoke.statusCode());
    assertTrue(revoke.body().contains("\"status\":\"revoked\""));
  }

  @Test
  void route_whenProviderAppIdIsGrants_expectServiceDescriptorIsReachable() throws Exception {
    PlatformApiRouter router =
        router(
            new InMemoryAppServiceGrantStore(), installedProvider("grants"), installedConsumer());
    PlatformApiPrincipal readOnly =
        PlatformApiPrincipal.appBrowserSession("social-inbox", List.of("app.services.read"));

    PlatformApiResponse services =
        router.route(
            request("GET", List.of("app-services", "grants", "services"), Map.of(), readOnly));
    PlatformApiResponse service =
        router.route(
            request(
                "GET",
                List.of("app-services", "grants", "services", "trust.score"),
                Map.of(),
                readOnly));

    assertEquals(200, services.statusCode());
    assertTrue(services.body().contains("\"providerAppId\":\"grants\""));
    assertEquals(200, service.statusCode());
    assertTrue(service.body().contains("\"serviceId\":\"trust.score\""));
    assertTrue(service.body().contains("\"providerAppId\":\"grants\""));
  }

  @Test
  void route_whenProviderAppIdIsDependencies_expectServiceListTakesPrecedence() throws Exception {
    PlatformApiRouter router =
        router(
            new InMemoryAppServiceGrantStore(),
            installedProvider("dependencies"),
            installedConsumer());
    PlatformApiPrincipal readOnly =
        PlatformApiPrincipal.appBrowserSession("social-inbox", List.of("app.services.read"));

    PlatformApiResponse services =
        router.route(
            request(
                "GET", List.of("app-services", "dependencies", "services"), Map.of(), readOnly));
    PlatformApiResponse service =
        router.route(
            request(
                "GET",
                List.of("app-services", "dependencies", "services", "trust.score"),
                Map.of(),
                readOnly));

    assertEquals(200, services.statusCode());
    assertTrue(services.body().contains("\"providerAppId\":\"dependencies\""));
    assertEquals(200, service.statusCode());
    assertTrue(service.body().contains("\"serviceId\":\"trust.score\""));
    assertTrue(service.body().contains("\"providerAppId\":\"dependencies\""));
  }

  @Test
  void route_whenConsumerAppIdIsServices_expectDependencyReadUsesUnambiguousRoute()
      throws Exception {
    PlatformApiRouter router =
        router(
            new InMemoryAppServiceGrantStore(), installedProvider(), installedConsumer("services"));
    PlatformApiPrincipal servicesApp =
        PlatformApiPrincipal.appBrowserSession("services", List.of("app.services.read"));

    PlatformApiResponse dependencies =
        router.route(
            request(
                "GET",
                List.of("app-services", "dependencies", "consumers", "services"),
                Map.of(),
                servicesApp));

    assertEquals(200, dependencies.statusCode());
    assertTrue(dependencies.body().contains("\"dependencyGraph\""));
    assertTrue(dependencies.body().contains("\"appId\":\"services\""));
    assertTrue(dependencies.body().contains("\"serviceId\":\"trust.score\""));
  }

  @Test
  void route_whenAppUsesDependencyAndBundleRoutes_expectScopedReviewFlow() throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    PlatformApiRouter router = router(store, installedProvider(), installedConsumer());
    PlatformApiPrincipal socialInbox =
        PlatformApiPrincipal.appBrowserSession(
            "social-inbox", List.of("app.services.read", "app.services.call"));

    PlatformApiResponse dependencies =
        router.route(
            request("GET", List.of("app-services", "dependencies"), Map.of(), socialInbox));
    PlatformApiResponse bundle =
        router.route(
            request(
                "POST",
                List.of("app-services", "grant-bundles"),
                Map.of("bundleAlias", List.of("trust-annotations")),
                socialInbox));
    String bundleId = store.listBundles().getFirst().bundleId();
    PlatformApiResponse appApprove =
        router.route(
            request(
                "POST",
                List.of("app-services", "grant-bundles", bundleId, "approve"),
                Map.of(),
                socialInbox));
    PlatformApiResponse hostApprove =
        router.route(
            request(
                "POST",
                List.of("app-services", "grant-bundles", bundleId, "approve"),
                Map.of(),
                PlatformApiPrincipal.hostOperator()));
    PlatformApiResponse bundles =
        router.route(
            request("GET", List.of("app-services", "grant-bundles"), Map.of(), socialInbox));

    assertEquals(200, dependencies.statusCode());
    assertTrue(dependencies.body().contains("\"dependencyGraph\""));
    assertTrue(dependencies.body().contains("\"trust-score\""));
    assertEquals(201, bundle.statusCode());
    assertTrue(bundle.body().contains("\"status\":\"pending\""));
    assertEquals(403, appApprove.statusCode());
    assertEquals(200, hostApprove.statusCode());
    assertTrue(hostApprove.body().contains("\"status\":\"approved\""));
    assertEquals(200, bundles.statusCode());
    assertTrue(bundles.body().contains("\"trust-annotations\""));
  }

  @Test
  void route_whenAppReadsOtherAppDependencies_expectForbidden() throws Exception {
    PlatformApiRouter router =
        router(
            new InMemoryAppServiceGrantStore(),
            installedProvider(),
            installedConsumer(),
            installedConsumer("other-inbox"));
    PlatformApiPrincipal socialInbox =
        PlatformApiPrincipal.appBrowserSession("social-inbox", List.of("app.services.read"));

    PlatformApiResponse response =
        router.route(
            request(
                "GET",
                List.of("app-services", "dependencies", "consumers", "other-inbox"),
                Map.of(),
                socialInbox));

    assertEquals(403, response.statusCode());
  }

  @Test
  void route_whenAppReadsAuditOrInvokesWithoutCallCapability_expectDenied() throws Exception {
    PlatformApiRouter router =
        router(new InMemoryAppServiceGrantStore(), installedProvider(), installedConsumer());
    PlatformApiPrincipal readOnly =
        PlatformApiPrincipal.appBrowserSession("social-inbox", List.of("app.services.read"));

    PlatformApiResponse audit =
        router.route(request("GET", List.of("app-services", "audit"), Map.of(), readOnly));
    PlatformApiResponse invoke =
        router.route(
            request(
                "POST",
                List.of("app-services", "trust-graph", "services", "trust.score", "invoke"),
                invokeParams(),
                readOnly));

    assertEquals(403, audit.statusCode());
    assertEquals(403, invoke.statusCode());
    assertEquals("forbidden", errorCode(invoke));
  }

  private PlatformApiRouter router(
      InMemoryAppServiceGrantStore store, InstalledAppSnapshot... installedApps) throws Exception {
    AppHost appHost = mock(AppHost.class);
    when(appHost.listInstalled()).thenReturn(List.of(installedApps));
    AppServiceCoordinator coordinator =
        new AppServiceCoordinator(appHost, store, CLOCK, List.of(fakeAdapter()));
    return new PlatformApiRouter(
        runtimePorts(),
        appHost,
        null,
        null,
        AppUiOriginRegistry.sameOriginOnly(),
        PlatformApiSharedAppServices.of(null, null, null, null, null, coordinator));
  }

  private AppServiceAdapter fakeAdapter() {
    return new AppServiceAdapter() {
      @Override
      public String adapterId() {
        return TrustGraphScoreAppServiceAdapter.ADAPTER_ID;
      }

      @Override
      public Map<String, Object> invoke(
          AppServiceDescriptor descriptor,
          AppServiceGrant grant,
          Map<String, List<String>> queryParameters) {
        LinkedHashMap<String, Object> result = LinkedHashMap.newLinkedHashMap(2);
        result.put("status", "ok");
        result.put("score", 0.5d);
        return result;
      }
    };
  }

  private InstalledAppSnapshot installedProvider() throws Exception {
    return installedProvider("trust-graph");
  }

  private InstalledAppSnapshot installedProvider(String appId) throws Exception {
    return installedApp(
        appId,
        "Trust Graph Preview",
        List.of(),
        """
        app.services.provides=trust-score
        app.service.trust-score.id=trust.score
        app.service.trust-score.name=Trust Score Service
        app.service.trust-score.version=1
        app.service.trust-score.kind=platform-adapter
        app.service.trust-score.adapter=trust-graph.score
        app.service.trust-score.scopes=score.read
        app.service.trust-score.contexts=message-author,profile
        app.service.trust-score.description=Returns a redacted score summary.
        """);
  }

  private InstalledAppSnapshot installedConsumer() throws Exception {
    return installedApp(
        "social-inbox",
        "Social Inbox Preview",
        List.of("app.services.read", "app.services.call"),
        """
        app.services.requests=trust-score
        app.service-request.trust-score.provider=trust-graph
        app.service-request.trust-score.service=trust.score
        app.service-request.trust-score.scopes=score.read
        app.service-request.trust-score.contexts=message-author
        app.service-request.trust-score.purpose=Annotate message authors.
        app.service-request.trust-score.dependency.kind=optional
        app.service-request.trust-score.dependency.required=false
        app.service-request.trust-score.dependency.featureId=trust-score-annotations
        app.service-request.trust-score.dependency.featureName=Trust score annotations
        app.service-request.trust-score.dependency.degradeBehavior=disable-feature
        app.service-request.trust-score.dependency.minServiceVersion=1
        app.service-request.trust-score.dependency.maxServiceVersion=1
        app.service-request.trust-score.dependency.grantBundle=trust-annotations
        app.service-request.trust-score.dependency.grantExpiresAfter=PT720H
        """);
  }

  private InstalledAppSnapshot installedConsumer(String appId) throws Exception {
    return installedApp(
        appId,
        "Social Inbox Preview",
        List.of("app.services.read", "app.services.call"),
        """
        app.services.requests=trust-score
        app.service-request.trust-score.provider=trust-graph
        app.service-request.trust-score.service=trust.score
        app.service-request.trust-score.scopes=score.read
        app.service-request.trust-score.contexts=message-author
        app.service-request.trust-score.purpose=Annotate message authors.
        app.service-request.trust-score.dependency.kind=optional
        app.service-request.trust-score.dependency.required=false
        app.service-request.trust-score.dependency.featureId=trust-score-annotations
        app.service-request.trust-score.dependency.featureName=Trust score annotations
        app.service-request.trust-score.dependency.degradeBehavior=disable-feature
        app.service-request.trust-score.dependency.minServiceVersion=1
        app.service-request.trust-score.dependency.maxServiceVersion=1
        app.service-request.trust-score.dependency.grantBundle=trust-annotations
        app.service-request.trust-score.dependency.grantExpiresAfter=PT720H
        """);
  }

  private InstalledAppSnapshot installedApp(
      String appId, String name, List<String> permissions, String serviceProperties)
      throws Exception {
    Path root = tempDir.resolve(appId).resolve("installed");
    Files.createDirectories(root);
    Files.writeString(root.resolve("cryptad-app.properties"), serviceProperties);
    AppManifest manifest =
        new AppManifest(
            1, appId, name, "1.0.0", "bin/app.sh", AppUiMode.NONE, null, permissions, null, null);
    InstalledAppPaths paths =
        new InstalledAppPaths(
            appId,
            root,
            tempDir.resolve(appId).resolve("data"),
            tempDir.resolve(appId).resolve("cache"),
            tempDir.resolve(appId).resolve("run"));
    return new InstalledAppSnapshot(manifest, paths);
  }

  private static PlatformApiRequest request(
      String method,
      List<String> segments,
      Map<String, List<String>> params,
      PlatformApiPrincipal principal) {
    return new PlatformApiRequest(method, segments, params, principal);
  }

  private static Map<String, List<String>> grantParams() {
    return Map.of(
        "providerAppId",
        List.of("trust-graph"),
        "serviceId",
        List.of("trust.score"),
        "scopes",
        List.of("score.read"),
        "contexts",
        List.of("message-author"),
        "purpose",
        List.of("Annotate message authors."));
  }

  private static Map<String, List<String>> invokeParams() {
    return Map.of(
        "subjectKind",
        List.of("identity"),
        "subjectUri",
        List.of("crypta:identity:alice"),
        "context",
        List.of("message-author"));
  }

  private static String errorCode(PlatformApiResponse response) {
    int index = response.body().indexOf("\"code\":\"");
    if (index < 0) {
      return "";
    }
    int start = index + "\"code\":\"".length();
    int end = response.body().indexOf('"', start);
    return response.body().substring(start, end);
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
