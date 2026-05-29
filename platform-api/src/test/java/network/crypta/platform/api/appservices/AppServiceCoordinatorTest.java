package network.crypta.platform.api.appservices;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiPrincipal;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AppServiceCoordinatorTest {
  private static final Clock CLOCK =
      Clock.fixed(Instant.parse("2026-05-24T12:00:00Z"), ZoneOffset.UTC);
  private static final PlatformApiPrincipal SOCIAL_INBOX =
      PlatformApiPrincipal.appBrowserSession(
          "social-inbox", List.of("app.services.read", "app.services.call"));
  private static final PlatformApiPrincipal HOST_OPERATOR = PlatformApiPrincipal.hostOperator();

  @TempDir private Path tempDir;

  @Test
  void grantLifecycle_whenApprovedThenRevoked_expectInvocationBoundary() throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(store, installedProvider(), installedConsumer());

    Map<String, Object> requested = coordinator.requestGrant(SOCIAL_INBOX, grantParams());

    assertEquals("pending", requested.get("status"));
    String grantId = requested.get("grantId").toString();
    Map<String, List<String>> invocationParams = invokeParams();
    PlatformApiException pendingFailure =
        assertThrows(
            PlatformApiException.class,
            () -> coordinator.invoke(SOCIAL_INBOX, "trust-graph", "trust.score", invocationParams));
    assertEquals("app_service_grant_required", pendingFailure.errorCode());
    PlatformApiException appApproval =
        assertThrows(
            PlatformApiException.class, () -> coordinator.approveGrant(SOCIAL_INBOX, grantId));
    assertEquals("forbidden", appApproval.errorCode());

    Map<String, Object> approved = coordinator.approveGrant(HOST_OPERATOR, grantId);
    Map<String, Object> invocation =
        coordinator.invoke(SOCIAL_INBOX, "trust-graph", "trust.score", invocationParams);

    assertEquals("active", approved.get("status"));
    assertTrue(invocation.toString().contains("\"providerAppId\"".replace("\"", "")));
    assertEquals(1L, store.readGrant(grantId).orElseThrow().useCount());

    coordinator.revokeGrant(HOST_OPERATOR, grantId);
    PlatformApiException revokedFailure =
        assertThrows(
            PlatformApiException.class,
            () -> coordinator.invoke(SOCIAL_INBOX, "trust-graph", "trust.score", invocationParams));
    assertEquals("app_service_grant_required", revokedFailure.errorCode());
  }

  @Test
  void approveGrant_whenGrantIsRevoked_expectRejectedAndGrantRemainsRevoked() throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(store, installedProvider(), installedConsumer());
    String grantId =
        coordinator.requestGrant(SOCIAL_INBOX, grantParams()).get("grantId").toString();
    coordinator.approveGrant(HOST_OPERATOR, grantId);
    coordinator.revokeGrant(HOST_OPERATOR, grantId);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> coordinator.approveGrant(HOST_OPERATOR, grantId));

    assertEquals(409, exception.statusCode());
    assertEquals("app_service_grant_not_pending", exception.errorCode());
    assertEquals(AppServiceGrantStatus.REVOKED, store.readGrant(grantId).orElseThrow().status());
  }

  @Test
  void approveGrant_whenGrantIsInactive_expectRejectedAndGrantRemainsInactive() throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(store, installedProvider(), installedConsumer());
    String grantId =
        coordinator.requestGrant(SOCIAL_INBOX, grantParams()).get("grantId").toString();
    coordinator.approveGrant(HOST_OPERATOR, grantId);
    coordinator.clearAppState("social-inbox");

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> coordinator.approveGrant(HOST_OPERATOR, grantId));

    assertEquals(409, exception.statusCode());
    assertEquals("app_service_grant_not_pending", exception.errorCode());
    assertEquals(AppServiceGrantStatus.INACTIVE, store.readGrant(grantId).orElseThrow().status());
  }

  @Test
  void approveGrant_whenProviderDropsRequestedScope_expectRejectedAndGrantRemainsPending()
      throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator requestCoordinator =
        coordinator(store, installedProvider(), installedConsumer());
    String grantId =
        requestCoordinator.requestGrant(SOCIAL_INBOX, grantParams()).get("grantId").toString();
    AppServiceCoordinator approvalCoordinator =
        coordinator(
            store,
            installedProvider("profile.read", "message-author,profile"),
            installedConsumer());

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> approvalCoordinator.approveGrant(HOST_OPERATOR, grantId));

    assertEquals(409, exception.statusCode());
    assertEquals("app_service_grant_stale", exception.errorCode());
    assertEquals(AppServiceGrantStatus.PENDING, store.readGrant(grantId).orElseThrow().status());
  }

  @Test
  void approveGrant_whenProviderDropsRequestedContext_expectRejectedAndGrantRemainsPending()
      throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator requestCoordinator =
        coordinator(store, installedProvider(), installedConsumer());
    String grantId =
        requestCoordinator.requestGrant(SOCIAL_INBOX, grantParams()).get("grantId").toString();
    AppServiceCoordinator approvalCoordinator =
        coordinator(store, installedProviderWithContexts("profile"), installedConsumer());

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> approvalCoordinator.approveGrant(HOST_OPERATOR, grantId));

    assertEquals(409, exception.statusCode());
    assertEquals("app_service_grant_stale", exception.errorCode());
    assertEquals(AppServiceGrantStatus.PENDING, store.readGrant(grantId).orElseThrow().status());
  }

  @Test
  void invoke_whenConsumerManifestDropsCallPermission_expectDenied() throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(
            store,
            installedProvider(),
            installedApp("social-inbox", "Social Inbox", List.of(), ""));
    store.writeGrant(
        new AppServiceGrant(
            "asg-111111111111111111111111",
            "social-inbox",
            "trust-graph",
            "trust.score",
            List.of("score.read"),
            List.of("message-author"),
            "Annotate message authors.",
            AppServiceGrantStatus.ACTIVE,
            CLOCK.instant(),
            CLOCK.instant(),
            CLOCK.instant(),
            null,
            null,
            0,
            null));
    Map<String, List<String>> invocationParams = invokeParams();

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> coordinator.invoke(SOCIAL_INBOX, "trust-graph", "trust.score", invocationParams));

    assertEquals("app_services_call_permission_missing", exception.errorCode());
  }

  @Test
  void requestGrant_whenContextualServiceOmitsContexts_expectRejected() throws Exception {
    AppServiceCoordinator coordinator =
        coordinator(new InMemoryAppServiceGrantStore(), installedProvider(), installedConsumer());
    Map<String, List<String>> grantParameters = grantParamsWithoutContexts();

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> coordinator.requestGrant(SOCIAL_INBOX, grantParameters));

    assertEquals(400, exception.statusCode());
    assertEquals("app_service_context_required", exception.errorCode());
  }

  @Test
  void requestGrant_whenUnscopedServiceIncludesContexts_expectRejected() throws Exception {
    AppServiceCoordinator coordinator =
        coordinator(
            new InMemoryAppServiceGrantStore(),
            installedProviderWithContexts(""),
            installedConsumer());
    Map<String, List<String>> grantParameters = grantParams();

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> coordinator.requestGrant(SOCIAL_INBOX, grantParameters));

    assertEquals(400, exception.statusCode());
    assertEquals("app_service_context_unsupported", exception.errorCode());
  }

  @Test
  void approveGrant_whenProviderRemovesContextScoping_expectRejectedAndGrantRemainsPending()
      throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator requestCoordinator =
        coordinator(store, installedProvider(), installedConsumer());
    String grantId =
        requestCoordinator.requestGrant(SOCIAL_INBOX, grantParams()).get("grantId").toString();
    AppServiceCoordinator approvalCoordinator =
        coordinator(store, installedProviderWithContexts(""), installedConsumer());

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> approvalCoordinator.approveGrant(HOST_OPERATOR, grantId));

    assertEquals(409, exception.statusCode());
    assertEquals("app_service_grant_stale", exception.errorCode());
    assertEquals(AppServiceGrantStatus.PENDING, store.readGrant(grantId).orElseThrow().status());
  }

  @Test
  void invoke_whenExistingContextualGrantHasEmptyContexts_expectDenied() throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(store, installedProvider(), installedConsumer());
    store.writeGrant(
        new AppServiceGrant(
            "asg-222222222222222222222222",
            "social-inbox",
            "trust-graph",
            "trust.score",
            List.of("score.read"),
            List.of(),
            "Legacy grant without contextual bounds.",
            AppServiceGrantStatus.ACTIVE,
            CLOCK.instant(),
            CLOCK.instant(),
            CLOCK.instant(),
            null,
            null,
            0,
            null));
    Map<String, List<String>> invocationParams = invokeParams();

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> coordinator.invoke(SOCIAL_INBOX, "trust-graph", "trust.score", invocationParams));

    assertEquals("app_service_grant_required", exception.errorCode());
  }

  @Test
  void invoke_whenContextHasWhitespaceAndMixedCase_expectNormalizedGrantMatchAndAdapterInput()
      throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(store, installedProvider(), installedConsumer());
    store.writeGrant(activeGrant("asg-111111111111111111111111", "social-inbox"));

    Map<String, Object> invocation =
        coordinator.invoke(
            SOCIAL_INBOX,
            "trust-graph",
            "trust.score",
            Map.of(
                "subjectKind",
                List.of("identity"),
                "subjectUri",
                List.of("crypta:identity:alice"),
                "context",
                List.of(" Message-Author ")));

    assertEquals("message-author", serviceCallResult(invocation).get("context"));
    assertEquals(1L, store.readGrant("asg-111111111111111111111111").orElseThrow().useCount());
  }

  @Test
  void invoke_whenServiceIsUnscoped_expectNoContextRequired() throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(store, installedProviderWithContexts(""), installedConsumer());
    String grantId =
        coordinator
            .requestGrant(SOCIAL_INBOX, grantParamsWithoutContexts())
            .get("grantId")
            .toString();
    coordinator.approveGrant(HOST_OPERATOR, grantId);

    Map<String, Object> invocation =
        coordinator.invoke(
            SOCIAL_INBOX, "trust-graph", "trust.score", invokeParamsWithoutContext());

    assertNull(serviceCallResult(invocation).get("context"));
    assertEquals(1L, store.readGrant(grantId).orElseThrow().useCount());
  }

  @Test
  void audit_whenDeniedInvocationsShareClockTick_expectDistinctDurableEvents() throws Exception {
    FileAppServiceGrantStore store = new FileAppServiceGrantStore(tempDir.resolve("store"));
    AppServiceCoordinator coordinator =
        coordinator(store, installedProvider(), installedConsumer());
    Map<String, List<String>> invocationParams = invokeParams();

    for (int attempt = 0; attempt < 2; attempt++) {
      PlatformApiException exception =
          assertThrows(
              PlatformApiException.class,
              () ->
                  coordinator.invoke(SOCIAL_INBOX, "trust-graph", "trust.score", invocationParams));
      assertEquals("app_service_grant_required", exception.errorCode());
    }

    List<AppServiceAuditEvent> events = store.listAuditEvents(10);

    assertEquals(2, events.size());
    assertEquals(2L, events.stream().map(AppServiceAuditEvent::eventId).distinct().count());
    assertTrue(
        events.stream().allMatch(event -> "service_invocation_denied".equals(event.eventType())));
  }

  @Test
  void listRequests_whenCalledByApp_expectOnlyOwnRequestVisible() throws Exception {
    AppServiceCoordinator coordinator =
        coordinator(
            new InMemoryAppServiceGrantStore(),
            installedProvider(),
            installedConsumer(),
            installedConsumer("other-inbox"));

    List<Map<String, Object>> appRequests = coordinator.listRequests(SOCIAL_INBOX);
    List<Map<String, Object>> hostRequests = coordinator.listRequests(HOST_OPERATOR);

    assertEquals(1, appRequests.size());
    assertEquals("social-inbox", appRequests.getFirst().get("consumerAppId"));
    assertEquals(
        List.of("other-inbox", "social-inbox"),
        hostRequests.stream().map(request -> request.get("consumerAppId").toString()).toList());
  }

  @Test
  void listGrants_whenCalledByApp_expectOnlyOwnGrantVisible() throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(
            store, installedProvider(), installedConsumer(), installedConsumer("other-inbox"));
    store.writeGrant(activeGrant("asg-111111111111111111111111", "social-inbox"));
    store.writeGrant(activeGrant("asg-222222222222222222222222", "other-inbox"));

    List<Map<String, Object>> appGrants = coordinator.listGrants(SOCIAL_INBOX);
    List<Map<String, Object>> hostGrants = coordinator.listGrants(HOST_OPERATOR);

    assertEquals(1, appGrants.size());
    assertEquals("social-inbox", appGrants.getFirst().get("consumerAppId"));
    assertEquals(
        List.of("social-inbox", "other-inbox"),
        hostGrants.stream().map(grant -> grant.get("consumerAppId").toString()).toList());
  }

  @Test
  void listGrants_whenProviderStopsAdvertisingService_expectInactiveEffectiveStatus()
      throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(
            store,
            installedApp("trust-graph", "Trust Graph Preview", List.of(), ""),
            installedConsumer());
    store.writeGrant(activeGrant("asg-111111111111111111111111", "social-inbox"));

    List<Map<String, Object>> grants = coordinator.listGrants(HOST_OPERATOR);

    assertEquals(1, grants.size());
    assertEquals("inactive", grants.getFirst().get("status"));
  }

  @Test
  void listGrants_whenConsumerManifestDropsCallPermission_expectInactiveEffectiveStatus()
      throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(
            store,
            installedProvider(),
            installedApp("social-inbox", "Social Inbox", List.of(), ""));
    store.writeGrant(activeGrant("asg-111111111111111111111111", "social-inbox"));

    List<Map<String, Object>> grants = coordinator.listGrants(HOST_OPERATOR);

    assertEquals(1, grants.size());
    assertEquals("inactive", grants.getFirst().get("status"));
  }

  @Test
  void listGrants_whenConsumerIsUninstalled_expectInactiveEffectiveStatus() throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator = coordinator(store, installedProvider());
    store.writeGrant(activeGrant("asg-111111111111111111111111", "social-inbox"));

    List<Map<String, Object>> grants = coordinator.listGrants(HOST_OPERATOR);

    assertEquals(1, grants.size());
    assertEquals("inactive", grants.getFirst().get("status"));
  }

  @Test
  void listGrants_whenProviderStopsSupportingGrantedContext_expectInactiveEffectiveStatus()
      throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(store, installedProviderWithContexts("profile"), installedConsumer());
    store.writeGrant(activeGrant("asg-111111111111111111111111", "social-inbox"));

    List<Map<String, Object>> grants = coordinator.listGrants(HOST_OPERATOR);

    assertEquals(1, grants.size());
    assertEquals("inactive", grants.getFirst().get("status"));
  }

  @Test
  void requestGrant_whenProviderNotInstalled_expectProviderMissing() throws Exception {
    AppServiceCoordinator coordinator =
        coordinator(new InMemoryAppServiceGrantStore(), installedConsumer());
    Map<String, List<String>> grantParameters = grantParams();

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> coordinator.requestGrant(SOCIAL_INBOX, grantParameters));

    assertEquals("provider_app_not_found", exception.errorCode());
  }

  private AppServiceCoordinator coordinator(
      AppServiceGrantStore store, InstalledAppSnapshot... installedApps) throws Exception {
    AppHost appHost = mock(AppHost.class);
    when(appHost.listInstalled()).thenReturn(List.of(installedApps));
    return new AppServiceCoordinator(appHost, store, CLOCK, List.of(fakeAdapter()));
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
        LinkedHashMap<String, Object> result = LinkedHashMap.newLinkedHashMap(3);
        result.put("status", "ok");
        result.put("score", 0.5d);
        List<String> contexts = queryParameters.get("context");
        result.put("context", contexts == null ? null : contexts.getFirst());
        return result;
      }
    };
  }

  private InstalledAppSnapshot installedProvider() throws Exception {
    return installedProvider("score.read", "message-author,profile");
  }

  private InstalledAppSnapshot installedProviderWithContexts(String contexts) throws Exception {
    return installedProvider("score.read", contexts);
  }

  private InstalledAppSnapshot installedProvider(String scopes, String contexts) throws Exception {
    return installedApp(
        "trust-graph",
        "Trust Graph Preview",
        List.of(),
        """
        app.services.provides=trust-score
        app.service.trust-score.id=trust.score
        app.service.trust-score.name=Trust Score Service
        app.service.trust-score.version=1
        app.service.trust-score.kind=platform-adapter
        app.service.trust-score.adapter=trust-graph.score
        app.service.trust-score.scopes=%s
        app.service.trust-score.contexts=%s
        app.service.trust-score.description=Returns a redacted score summary.
        """
            .formatted(scopes, contexts));
  }

  private InstalledAppSnapshot installedConsumer() throws Exception {
    return installedConsumer("social-inbox");
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

  private static AppServiceGrant activeGrant(String grantId, String consumerAppId) {
    return new AppServiceGrant(
        grantId,
        consumerAppId,
        "trust-graph",
        "trust.score",
        List.of("score.read"),
        List.of("message-author"),
        "Annotate message authors.",
        AppServiceGrantStatus.ACTIVE,
        CLOCK.instant(),
        CLOCK.instant(),
        CLOCK.instant(),
        null,
        null,
        0,
        null);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> serviceCallResult(Map<String, Object> invocation) {
    Map<String, Object> serviceCall = (Map<String, Object>) invocation.get("serviceCall");
    return (Map<String, Object>) serviceCall.get("result");
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

  private static Map<String, List<String>> grantParamsWithoutContexts() {
    return Map.of(
        "providerAppId",
        List.of("trust-graph"),
        "serviceId",
        List.of("trust.score"),
        "scopes",
        List.of("score.read"),
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

  private static Map<String, List<String>> invokeParamsWithoutContext() {
    return Map.of(
        "subjectKind", List.of("identity"), "subjectUri", List.of("crypta:identity:alice"));
  }
}
