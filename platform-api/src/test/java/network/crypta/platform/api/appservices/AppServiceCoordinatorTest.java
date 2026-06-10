package network.crypta.platform.api.appservices;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
  private static final String DISPLAY_PROVIDER_VERSION = "RC 1";
  private static final String REVISED_PURPOSE =
      "Annotate message authors with revised review text.";
  private static final String SHORT_GRANT_EXPIRES_AFTER = "PT120H";
  private static final String UNSUPPORTED_ADAPTER_ID = "unsupported.score";

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
  void approveGrant_whenProviderVersionUsesDisplayText_expectInvocationRemainsActive()
      throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(store, installedProviderWithDisplayVersion(), installedConsumer());
    String grantId =
        coordinator.requestGrant(SOCIAL_INBOX, grantParams()).get("grantId").toString();

    coordinator.approveGrant(HOST_OPERATOR, grantId);

    AppServiceGrant grant = store.readGrant(grantId).orElseThrow();
    assertEquals(DISPLAY_PROVIDER_VERSION, grant.providerServiceVersionAtApproval());
    assertEquals("active", coordinator.listGrants(HOST_OPERATOR).getFirst().get("status"));
    coordinator.invoke(SOCIAL_INBOX, "trust-graph", "trust.score", invokeParams());
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
  void requestGrant_whenSameGrantRequestedAcrossClockTicks_expectExistingGrantReturned()
      throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator firstCoordinator =
        coordinator(CLOCK, store, installedProvider(), installedConsumer());
    Clock laterClock = Clock.fixed(CLOCK.instant().plusSeconds(1), ZoneOffset.UTC);
    AppServiceCoordinator secondCoordinator =
        coordinator(laterClock, store, installedProvider(), installedConsumer());

    Map<String, Object> firstGrant = firstCoordinator.requestGrant(SOCIAL_INBOX, grantParams());
    Map<String, Object> secondGrant = secondCoordinator.requestGrant(SOCIAL_INBOX, grantParams());

    assertEquals(firstGrant.get("grantId"), secondGrant.get("grantId"));
    assertEquals("pending", secondGrant.get("status"));
    assertEquals(1, store.listGrants().size());
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
  void invoke_whenActiveGrantContainsStaleScope_expectDeniedAndInactive() throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(store, installedProvider(), installedConsumer());
    store.writeGrant(
        activeGrant(
            "asg-111111111111111111111111",
            "social-inbox",
            List.of("score.read", "profile.read"),
            List.of("message-author")));
    Map<String, List<String>> invocationParams = invokeParams();

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> coordinator.invoke(SOCIAL_INBOX, "trust-graph", "trust.score", invocationParams));

    assertEquals("app_service_grant_required", exception.errorCode());
    assertEquals(
        "revalidation-required", coordinator.listGrants(HOST_OPERATOR).getFirst().get("status"));
  }

  @Test
  void invoke_whenActiveGrantContainsStaleContext_expectDeniedAndInactive() throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(store, installedProviderWithContexts("message-author"), installedConsumer());
    store.writeGrant(
        activeGrant(
            "asg-111111111111111111111111",
            "social-inbox",
            List.of("score.read"),
            List.of("message-author", "profile")));
    Map<String, List<String>> invocationParams = invokeParams();

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> coordinator.invoke(SOCIAL_INBOX, "trust-graph", "trust.score", invocationParams));

    assertEquals("app_service_grant_required", exception.errorCode());
    assertEquals(
        "revalidation-required", coordinator.listGrants(HOST_OPERATOR).getFirst().get("status"));
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
  void listGrants_whenProviderStopsSupportingGrantedContext_expectRevalidationRequired()
      throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(store, installedProviderWithContexts("profile"), installedConsumer());
    store.writeGrant(activeGrant("asg-111111111111111111111111", "social-inbox"));

    List<Map<String, Object>> grants = coordinator.listGrants(HOST_OPERATOR);

    assertEquals(1, grants.size());
    assertEquals("revalidation-required", grants.getFirst().get("status"));
  }

  @Test
  void clearAppState_whenGrantCleanupCannotPersist_expectFailClosedUntilCleanupSucceeds()
      throws Exception {
    FailingWriteGrantStore store = new FailingWriteGrantStore();
    store.writeGrant(activeGrant("asg-111111111111111111111111", "social-inbox"));
    AppServiceCoordinator coordinator =
        coordinator(store, installedProvider(), installedConsumer());
    Map<String, List<String>> invocationParams = invokeParams();
    store.failWrites(true);

    PlatformApiException cleanupFailure =
        assertThrows(PlatformApiException.class, () -> coordinator.clearAppState("social-inbox"));

    assertEquals("app_services_unavailable", cleanupFailure.errorCode());
    assertEquals("inactive", coordinator.listGrants(HOST_OPERATOR).getFirst().get("status"));
    PlatformApiException failClosedInvocation =
        assertThrows(
            PlatformApiException.class,
            () -> coordinator.invoke(SOCIAL_INBOX, "trust-graph", "trust.score", invocationParams));
    assertEquals("app_services_unavailable", failClosedInvocation.errorCode());

    store.failWrites(false);
    coordinator.clearAppState("social-inbox");

    assertEquals(
        AppServiceGrantStatus.INACTIVE,
        store.readGrant("asg-111111111111111111111111").orElseThrow().status());
    PlatformApiException inactiveGrantInvocation =
        assertThrows(
            PlatformApiException.class,
            () -> coordinator.invoke(SOCIAL_INBOX, "trust-graph", "trust.score", invocationParams));
    assertEquals("app_service_grant_required", inactiveGrantInvocation.errorCode());
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

  @Test
  void dependencyGraph_whenProviderAvailable_expectSocialInboxTrustGraphEdge() throws Exception {
    AppServiceCoordinator coordinator =
        coordinator(new InMemoryAppServiceGrantStore(), installedProvider(), installedConsumer());

    Map<String, Object> graph = coordinator.dependencyGraph(HOST_OPERATOR);

    assertTrue(graph.toString().contains("consumerAppId=social-inbox"));
    assertTrue(graph.toString().contains("providerAppId=trust-graph"));
    assertTrue(graph.toString().contains("serviceId=trust.score"));
    assertTrue(graph.toString().contains("kind=optional"));
    assertTrue(graph.toString().contains("status=available"));
    assertTrue(graph.toString().contains("blocking=false"));
  }

  @Test
  void dependencyGraph_whenProviderVersionUsesDisplayTextWithRange_expectVersionMismatch()
      throws Exception {
    AppServiceCoordinator coordinator =
        coordinator(
            new InMemoryAppServiceGrantStore(),
            installedProviderWithDisplayVersion(),
            installedConsumer());

    Map<String, Object> graph = coordinator.dependencyGraph(HOST_OPERATOR);

    assertTrue(graph.toString().contains("status=version-mismatch"));
  }

  @Test
  void dependencyGraph_whenProviderAdapterUnsupported_expectDependencyUnavailable()
      throws Exception {
    AppServiceCoordinator coordinator =
        coordinator(
            new InMemoryAppServiceGrantStore(),
            installedProviderWithUnsupportedAdapter(),
            installedConsumer());

    Map<String, Object> graph = coordinator.dependencyGraph(HOST_OPERATOR);

    assertTrue(graph.toString().contains("status=unavailable"));
  }

  @Test
  void approveBundle_whenProviderVersionUsesDisplayTextWithRange_expectDependencyUnavailable()
      throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(store, installedProviderWithDisplayVersion(), installedConsumer());
    String bundleId =
        coordinator
            .requestBundle(SOCIAL_INBOX, Map.of("bundleAlias", List.of("trust-annotations")))
            .get("bundleId")
            .toString();

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> coordinator.approveBundle(HOST_OPERATOR, bundleId));

    assertEquals("app_service_dependency_unavailable", exception.errorCode());
    assertTrue(store.listGrants().isEmpty());
    assertEquals("pending", coordinator.listBundles(HOST_OPERATOR).getFirst().get("status"));
  }

  @Test
  void approveBundle_whenDependencyAliasChangesBeforeApproval_expectManifestStale()
      throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator requestCoordinator =
        coordinator(store, installedProvider(), installedConsumer());
    String bundleId =
        requestCoordinator
            .requestBundle(SOCIAL_INBOX, Map.of("bundleAlias", List.of("trust-annotations")))
            .get("bundleId")
            .toString();
    AppServiceCoordinator approvalCoordinator =
        coordinator(
            store,
            installedProvider(),
            installedProfileProvider(),
            installedConsumerWithDriftedTrustScoreAlias());

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> approvalCoordinator.approveBundle(HOST_OPERATOR, bundleId));

    assertEquals("app_service_bundle_manifest_stale", exception.errorCode());
    assertTrue(store.listGrants().isEmpty());
    assertEquals(
        "pending", approvalCoordinator.listBundles(HOST_OPERATOR).getFirst().get("status"));
  }

  @Test
  void approveBundle_whenDependencyPurposeChangesBeforeApproval_expectManifestStale()
      throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator requestCoordinator =
        coordinator(store, installedProvider(), installedConsumer());
    String bundleId =
        requestCoordinator
            .requestBundle(SOCIAL_INBOX, Map.of("bundleAlias", List.of("trust-annotations")))
            .get("bundleId")
            .toString();
    AppServiceCoordinator approvalCoordinator =
        coordinator(store, installedProvider(), installedConsumerWithRevisedPurpose());

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> approvalCoordinator.approveBundle(HOST_OPERATOR, bundleId));

    assertEquals("app_service_bundle_manifest_stale", exception.errorCode());
    assertTrue(store.listGrants().isEmpty());
    assertEquals(
        "pending", approvalCoordinator.listBundles(HOST_OPERATOR).getFirst().get("status"));
  }

  @Test
  void dependencyGraph_whenAppReadsOtherConsumer_expectForbidden() throws Exception {
    AppServiceCoordinator coordinator =
        coordinator(
            new InMemoryAppServiceGrantStore(),
            installedProvider(),
            installedConsumer(),
            installedConsumer("other-inbox"));

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> coordinator.dependencyGraph(SOCIAL_INBOX, "other-inbox"));

    assertEquals("forbidden", exception.errorCode());
  }

  @Test
  void grantBundleLifecycle_whenApprovedExpiredAndRenewed_expectInvocationBoundary()
      throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(store, installedProvider(), installedConsumer());

    Map<String, Object> requested =
        coordinator.requestBundle(
            SOCIAL_INBOX, Map.of("bundleAlias", List.of("trust-annotations")));
    String bundleId = requested.get("bundleId").toString();

    assertEquals("pending", requested.get("status"));
    assertEquals(0, store.listGrants().size());
    PlatformApiException appApproval =
        assertThrows(
            PlatformApiException.class, () -> coordinator.approveBundle(SOCIAL_INBOX, bundleId));
    assertEquals("forbidden", appApproval.errorCode());

    Map<String, Object> approved = coordinator.approveBundle(HOST_OPERATOR, bundleId);
    assertEquals("approved", approved.get("status"));
    assertEquals(1, store.listGrants().size());
    assertEquals("active", coordinator.listGrants(HOST_OPERATOR).getFirst().get("status"));
    coordinator.invoke(SOCIAL_INBOX, "trust-graph", "trust.score", invokeParams());

    Clock expiredClock = Clock.fixed(CLOCK.instant().plus(Duration.ofDays(31)), ZoneOffset.UTC);
    AppServiceCoordinator expiredCoordinator =
        coordinator(expiredClock, store, installedProvider(), installedConsumer());
    assertEquals("expired", expiredCoordinator.listGrants(HOST_OPERATOR).getFirst().get("status"));
    Map<String, List<String>> expiredInvokeParams = invokeParams();
    PlatformApiException expiredInvocation =
        assertThrows(
            PlatformApiException.class,
            () ->
                expiredCoordinator.invoke(
                    SOCIAL_INBOX, "trust-graph", "trust.score", expiredInvokeParams));
    assertEquals("app_service_grant_required", expiredInvocation.errorCode());

    Map<String, Object> renewed = expiredCoordinator.renewBundle(HOST_OPERATOR, bundleId);
    assertEquals("approved", renewed.get("status"));
    assertEquals("active", expiredCoordinator.listGrants(HOST_OPERATOR).getFirst().get("status"));
    expiredCoordinator.invoke(SOCIAL_INBOX, "trust-graph", "trust.score", invokeParams());
  }

  @Test
  void dependencyGraph_whenExpiredGrantPrecedesFreshActiveGrant_expectGrantActive()
      throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(store, installedProvider(), installedConsumer());
    String bundleId =
        coordinator
            .requestBundle(SOCIAL_INBOX, Map.of("bundleAlias", List.of("trust-annotations")))
            .get("bundleId")
            .toString();
    coordinator.approveBundle(HOST_OPERATOR, bundleId);
    Clock expiredClock = Clock.fixed(CLOCK.instant().plus(Duration.ofDays(31)), ZoneOffset.UTC);
    AppServiceCoordinator expiredCoordinator =
        coordinator(expiredClock, store, installedProvider(), installedConsumer());
    assertEquals("expired", expiredCoordinator.listGrants(HOST_OPERATOR).getFirst().get("status"));
    String freshGrantId =
        expiredCoordinator.requestGrant(SOCIAL_INBOX, grantParams()).get("grantId").toString();
    expiredCoordinator.approveGrant(HOST_OPERATOR, freshGrantId);

    Map<String, Object> graph = expiredCoordinator.dependencyGraph(HOST_OPERATOR);

    assertTrue(graph.toString().contains("status=grant-active"));
  }

  @Test
  void approveBundle_whenDuplicateDependenciesHaveDifferentExpiry_expectSharedGrantKeepsExpiry()
      throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(store, installedProvider(), installedConsumerWithDuplicateExpiryPolicies());
    String bundleId =
        coordinator
            .requestBundle(SOCIAL_INBOX, Map.of("bundleAlias", List.of("combined-review")))
            .get("bundleId")
            .toString();

    coordinator.approveBundle(HOST_OPERATOR, bundleId);

    assertEquals(1, store.listGrants().size());
    assertNotNull(store.listGrants().getFirst().expiresAt());
    Clock expiredClock = Clock.fixed(CLOCK.instant().plus(Duration.ofDays(31)), ZoneOffset.UTC);
    AppServiceCoordinator expiredCoordinator =
        coordinator(
            expiredClock,
            store,
            installedProvider(),
            installedConsumerWithDuplicateExpiryPolicies());
    assertEquals("expired", expiredCoordinator.listGrants(HOST_OPERATOR).getFirst().get("status"));
    Map<String, List<String>> expiredInvokeParams = invokeParams();
    PlatformApiException expiredInvocation =
        assertThrows(
            PlatformApiException.class,
            () ->
                expiredCoordinator.invoke(
                    SOCIAL_INBOX, "trust-graph", "trust.score", expiredInvokeParams));
    assertEquals("app_service_grant_required", expiredInvocation.errorCode());
  }

  @Test
  void approveBundle_whenPriorMatchingGrantExpired_expectFreshApprovalRefreshesExpiry()
      throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(store, installedProvider(), installedConsumer());
    String firstBundleId =
        coordinator
            .requestBundle(SOCIAL_INBOX, Map.of("bundleAlias", List.of("trust-annotations")))
            .get("bundleId")
            .toString();
    coordinator.approveBundle(HOST_OPERATOR, firstBundleId);

    Clock expiredClock = Clock.fixed(CLOCK.instant().plus(Duration.ofDays(31)), ZoneOffset.UTC);
    AppServiceCoordinator expiredCoordinator =
        coordinator(expiredClock, store, installedProvider(), installedConsumer());
    assertEquals("expired", expiredCoordinator.listGrants(HOST_OPERATOR).getFirst().get("status"));
    String secondBundleId =
        expiredCoordinator
            .requestBundle(SOCIAL_INBOX, Map.of("bundleAlias", List.of("trust-annotations")))
            .get("bundleId")
            .toString();

    expiredCoordinator.approveBundle(HOST_OPERATOR, secondBundleId);

    AppServiceGrant refreshedGrant = store.listGrants().getFirst();
    assertTrue(refreshedGrant.expiresAt().isAfter(expiredClock.instant()));
    assertEquals("active", expiredCoordinator.listGrants(HOST_OPERATOR).getFirst().get("status"));
    expiredCoordinator.invoke(SOCIAL_INBOX, "trust-graph", "trust.score", invokeParams());
  }

  @Test
  void approveBundle_whenReusingActiveGrantWithEarlierExpiry_expectBundleExpiryMatchesGrant()
      throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator shortExpiryCoordinator =
        coordinator(store, installedProvider(), installedConsumerWithShortGrantExpiry());
    String firstBundleId =
        shortExpiryCoordinator
            .requestBundle(SOCIAL_INBOX, Map.of("bundleAlias", List.of("trust-annotations")))
            .get("bundleId")
            .toString();
    shortExpiryCoordinator.approveBundle(HOST_OPERATOR, firstBundleId);
    Instant reusedGrantExpiry = store.listGrants().getFirst().expiresAt();
    assertEquals(CLOCK.instant().plus(Duration.ofDays(5)), reusedGrantExpiry);
    Clock laterClock = Clock.fixed(CLOCK.instant().plusSeconds(1), ZoneOffset.UTC);
    AppServiceCoordinator laterCoordinator =
        coordinator(laterClock, store, installedProvider(), installedConsumer());
    String secondBundleId =
        laterCoordinator
            .requestBundle(SOCIAL_INBOX, Map.of("bundleAlias", List.of("trust-annotations")))
            .get("bundleId")
            .toString();

    Map<String, Object> approved = laterCoordinator.approveBundle(HOST_OPERATOR, secondBundleId);

    assertEquals(reusedGrantExpiry.toString(), approved.get("expiresAt"));
    assertEquals(reusedGrantExpiry, store.readBundle(secondBundleId).orElseThrow().expiresAt());
    assertEquals(reusedGrantExpiry, store.listGrants().getFirst().expiresAt());
  }

  @Test
  void listBundles_whenApprovedDependencyPurposeDrifts_expectRevalidationRequired()
      throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(store, installedProvider(), installedConsumer());
    String bundleId =
        coordinator
            .requestBundle(SOCIAL_INBOX, Map.of("bundleAlias", List.of("trust-annotations")))
            .get("bundleId")
            .toString();
    coordinator.approveBundle(HOST_OPERATOR, bundleId);
    assertEquals("active", coordinator.listGrants(HOST_OPERATOR).getFirst().get("status"));

    AppServiceCoordinator driftedCoordinator =
        coordinator(store, installedProvider(), installedConsumerWithRevisedPurpose());

    Map<String, Object> bundle = driftedCoordinator.listBundles(HOST_OPERATOR).getFirst();
    assertEquals(bundleId, bundle.get("bundleId"));
    assertEquals("revalidation-required", bundle.get("status"));
    assertEquals("active", driftedCoordinator.listGrants(HOST_OPERATOR).getFirst().get("status"));
  }

  @Test
  void listBundles_whenApprovedGrantRevoked_expectRevalidationRequired() throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(store, installedProvider(), installedConsumer());
    String bundleId =
        coordinator
            .requestBundle(SOCIAL_INBOX, Map.of("bundleAlias", List.of("trust-annotations")))
            .get("bundleId")
            .toString();
    coordinator.approveBundle(HOST_OPERATOR, bundleId);
    String grantId = store.listGrants().getFirst().grantId();

    coordinator.revokeGrant(HOST_OPERATOR, grantId);

    assertEquals(
        "revalidation-required", coordinator.listBundles(HOST_OPERATOR).getFirst().get("status"));
  }

  @Test
  void listBundles_whenApprovedGrantReferenceMissing_expectRevalidationRequired() throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(store, installedProvider(), installedConsumer());
    String bundleId =
        coordinator
            .requestBundle(SOCIAL_INBOX, Map.of("bundleAlias", List.of("trust-annotations")))
            .get("bundleId")
            .toString();
    AppServiceGrantBundle pending = store.readBundle(bundleId).orElseThrow();
    AppServiceGrantBundle approvedWithMissingGrant =
        pending.withStatus(
            AppServiceGrantBundleStatus.APPROVED,
            CLOCK.instant(),
            CLOCK.instant(),
            null,
            null,
            null,
            List.of("asg-000000000000000000000000"));
    store.writeBundle(approvedWithMissingGrant);

    assertEquals(
        "revalidation-required", coordinator.listBundles(HOST_OPERATOR).getFirst().get("status"));
  }

  @Test
  void approveBundle_whenRejected_expectNoActiveGrantCreated() throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(store, installedProvider(), installedConsumer());
    String bundleId =
        coordinator
            .requestBundle(SOCIAL_INBOX, Map.of("bundleAlias", List.of("trust-annotations")))
            .get("bundleId")
            .toString();

    Map<String, Object> rejected = coordinator.rejectBundle(HOST_OPERATOR, bundleId);

    assertEquals("rejected", rejected.get("status"));
    assertTrue(store.listGrants().isEmpty());
  }

  @Test
  void approveBundle_whenLaterDependencyUnavailable_expectNoPartialGrantActivation()
      throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(store, installedProvider(), installedConsumerWithMixedBundle());
    String bundleId =
        coordinator
            .requestBundle(SOCIAL_INBOX, Map.of("bundleAlias", List.of("combined-review")))
            .get("bundleId")
            .toString();

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> coordinator.approveBundle(HOST_OPERATOR, bundleId));

    assertEquals("app_service_dependency_unavailable", exception.errorCode());
    assertTrue(store.listGrants().isEmpty());
    assertEquals("pending", coordinator.listBundles(HOST_OPERATOR).getFirst().get("status"));
  }

  @Test
  void approveBundle_whenBundleCommitFails_expectNoGrantActivated() throws Exception {
    FailingWriteGrantStore store = new FailingWriteGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(store, installedProvider(), installedConsumer());
    String bundleId =
        coordinator
            .requestBundle(SOCIAL_INBOX, Map.of("bundleAlias", List.of("trust-annotations")))
            .get("bundleId")
            .toString();
    store.failBundleWrites();

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> coordinator.approveBundle(HOST_OPERATOR, bundleId));

    assertEquals("app_services_unavailable", exception.errorCode());
    assertTrue(store.listGrants().isEmpty());
    assertEquals("pending", coordinator.listBundles(HOST_OPERATOR).getFirst().get("status"));
  }

  @Test
  void approveBundle_whenGrantWriteFailsAfterPartialPersist_expectRollbackRemovesActiveGrant()
      throws Exception {
    FailingWriteGrantStore store = new FailingWriteGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(store, installedProvider(), installedConsumerWithTwoCompatibleDependencies());
    String bundleId =
        coordinator
            .requestBundle(SOCIAL_INBOX, Map.of("bundleAlias", List.of("combined-review")))
            .get("bundleId")
            .toString();
    store.failNextGrantWriteAfterFirstSuccess();

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> coordinator.approveBundle(HOST_OPERATOR, bundleId));

    assertEquals("app_services_unavailable", exception.errorCode());
    assertTrue(
        store.listGrants().stream()
            .noneMatch(grant -> grant.status() == AppServiceGrantStatus.ACTIVE));
    assertEquals("pending", coordinator.listBundles(HOST_OPERATOR).getFirst().get("status"));
  }

  @Test
  void invoke_whenProviderDescriptorDriftsAfterBundleApproval_expectRevalidationRequired()
      throws Exception {
    InMemoryAppServiceGrantStore store = new InMemoryAppServiceGrantStore();
    AppServiceCoordinator coordinator =
        coordinator(store, installedProvider(), installedConsumer());
    String bundleId =
        coordinator
            .requestBundle(SOCIAL_INBOX, Map.of("bundleAlias", List.of("trust-annotations")))
            .get("bundleId")
            .toString();
    coordinator.approveBundle(HOST_OPERATOR, bundleId);
    AppServiceCoordinator driftedCoordinator =
        coordinator(
            store,
            installedProvider("score.read", "message-author,profile,thread"),
            installedConsumer());

    Map<String, List<String>> driftedInvokeParams = invokeParams();
    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () ->
                driftedCoordinator.invoke(
                    SOCIAL_INBOX, "trust-graph", "trust.score", driftedInvokeParams));

    assertEquals("app_service_grant_required", exception.errorCode());
    assertEquals(
        "revalidation-required",
        driftedCoordinator.listGrants(HOST_OPERATOR).getFirst().get("status"));
  }

  private AppServiceCoordinator coordinator(
      AppServiceGrantStore store, InstalledAppSnapshot... installedApps) throws Exception {
    return coordinator(CLOCK, store, installedApps);
  }

  private AppServiceCoordinator coordinator(
      Clock clock, AppServiceGrantStore store, InstalledAppSnapshot... installedApps)
      throws Exception {
    AppHost appHost = mock(AppHost.class);
    when(appHost.listInstalled()).thenReturn(List.of(installedApps));
    return new AppServiceCoordinator(appHost, store, clock, List.of(fakeAdapter()));
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

  private InstalledAppSnapshot installedProfileProvider() throws Exception {
    return installedApp(
        "profile-graph",
        "Profile Graph Preview",
        List.of(),
        """
        app.services.provides=profile-score
        app.service.profile-score.id=profile.score
        app.service.profile-score.name=Profile Score Service
        app.service.profile-score.version=1
        app.service.profile-score.kind=platform-adapter
        app.service.profile-score.adapter=trust-graph.score
        app.service.profile-score.scopes=profile.read
        app.service.profile-score.contexts=message-author
        app.service.profile-score.description=Returns a redacted profile score summary.
        """);
  }

  private InstalledAppSnapshot installedProviderWithContexts(String contexts) throws Exception {
    return installedProvider("score.read", contexts);
  }

  private InstalledAppSnapshot installedProviderWithUnsupportedAdapter() throws Exception {
    return installedProvider("score.read", "message-author,profile", UNSUPPORTED_ADAPTER_ID);
  }

  private InstalledAppSnapshot installedProviderWithDisplayVersion() throws Exception {
    return installedProvider(
        "score.read",
        "message-author,profile",
        TrustGraphScoreAppServiceAdapter.ADAPTER_ID,
        DISPLAY_PROVIDER_VERSION);
  }

  private InstalledAppSnapshot installedProvider(String scopes, String contexts) throws Exception {
    return installedProvider(scopes, contexts, TrustGraphScoreAppServiceAdapter.ADAPTER_ID);
  }

  private InstalledAppSnapshot installedProvider(String scopes, String contexts, String adapter)
      throws Exception {
    return installedProvider(scopes, contexts, adapter, "1");
  }

  private InstalledAppSnapshot installedProvider(
      String scopes, String contexts, String adapter, String version) throws Exception {
    return installedApp(
        "trust-graph",
        "Trust Graph Preview",
        List.of(),
        """
        app.services.provides=trust-score
        app.service.trust-score.id=trust.score
        app.service.trust-score.name=Trust Score Service
        app.service.trust-score.version=%s
        app.service.trust-score.kind=platform-adapter
        app.service.trust-score.adapter=%s
        app.service.trust-score.scopes=%s
        app.service.trust-score.contexts=%s
        app.service.trust-score.description=Returns a redacted score summary.
        """
            .formatted(version, adapter, scopes, contexts));
  }

  private InstalledAppSnapshot installedConsumer() throws Exception {
    return installedConsumer("social-inbox");
  }

  private InstalledAppSnapshot installedConsumer(String appId) throws Exception {
    return installedConsumer(appId, "Annotate message authors.");
  }

  private InstalledAppSnapshot installedConsumerWithRevisedPurpose() throws Exception {
    return installedConsumer("social-inbox", REVISED_PURPOSE);
  }

  private InstalledAppSnapshot installedConsumer(String appId, String purpose) throws Exception {
    return installedConsumer(appId, purpose, "PT720H");
  }

  private InstalledAppSnapshot installedConsumerWithShortGrantExpiry() throws Exception {
    return installedConsumer(
        "social-inbox", "Annotate message authors.", SHORT_GRANT_EXPIRES_AFTER);
  }

  private InstalledAppSnapshot installedConsumer(
      String appId, String purpose, String grantExpiresAfter) throws Exception {
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
        app.service-request.trust-score.purpose=%s
        app.service-request.trust-score.dependency.kind=optional
        app.service-request.trust-score.dependency.required=false
        app.service-request.trust-score.dependency.featureId=trust-score-annotations
        app.service-request.trust-score.dependency.featureName=Trust score annotations
        app.service-request.trust-score.dependency.degradeBehavior=disable-feature
        app.service-request.trust-score.dependency.minServiceVersion=1
        app.service-request.trust-score.dependency.maxServiceVersion=1
        app.service-request.trust-score.dependency.grantBundle=trust-annotations
        app.service-request.trust-score.dependency.grantExpiresAfter=%s
        """
            .formatted(purpose, grantExpiresAfter));
  }

  private InstalledAppSnapshot installedConsumerWithDriftedTrustScoreAlias() throws Exception {
    return installedApp(
        "social-inbox",
        "Social Inbox Preview",
        List.of("app.services.read", "app.services.call"),
        """
        app.services.requests=trust-score
        app.service-request.trust-score.provider=profile-graph
        app.service-request.trust-score.service=profile.score
        app.service-request.trust-score.scopes=profile.read
        app.service-request.trust-score.contexts=message-author
        app.service-request.trust-score.purpose=Annotate message authors with profile scores.
        app.service-request.trust-score.dependency.kind=optional
        app.service-request.trust-score.dependency.required=false
        app.service-request.trust-score.dependency.featureId=profile-score-annotations
        app.service-request.trust-score.dependency.featureName=Profile score annotations
        app.service-request.trust-score.dependency.degradeBehavior=disable-feature
        app.service-request.trust-score.dependency.minServiceVersion=1
        app.service-request.trust-score.dependency.maxServiceVersion=1
        app.service-request.trust-score.dependency.grantBundle=trust-annotations
        app.service-request.trust-score.dependency.grantExpiresAfter=PT720H
        """);
  }

  private InstalledAppSnapshot installedConsumerWithMixedBundle() throws Exception {
    return installedApp(
        "social-inbox",
        "Social Inbox Preview",
        List.of("app.services.read", "app.services.call"),
        """
        app.services.requests=alpha-trust-score,beta-missing-profile
        app.service-request.alpha-trust-score.provider=trust-graph
        app.service-request.alpha-trust-score.service=trust.score
        app.service-request.alpha-trust-score.scopes=score.read
        app.service-request.alpha-trust-score.contexts=message-author
        app.service-request.alpha-trust-score.purpose=Annotate message authors.
        app.service-request.alpha-trust-score.dependency.kind=optional
        app.service-request.alpha-trust-score.dependency.required=false
        app.service-request.alpha-trust-score.dependency.featureId=trust-score-annotations
        app.service-request.alpha-trust-score.dependency.featureName=Trust score annotations
        app.service-request.alpha-trust-score.dependency.degradeBehavior=disable-feature
        app.service-request.alpha-trust-score.dependency.minServiceVersion=1
        app.service-request.alpha-trust-score.dependency.maxServiceVersion=1
        app.service-request.alpha-trust-score.dependency.grantBundle=combined-review
        app.service-request.beta-missing-profile.provider=profile-graph
        app.service-request.beta-missing-profile.service=profile.score
        app.service-request.beta-missing-profile.scopes=profile.read
        app.service-request.beta-missing-profile.contexts=message-author
        app.service-request.beta-missing-profile.purpose=Annotate profile authors.
        app.service-request.beta-missing-profile.dependency.kind=optional
        app.service-request.beta-missing-profile.dependency.required=false
        app.service-request.beta-missing-profile.dependency.featureId=profile-score-annotations
        app.service-request.beta-missing-profile.dependency.featureName=Profile score annotations
        app.service-request.beta-missing-profile.dependency.degradeBehavior=disable-feature
        app.service-request.beta-missing-profile.dependency.minServiceVersion=1
        app.service-request.beta-missing-profile.dependency.maxServiceVersion=1
        app.service-request.beta-missing-profile.dependency.grantBundle=combined-review
        """);
  }

  private InstalledAppSnapshot installedConsumerWithTwoCompatibleDependencies() throws Exception {
    return installedApp(
        "social-inbox",
        "Social Inbox Preview",
        List.of("app.services.read", "app.services.call"),
        """
        app.services.requests=alpha-trust-score,beta-trust-profile
        app.service-request.alpha-trust-score.provider=trust-graph
        app.service-request.alpha-trust-score.service=trust.score
        app.service-request.alpha-trust-score.scopes=score.read
        app.service-request.alpha-trust-score.contexts=message-author
        app.service-request.alpha-trust-score.purpose=Annotate message authors.
        app.service-request.alpha-trust-score.dependency.kind=optional
        app.service-request.alpha-trust-score.dependency.required=false
        app.service-request.alpha-trust-score.dependency.featureId=trust-score-annotations
        app.service-request.alpha-trust-score.dependency.featureName=Trust score annotations
        app.service-request.alpha-trust-score.dependency.degradeBehavior=disable-feature
        app.service-request.alpha-trust-score.dependency.minServiceVersion=1
        app.service-request.alpha-trust-score.dependency.maxServiceVersion=1
        app.service-request.alpha-trust-score.dependency.grantBundle=combined-review
        app.service-request.beta-trust-profile.provider=trust-graph
        app.service-request.beta-trust-profile.service=trust.score
        app.service-request.beta-trust-profile.scopes=score.read
        app.service-request.beta-trust-profile.contexts=profile
        app.service-request.beta-trust-profile.purpose=Annotate profile authors.
        app.service-request.beta-trust-profile.dependency.kind=optional
        app.service-request.beta-trust-profile.dependency.required=false
        app.service-request.beta-trust-profile.dependency.featureId=profile-score-annotations
        app.service-request.beta-trust-profile.dependency.featureName=Profile score annotations
        app.service-request.beta-trust-profile.dependency.degradeBehavior=disable-feature
        app.service-request.beta-trust-profile.dependency.minServiceVersion=1
        app.service-request.beta-trust-profile.dependency.maxServiceVersion=1
        app.service-request.beta-trust-profile.dependency.grantBundle=combined-review
        """);
  }

  private InstalledAppSnapshot installedConsumerWithDuplicateExpiryPolicies() throws Exception {
    return installedApp(
        "social-inbox",
        "Social Inbox Preview",
        List.of("app.services.read", "app.services.call"),
        """
        app.services.requests=alpha-trust-score,beta-trust-score
        app.service-request.alpha-trust-score.provider=trust-graph
        app.service-request.alpha-trust-score.service=trust.score
        app.service-request.alpha-trust-score.scopes=score.read
        app.service-request.alpha-trust-score.contexts=message-author
        app.service-request.alpha-trust-score.purpose=Annotate message authors.
        app.service-request.alpha-trust-score.dependency.kind=optional
        app.service-request.alpha-trust-score.dependency.required=false
        app.service-request.alpha-trust-score.dependency.featureId=trust-score-annotations
        app.service-request.alpha-trust-score.dependency.featureName=Trust score annotations
        app.service-request.alpha-trust-score.dependency.degradeBehavior=disable-feature
        app.service-request.alpha-trust-score.dependency.grantBundle=combined-review
        app.service-request.alpha-trust-score.dependency.grantExpiresAfter=PT720H
        app.service-request.beta-trust-score.provider=trust-graph
        app.service-request.beta-trust-score.service=trust.score
        app.service-request.beta-trust-score.scopes=score.read
        app.service-request.beta-trust-score.contexts=message-author
        app.service-request.beta-trust-score.purpose=Annotate message authors.
        app.service-request.beta-trust-score.dependency.kind=optional
        app.service-request.beta-trust-score.dependency.required=false
        app.service-request.beta-trust-score.dependency.featureId=trust-score-annotations-secondary
        app.service-request.beta-trust-score.dependency.featureName=Trust score annotations secondary
        app.service-request.beta-trust-score.dependency.degradeBehavior=disable-feature
        app.service-request.beta-trust-score.dependency.grantBundle=combined-review
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
    return activeGrant(grantId, consumerAppId, List.of("score.read"), List.of("message-author"));
  }

  private static AppServiceGrant activeGrant(
      String grantId, String consumerAppId, List<String> scopes, List<String> contexts) {
    return new AppServiceGrant(
        grantId,
        consumerAppId,
        "trust-graph",
        "trust.score",
        scopes,
        contexts,
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

  private static final class FailingWriteGrantStore implements AppServiceGrantStore {
    private final InMemoryAppServiceGrantStore delegate = new InMemoryAppServiceGrantStore();
    private boolean failWrites;
    private boolean failBundleWrites;
    private int grantWritesBeforeFailure = -1;

    @Override
    public List<AppServiceGrant> listGrants() {
      return delegate.listGrants();
    }

    @Override
    public Optional<AppServiceGrant> readGrant(String grantId) {
      return delegate.readGrant(grantId);
    }

    @Override
    public void writeGrant(AppServiceGrant grant) throws IOException {
      if (failWrites) {
        throw new IOException("grant writes disabled");
      }
      if (grantWritesBeforeFailure == 0) {
        grantWritesBeforeFailure = -1;
        throw new IOException("grant write failed once");
      }
      if (grantWritesBeforeFailure > 0) {
        grantWritesBeforeFailure--;
      }
      delegate.writeGrant(grant);
    }

    @Override
    public List<AppServiceGrantBundle> listBundles() {
      return delegate.listBundles();
    }

    @Override
    public Optional<AppServiceGrantBundle> readBundle(String bundleId) {
      return delegate.readBundle(bundleId);
    }

    @Override
    public void writeBundle(AppServiceGrantBundle bundle) throws IOException {
      if (failBundleWrites) {
        throw new IOException("bundle writes disabled");
      }
      delegate.writeBundle(bundle);
    }

    @Override
    public void appendAuditEvent(AppServiceAuditEvent event) {
      delegate.appendAuditEvent(event);
    }

    @Override
    public List<AppServiceAuditEvent> listAuditEvents(int limit) {
      return delegate.listAuditEvents(limit);
    }

    private void failWrites(boolean failWrites) {
      this.failWrites = failWrites;
    }

    private void failBundleWrites() {
      this.failBundleWrites = true;
    }

    private void failNextGrantWriteAfterFirstSuccess() {
      this.grantWritesBeforeFailure = 1;
    }
  }
}
