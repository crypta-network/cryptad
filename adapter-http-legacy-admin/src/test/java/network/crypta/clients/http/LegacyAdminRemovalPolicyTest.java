package network.crypta.clients.http;

import java.net.URI;
import java.util.Optional;
import java.util.stream.Stream;
import network.crypta.platform.webshell.routes.WebShellPaths;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class LegacyAdminRemovalPolicyTest {
  @Test
  void decide_whenWaveOneGetRequested_expectReplacementRedirect() {
    LegacyAdminRemovalDecision decision =
        LegacyAdminRemovalPolicy.decide("GET", URI.create(QueueToadlet.PATH_DOWNLOADS))
            .orElseThrow();

    assertEquals("queue-downloads", decision.surface().id());
    assertEquals(303, decision.statusCode());
    assertTrue(decision.redirect());
    assertEquals("/apps/queue-manager/", decision.replacementUrl());
    assertEquals(LegacyAdminUsageEvent.REPLACEMENT_RESPONSE, decision.usageEvent());
  }

  @Test
  void decide_whenWaveOneSlashlessHeadRequested_expectReplacementRedirectWithoutBodyPolicy() {
    LegacyAdminRemovalDecision decision =
        LegacyAdminRemovalPolicy.decide("HEAD", URI.create("/friends")).orElseThrow();

    assertEquals("friends", decision.surface().id());
    assertEquals(303, decision.statusCode());
    assertTrue(decision.redirect());
    assertEquals("/app/node/#peers", decision.replacementUrl());
  }

  @Test
  void decide_whenWaveOnePostRequested_expectBlockedMutation() {
    LegacyAdminRemovalDecision decision =
        LegacyAdminRemovalPolicy.decide("POST", URI.create("/addfriend/")).orElseThrow();

    assertEquals("add-friend", decision.surface().id());
    assertEquals(410, decision.statusCode());
    assertFalse(decision.redirect());
    assertEquals(LegacyAdminUsageEvent.BLOCKED_MUTATING_REQUEST, decision.usageEvent());
  }

  @Test
  void decide_whenRetainedLaterWavePrimaryReplacedRequested_expectNoDecision() {
    assertFalse(
        LegacyAdminRemovalPolicy.decide("GET", URI.create(SecurityLevelsToadlet.PATH)).isPresent());
    assertFalse(
        LegacyAdminRemovalPolicy.decide("GET", URI.create(DiagnosticToadlet.TOADLET_URL))
            .isPresent());
  }

  @Test
  void decide_whenWaveOneHelperSubpathRequested_expectNoDecision() {
    assertFalse(
        LegacyAdminRemovalPolicy.decide("GET", URI.create(QueueToadlet.PATH_DOWNLOADS + "finished"))
            .isPresent());
  }

  @Test
  void decide_whenWaveTwoAlertsGetRequested_expectWebShellRedirect() {
    LegacyAdminRemovalDecision decision =
        LegacyAdminRemovalPolicy.decide("GET", URI.create("/alerts/?token=secret")).orElseThrow();

    assertEquals("alerts", decision.surface().id());
    assertEquals(303, decision.statusCode());
    assertTrue(decision.redirect());
    assertEquals("/app/node/#alerts", decision.replacementUrl());
  }

  @Test
  void decide_whenWaveTwoAlertsPostRequested_expectLegacyFallbackForBulkActions() {
    assertFalse(LegacyAdminRemovalPolicy.decide("POST", URI.create("/alerts/")).isPresent());
  }

  @Test
  void decide_whenWaveTwoConfigFamilyGetRequested_expectReplacementRedirect() {
    LegacyAdminRemovalDecision decision =
        LegacyAdminRemovalPolicy.decide(
                "GET", URI.create(LegacyHttpPaths.CONFIG_PATH + "node?x=secret"))
            .orElseThrow();

    assertEquals("config", decision.surface().id());
    assertEquals(303, decision.statusCode());
    assertTrue(decision.redirect());
    assertEquals("/app/node/#config", decision.replacementUrl());
  }

  @Test
  void decide_whenWaveTwoConfigFamilyPostRequested_expectBlockedMutation() {
    LegacyAdminRemovalDecision decision =
        LegacyAdminRemovalPolicy.decide("POST", URI.create(LegacyHttpPaths.CONFIG_PATH + "node"))
            .orElseThrow();

    assertEquals("config", decision.surface().id());
    assertEquals(410, decision.statusCode());
    assertFalse(decision.redirect());
    assertEquals(LegacyAdminUsageEvent.BLOCKED_MUTATING_REQUEST, decision.usageEvent());
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("waveTwoUpdateAndDiagnosticsRouteCases")
  void decide_whenWaveTwoUpdateOrDiagnosticsRouteRequested_expectPolicyDecision(
      String name,
      String method,
      String path,
      String expectedSurfaceId,
      Integer expectedStatusCode,
      String expectedReplacementUrl) {
    Optional<LegacyAdminRemovalDecision> decision =
        LegacyAdminRemovalPolicy.decide(method, URI.create(path));

    if (expectedSurfaceId == null) {
      assertFalse(decision.isPresent());
      return;
    }
    LegacyAdminRemovalDecision actual = decision.orElseThrow();
    assertEquals(expectedSurfaceId, actual.surface().id());
    assertEquals(expectedStatusCode, actual.statusCode());
    assertTrue(actual.redirect());
    assertEquals(expectedReplacementUrl, actual.replacementUrl());
  }

  @Test
  void decide_whenQueueExplicitHelperRequested_expectReplacementRedirect() {
    LegacyAdminRemovalDecision decision =
        LegacyAdminRemovalPolicy.decide("GET", URI.create("/downloads/listKeys.txt")).orElseThrow();

    assertEquals("queue-downloads", decision.surface().id());
    assertEquals(303, decision.statusCode());
    assertEquals("/apps/queue-manager/", decision.replacementUrl());
  }

  @Test
  void decide_whenQueueExplicitHelperSiblingRequested_expectNoDecision() {
    assertFalse(
        LegacyAdminRemovalPolicy.decide("GET", URI.create("/downloads/listKeys.txt/extra"))
            .isPresent());
    assertFalse(
        LegacyAdminRemovalPolicy.decide("GET", URI.create("/downloads/countRequests.html.bak"))
            .isPresent());
  }

  @Test
  void isRemovedMutatingPath_whenPartialReplacementRequested_expectFalse() {
    assertFalse(LegacyAdminRemovalPolicy.isRemovedMutatingPath(URI.create("/alerts/")));
    assertFalse(LegacyAdminRemovalPolicy.isRemovedMutatingPath(URI.create("/core-update/")));
    assertFalse(LegacyAdminRemovalPolicy.isRemovedMutatingPath(URI.create("/stats/")));
  }

  @Test
  void isRemovedMutatingPath_whenCoveredMutationRequested_expectTrue() {
    assertTrue(LegacyAdminRemovalPolicy.isRemovedMutatingPath(URI.create("/downloads/")));
    assertTrue(
        LegacyAdminRemovalPolicy.isRemovedMutatingPath(URI.create("/downloads/listKeys.txt")));
    assertTrue(
        LegacyAdminRemovalPolicy.isRemovedMutatingPath(
            URI.create(LegacyHttpPaths.CONFIG_PATH + "node")));
  }

  @Test
  void decide_whenRetainedOrInfrastructureRoutesRequested_expectNoDecision() {
    assertFalse(LegacyAdminRemovalPolicy.decide("GET", URI.create("/filterfile/")).isPresent());
    assertFalse(LegacyAdminRemovalPolicy.decide("GET", URI.create("/wizard/")).isPresent());
    assertFalse(LegacyAdminRemovalPolicy.decide("GET", URI.create("/send_n2ntm/")).isPresent());
    assertFalse(LegacyAdminRemovalPolicy.decide("GET", URI.create("/translation/")).isPresent());
    assertFalse(LegacyAdminRemovalPolicy.decide("GET", URI.create("/help/")).isPresent());
    assertFalse(LegacyAdminRemovalPolicy.decide("GET", URI.create("/chat/")).isPresent());
    assertFalse(LegacyAdminRemovalPolicy.decide("GET", URI.create("/")).isPresent());
    assertFalse(LegacyAdminRemovalPolicy.decide("GET", URI.create("/CHK@abc")).isPresent());
    assertFalse(
        LegacyAdminRemovalPolicy.decide("GET", URI.create("/api/v1/diagnostics")).isPresent());
    assertFalse(LegacyAdminRemovalPolicy.decide("GET", URI.create("/app/node/")).isPresent());
    assertFalse(
        LegacyAdminRemovalPolicy.decide("GET", URI.create("/apps/queue-manager/")).isPresent());
  }

  @Test
  void decide_whenQueueReplacementUnavailable_expectNoRemovalDecision() {
    ToadletContainer container = availableReplacementContainer();
    when(container.isStaticAppUiAvailable("queue-manager")).thenReturn(false);
    ToadletContext ctx = requestContext(container, true);

    assertFalse(
        LegacyAdminRemovalPolicy.decide("GET", URI.create(QueueToadlet.PATH_DOWNLOADS), ctx)
            .isPresent());
  }

  @Test
  void decide_whenWaveTwoWebShellReplacementUnavailable_expectNoRemovalDecision() {
    ToadletContainer container = availableReplacementContainer();
    when(container.primaryUiRoot()).thenReturn("/");
    ToadletContext ctx = requestContext(container, true);

    assertFalse(LegacyAdminRemovalPolicy.decide("GET", URI.create("/alerts/"), ctx).isPresent());
    assertFalse(
        LegacyAdminRemovalPolicy.decide(
                "GET", URI.create(LegacyHttpPaths.CONFIG_PATH + "node"), ctx)
            .isPresent());
  }

  @Test
  void decide_whenPublisherReplacementAvailable_expectReplacementRedirect() {
    ToadletContainer container = availableReplacementContainer();
    ToadletContext ctx = requestContext(container, true);

    LegacyAdminRemovalDecision decision =
        LegacyAdminRemovalPolicy.decide("GET", URI.create(FileInsertWizardToadlet.PATH), ctx)
            .orElseThrow();

    assertEquals("file-insert", decision.surface().id());
    assertEquals("/apps/publisher/", decision.replacementUrl());
    assertTrue(decision.redirect());
  }

  @Test
  void decide_whenWebShellReplacementUnavailable_expectNoRemovalDecision() {
    ToadletContainer container = availableReplacementContainer();
    when(container.primaryUiRoot()).thenReturn("/");
    ToadletContext ctx = requestContext(container, true);

    assertFalse(
        LegacyAdminRemovalPolicy.decide("GET", URI.create(LegacyHttpPaths.FRIENDS_PATH), ctx)
            .isPresent());
  }

  @Test
  void decide_whenFullAccessDenied_expectNoRemovalDecision() {
    ToadletContainer container = availableReplacementContainer();
    ToadletContext ctx = requestContext(container, false);

    assertFalse(
        LegacyAdminRemovalPolicy.decide("GET", URI.create(LegacyHttpPaths.FRIENDS_PATH), ctx)
            .isPresent());
  }

  private static Stream<Arguments> waveTwoUpdateAndDiagnosticsRouteCases() {
    return Stream.of(
        Arguments.of(
            "core update safe read redirects",
            "GET",
            "/core-update/",
            "core-update",
            303,
            "/app/node/#updates"),
        Arguments.of(
            "core update post falls back for partial actions",
            "POST",
            "/core-update/",
            null,
            null,
            null),
        Arguments.of(
            "statistics child safe read redirects",
            "GET",
            "/stats/requesters.html",
            "statistics",
            303,
            "/app/node/#diagnostics"));
  }

  private static ToadletContainer availableReplacementContainer() {
    ToadletContainer container = mock(ToadletContainer.class);
    when(container.isFProxyJavascriptEnabled()).thenReturn(true);
    when(container.isStaticAppUiAvailable("queue-manager")).thenReturn(true);
    when(container.isStaticAppUiAvailable("publisher")).thenReturn(true);
    when(container.primaryUiRoot()).thenReturn(WebShellPaths.SHELL_ROOT);
    return container;
  }

  private static ToadletContext requestContext(ToadletContainer container, boolean fullAccess) {
    ToadletContext ctx = mock(ToadletContext.class);
    when(ctx.getContainer()).thenReturn(container);
    when(ctx.isAllowedFullAccess()).thenReturn(fullAccess);
    return ctx;
  }
}
