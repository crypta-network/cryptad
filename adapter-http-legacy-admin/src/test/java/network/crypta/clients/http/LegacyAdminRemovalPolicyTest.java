package network.crypta.clients.http;

import java.net.URI;
import network.crypta.platform.webshell.routes.WebShellPaths;
import org.junit.jupiter.api.Test;

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
  void decide_whenLaterWavePrimaryReplacedRequested_expectNoDecision() {
    assertFalse(LegacyAdminRemovalPolicy.decide("GET", URI.create("/alerts/")).isPresent());
    assertFalse(
        LegacyAdminRemovalPolicy.decide("GET", URI.create(LegacyHttpPaths.CONFIG_PATH + "node"))
            .isPresent());
  }

  @Test
  void decide_whenWaveOneHelperSubpathRequested_expectNoDecision() {
    assertFalse(
        LegacyAdminRemovalPolicy.decide("GET", URI.create(QueueToadlet.PATH_DOWNLOADS + "finished"))
            .isPresent());
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
