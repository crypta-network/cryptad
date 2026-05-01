package network.crypta.clients.http;

import java.util.List;
import network.crypta.platform.appui.AppUiPaths;
import network.crypta.platform.webshell.routes.WebShellPaths;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class LegacyAdminRetirementRegistryTest {
  @Test
  void require_whenQueueDownloadsRequested_expectPrimaryReplacementToQueueManager() {
    LegacyAdminSurface surface = LegacyAdminRetirementRegistry.require("queue-downloads");

    assertEquals(LegacyAdminRetirementState.PRIMARY_REPLACED, surface.state());
    assertEquals(QueueToadlet.PATH_DOWNLOADS, surface.legacyPath());
    assertEquals(AppUiPaths.APPS_ROOT + "queue-manager/", surface.replacementUrl());
    assertTrue(surface.includeInUsageDiagnostics());
    assertFalse(surface.includeInWebShellFallbackLinks());
  }

  @Test
  void findByLegacyPath_whenConfigSubpageRequested_expectConfigSurface() {
    LegacyAdminSurface surface =
        LegacyAdminRetirementRegistry.findByLegacyPath(LegacyHttpPaths.CONFIG_PATH + "node")
            .orElseThrow();

    assertEquals("config", surface.id());
    assertEquals(LegacyAdminRetirementState.PRIMARY_REPLACED, surface.state());
    assertEquals(WebShellPaths.SHELL_ROOT + "#config", surface.replacementUrl());
  }

  @Test
  void findByLegacyPath_whenPlatformApiRequested_expectInfrastructureSurface() {
    LegacyAdminSurface surface =
        LegacyAdminRetirementRegistry.findByLegacyPath(
                PlatformApiToadlet.MOUNT_PATH + "diagnostics")
            .orElseThrow();

    assertEquals("platform-api", surface.id());
    assertEquals(LegacyAdminRetirementState.INFRASTRUCTURE, surface.state());
    assertFalse(surface.includeInUsageDiagnostics());
  }

  @Test
  void webShellFallbackSurfaces_whenRequested_expectOnlyRetainedOrPendingLinks() {
    List<String> fallbackIds =
        LegacyAdminRetirementRegistry.webShellFallbackSurfaces().stream()
            .map(LegacyAdminSurface::id)
            .toList();

    assertEquals(
        List.of("node-to-node-message", "chat", "translation", "help", "content-filter"),
        fallbackIds);
    assertFalse(fallbackIds.contains("queue-downloads"));
    assertFalse(fallbackIds.contains("friends"));
    assertFalse(fallbackIds.contains("alerts"));
  }

  @Test
  void shouldPromoteInLegacyNavigation_whenRequested_expectPrimaryReplacedHiddenOnly() {
    assertFalse(LegacyAdminRetirementRegistry.shouldPromoteInLegacyNavigation("/alerts/"));
    assertFalse(
        LegacyAdminRetirementRegistry.shouldPromoteInLegacyNavigation(
            LegacyHttpPaths.CONFIG_PATH + "node"));
    assertFalse(
        LegacyAdminRetirementRegistry.shouldPromoteInLegacyNavigation(QueueToadlet.PATH_DOWNLOADS));

    assertTrue(LegacyAdminRetirementRegistry.shouldPromoteInLegacyNavigation("/chat/"));
    assertTrue(LegacyAdminRetirementRegistry.shouldPromoteInLegacyNavigation("/send_n2ntm/"));
    assertTrue(LegacyAdminRetirementRegistry.shouldPromoteInLegacyNavigation("/not-in-map/"));
  }
}
