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
    assertEquals(LegacyAdminRemovalMode.REDIRECT_TO_REPLACEMENT, surface.removalMode());
    assertEquals(1, surface.removalWave());
    assertEquals("phase-6-pr-8", surface.removedByDefaultSince());
    assertEquals("none", surface.fallbackPolicy());
    assertEquals(LegacyAdminRemovalScope.EXPLICIT_CHILDREN, surface.removalScope());
    assertEquals(2, surface.scopeExpandedInWave());
    assertEquals(
        List.of(
            QueueToadlet.PATH_DOWNLOADS + "countRequests.html",
            QueueToadlet.PATH_DOWNLOADS + "listKeys.txt"),
        surface.explicitRemovalChildPaths());
    assertTrue(surface.includeInUsageDiagnostics());
    assertFalse(surface.includeInWebShellFallbackLinks());
  }

  @Test
  void removalWaveSurfaces_whenWaveOneRequested_expectFirstRemovalSetOnly() {
    List<String> waveOneIds =
        LegacyAdminRetirementRegistry.removalWaveSurfaces(1).stream()
            .map(LegacyAdminSurface::id)
            .toList();

    assertEquals(
        List.of(
            "queue-downloads",
            "queue-uploads",
            "file-insert",
            "local-file-insert",
            "friends",
            "add-friend",
            "strangers",
            "connectivity"),
        waveOneIds);
    assertFalse(waveOneIds.contains("alerts"));
    assertFalse(waveOneIds.contains("config"));
    assertFalse(waveOneIds.contains("security-levels"));
    assertFalse(waveOneIds.contains("first-time-wizard"));
    assertFalse(waveOneIds.contains("content-filter"));
  }

  @Test
  void removalWaveSurfaces_whenWaveTwoRequested_expectSecondRemovalSetOnly() {
    List<String> waveTwoIds =
        LegacyAdminRetirementRegistry.removalWaveSurfaces(2).stream()
            .map(LegacyAdminSurface::id)
            .toList();

    assertEquals(List.of("alerts", "config", "core-update", "statistics"), waveTwoIds);
    assertFalse(waveTwoIds.contains("queue-downloads"));
    assertFalse(waveTwoIds.contains("queue-uploads"));
    assertFalse(waveTwoIds.contains("security-levels"));
    assertFalse(waveTwoIds.contains("diagnostic"));
  }

  @Test
  void scopeExpandedInWaveSurfaces_whenWaveTwoRequested_expectExpandedScopeSurfaces() {
    List<String> expandedIds =
        LegacyAdminRetirementRegistry.scopeExpandedInWaveSurfaces(2).stream()
            .map(LegacyAdminSurface::id)
            .toList();

    assertEquals(List.of("queue-downloads", "queue-uploads", "config", "statistics"), expandedIds);
  }

  @Test
  void findByLegacyPath_whenConfigSubpageRequested_expectConfigSurface() {
    LegacyAdminSurface surface =
        LegacyAdminRetirementRegistry.findByLegacyPath(LegacyHttpPaths.CONFIG_PATH + "node")
            .orElseThrow();

    assertEquals("config", surface.id());
    assertEquals(LegacyAdminRetirementState.PRIMARY_REPLACED, surface.state());
    assertEquals(LegacyAdminRemovalMode.REDIRECT_TO_REPLACEMENT, surface.removalMode());
    assertEquals(2, surface.removalWave());
    assertEquals("phase-7-pr-230", surface.removedByDefaultSince());
    assertEquals(LegacyAdminRemovalScope.PREFIX_FAMILY, surface.removalScope());
    assertEquals(WebShellPaths.SHELL_ROOT + "#config", surface.replacementUrl());
  }

  @Test
  void require_whenDiagnosticRequested_expectPlainTextExportRetainedAsLegacyFallback() {
    LegacyAdminSurface surface = LegacyAdminRetirementRegistry.require("diagnostic");

    assertEquals(LegacyAdminRetirementState.PRIMARY_REPLACED, surface.state());
    assertEquals(LegacyAdminRemovalMode.RENDER_LEGACY, surface.removalMode());
    assertEquals(0, surface.removalWave());
    assertEquals(WebShellPaths.SHELL_ROOT + "#diagnostics", surface.replacementUrl());
  }

  @Test
  void findByLegacyPath_whenPlatformApiRequested_expectInfrastructureSurface() {
    LegacyAdminSurface surface =
        LegacyAdminRetirementRegistry.findByLegacyPath(
                PlatformApiToadlet.MOUNT_PATH + "diagnostics")
            .orElseThrow();

    assertEquals("platform-api", surface.id());
    assertEquals(LegacyAdminRetirementState.INFRASTRUCTURE, surface.state());
    assertEquals(LegacyAdminRemovalMode.INFRASTRUCTURE, surface.removalMode());
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
