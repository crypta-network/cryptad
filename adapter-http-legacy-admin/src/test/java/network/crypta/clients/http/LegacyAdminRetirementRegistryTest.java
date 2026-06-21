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
  void removalWaveSurfaces_whenWaveThreeRequested_expectSecurityLevelsOnly() {
    List<String> waveThreeIds =
        LegacyAdminRetirementRegistry.removalWaveSurfaces(3).stream()
            .map(LegacyAdminSurface::id)
            .toList();

    assertEquals(List.of("security-levels"), waveThreeIds);
    assertFalse(waveThreeIds.contains("queue-downloads"));
    assertFalse(waveThreeIds.contains("alerts"));
    assertFalse(waveThreeIds.contains("diagnostic"));
    assertFalse(waveThreeIds.contains("content-filter"));
  }

  @Test
  void removalWaveSurfaces_whenWaveFourRequested_expectDiagnosticOnly() {
    List<String> waveFourIds =
        LegacyAdminRetirementRegistry.removalWaveSurfaces(4).stream()
            .map(LegacyAdminSurface::id)
            .toList();

    assertEquals(List.of("diagnostic"), waveFourIds);
    assertFalse(waveFourIds.contains("queue-downloads"));
    assertFalse(waveFourIds.contains("alerts"));
    assertFalse(waveFourIds.contains("security-levels"));
    assertFalse(waveFourIds.contains("content-filter"));
    assertFalse(waveFourIds.contains("first-time-wizard"));
    assertFalse(waveFourIds.contains("node-to-node-message"));
  }

  @Test
  void removalWaveSurfaces_whenWaveFiveRequested_expectNoUnprovenRoutePromotions() {
    List<String> waveFiveIds =
        LegacyAdminRetirementRegistry.removalWaveSurfaces(
                LegacyAdminRetirementRegistry.REMOVAL_WAVE_5)
            .stream()
            .map(LegacyAdminSurface::id)
            .toList();

    assertEquals(List.of(), waveFiveIds);
  }

  @Test
  void finalSurfacePolicy_whenRequested_expectWaveFiveMetadataAndNoPromotedRoutes() {
    LegacyAdminRetirementRegistry.FinalSurfacePolicy policy =
        LegacyAdminRetirementRegistry.finalSurfacePolicy();

    assertEquals("legacy-admin.final-admin-surface", policy.evidenceId());
    assertEquals(LegacyAdminRetirementRegistry.REMOVAL_WAVE_5, policy.readinessWave());
    assertEquals(LegacyAdminRetirementRegistry.REMOVED_BY_DEFAULT_SINCE_WAVE_5, policy.since());
    assertTrue(policy.waveFivePromotedEntries().isEmpty());
  }

  @Test
  void finalSurfacePolicy_whenRemovedAdminRequested_expectAllRemovalWavesRepresented() {
    List<String> removedIds =
        finalSurfaceIdsIn(
            LegacyAdminRetirementRegistry.FinalSurfaceCategory.REMOVED_BY_DEFAULT_ADMIN);

    assertEquals(
        List.of(
            "queue-downloads",
            "queue-uploads",
            "file-insert",
            "local-file-insert",
            "friends",
            "add-friend",
            "strangers",
            "connectivity",
            "alerts",
            "config",
            "security-levels",
            "core-update",
            "statistics",
            "diagnostic"),
        removedIds);
  }

  @Test
  void finalSurfacePolicy_whenRetainedBrowseRequested_expectBrowseAndFilterExplicit() {
    assertEquals(
        List.of("chat", "fproxy-browse-root", "fproxy-key-content-rendering"),
        finalSurfaceIdsIn(
            LegacyAdminRetirementRegistry.FinalSurfaceCategory.RETAINED_BROWSE_SURFACE));
    assertEquals(
        List.of("content-filter"),
        finalSurfaceIdsIn(
            LegacyAdminRetirementRegistry.FinalSurfaceCategory.RETAINED_BROWSE_SAFETY));
  }

  @Test
  void finalSurfacePolicy_whenFallbacksRequested_expectRecoveryAndSupportExplicit() {
    assertEquals(
        List.of("diagnostic"),
        finalSurfaceIdsIn(
            LegacyAdminRetirementRegistry.FinalSurfaceCategory.SUPPORT_EMERGENCY_FALLBACK));
    assertEquals(
        List.of("security-levels", "first-time-wizard", "first-time-wizard-js"),
        finalSurfaceIdsIn(
            LegacyAdminRetirementRegistry.FinalSurfaceCategory.STARTUP_RECOVERY_FALLBACK));
    assertEquals(
        List.of(
            "alerts",
            "core-update",
            "first-time-wizard",
            "first-time-wizard-js",
            "node-to-node-message"),
        finalSurfaceIdsIn(
            LegacyAdminRetirementRegistry.FinalSurfaceCategory.PENDING_MIGRATION_GAP));
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
  void findByLegacyPath_whenAppUiChildRequested_expectLongestSpecificInfrastructureSurface() {
    LegacyAdminSurface surface =
        LegacyAdminRetirementRegistry.findByLegacyPath("/apps/queue-manager/static/main.js")
            .orElseThrow();

    assertEquals("app-ui", surface.id());
    assertEquals(LegacyAdminRetirementState.INFRASTRUCTURE, surface.state());
  }

  @Test
  void require_whenSecurityLevelsRequested_expectWaveThreeSafeReadRedirectWithMutationFallback() {
    LegacyAdminSurface surface = LegacyAdminRetirementRegistry.require("security-levels");

    assertEquals(LegacyAdminRetirementState.PRIMARY_REPLACED, surface.state());
    assertEquals(LegacyAdminRemovalMode.REDIRECT_TO_REPLACEMENT, surface.removalMode());
    assertEquals(3, surface.removalWave());
    assertEquals("phase-8-pr-244", surface.removedByDefaultSince());
    assertEquals("mutating-legacy-fallback", surface.fallbackPolicy());
    assertEquals(LegacyAdminRemovalScope.CANONICAL_AND_SLASHLESS_ALIAS, surface.removalScope());
    assertEquals(0, surface.scopeExpandedInWave());
    assertEquals(List.of(), surface.explicitRemovalChildPaths());
    assertFalse(surface.blockMutatingRequests());
    assertEquals(SecurityLevelsToadlet.PATH, surface.legacyPath());
    assertEquals(WebShellPaths.SHELL_ROOT + "#security", surface.replacementUrl());
  }

  @Test
  void require_whenDiagnosticRequested_expectWaveFourRedirectWithExplicitFallback() {
    LegacyAdminSurface surface = LegacyAdminRetirementRegistry.require("diagnostic");

    assertEquals(LegacyAdminRetirementState.PRIMARY_REPLACED, surface.state());
    assertEquals(LegacyAdminRemovalMode.REDIRECT_TO_REPLACEMENT, surface.removalMode());
    assertEquals(4, surface.removalWave());
    assertEquals("phase-9-pr-254", surface.removedByDefaultSince());
    assertEquals("support-emergency-fallback", surface.fallbackPolicy());
    assertEquals(LegacyAdminRemovalScope.CANONICAL_AND_SLASHLESS_ALIAS, surface.removalScope());
    assertEquals(0, surface.scopeExpandedInWave());
    assertEquals(List.of(), surface.explicitRemovalChildPaths());
    assertTrue(surface.blockMutatingRequests());
    assertEquals(DiagnosticToadlet.TOADLET_URL, surface.legacyPath());
    assertEquals(WebShellPaths.SHELL_ROOT + "#diagnostics", surface.replacementUrl());
  }

  @Test
  void require_whenRetainedOrPendingSurfacesRequested_expectNotRemovedByDefault() {
    for (String id :
        List.of(
            "content-filter",
            "chat",
            "translation",
            "help",
            "first-time-wizard",
            "first-time-wizard-js")) {
      LegacyAdminSurface surface = LegacyAdminRetirementRegistry.require(id);

      assertEquals(0, surface.removalWave(), id);
      assertTrue(
          surface.state() == LegacyAdminRetirementState.RETAINED
              || surface.state() == LegacyAdminRetirementState.PENDING,
          id);
    }
  }

  @Test
  void findByLegacyPath_whenFProxyBrowseRouteRequested_expectNoRetirementSurface() {
    assertFalse(LegacyAdminRetirementRegistry.findByLegacyPath("/").isPresent());
    assertFalse(LegacyAdminRetirementRegistry.findByLegacyPath("/CHK@abc").isPresent());
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

  private static List<String> finalSurfaceIdsIn(
      LegacyAdminRetirementRegistry.FinalSurfaceCategory category) {
    return LegacyAdminRetirementRegistry.finalSurfacePolicy().entriesInCategory(category).stream()
        .map(LegacyAdminRetirementRegistry.FinalSurfaceEntry::id)
        .toList();
  }
}
