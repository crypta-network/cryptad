package network.crypta.clients.http;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import network.crypta.runtime.spi.LegacyAdminSurfaceUsage;
import network.crypta.runtime.spi.LegacyAdminUsageSnapshot;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S100")
class LegacyAdminUsageRecorderTest {
  @Test
  void recordPath_whenKnownSurfaceVisited_expectCountAndTimestampInSnapshot() {
    LegacyAdminUsageRecorder recorder =
        new LegacyAdminUsageRecorder(
            Clock.fixed(Instant.ofEpochMilli(1_770_000_000_000L), ZoneOffset.UTC));

    recorder.recordPath(QueueToadlet.PATH_DOWNLOADS);
    recorder.recordPath(QueueToadlet.PATH_DOWNLOADS + "finished");

    LegacyAdminSurfaceUsage usage = usage(recorder.snapshot(), "queue-downloads");
    assertEquals(2L, usage.count());
    assertEquals(0L, usage.replacementResponseCount());
    assertEquals(0L, usage.blockedMutatingRequestCount());
    assertEquals(2L, usage.fallbackRenderCount());
    assertEquals(0L, usage.retainedOrPendingRenderCount());
    assertEquals(1_770_000_000_000L, usage.lastSeenEpochMillis());
    assertEquals(LegacyAdminRetirementState.PRIMARY_REPLACED.name(), usage.state());
    assertEquals("/apps/queue-manager/", usage.replacementUrl());
    assertEquals(LegacyAdminRemovalMode.REDIRECT_TO_REPLACEMENT.name(), usage.removalMode());
    assertEquals(1, usage.removalWave());
    assertEquals("phase-6-pr-8", usage.removedByDefaultSince());
    assertEquals("none", usage.fallbackPolicy());
    assertEquals(LegacyAdminRemovalScope.EXPLICIT_CHILDREN.name(), usage.removalScope());
    assertEquals(2, usage.scopeExpandedInWave());
  }

  @Test
  void snapshot_whenWaveTwoSurfaceIncluded_expectWaveTwoMetadataAndScope() {
    LegacyAdminUsageRecorder recorder =
        new LegacyAdminUsageRecorder(
            Clock.fixed(Instant.ofEpochMilli(1_770_000_000_000L), ZoneOffset.UTC));

    recorder.recordPath(LegacyHttpPaths.CONFIG_PATH + "node");

    LegacyAdminSurfaceUsage usage = usage(recorder.snapshot(), "config");
    assertEquals(1L, usage.count());
    assertEquals(LegacyAdminRemovalMode.REDIRECT_TO_REPLACEMENT.name(), usage.removalMode());
    assertEquals(2, usage.removalWave());
    assertEquals("phase-7-pr-230", usage.removedByDefaultSince());
    assertEquals("none", usage.fallbackPolicy());
    assertEquals(LegacyAdminRemovalScope.PREFIX_FAMILY.name(), usage.removalScope());
    assertEquals(2, usage.scopeExpandedInWave());
  }

  @Test
  void recordSurface_whenRemovalEventsRecorded_expectSeparateCounters() {
    LegacyAdminUsageRecorder recorder =
        new LegacyAdminUsageRecorder(
            Clock.fixed(Instant.ofEpochMilli(1_770_000_000_000L), ZoneOffset.UTC));
    LegacyAdminSurface downloads = LegacyAdminRetirementRegistry.require("queue-downloads");

    recorder.recordSurface(downloads, LegacyAdminUsageEvent.REPLACEMENT_RESPONSE);
    recorder.recordSurface(downloads, LegacyAdminUsageEvent.BLOCKED_MUTATING_REQUEST);

    LegacyAdminSurfaceUsage usage = usage(recorder.snapshot(), "queue-downloads");
    assertEquals(0L, usage.count());
    assertEquals(1L, usage.replacementResponseCount());
    assertEquals(1L, usage.blockedMutatingRequestCount());
    assertEquals(0L, usage.fallbackRenderCount());
    assertEquals(0L, usage.retainedOrPendingRenderCount());
    assertEquals(1_770_000_000_000L, usage.lastSeenEpochMillis());
  }

  @Test
  void recordSurface_whenRetainedRendered_expectRetainedOrPendingCounter() {
    LegacyAdminUsageRecorder recorder =
        new LegacyAdminUsageRecorder(
            Clock.fixed(Instant.ofEpochMilli(1_770_000_000_000L), ZoneOffset.UTC));

    recorder.recordSurface(LegacyAdminRetirementRegistry.require("help"));

    LegacyAdminSurfaceUsage usage = usage(recorder.snapshot(), "help");
    assertEquals(1L, usage.count());
    assertEquals(0L, usage.replacementResponseCount());
    assertEquals(0L, usage.blockedMutatingRequestCount());
    assertEquals(0L, usage.fallbackRenderCount());
    assertEquals(1L, usage.retainedOrPendingRenderCount());
  }

  @Test
  void recordPath_whenInfrastructureOrUnknownVisited_expectNoDiagnosticCount() {
    LegacyAdminUsageRecorder recorder =
        new LegacyAdminUsageRecorder(
            Clock.fixed(Instant.ofEpochMilli(1_770_000_000_000L), ZoneOffset.UTC));

    recorder.recordPath(PlatformApiToadlet.MOUNT_PATH + "diagnostics");
    recorder.recordPath("/not-a-legacy-admin-page/");

    LegacyAdminSurfaceUsage diagnostic = usage(recorder.snapshot(), "diagnostic");
    assertEquals(0L, diagnostic.count());
    assertEquals(0L, diagnostic.replacementResponseCount());
    assertEquals(0L, diagnostic.blockedMutatingRequestCount());
    assertEquals(0L, diagnostic.fallbackRenderCount());
    assertEquals(0L, diagnostic.retainedOrPendingRenderCount());
    assertEquals(0L, diagnostic.lastSeenEpochMillis());
  }

  private static LegacyAdminSurfaceUsage usage(
      LegacyAdminUsageSnapshot snapshot, String surfaceId) {
    return snapshot.surfaces().stream()
        .filter(surface -> surface.surfaceId().equals(surfaceId))
        .findFirst()
        .orElseThrow();
  }
}
