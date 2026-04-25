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
    assertEquals(1_770_000_000_000L, usage.lastSeenEpochMillis());
    assertEquals(LegacyAdminRetirementState.PRIMARY_REPLACED.name(), usage.state());
    assertEquals("/apps/queue-manager/", usage.replacementUrl());
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
