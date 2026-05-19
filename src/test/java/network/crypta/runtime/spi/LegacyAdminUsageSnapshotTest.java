package network.crypta.runtime.spi;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class LegacyAdminUsageSnapshotTest {
  @Test
  void constructor_whenSourceListMutatedAfterCreation_expectDefensiveCopy() {
    LegacyAdminSurfaceUsage usage = usage("queue-downloads", 1L, 1_770_000_000_000L);
    ArrayList<LegacyAdminSurfaceUsage> source = new ArrayList<>();
    source.add(usage);

    LegacyAdminUsageSnapshot snapshot = new LegacyAdminUsageSnapshot(source);

    source.clear();

    assertEquals(List.of(usage), snapshot.surfaces());
  }

  @Test
  void surfaces_whenSnapshotExposed_expectUnmodifiableList() {
    LegacyAdminUsageSnapshot snapshot =
        new LegacyAdminUsageSnapshot(List.of(usage("queue-downloads", 1L, 1L)));
    List<LegacyAdminSurfaceUsage> surfaces = snapshot.surfaces();
    LegacyAdminSurfaceUsage usageToAdd = usage("statistics", 2L, 2L);

    assertThrows(UnsupportedOperationException.class, () -> surfaces.add(usageToAdd));
  }

  @Test
  void surfaceUsageConstructor_whenCountNegative_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class, () -> usage("queue-downloads", -1L, 1_770_000_000_000L));
  }

  @Test
  void surfaceUsageConstructor_whenTimestampNegative_expectIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> usage("queue-downloads", 1L, -1L));
  }

  @Test
  void surfaceUsageConstructor_whenRemovalWaveNegative_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new LegacyAdminSurfaceUsage(
                "queue-downloads",
                "Download queue",
                "/downloads/",
                "PRIMARY_REPLACED",
                "/apps/queue-manager/",
                "REDIRECT_TO_REPLACEMENT",
                -1,
                "phase-6-pr-8",
                "none",
                "CANONICAL_AND_SLASHLESS_ALIAS",
                0,
                0L,
                0L,
                0L,
                0L,
                0L,
                0L));
  }

  @Test
  void surfaceUsageConstructor_whenRemovalScopeBlank_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new LegacyAdminSurfaceUsage(
                "queue-downloads",
                "Download queue",
                "/downloads/",
                "PRIMARY_REPLACED",
                "/apps/queue-manager/",
                "REDIRECT_TO_REPLACEMENT",
                1,
                "phase-6-pr-8",
                "none",
                " ",
                0,
                0L,
                0L,
                0L,
                0L,
                0L,
                0L));
  }

  @Test
  void surfaceUsageConstructor_whenScopeExpandedInWaveNegative_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new LegacyAdminSurfaceUsage(
                "queue-downloads",
                "Download queue",
                "/downloads/",
                "PRIMARY_REPLACED",
                "/apps/queue-manager/",
                "REDIRECT_TO_REPLACEMENT",
                1,
                "phase-6-pr-8",
                "none",
                "CANONICAL_AND_SLASHLESS_ALIAS",
                -1,
                0L,
                0L,
                0L,
                0L,
                0L,
                0L));
  }

  @Test
  void surfaceUsageConstructor_whenEventCounterNegative_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new LegacyAdminSurfaceUsage(
                "queue-downloads",
                "Download queue",
                "/downloads/",
                "PRIMARY_REPLACED",
                "/apps/queue-manager/",
                "REDIRECT_TO_REPLACEMENT",
                1,
                "phase-6-pr-8",
                "none",
                "CANONICAL_AND_SLASHLESS_ALIAS",
                0,
                0L,
                -1L,
                0L,
                0L,
                0L,
                0L));
  }

  @Test
  void surfaceUsageConstructor_whenReplacementUrlNull_expectAccepted() {
    LegacyAdminSurfaceUsage usage =
        new LegacyAdminSurfaceUsage(
            "help",
            "Help",
            "/help/",
            "RETAINED",
            null,
            "RETAINED",
            0,
            null,
            "retained",
            "CANONICAL_AND_SLASHLESS_ALIAS",
            0,
            0L,
            0L,
            0L,
            0L,
            0L,
            0L);

    assertEquals("help", usage.surfaceId());
    assertNull(usage.replacementUrl());
  }

  private static LegacyAdminSurfaceUsage usage(
      String surfaceId, long count, long lastSeenEpochMillis) {
    return new LegacyAdminSurfaceUsage(
        surfaceId,
        "Download queue",
        "/downloads/",
        "PRIMARY_REPLACED",
        "/apps/queue-manager/",
        "REDIRECT_TO_REPLACEMENT",
        1,
        "phase-6-pr-8",
        "none",
        "CANONICAL_AND_SLASHLESS_ALIAS",
        0,
        count,
        0L,
        0L,
        0L,
        0L,
        lastSeenEpochMillis);
  }
}
