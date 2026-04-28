package network.crypta.platform.apphost;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppRuntimeSnapshotsTest {
  private static final Instant STARTED_AT = Instant.parse("2026-04-26T10:15:30Z");
  private static final Instant EXITED_AT = Instant.parse("2026-04-26T10:16:30Z");
  private static final Instant LOG_MODIFIED_AT = Instant.parse("2026-04-26T10:17:30Z");

  @Test
  void appProcessLogSnapshot_whenConstructed_expectNormalizedAppIdAndMetadata() {
    AppProcessLogSnapshot snapshot =
        new AppProcessLogSnapshot(" Mixed-App ", true, true, 512, 2048L, "tail", LOG_MODIFIED_AT);

    assertEquals("mixed-app", snapshot.appId());
    assertTrue(snapshot.available());
    assertTrue(snapshot.truncated());
    assertEquals(512, snapshot.maxBytes());
    assertEquals(2048L, snapshot.sizeBytes());
    assertEquals("tail", snapshot.text());
    assertEquals(LOG_MODIFIED_AT, snapshot.lastModifiedAt());
  }

  @Test
  void appProcessLogSnapshot_whenLogIsUnavailable_expectOptionalMetadataAllowed() {
    AppProcessLogSnapshot snapshot =
        new AppProcessLogSnapshot("sample-app", false, false, 1, 0L, "", null);

    assertFalse(snapshot.available());
    assertFalse(snapshot.truncated());
    assertEquals("", snapshot.text());
    assertNull(snapshot.lastModifiedAt());
  }

  @Test
  void appProcessLogSnapshot_whenMaxBytesIsNonPositive_expectFailure() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> new AppProcessLogSnapshot("sample-app", true, false, 0, 0L, "", null));

    assertEquals("maxBytes must be positive", exception.getMessage());
  }

  @Test
  void appProcessLogSnapshot_whenSizeBytesIsNegative_expectFailure() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> new AppProcessLogSnapshot("sample-app", true, false, 1, -1L, "", null));

    assertEquals("sizeBytes must be non-negative", exception.getMessage());
  }

  @Test
  void appProcessLogSnapshot_whenTextIsNull_expectFailure() {
    NullPointerException exception =
        assertThrows(
            NullPointerException.class,
            () -> new AppProcessLogSnapshot("sample-app", true, false, 1, 0L, null, null));

    assertEquals("text", exception.getMessage());
  }

  @Test
  void appRuntimeStatusSnapshot_whenConstructed_expectNormalizedAppIdAndMetadata() {
    AppRuntimeStatusSnapshot snapshot =
        new AppRuntimeStatusSnapshot(
            " Mixed-App ",
            AppRuntimeState.RESTARTING,
            false,
            null,
            null,
            EXITED_AT,
            7,
            2,
            3,
            true,
            4096L);

    assertEquals("mixed-app", snapshot.appId());
    assertEquals(AppRuntimeState.RESTARTING, snapshot.state());
    assertFalse(snapshot.running());
    assertNull(snapshot.pid());
    assertNull(snapshot.startedAt());
    assertEquals(EXITED_AT, snapshot.lastExitAt());
    assertEquals(7, snapshot.lastExitCode());
    assertEquals(2, snapshot.restartCount());
    assertEquals(3, snapshot.currentRestartAttempt());
    assertTrue(snapshot.logAvailable());
    assertEquals(4096L, snapshot.logSizeBytes());
    assertEquals(AppQuotaStatus.unlimited(), snapshot.quotaStatus());
    assertTrue(snapshot.warnings().isEmpty());
  }

  @Test
  void appQuotaPolicy_whenZeroOrAbsentQuotas_expectUnlimited() {
    AppQuotaPolicy policy = new AppQuotaPolicy(0L, null, 1024L);

    assertEquals(Long.valueOf(0L), policy.dataQuotaBytes());
    assertNull(policy.effectiveDataQuotaBytes());
    assertNull(policy.effectiveCacheQuotaBytes());
    assertFalse(policy.dataQuotaEnforced());
    assertFalse(policy.cacheQuotaEnforced());
    assertEquals(1024L, policy.processLogMaxBytes());
  }

  @Test
  void appQuotaPolicy_whenPositiveQuotas_expectEnforced() {
    AppQuotaPolicy policy = new AppQuotaPolicy(128L, 256L, 1024L);

    assertEquals(Long.valueOf(128L), policy.effectiveDataQuotaBytes());
    assertEquals(Long.valueOf(256L), policy.effectiveCacheQuotaBytes());
    assertTrue(policy.dataQuotaEnforced());
    assertTrue(policy.cacheQuotaEnforced());
  }

  @Test
  void appQuotaPolicy_whenNegativeQuota_expectFailure() {
    IllegalArgumentException exception =
        assertThrows(IllegalArgumentException.class, () -> new AppQuotaPolicy(-1L, null, 1024L));

    assertEquals("dataQuotaBytes must be non-negative when present", exception.getMessage());
  }

  @Test
  void appQuotaPolicy_whenProcessLogLimitIsNonPositive_expectFailure() {
    IllegalArgumentException exception =
        assertThrows(IllegalArgumentException.class, () -> new AppQuotaPolicy(null, null, 0L));

    assertEquals("processLogMaxBytes must be positive", exception.getMessage());
  }

  @Test
  void appQuotaUsage_whenNegativeUsage_expectFailure() {
    IllegalArgumentException exception =
        assertThrows(IllegalArgumentException.class, () -> new AppQuotaUsage(0L, -1L, null));

    assertEquals("cacheUsageBytes must be non-negative", exception.getMessage());
  }

  @Test
  void appQuotaStatus_whenUsageExceedsPositiveQuota_expectOverLimitAndImmutableWarnings() {
    AppQuotaStatus status =
        new AppQuotaStatus(
            new AppQuotaPolicy(10L, 0L, 1024L),
            new AppQuotaUsage(11L, 500L, 2048L),
            List.of(AppQuotaWarning.dataQuotaExceeded()));

    assertTrue(status.dataQuotaEnforced());
    assertFalse(status.cacheQuotaEnforced());
    assertTrue(status.dataOverLimit());
    assertFalse(status.cacheOverLimit());
    assertEquals(List.of("Data usage exceeds the configured app quota."), status.warningMessages());
    List<AppQuotaWarning> warnings = status.warnings();
    AppQuotaWarning cacheQuotaExceeded = AppQuotaWarning.cacheQuotaExceeded();

    assertThrows(UnsupportedOperationException.class, () -> warnings.add(cacheQuotaExceeded));
  }

  @Test
  void appQuotaStatus_whenCacheUsageExceedsPositiveQuota_expectCacheOverLimit() {
    AppQuotaStatus status =
        new AppQuotaStatus(
            new AppQuotaPolicy(0L, 10L, 1024L),
            new AppQuotaUsage(500L, 11L, null),
            List.of(AppQuotaWarning.cacheQuotaExceeded()));

    assertFalse(status.dataQuotaEnforced());
    assertTrue(status.cacheQuotaEnforced());
    assertFalse(status.dataOverLimit());
    assertTrue(status.cacheOverLimit());
    assertEquals(
        List.of("Cache usage exceeds the configured app quota."), status.warningMessages());
  }

  @Test
  void appQuotaWarning_whenAreaNamesVary_expectNormalizedPathFreeWarnings() {
    AppQuotaWarning symlinkWarning = AppQuotaWarning.symlinkSkipped("Cache");
    AppQuotaWarning scanWarning = AppQuotaWarning.scanIncomplete("DATA");

    assertEquals("cache_symlink_skipped", symlinkWarning.code());
    assertEquals("Cache usage ignores symlink entries.", symlinkWarning.message());
    assertEquals("data_scan_incomplete", scanWarning.code());
    assertEquals(
        "Data usage may be incomplete because some entries could not be inspected.",
        scanWarning.message());
  }

  @Test
  void appQuotaWarning_whenAreaIsInvalid_expectFailure() {
    IllegalArgumentException exception =
        assertThrows(IllegalArgumentException.class, () -> AppQuotaWarning.scanIncomplete("logs"));

    assertEquals("area must be data or cache", exception.getMessage());
  }

  @Test
  void appRuntimeStatusSnapshot_whenQuotaAndWarningsProvided_expectStoredPathFreeValues() {
    AppQuotaStatus quotaStatus =
        new AppQuotaStatus(
            new AppQuotaPolicy(1024L, 0L, 2048L), new AppQuotaUsage(128L, 64L, 512L), List.of());
    AppRuntimeStatusSnapshot snapshot =
        new AppRuntimeStatusSnapshot(
            "sample-app",
            AppRuntimeState.RUNNING,
            true,
            42L,
            STARTED_AT,
            null,
            null,
            0,
            0,
            true,
            512L,
            network.crypta.platform.apphost.sandbox.AppSandboxProviders.inactiveStatus(
                network.crypta.platform.apphost.sandbox.AppSandboxPolicy.defaults()),
            quotaStatus,
            List.of("Automatic restart suppressed after 5 attempts within 300000 ms."));

    assertEquals(quotaStatus, snapshot.quotaStatus());
    assertEquals(
        List.of("Automatic restart suppressed after 5 attempts within 300000 ms."),
        snapshot.warnings());
    assertFalse(snapshot.toString().contains("/"));
  }

  @Test
  void appRuntimeStatusSnapshot_whenRunning_expectProcessMetadataAllowed() {
    AppRuntimeStatusSnapshot snapshot =
        new AppRuntimeStatusSnapshot(
            "sample-app",
            AppRuntimeState.RUNNING,
            true,
            42L,
            STARTED_AT,
            null,
            null,
            0,
            0,
            false,
            null);

    assertTrue(snapshot.running());
    assertEquals(42L, snapshot.pid());
    assertEquals(STARTED_AT, snapshot.startedAt());
    assertNull(snapshot.lastExitAt());
    assertNull(snapshot.lastExitCode());
    assertFalse(snapshot.logAvailable());
    assertNull(snapshot.logSizeBytes());
  }

  @Test
  void appRuntimeStatusSnapshot_whenStateIsNull_expectFailure() {
    NullPointerException exception =
        assertThrows(
            NullPointerException.class,
            () ->
                new AppRuntimeStatusSnapshot(
                    "sample-app", null, false, null, null, null, null, 0, 0, false, null));

    assertEquals("state", exception.getMessage());
  }

  @Test
  void appRuntimeStatusSnapshot_whenPidIsNonPositive_expectFailure() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                new AppRuntimeStatusSnapshot(
                    "sample-app",
                    AppRuntimeState.RUNNING,
                    true,
                    0L,
                    STARTED_AT,
                    null,
                    null,
                    0,
                    0,
                    false,
                    null));

    assertEquals("pid must be positive when present", exception.getMessage());
  }

  @Test
  void appRuntimeStatusSnapshot_whenRestartCountIsNegative_expectFailure() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                new AppRuntimeStatusSnapshot(
                    "sample-app",
                    AppRuntimeState.CRASHED,
                    false,
                    null,
                    null,
                    EXITED_AT,
                    1,
                    -1,
                    0,
                    false,
                    null));

    assertEquals("restartCount must be non-negative", exception.getMessage());
  }

  @Test
  void appRuntimeStatusSnapshot_whenCurrentRestartAttemptIsNegative_expectFailure() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                new AppRuntimeStatusSnapshot(
                    "sample-app",
                    AppRuntimeState.RESTARTING,
                    false,
                    null,
                    null,
                    EXITED_AT,
                    1,
                    0,
                    -1,
                    false,
                    null));

    assertEquals("currentRestartAttempt must be non-negative", exception.getMessage());
  }

  @Test
  void appRuntimeStatusSnapshot_whenLogSizeBytesIsNegative_expectFailure() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                new AppRuntimeStatusSnapshot(
                    "sample-app",
                    AppRuntimeState.EXITED,
                    false,
                    null,
                    null,
                    EXITED_AT,
                    0,
                    0,
                    0,
                    true,
                    -1L));

    assertEquals("logSizeBytes must be non-negative when present", exception.getMessage());
  }
}
