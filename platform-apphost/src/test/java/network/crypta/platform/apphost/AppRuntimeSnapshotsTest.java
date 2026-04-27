package network.crypta.platform.apphost;

import java.time.Instant;
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
