package network.crypta.platform.apphost;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import network.crypta.platform.apphost.manifest.AppManifest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RunningAppSnapshotTest {
  private static final String SAMPLE_APP_ID = "sample-app";
  private static final AppManifest SAMPLE_MANIFEST =
      new AppManifest(
          1, SAMPLE_APP_ID, "Sample App", "1.0", "bin/start.sh", null, List.of(), null, null);

  @TempDir Path tempDir;

  @Test
  void constructor_whenTokenIsBlank_expectFailure() {
    InstalledAppPaths paths = paths();

    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> new RunningAppSnapshot(SAMPLE_MANIFEST, paths, "  ", 123L, Instant.EPOCH));

    assertEquals("token must not be blank", exception.getMessage());
  }

  @Test
  void constructor_whenPidIsNonPositive_expectFailure() {
    InstalledAppPaths paths = paths();

    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> new RunningAppSnapshot(SAMPLE_MANIFEST, paths, "token", 0L, Instant.EPOCH));

    assertEquals("pid must be positive", exception.getMessage());
  }

  @Test
  void toString_whenSnapshotContainsTokenAndPaths_expectRedactedDiagnosticText() {
    InstalledAppPaths paths = paths();
    RunningAppSnapshot snapshot =
        new RunningAppSnapshot(SAMPLE_MANIFEST, paths, "secret-token", 123L, Instant.EPOCH);

    String text = snapshot.toString();

    assertTrue(text.contains("token=[REDACTED]"));
    assertFalse(text.contains("secret-token"));
    assertFalse(text.contains(paths.installedRoot().toString()));
    assertFalse(text.contains(paths.runDir().toString()));
  }

  @Test
  void redact_whenTokenAppearsInLogText_expectAssignmentAndExactTokenRedacted() {
    String redacted =
        AppHostTokenRedactor.redact(
            "CRYPTAD_APP_TOKEN=secret-token\nraw secret-token", "secret-token");

    assertEquals("CRYPTAD_APP_TOKEN=[REDACTED]\nraw [REDACTED]", redacted);
  }

  @Test
  void redact_whenTokenAssignmentUsesColonAndWhitespace_expectAssignmentRedacted() {
    String token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    String redacted = AppHostTokenRedactor.redact("CRYPTAD_APP_TOKEN \t: \t" + token + "\n", null);

    assertEquals("CRYPTAD_APP_TOKEN \t: \t[REDACTED]\n", redacted);
  }

  @Test
  void redact_whenKnownAppHostPathsAppearInLogText_expectPathRolesRedacted() {
    InstalledAppPaths paths = paths();

    String redacted =
        AppHostTokenRedactor.redact(
            """
            cwd=%s
            data=%s
            cache=%s
            run=%s
            log=%s
            """
                .formatted(
                    paths.installedRoot(),
                    paths.dataDir(),
                    paths.cacheDir(),
                    paths.runDir(),
                    paths.processLogFile()),
            "token",
            paths);

    assertFalse(redacted.contains(paths.installedRoot().toString()));
    assertFalse(redacted.contains(paths.dataDir().toString()));
    assertFalse(redacted.contains(paths.cacheDir().toString()));
    assertFalse(redacted.contains(paths.runDir().toString()));
    assertFalse(redacted.contains(paths.processLogFile().toString()));
    assertTrue(redacted.contains("cwd=[APP_INSTALL_DIR]"));
    assertTrue(redacted.contains("data=[APP_DATA_DIR]"));
    assertTrue(redacted.contains("cache=[APP_CACHE_DIR]"));
    assertTrue(redacted.contains("run=[APP_RUN_DIR]"));
    assertTrue(redacted.contains("log=[APP_PROCESS_LOG]"));
  }

  @Test
  void redactionOverlapBytes_whenTokenUnknown_expectAssignmentOverlapReserved() {
    InstalledAppPaths shortPaths =
        new InstalledAppPaths(
            SAMPLE_APP_ID, Path.of("i"), Path.of("d"), Path.of("c"), Path.of("r"));
    String longestAcceptedAssignment =
        "CRYPTAD_APP_TOKEN" + " ".repeat(16) + ":" + " ".repeat(16) + "0".repeat(64);

    int overlapBytes = AppHostTokenRedactor.redactionOverlapBytes(null, shortPaths);

    assertTrue(
        overlapBytes >= longestAcceptedAssignment.getBytes(StandardCharsets.UTF_8).length - 1);
  }

  private InstalledAppPaths paths() {
    return new InstalledAppPaths(
        SAMPLE_APP_ID,
        tempDir.resolve("installed").resolve(SAMPLE_APP_ID),
        tempDir.resolve("data").resolve(SAMPLE_APP_ID),
        tempDir.resolve("cache").resolve(SAMPLE_APP_ID),
        tempDir.resolve("run").resolve(SAMPLE_APP_ID));
  }
}
