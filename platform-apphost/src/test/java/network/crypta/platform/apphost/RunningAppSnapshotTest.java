package network.crypta.platform.apphost;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import network.crypta.platform.apphost.manifest.AppManifest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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

  private InstalledAppPaths paths() {
    return new InstalledAppPaths(
        SAMPLE_APP_ID,
        tempDir.resolve("installed").resolve(SAMPLE_APP_ID),
        tempDir.resolve("data").resolve(SAMPLE_APP_ID),
        tempDir.resolve("cache").resolve(SAMPLE_APP_ID),
        tempDir.resolve("run").resolve(SAMPLE_APP_ID));
  }
}
