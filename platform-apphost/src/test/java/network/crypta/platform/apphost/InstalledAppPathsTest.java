package network.crypta.platform.apphost;

import java.nio.file.Path;
import network.crypta.platform.apphost.manifest.AppManifest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class InstalledAppPathsTest {
  private static final String SAMPLE_APP_ID = "sample-app";

  @TempDir private Path tempDir;

  @Test
  void resolveInstalledPath_whenRelativePathEscapesInstalledRoot_expectFailure() {
    InstalledAppPaths paths = paths();
    Path relativeEscape = Path.of("../outside");

    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class, () -> paths.resolveInstalledPath(relativeEscape));

    assertEquals("resolved path must stay under installedRoot: ../outside", exception.getMessage());
  }

  @Test
  void executablePath_whenManifestExecPathIsAbsolute_expectFailure() {
    InstalledAppPaths paths = paths();
    AppManifest manifest =
        new AppManifest(
            1,
            SAMPLE_APP_ID,
            "Sample App",
            "1.0",
            "/outside",
            null,
            java.util.List.of(),
            null,
            null);

    IllegalArgumentException exception =
        assertThrows(IllegalArgumentException.class, () -> paths.executablePath(manifest));

    assertEquals("resolved path must stay under installedRoot: /outside", exception.getMessage());
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
