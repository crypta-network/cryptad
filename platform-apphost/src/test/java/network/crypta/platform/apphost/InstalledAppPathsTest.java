package network.crypta.platform.apphost;

import java.nio.file.Path;
import network.crypta.platform.apphost.manifest.AppManifest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class InstalledAppPathsTest {
  @TempDir private Path tempDir;

  @Test
  void resolveInstalledPath_whenRelativePathEscapesInstalledRoot_expectFailure() {
    InstalledAppPaths paths = paths();

    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> paths.resolveInstalledPath(Path.of("../outside")));

    assertEquals("resolved path must stay under installedRoot: ../outside", exception.getMessage());
  }

  @Test
  void executablePath_whenManifestExecPathIsAbsolute_expectFailure() {
    InstalledAppPaths paths = paths();
    AppManifest manifest =
        new AppManifest(
            1,
            "sample-app",
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
        "sample-app",
        tempDir.resolve("installed").resolve("sample-app"),
        tempDir.resolve("data").resolve("sample-app"),
        tempDir.resolve("cache").resolve("sample-app"),
        tempDir.resolve("run").resolve("sample-app"));
  }
}
