package network.crypta.platform.apphost;

import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.fs.AppEnv;
import network.crypta.platform.apphost.manifest.AppManifest;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

  @Test
  void normalizeAppId_whenValueHasUppercaseAndWhitespace_expectNormalized() {
    assertEquals(SAMPLE_APP_ID, InstalledAppPaths.normalizeAppId("  Sample-App  "));
  }

  @Test
  void ensureInstallParentDirectory_whenParentMissing_expectCreated() throws Exception {
    InstalledAppPaths paths = paths();

    paths.ensureInstallParentDirectory();

    assertTrue(Files.isDirectory(paths.installedRoot().getParent()));
  }

  @Test
  void ensureMutableDirectories_whenDirectoriesMissing_expectCreated() throws Exception {
    InstalledAppPaths paths = paths();

    paths.ensureMutableDirectories();

    assertTrue(Files.isDirectory(paths.dataDir()));
    assertTrue(Files.isDirectory(paths.cacheDir()));
    assertTrue(Files.isDirectory(paths.runDir()));
  }

  @Test
  void ensureMutableDirectories_whenManagedDirectoryIsFile_expectFailure() throws Exception {
    InstalledAppPaths paths = paths();
    Files.createDirectories(parentOrThrow(paths.dataDir()));
    Files.writeString(paths.dataDir(), "not-a-directory");

    AppHostException exception =
        assertThrows(AppHostException.class, paths::ensureMutableDirectories);

    assertEquals("dataDir must be a directory: " + paths.dataDir(), exception.getMessage());
  }

  @Test
  void ensureMutableDirectories_whenManagedDirectoryIsSymlink_expectFailure() throws Exception {
    Assumptions.assumeFalse(new AppEnv().isWindows());
    InstalledAppPaths paths = paths();
    Path targetDirectory = tempDir.resolve("symlink-target");
    Files.createDirectories(targetDirectory);
    Files.createDirectories(parentOrThrow(paths.runDir()));
    Files.createSymbolicLink(paths.runDir(), targetDirectory);

    AppHostException exception =
        assertThrows(AppHostException.class, paths::ensureMutableDirectories);

    assertEquals(
        "runDir must not be a symlink, reparse point, or alias: " + paths.runDir(),
        exception.getMessage());
  }

  private InstalledAppPaths paths() {
    return new InstalledAppPaths(
        SAMPLE_APP_ID,
        tempDir.resolve("installed").resolve(SAMPLE_APP_ID),
        tempDir.resolve("data").resolve(SAMPLE_APP_ID),
        tempDir.resolve("cache").resolve(SAMPLE_APP_ID),
        tempDir.resolve("run").resolve(SAMPLE_APP_ID));
  }

  private static Path parentOrThrow(Path path) {
    Path parent = path.getParent();
    assertTrue(parent != null, "Expected parent for path " + path);
    return parent;
  }
}
