package network.crypta.platform.apphost;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import network.crypta.platform.apphost.manifest.AppManifest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppQuotaEnforcerTest {
  private static final String SAMPLE_APP_ID = "sample-app";

  @TempDir Path tempDir;

  @Test
  void enforceLaunch_whenPositiveDataQuotaScanIncomplete_expectLaunchBlocked() throws IOException {
    InstalledAppPaths paths = paths();
    writeManagedEntryAsFile(paths.dataDir());
    Files.createDirectories(paths.cacheDir());

    AppHostException exception =
        assertThrows(
            AppHostException.class,
            () -> new AppQuotaEnforcer().enforceLaunch(manifest(1024L, null), paths));

    assertEquals("app data quota scan incomplete: " + SAMPLE_APP_ID, exception.getMessage());
    AppQuotaStatus status = new AppQuotaEnforcer().status(manifest(1024L, null), paths);
    assertTrue(status.dataQuotaEnforced());
    assertTrue(hasWarning(status, "data_scan_incomplete"));
    assertFalse(status.toString().contains(paths.dataDir().toString()));
  }

  @Test
  void enforceLaunch_whenPositiveCacheQuotaScanIncomplete_expectLaunchBlocked() throws IOException {
    InstalledAppPaths paths = paths();
    Files.createDirectories(paths.dataDir());
    writeManagedEntryAsFile(paths.cacheDir());

    AppHostException exception =
        assertThrows(
            AppHostException.class,
            () -> new AppQuotaEnforcer().enforceLaunch(manifest(null, 1024L), paths));

    assertEquals("app cache quota scan incomplete: " + SAMPLE_APP_ID, exception.getMessage());
    AppQuotaStatus status = new AppQuotaEnforcer().status(manifest(null, 1024L), paths);
    assertTrue(status.cacheQuotaEnforced());
    assertTrue(hasWarning(status, "cache_scan_incomplete"));
    assertFalse(status.toString().contains(paths.cacheDir().toString()));
  }

  @Test
  void enforceLaunch_whenUnlimitedQuotaScanIncomplete_expectLaunchAllowedAndStatusWarns()
      throws IOException {
    InstalledAppPaths paths = paths();
    writeManagedEntryAsFile(paths.dataDir());
    writeManagedEntryAsFile(paths.cacheDir());

    AppQuotaStatus status = new AppQuotaEnforcer().enforceLaunch(manifest(0L, null), paths);

    assertFalse(status.dataQuotaEnforced());
    assertFalse(status.cacheQuotaEnforced());
    assertTrue(hasWarning(status, "data_scan_incomplete"));
    assertTrue(hasWarning(status, "cache_scan_incomplete"));
    assertFalse(status.toString().contains(paths.dataDir().toString()));
    assertFalse(status.toString().contains(paths.cacheDir().toString()));
  }

  private static AppManifest manifest(Long dataQuotaBytes, Long cacheQuotaBytes) {
    return new AppManifest(
        1,
        SAMPLE_APP_ID,
        "Sample App",
        "1.0",
        "bin/start.sh",
        null,
        List.of(),
        dataQuotaBytes,
        cacheQuotaBytes);
  }

  private InstalledAppPaths paths() {
    return new InstalledAppPaths(
        SAMPLE_APP_ID,
        tempDir.resolve("installed").resolve(SAMPLE_APP_ID),
        tempDir.resolve("data").resolve(SAMPLE_APP_ID),
        tempDir.resolve("cache").resolve(SAMPLE_APP_ID),
        tempDir.resolve("run").resolve(SAMPLE_APP_ID));
  }

  private static void writeManagedEntryAsFile(Path path) throws IOException {
    Files.createDirectories(path.getParent());
    Files.writeString(path, "not a directory", StandardCharsets.UTF_8);
  }

  private static boolean hasWarning(AppQuotaStatus status, String code) {
    return status.warnings().stream().anyMatch(warning -> warning.code().equals(code));
  }
}
