package network.crypta.platform.apphost;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.fs.AppEnv;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppDiskUsageScannerTest {
  @TempDir Path tempDir;

  @Test
  void scan_whenRegularFilesExist_expectDataAndCacheBytesCounted() throws IOException {
    InstalledAppPaths paths = paths();
    Files.createDirectories(paths.dataDir().resolve("nested"));
    Files.createDirectories(paths.cacheDir());
    Files.writeString(paths.dataDir().resolve("a.txt"), "abc", StandardCharsets.UTF_8);
    Files.writeString(
        paths.dataDir().resolve("nested").resolve("b.txt"), "de", StandardCharsets.UTF_8);
    Files.writeString(paths.cacheDir().resolve("c.txt"), "cache", StandardCharsets.UTF_8);

    AppDiskUsageScanner.ScanResult result = new AppDiskUsageScanner().scan(paths, 12L);

    assertEquals(5L, result.usage().dataUsageBytes());
    assertEquals(5L, result.usage().cacheUsageBytes());
    assertEquals(12L, result.usage().processLogSizeBytes());
    assertTrue(result.warnings().isEmpty());
  }

  @Test
  void scan_whenDirectoriesAreMissing_expectZeroUsageWithoutWarnings() {
    InstalledAppPaths paths = paths();

    AppDiskUsageScanner.ScanResult result = new AppDiskUsageScanner().scan(paths, null);

    assertEquals(0L, result.usage().dataUsageBytes());
    assertEquals(0L, result.usage().cacheUsageBytes());
    assertTrue(result.warnings().isEmpty());
  }

  @Test
  void scan_whenSymlinkExists_expectNotFollowedAndPathFreeWarning() throws IOException {
    Assumptions.assumeFalse(new AppEnv().isWindows());
    InstalledAppPaths paths = paths();
    Files.createDirectories(paths.dataDir());
    Path external = tempDir.resolve("external.txt");
    Files.writeString(external, "outside", StandardCharsets.UTF_8);
    Files.createSymbolicLink(paths.dataDir().resolve("linked.txt"), external.toAbsolutePath());

    AppDiskUsageScanner.ScanResult result = new AppDiskUsageScanner().scan(paths, null);

    assertEquals(0L, result.usage().dataUsageBytes());
    assertEquals(0L, result.usage().cacheUsageBytes());
    assertEquals(1, result.warnings().size());
    assertEquals("data_symlink_skipped", result.warnings().getFirst().code());
    assertFalse(result.warnings().getFirst().message().contains(external.toString()));
  }

  @Test
  void scan_whenDataRootIsNotDirectory_expectPathFreeIncompleteWarning() throws IOException {
    InstalledAppPaths paths = paths();
    Files.createDirectories(paths.dataDir().getParent());
    Files.writeString(paths.dataDir(), "not a directory", StandardCharsets.UTF_8);

    AppDiskUsageScanner.ScanResult result = new AppDiskUsageScanner().scan(paths, null);

    assertEquals(0L, result.usage().dataUsageBytes());
    assertEquals("data_scan_incomplete", result.warnings().getFirst().code());
    assertFalse(result.warnings().getFirst().message().contains(paths.dataDir().toString()));
  }

  @Test
  void scan_whenCacheRootIsNotDirectory_expectPathFreeIncompleteWarning() throws IOException {
    InstalledAppPaths paths = paths();
    Files.createDirectories(paths.cacheDir().getParent());
    Files.writeString(paths.cacheDir(), "not a directory", StandardCharsets.UTF_8);

    AppDiskUsageScanner.ScanResult result = new AppDiskUsageScanner().scan(paths, null);

    assertEquals(0L, result.usage().cacheUsageBytes());
    assertEquals("cache_scan_incomplete", result.warnings().getFirst().code());
    assertFalse(result.warnings().getFirst().message().contains(paths.cacheDir().toString()));
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
