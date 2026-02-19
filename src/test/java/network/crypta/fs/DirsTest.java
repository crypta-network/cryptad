package network.crypta.fs;

import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100") // Enforce method_whenCondition_expectOutcome naming for tests.
class DirsTest {

  @TempDir Path tempDir;

  @Test
  void ensureDir_whenPathMissing_expectDirectoryCreated() {
    // Arrange
    Path target = tempDir.resolve("created-dir");

    // Act
    Dirs.ensureDir(target, Dirs.PERM_USER_RWX);

    // Assert
    assertTrue(Files.isDirectory(target));
  }

  @Test
  void ensureDir_whenParentIsFile_expectUncheckedIOException() throws Exception {
    // Arrange
    Path file = tempDir.resolve("not-a-directory");
    Files.writeString(file, "x");
    Path child = file.resolve("child");

    // Act
    UncheckedIOException error =
        assertThrows(UncheckedIOException.class, () -> Dirs.ensureDir(child, Dirs.PERM_USER_RWX));

    // Assert
    assertTrue(error.getMessage().contains("Failed to create directory"));
  }

  @Test
  void ensureDir_whenPermissionsStringInvalid_expectNoException() {
    // Arrange
    Path target = tempDir.resolve("invalid-perms");

    // Act
    assertDoesNotThrow(() -> Dirs.ensureDir(target, "invalid"));

    // Assert
    assertTrue(Files.isDirectory(target));
  }

  @Test
  void isUnitTestRuntime_whenRunningUnderJUnit_expectTrue() {
    // Arrange

    // Act
    boolean detected = Dirs.isUnitTestRuntime();

    // Assert
    assertTrue(detected);
  }

  @Test
  void buildResolved_whenBasesProvided_expectAppSubdirectoriesResolved() {
    // Arrange
    Path configBase = tempDir.resolve("config-base");
    Path dataBase = tempDir.resolve("data-base");
    Path cacheBase = tempDir.resolve("cache-base");
    Path runtime = tempDir.resolve("runtime");
    Path logs = tempDir.resolve("logs");
    Dirs.Bases bases = new Dirs.Bases(configBase, dataBase, cacheBase);

    // Act
    Resolved resolved = Dirs.buildResolved(bases, "cryptad", runtime, logs);

    // Assert
    assertEquals(configBase.resolve("cryptad").resolve("config"), resolved.configDir());
    assertEquals(dataBase.resolve("cryptad").resolve("data"), resolved.dataDir());
    assertEquals(cacheBase.resolve("cryptad"), resolved.cacheDir());
    assertEquals(runtime, resolved.runDir());
    assertEquals(logs, resolved.logsDir());
  }

  @Test
  void xdgBases_whenEnvironmentUnset_expectHomeDefaultsUsed() {
    // Arrange
    String home = tempDir.resolve("home").toString();
    Map<String, String> env = Map.of();

    // Act
    Dirs.Bases bases = Dirs.xdgBases(env, home);

    // Assert
    assertEquals(Paths.get(home, ".config"), bases.config());
    assertEquals(Paths.get(home, ".local", "share"), bases.data());
    assertEquals(Paths.get(home, ".cache"), bases.cache());
  }

  @Test
  void xdgBases_whenEnvironmentOverridesPresent_expectOverridesUsed() {
    // Arrange
    Path xdgConfig = tempDir.resolve("xdg-config");
    Path xdgData = tempDir.resolve("xdg-data");
    Path xdgCache = tempDir.resolve("xdg-cache");
    Map<String, String> env = new HashMap<>();
    env.put("XDG_CONFIG_HOME", xdgConfig.toString());
    env.put("XDG_DATA_HOME", xdgData.toString());
    env.put("XDG_CACHE_HOME", xdgCache.toString());

    // Act
    Dirs.Bases bases = Dirs.xdgBases(env, tempDir.toString());

    // Assert
    assertEquals(xdgConfig, bases.config());
    assertEquals(xdgData, bases.data());
    assertEquals(xdgCache, bases.cache());
  }

  @Test
  void computeStandardXdgRuntime_whenFlatpakWithRuntimeDir_expectRuntimeUnderFlatpakApp() {
    // Arrange
    Path xdgRuntime = tempDir.resolve("xdg-runtime");
    Map<String, String> env = new HashMap<>();
    env.put("XDG_RUNTIME_DIR", xdgRuntime.toString());
    env.put("FLATPAK_ID", "network.crypta.Cryptad");
    AppEnv appEnv = new AppEnv(env, "Linux", "tester");

    // Act
    Path runtime = Dirs.computeStandardXdgRuntime(env, Map.of(), appEnv, tempDir.resolve("cache"));

    // Assert
    assertEquals(
        xdgRuntime
            .resolve("app")
            .resolve("network.crypta.Cryptad")
            .resolve(Dirs.APP_RUNTIME_SUBPATH),
        runtime);
  }

  @Test
  void computeStandardXdgRuntime_whenFlatpakWithoutRuntimeDir_expectRunUserFromSystemProperties() {
    // Arrange
    Map<String, String> env = new HashMap<>();
    env.put("FLATPAK_ID", "network.crypta.Cryptad");
    Map<String, String> systemProperties = Map.of("user.name", "flatpak-user");
    AppEnv appEnv = new AppEnv(env, "Linux", "tester");

    // Act
    Path runtime =
        Dirs.computeStandardXdgRuntime(env, systemProperties, appEnv, tempDir.resolve("cache"));

    // Assert
    assertEquals(
        Paths.get(Dirs.LINUX_RUN_USER_PREFIX, "flatpak-user")
            .resolve("app")
            .resolve("network.crypta.Cryptad")
            .resolve(Dirs.APP_RUNTIME_SUBPATH),
        runtime);
  }

  @Test
  void computeStandardXdgRuntime_whenRuntimeDirProvided_expectRuntimeSubpath() {
    // Arrange
    Path xdgRuntime = tempDir.resolve("xdg-runtime");
    Map<String, String> env = Map.of("XDG_RUNTIME_DIR", xdgRuntime.toString());
    AppEnv appEnv = new AppEnv(env, "Linux", "tester");

    // Act
    Path runtime = Dirs.computeStandardXdgRuntime(env, Map.of(), appEnv, tempDir.resolve("cache"));

    // Assert
    assertEquals(xdgRuntime.resolve(Dirs.APP_RUNTIME_SUBPATH), runtime);
  }

  @Test
  void computeStandardXdgRuntime_whenRuntimeDirMissingAndParentWritable_expectRunUserPath() {
    // Arrange
    Map<String, String> env = Map.of();
    AppEnv appEnv = new AppEnv(env, "Linux", "tester");
    Path expected =
        Paths.get(Dirs.LINUX_RUN_USER_PREFIX)
            .resolve(System.getProperty("user.name", "0"))
            .resolve(Dirs.APP_RUNTIME_SUBPATH);

    // Act
    Path runtime;
    try (MockedStatic<Files> files = Mockito.mockStatic(Files.class)) {
      files.when(() -> Files.isWritable(expected.getParent())).thenReturn(true);
      runtime = Dirs.computeStandardXdgRuntime(env, Map.of(), appEnv, tempDir.resolve("cache"));
    }

    // Assert
    assertEquals(expected, runtime);
  }

  @Test
  void computeStandardXdgRuntime_whenRuntimeDirMissingAndParentNotWritable_expectCacheFallback() {
    // Arrange
    Map<String, String> env = Map.of();
    Path cacheBase = tempDir.resolve("cache");
    AppEnv appEnv = new AppEnv(env, "Linux", "tester");

    // Act
    Path runtime;
    try (MockedStatic<Files> files = Mockito.mockStatic(Files.class)) {
      files.when(() -> Files.isWritable(Mockito.any(Path.class))).thenReturn(false);
      runtime = Dirs.computeStandardXdgRuntime(env, Map.of(), appEnv, cacheBase);
    }

    // Assert
    assertEquals(cacheBase.resolve("rt"), runtime);
  }

  @Test
  void computeSnapRuntime_whenUidAndInstanceProvidedAndParentWritable_expectCandidate() {
    // Arrange
    Map<String, String> env = new HashMap<>();
    env.put("UID", "10101");
    env.put("SNAP_INSTANCE_NAME", "cryptad.test");
    Path expected = Paths.get(Dirs.LINUX_RUN_USER_PREFIX, "10101", "snap.cryptad.test");

    // Act
    Path runtime;
    try (MockedStatic<Files> files = Mockito.mockStatic(Files.class)) {
      files.when(() -> Files.isWritable(expected.getParent())).thenReturn(true);
      runtime = Dirs.computeSnapRuntime(env, tempDir.resolve("cache"));
    }

    // Assert
    assertEquals(expected, runtime);
  }

  @Test
  void computeSnapRuntime_whenUidMissingAndRuntimeDirMatches_expectUidExtractedFromRuntimeDir() {
    // Arrange
    Map<String, String> env = new HashMap<>();
    env.put("XDG_RUNTIME_DIR", "/run/user/424242/runtime");
    env.put("SNAP_NAME", "cryptad.snap");
    Path expected = Paths.get(Dirs.LINUX_RUN_USER_PREFIX, "424242", "snap.cryptad.snap");

    // Act
    Path runtime;
    try (MockedStatic<Files> files = Mockito.mockStatic(Files.class)) {
      files.when(() -> Files.isWritable(expected.getParent())).thenReturn(true);
      runtime = Dirs.computeSnapRuntime(env, tempDir.resolve("cache"));
    }

    // Assert
    assertEquals(expected, runtime);
  }

  @Test
  void computeSnapRuntime_whenUidMissingAndRuntimeDirDoesNotMatch_expectUidDefaultsToZero() {
    // Arrange
    Map<String, String> env = new HashMap<>();
    env.put("XDG_RUNTIME_DIR", tempDir.resolve("runtime").toString());
    env.put("SNAP_INSTANCE_NAME", "cryptad.instance");
    Path expected = Paths.get(Dirs.LINUX_RUN_USER_PREFIX, "0", "snap.cryptad.instance");

    // Act
    Path runtime;
    try (MockedStatic<Files> files = Mockito.mockStatic(Files.class)) {
      files.when(() -> Files.isWritable(expected.getParent())).thenReturn(true);
      runtime = Dirs.computeSnapRuntime(env, tempDir.resolve("cache"));
    }

    // Assert
    assertEquals(expected, runtime);
  }

  @Test
  void computeSnapRuntime_whenParentNotWritable_expectCacheFallback() {
    // Arrange
    Map<String, String> env = Map.of("UID", "no-write-user");
    Path cacheBase = tempDir.resolve("cache-base");

    // Act
    Path runtime;
    try (MockedStatic<Files> files = Mockito.mockStatic(Files.class)) {
      files.when(() -> Files.isWritable(Mockito.any(Path.class))).thenReturn(false);
      runtime = Dirs.computeSnapRuntime(env, cacheBase);
    }

    // Assert
    assertEquals(cacheBase.resolve("rt"), runtime);
  }
}
