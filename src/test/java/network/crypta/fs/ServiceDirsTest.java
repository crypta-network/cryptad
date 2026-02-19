package network.crypta.fs;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

@SuppressWarnings("java:S100") // Enforce method_whenCondition_expectOutcome naming for tests.
class ServiceDirsTest {

  @TempDir Path tempDir;

  @Test
  void resolve_whenLinuxSystemdDirectoriesSet_expectConfiguredRootsAndNoAutoCreation() {
    // Arrange
    Path config = tempDir.resolve("etc");
    Path data = tempDir.resolve("lib");
    Path cache = tempDir.resolve("cache");
    Path run = tempDir.resolve("run");
    Path logs = tempDir.resolve("log");

    Map<String, String> env = new HashMap<>();
    env.put("CONFIGURATION_DIRECTORY", config.toString());
    env.put("STATE_DIRECTORY", data.toString());
    env.put("CACHE_DIRECTORY", cache.toString());
    env.put("RUNTIME_DIRECTORY", run.toString());
    env.put("LOGS_DIRECTORY", logs.toString());

    ServiceDirs serviceDirs = new ServiceDirs(env, new AppEnv(env, "Linux", "root"));

    // Act
    Resolved resolved = serviceDirs.resolve();

    // Assert
    assertEquals(config, resolved.configDir());
    assertEquals(data, resolved.dataDir());
    assertEquals(cache, resolved.cacheDir());
    assertEquals(run, resolved.runDir());
    assertEquals(logs, resolved.logsDir());
    assertFalse(Files.exists(config));
  }

  @Test
  void resolve_whenLinuxNoSystemdOverrides_expectDefaultLinuxServicePaths() {
    // Arrange
    Map<String, String> env = new HashMap<>();
    ServiceDirs serviceDirs = new ServiceDirs(env, new AppEnv(env, "Linux", "root"));

    // Act
    Resolved resolved = serviceDirs.resolve();

    // Assert
    assertEquals(Paths.get("/etc/cryptad"), resolved.configDir());
    assertEquals(Paths.get("/var/lib/cryptad"), resolved.dataDir());
    assertEquals(Paths.get("/var/cache/cryptad"), resolved.cacheDir());
    assertEquals(Paths.get("/run/cryptad"), resolved.runDir());
    assertEquals(Paths.get("/var/log/cryptad"), resolved.logsDir());
  }

  @Test
  void resolve_whenWindowsProgramDataProvided_expectProgramDataCryptadRoots() {
    // Arrange
    Path programData = tempDir.resolve("ProgramData");
    Map<String, String> env = new HashMap<>();
    env.put("PROGRAMDATA", programData.toString());

    ServiceDirs serviceDirs = new ServiceDirs(env, new AppEnv(env, "Windows 10", "SYSTEM"));

    // Act
    Resolved resolved = serviceDirs.resolve();

    // Assert
    Path root = programData.resolve("Cryptad");
    assertEquals(root.resolve("config"), resolved.configDir());
    assertEquals(root.resolve("data"), resolved.dataDir());
    assertEquals(root.resolve("cache"), resolved.cacheDir());
    assertEquals(root.resolve("run"), resolved.runDir());
    assertEquals(root.resolve("logs"), resolved.logsDir());
  }

  @Test
  void resolve_whenWindowsProgramDataMissing_expectUserHomeFallback() {
    // Arrange
    Map<String, String> env = new HashMap<>();
    Map<String, String> systemProperties = new HashMap<>();
    systemProperties.put(Dirs.USER_HOME, tempDir.resolve("home").toString());

    ServiceDirs serviceDirs =
        new ServiceDirs(env, systemProperties, Map.of(), new AppEnv(env, "Windows 11", "SYSTEM"));

    // Act
    Resolved resolved = serviceDirs.resolve();

    // Assert
    Path root = tempDir.resolve("home").resolve("AppData").resolve("Local").resolve("Cryptad");
    assertEquals(root.resolve("config"), resolved.configDir());
    assertEquals(root.resolve("data"), resolved.dataDir());
    assertEquals(root.resolve("cache"), resolved.cacheDir());
    assertEquals(root.resolve("run"), resolved.runDir());
    assertEquals(root.resolve("logs"), resolved.logsDir());
  }

  @Test
  void resolve_whenMacService_expectLibraryServicePaths() {
    // Arrange
    Map<String, String> env = new HashMap<>();
    ServiceDirs serviceDirs = new ServiceDirs(env, new AppEnv(env, "Mac OS X", "root"));

    // Act
    Resolved resolved = serviceDirs.resolve();

    // Assert
    Path root = Paths.get("/Library", "Application Support", "Cryptad");
    assertEquals(root.resolve("config"), resolved.configDir());
    assertEquals(root.resolve("data"), resolved.dataDir());
    assertEquals(Paths.get("/Library", "Caches", "Cryptad"), resolved.cacheDir());
    assertEquals(Paths.get("/Library", "Caches", "Cryptad", "run"), resolved.runDir());
    assertEquals(Paths.get("/Library", "Logs", "Cryptad"), resolved.logsDir());
  }

  @Test
  void resolve_whenCliOverridesProvided_expectCliOverridesTakePrecedenceOverEnv() {
    // Arrange
    Path envConfig = tempDir.resolve("env-config");
    Path envData = tempDir.resolve("env-data");
    Path envCache = tempDir.resolve("env-cache");
    Path envRun = tempDir.resolve("env-run");
    Path envLogs = tempDir.resolve("env-logs");

    Map<String, String> env = new HashMap<>();
    env.put("CONFIGURATION_DIRECTORY", envConfig.toString());
    env.put("STATE_DIRECTORY", envData.toString());
    env.put("CACHE_DIRECTORY", envCache.toString());
    env.put("RUNTIME_DIRECTORY", envRun.toString());
    env.put("LOGS_DIRECTORY", envLogs.toString());

    Map<String, String> cliOverrides = new HashMap<>();
    cliOverrides.put("configDir", tempDir.resolve("cli-config").toString());
    cliOverrides.put("dataDir", tempDir.resolve("cli-data").toString());

    ServiceDirs serviceDirs =
        new ServiceDirs(env, Map.of(), cliOverrides, new AppEnv(env, "Linux", "root"));

    // Act
    Resolved resolved = serviceDirs.resolve();

    // Assert
    assertEquals(tempDir.resolve("cli-config"), resolved.configDir());
    assertEquals(tempDir.resolve("cli-data"), resolved.dataDir());
    assertEquals(envCache, resolved.cacheDir());
    assertEquals(envRun, resolved.runDir());
    assertEquals(envLogs, resolved.logsDir());
  }

  @Test
  void resolve_whenNonLinuxAndSystemdEnvSet_expectSystemdVariablesIgnored() {
    // Arrange
    Path programData = tempDir.resolve("ProgramData");
    Path ignoredConfig = tempDir.resolve("ignored-config");

    Map<String, String> env = new HashMap<>();
    env.put("PROGRAMDATA", programData.toString());
    env.put("CONFIGURATION_DIRECTORY", ignoredConfig.toString());

    ServiceDirs serviceDirs = new ServiceDirs(env, new AppEnv(env, "Windows 10", "SYSTEM"));

    // Act
    Resolved resolved = serviceDirs.resolve();

    // Assert
    assertEquals(programData.resolve("Cryptad").resolve("config"), resolved.configDir());
  }
}
