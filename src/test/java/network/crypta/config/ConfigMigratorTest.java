package network.crypta.config;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import network.crypta.fs.Resolved;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100") // Enforce method_whenCondition_expectOutcome naming for tests.
@Execution(ExecutionMode.SAME_THREAD)
@ResourceLock("java.nio.file.Paths#get")
class ConfigMigratorTest {

  @TempDir Path tempDir;

  @Test
  void migrateIfNeeded_whenCwdConfigExists_expectCopiedRewrittenAndLegacyDirectoriesMoved()
      throws Exception {
    // Arrange
    Path cwd = tempDir.resolve("cwd");
    Path executableDir = tempDir.resolve("exe");
    Files.createDirectories(cwd);
    Files.createDirectories(executableDir);

    Resolved dirs = resolved(tempDir.resolve("resolved"));

    Path cwdConfig = cwd.resolve(ConfigMigrator.CONFIG_FILE);
    Files.writeString(cwdConfig, legacyConfigTemplate());

    createLegacyDirectory(cwd.resolve("datastore"), "store.bin");
    createLegacyDirectory(cwd.resolve("temp"), "tmp.bin");
    createLegacyDirectory(cwd.resolve("persistent-temp"), "ptmp.bin");
    createLegacyDirectory(cwd.resolve("downloads"), "download.bin");
    createLegacyDirectory(cwd.resolve("logs"), "app.log");

    // Act
    runWithCwd(cwd, () -> ConfigMigrator.migrateIfNeeded(dirs, executableDir));

    // Assert
    Path cfgFile = dirs.configDir().resolve(ConfigMigrator.CONFIG_FILE);
    assertTrue(Files.exists(cfgFile));

    SimpleFieldSet rewritten = readSimpleFieldSet(cfgFile);
    assertEquals("${configDir}", rewritten.get("node.install.cfgDir"));
    assertEquals("${dataDir}/datastore", rewritten.get("node.install.storeDir"));
    assertEquals("${cacheDir}/tmp", rewritten.get("node.install.tempDir"));
    assertEquals("${cacheDir}/persistent-temp", rewritten.get("node.install.persistentTempDir"));
    assertEquals("${dataDir}/downloads", rewritten.get("node.downloadsDir"));
    assertEquals("${logsDir}", rewritten.get("logger.dirname"));

    assertFalse(Files.exists(cwd.resolve("datastore")));
    assertFalse(Files.exists(cwd.resolve("temp")));
    assertFalse(Files.exists(cwd.resolve("persistent-temp")));
    assertFalse(Files.exists(cwd.resolve("downloads")));
    assertFalse(Files.exists(cwd.resolve("logs")));

    assertTrue(Files.exists(dirs.dataDir().resolve("datastore").resolve("store.bin")));
    assertTrue(Files.exists(dirs.cacheDir().resolve("tmp").resolve("tmp.bin")));
    assertTrue(Files.exists(dirs.cacheDir().resolve("persistent-temp").resolve("ptmp.bin")));
    assertTrue(Files.exists(dirs.dataDir().resolve("downloads").resolve("download.bin")));
    assertTrue(Files.exists(dirs.logsDir().resolve("app.log")));
  }

  @Test
  void migrateIfNeeded_whenExecutableConfigExists_expectExecutableTemplateUsedAndRewritten()
      throws Exception {
    // Arrange
    Path cwd = tempDir.resolve("cwd");
    Path executableDir = tempDir.resolve("exe");
    Files.createDirectories(cwd);
    Files.createDirectories(executableDir);

    Resolved dirs = resolved(tempDir.resolve("resolved"));

    Path exeConfig = executableDir.resolve(ConfigMigrator.CONFIG_FILE);
    Files.writeString(
        exeConfig,
        String.join(
                "\n",
                List.of(
                    "node.install.cfgDir=.",
                    "node.install.storeDir=./datastore",
                    "logger.priority=DEBUG",
                    "End"))
            + "\n");

    // Act
    runWithCwd(cwd, () -> ConfigMigrator.migrateIfNeeded(dirs, executableDir));

    // Assert
    Path cfgFile = dirs.configDir().resolve(ConfigMigrator.CONFIG_FILE);
    assertTrue(Files.exists(cfgFile));

    SimpleFieldSet rewritten = readSimpleFieldSet(cfgFile);
    assertEquals("${configDir}", rewritten.get("node.install.cfgDir"));
    assertEquals("${dataDir}/datastore", rewritten.get("node.install.storeDir"));
    assertEquals("DEBUG", rewritten.get("logger.priority"));
  }

  @Test
  void migrateIfNeeded_whenNoSourceConfigExists_expectDefaultTemplateCreated() throws Exception {
    // Arrange
    Path cwd = tempDir.resolve("cwd");
    Path executableDir = tempDir.resolve("exe");
    Files.createDirectories(cwd);
    Files.createDirectories(executableDir);

    Resolved dirs = resolved(tempDir.resolve("resolved"));

    // Act
    runWithCwd(cwd, () -> ConfigMigrator.migrateIfNeeded(dirs, executableDir));

    // Assert
    Path cfgFile = dirs.configDir().resolve(ConfigMigrator.CONFIG_FILE);
    assertTrue(Files.exists(cfgFile));
    String generated = Files.readString(cfgFile);
    assertTrue(generated.contains("# Cryptad config (auto-generated)"));
    assertTrue(generated.contains("logger.priority=NORMAL"));
  }

  @Test
  void migrateIfNeeded_whenDestinationExists_expectSourceDirectoryNotMoved() throws Exception {
    // Arrange
    Path cwd = tempDir.resolve("cwd");
    Path executableDir = tempDir.resolve("exe");
    Files.createDirectories(cwd);
    Files.createDirectories(executableDir);

    Resolved dirs = resolved(tempDir.resolve("resolved"));

    Path cfgFile = dirs.configDir().resolve(ConfigMigrator.CONFIG_FILE);
    Files.createDirectories(cfgFile.getParent());
    Files.writeString(cfgFile, "logger.priority=NORMAL\nEnd\n");

    Path sourceDownloads = cwd.resolve("downloads");
    createLegacyDirectory(sourceDownloads, "from-cwd.bin");

    Path targetDownloads = dirs.dataDir().resolve("downloads");
    createLegacyDirectory(targetDownloads, "already-there.bin");

    // Act
    runWithCwd(cwd, () -> ConfigMigrator.migrateIfNeeded(dirs, executableDir));

    // Assert
    assertTrue(Files.exists(sourceDownloads.resolve("from-cwd.bin")));
    assertTrue(Files.exists(targetDownloads.resolve("already-there.bin")));
  }

  @Test
  void migrateIfNeeded_whenLegacyPluginDirectoriesPresent_expectDirectoriesLeftInPlace()
      throws Exception {
    // Arrange
    Path cwd = tempDir.resolve("cwd");
    Path executableDir = tempDir.resolve("exe");
    Files.createDirectories(cwd);
    Files.createDirectories(executableDir);

    Resolved dirs = resolved(tempDir.resolve("resolved"));

    Path cfgFile = dirs.configDir().resolve(ConfigMigrator.CONFIG_FILE);
    Files.createDirectories(cfgFile.getParent());
    Files.writeString(cfgFile, "logger.priority=NORMAL\nEnd\n");

    createLegacyDirectory(cwd.resolve("plugins"), "plugin.jar");
    createLegacyDirectory(cwd.resolve("plugin-data"), "plugin-store.bin");

    // Act
    runWithCwd(cwd, () -> ConfigMigrator.migrateIfNeeded(dirs, executableDir));

    // Assert
    assertTrue(Files.exists(cwd.resolve("plugins").resolve("plugin.jar")));
    assertTrue(Files.exists(cwd.resolve("plugin-data").resolve("plugin-store.bin")));
    assertFalse(Files.exists(dirs.dataDir().resolve("plugins").resolve("plugin.jar")));
  }

  private static Resolved resolved(Path root) {
    return new Resolved(
        root.resolve("config"),
        root.resolve("data"),
        root.resolve("cache"),
        root.resolve("run"),
        root.resolve("logs"));
  }

  private static String legacyConfigTemplate() {
    return String.join(
            "\n",
            List.of(
                "node.install.cfgDir=.",
                "node.install.storeDir=./datastore",
                "node.install.tempDir=./temp",
                "node.install.persistentTempDir=./persistent-temp",
                "node.downloadsDir=./downloads",
                "logger.dirname=./logs",
                "logger.priority=NORMAL",
                "End"))
        + "\n";
  }

  private static void createLegacyDirectory(Path dir, String fileName) throws IOException {
    Files.createDirectories(dir);
    Files.writeString(dir.resolve(fileName), "payload");
  }

  private static SimpleFieldSet readSimpleFieldSet(Path configFile) throws IOException {
    try (InputStream in = Files.newInputStream(configFile)) {
      return SimpleFieldSet.readFrom(in, true, true);
    }
  }

  private static void runWithCwd(Path cwd, ThrowingRunnable runnable) throws Exception {
    try (MockedStatic<Paths> mockedPaths =
        Mockito.mockStatic(Paths.class, Mockito.CALLS_REAL_METHODS)) {
      mockedPaths.when(() -> Paths.get("")).thenReturn(cwd);
      runnable.run();
    }
  }

  @FunctionalInterface
  private interface ThrowingRunnable {
    void run() throws Exception;
  }
}
