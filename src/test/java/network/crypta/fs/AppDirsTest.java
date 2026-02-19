package network.crypta.fs;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import network.crypta.config.CryptadConfig;
import network.crypta.support.SimpleFieldSet;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100") // Enforce method_whenCondition_expectOutcome naming for tests.
class AppDirsTest {

  @TempDir Path tmp;

  private static String norm(String s) {
    return s.replace('\\', '/');
  }

  private static void ensureDir(Path dir) {
    try {
      Files.createDirectories(dir);
    } catch (IOException e) {
      throw new AssertionError("Failed to create test directory: " + dir, e);
    }
  }

  private Map<String, String> sysProps(Path home, Path tmpdir) {
    Map<String, String> p = new HashMap<>();
    p.put("user.home", home.toString());
    p.put("java.io.tmpdir", tmpdir.toString());
    p.put("os.name", "Linux");
    return p;
  }

  @Test
  void resolve_whenLinuxXdgUnset_expectDefaultsUnderHome() {
    // Arrange
    Path home = tmp.resolve("home");
    Path t = tmp.resolve("t");
    ensureDir(home);
    ensureDir(t);
    Map<String, String> env = new HashMap<>();
    AppEnv ae = new AppEnv(env, "Linux", "tester");
    AppDirs dirs = new AppDirs(env, sysProps(home, t), new HashMap<>(), ae);

    // Act
    Resolved r = dirs.resolve();

    // Assert
    assertTrue(norm(r.getConfigDir().toString()).contains(".config/cryptad/config"));
    assertTrue(norm(r.getDataDir().toString()).contains(".local/share/cryptad/data"));
    assertTrue(Files.exists(r.getConfigDir()));
  }

  @Test
  void resolve_whenLinuxXdgSet_expectEnvBasesUsed() {
    // Arrange
    Path root = tmp;
    Path home = root.resolve("home");
    Path t = root.resolve("t");
    Path xdgConfig = root.resolve("xdg-config");
    Path xdgData = root.resolve("xdg-data");
    Path xdgCache = root.resolve("xdg-cache");
    ensureDir(home);
    ensureDir(t);
    ensureDir(xdgConfig);
    ensureDir(xdgData);
    ensureDir(xdgCache);
    Map<String, String> env = new HashMap<>();
    env.put("XDG_CONFIG_HOME", xdgConfig.toString());
    env.put("XDG_DATA_HOME", xdgData.toString());
    env.put("XDG_CACHE_HOME", xdgCache.toString());
    AppEnv ae = new AppEnv(env, "Linux", "tester");
    AppDirs dirs = new AppDirs(env, sysProps(home, t), new HashMap<>(), ae);

    // Act
    Resolved r = dirs.resolve();

    // Assert
    assertTrue(r.getConfigDir().startsWith(xdgConfig));
    assertTrue(r.getDataDir().startsWith(xdgData));
    assertTrue(r.getCacheDir().startsWith(xdgCache));
  }

  @Test
  void resolve_whenMacNativeWithoutXdg_expectLibraryPaths() {
    // Arrange
    Path home = tmp.resolve("home");
    ensureDir(home);
    Map<String, String> env = new HashMap<>();
    AppEnv ae = new AppEnv(env, "Mac OS X", "user");
    Map<String, String> sp = sysProps(home, tmp);
    sp.put("os.name", "Mac OS X");
    AppDirs dirs = new AppDirs(env, sp, new HashMap<>(), ae);

    // Act
    Resolved r = dirs.resolve();

    // Assert
    assertTrue(
        norm(r.getConfigDir().toString()).contains("Library/Application Support/Cryptad/config"));
    assertTrue(norm(r.getCacheDir().toString()).contains("Library/Caches/Cryptad"));
  }

  @Test
  void resolve_whenMacWithXdg_expectXdgPaths() {
    // Arrange
    Path home = tmp.resolve("home");
    Path xdgConfig = tmp.resolve("xdg");
    ensureDir(home);
    ensureDir(xdgConfig);
    Map<String, String> env = new HashMap<>();
    env.put("XDG_CONFIG_HOME", xdgConfig.toString());
    AppEnv ae = new AppEnv(env, "Mac OS X", "user");
    Map<String, String> sp = sysProps(home, tmp);
    sp.put("os.name", "Mac OS X");
    AppDirs dirs = new AppDirs(env, sp, new HashMap<>(), ae);

    // Act
    Resolved r = dirs.resolve();

    // Assert
    assertTrue(r.getConfigDir().startsWith(xdgConfig));
  }

  @Test
  void resolve_whenSnapWithUserCommon_expectDataUnderCommon() {
    // Arrange
    Path root = tmp;
    Path home = root.resolve("home");
    Path common = root.resolve("snap-common");
    ensureDir(home);
    ensureDir(common);
    Map<String, String> env = new HashMap<>();
    env.put("SNAP", "/snap/app");
    env.put("SNAP_USER_COMMON", common.toString());
    env.put("SNAP_USER_DATA", home.toString());
    env.put("XDG_CONFIG_HOME", home.resolve(".config").toString());
    env.put("XDG_DATA_HOME", home.resolve(".local/share").toString());
    env.put("XDG_CACHE_HOME", home.resolve(".cache").toString());
    AppEnv ae = new AppEnv(env, "Linux", "user");
    AppDirs dirs = new AppDirs(env, sysProps(home, root), new HashMap<>(), ae);

    // Act
    Resolved r = dirs.resolve();

    // Assert
    assertTrue(r.getDataDir().startsWith(common.resolve("cryptad")));
  }

  @Test
  void resolve_whenSnapWithoutUserCommon_expectXdgAndRuntimeDir() {
    // Arrange
    Path root = tmp;
    Path home = root.resolve("home");
    Path xdgConfig = root.resolve("xdg-config");
    Path xdgData = root.resolve("xdg-data");
    Path xdgCache = root.resolve("xdg-cache");
    Path xdgRt = root.resolve("xdg-rt");
    ensureDir(home);
    ensureDir(xdgConfig);
    ensureDir(xdgData);
    ensureDir(xdgCache);
    ensureDir(xdgRt);
    Map<String, String> env = new HashMap<>();
    env.put("SNAP", "/snap/app");
    env.put("XDG_CONFIG_HOME", xdgConfig.toString());
    env.put("XDG_DATA_HOME", xdgData.toString());
    env.put("XDG_CACHE_HOME", xdgCache.toString());
    env.put("XDG_RUNTIME_DIR", xdgRt.toString());
    AppEnv ae = new AppEnv(env, "Linux", "user");
    AppDirs dirs = new AppDirs(env, sysProps(home, root), new HashMap<>(), ae);

    // Act
    Resolved r = dirs.resolve();

    // Assert
    assertTrue(r.getConfigDir().startsWith(xdgConfig.resolve("cryptad/config")));
    assertTrue(r.getDataDir().startsWith(xdgData.resolve("cryptad/data")));
    assertTrue(r.getCacheDir().startsWith(xdgCache.resolve("cryptad")));
    assertTrue(r.getRunDir().startsWith(xdgRt.resolve(network.crypta.fs.Dirs.APP_RUNTIME_SUBPATH)));
  }

  @Test
  void resolve_whenSnapWithCommonAndRuntimeUnwritable_expectCacheRuntimeFallback() {
    // Arrange
    Path root = tmp;
    Path home = root.resolve("home");
    Path common = root.resolve("snap-common");
    Path xdgCache = common.resolve(".cache");
    ensureDir(home);
    ensureDir(common);
    ensureDir(xdgCache);
    Map<String, String> env = new HashMap<>();
    env.put("SNAP", "/snap/app");
    env.put("UID", "99999");
    env.put("SNAP_INSTANCE_NAME", "cryptad.test");
    env.put("SNAP_USER_COMMON", common.toString());
    // Do not set XDG_RUNTIME_DIR; computeSnapRuntime will attempt /run (unwritable in tests) and
    // fall back to cache/rt.
    AppEnv ae = new AppEnv(env, "Linux", "user");
    AppDirs dirs = new AppDirs(env, sysProps(home, root), new HashMap<>(), ae);

    // Act
    Resolved r = dirs.resolve();

    // Assert
    assertTrue(r.getConfigDir().startsWith(common.resolve("cryptad/config")));
    assertTrue(r.getDataDir().startsWith(common.resolve("cryptad/data")));
    assertTrue(r.getCacheDir().startsWith(xdgCache.resolve("cryptad")));
    assertTrue(r.getRunDir().startsWith(xdgCache.resolve("rt")));
    assertTrue(r.getLogsDir().startsWith(common.resolve("cryptad/logs")));
  }

  @Test
  void resolve_whenMacUsesXdg_expectLowercaseCryptadCasing() {
    // Arrange
    Path home = tmp.resolve("home");
    Path xdgConfig = tmp.resolve("xdg");
    ensureDir(home);
    ensureDir(xdgConfig);
    Map<String, String> env = new HashMap<>();
    env.put("XDG_CONFIG_HOME", xdgConfig.toString());
    AppEnv ae = new AppEnv(env, "Mac OS X", "user");
    Map<String, String> sp = sysProps(home, tmp);
    sp.put("os.name", "Mac OS X");
    AppDirs dirs = new AppDirs(env, sp, new HashMap<>(), ae);

    // Act
    Resolved r = dirs.resolve();

    // Assert
    assertTrue(norm(r.getConfigDir().toString()).contains("/cryptad/config"));
  }

  @Test
  void resolve_whenWindowsAppDirs_expectCryptadCasing() {
    // Arrange
    Path root = tmp;
    Path home = root.resolve("home");
    Path roaming = home.resolve("AppData/Roaming");
    Path local = home.resolve("AppData/Local");
    ensureDir(roaming);
    ensureDir(local);
    Map<String, String> env = new HashMap<>();
    env.put("APPDATA", roaming.toString());
    env.put("LOCALAPPDATA", local.toString());
    AppEnv ae = new AppEnv(env, "Windows 10", "user");
    Map<String, String> sp = sysProps(home, root);
    sp.put("os.name", "Windows 10");
    AppDirs dirs = new AppDirs(env, sp, new HashMap<>(), ae);

    // Act
    Resolved r = dirs.resolve();

    // Assert
    assertTrue(norm(r.getConfigDir().toString()).contains("/Cryptad/config"));
    assertTrue(norm(r.getCacheDir().toString()).contains("/Cryptad"));
  }

  @Test
  void resolve_whenXdgRuntimeMissing_expectCacheRtFallback() {
    // Arrange
    Path root = tmp;
    Path home = root.resolve("home");
    Path xdgCache = root.resolve("xdg-cache");
    Path xdgConfig = root.resolve("xdg-config");
    Path xdgData = root.resolve("xdg-data");
    ensureDir(home);
    ensureDir(xdgCache);
    ensureDir(xdgConfig);
    ensureDir(xdgData);
    Map<String, String> env = new HashMap<>();
    env.put("XDG_CONFIG_HOME", xdgConfig.toString());
    env.put("XDG_DATA_HOME", xdgData.toString());
    env.put("XDG_CACHE_HOME", xdgCache.toString());
    AppEnv ae = new AppEnv(env, "Linux", "user");
    AppDirs dirs = new AppDirs(env, sysProps(home, root), new HashMap<>(), ae);

    // Act
    Resolved r = dirs.resolve();

    // Assert
    // Without XDG_RUNTIME_DIR and without a writable /run parent, runDir should be <cache>/rt
    assertTrue(r.getRunDir().startsWith(xdgCache.resolve("rt")));
  }

  @Test
  void resolve_whenFlatpakWithXdg_expectXdgAndFlatpakRuntime() {
    // Arrange
    Path root = tmp;
    Path home = root.resolve("home");
    Path xdgConfig = root.resolve("xdg-config");
    Map<String, String> env = getStringStringMap(root, home, xdgConfig);
    AppEnv ae = new AppEnv(env, "Linux", "user");
    AppDirs dirs = new AppDirs(env, sysProps(home, root), new HashMap<>(), ae);

    // Act
    Resolved r = dirs.resolve();

    // Assert
    assertTrue(r.getConfigDir().startsWith(xdgConfig));
    assertTrue(
        norm(r.getRunDir().toString())
            .contains("/app/org.example.Cryptad/" + network.crypta.fs.Dirs.APP_RUNTIME_SUBPATH));
  }

  @NotNull
  private static Map<String, String> getStringStringMap(Path root, Path home, Path xdgConfig) {
    Path xdgData = root.resolve("xdg-data");
    Path xdgCache = root.resolve("xdg-cache");
    ensureDir(home);
    ensureDir(xdgConfig);
    ensureDir(xdgData);
    ensureDir(xdgCache);
    Map<String, String> env = new HashMap<>();
    env.put("FLATPAK_ID", "org.example.Cryptad");
    env.put("XDG_CONFIG_HOME", xdgConfig.toString());
    env.put("XDG_DATA_HOME", xdgData.toString());
    env.put("XDG_CACHE_HOME", xdgCache.toString());
    env.put("XDG_RUNTIME_DIR", root.resolve("xdg-rt").toString());
    return env;
  }

  @Test
  void resolve_whenSystemdServiceDirsExported_expectConfiguredRoots() {
    // Arrange
    Path root = tmp;
    Map<String, String> env = new HashMap<>();
    env.put("CONFIGURATION_DIRECTORY", root.resolve("etc").toString());
    env.put("STATE_DIRECTORY", root.resolve("lib").toString());
    env.put("CACHE_DIRECTORY", root.resolve("cache").toString());
    env.put("LOGS_DIRECTORY", root.resolve("log").toString());
    env.put("RUNTIME_DIRECTORY", root.resolve("run").toString());
    ServiceDirs svc = new ServiceDirs(env, new AppEnv(env, "Linux", "root"));

    // Act
    Resolved r = svc.resolve();

    // Assert
    assertTrue(r.getConfigDir().startsWith(root.resolve("etc")));
    assertTrue(r.getDataDir().startsWith(root.resolve("lib")));
    assertTrue(r.getLogsDir().startsWith(root.resolve("log")));
  }

  @Test
  void resolve_whenWindowsService_expectProgramDataRoots() {
    // Arrange
    Path root = tmp;
    Map<String, String> env = new HashMap<>();
    env.put("PROGRAMDATA", root.resolve("ProgramData").toString());
    ServiceDirs svc = new ServiceDirs(env, new AppEnv(env, "Windows 10", "SYSTEM"));

    // Act
    Resolved r = svc.resolve();

    // Assert
    assertTrue(r.getConfigDir().toString().contains("ProgramData"));
    assertTrue(r.getLogsDir().toString().contains("ProgramData"));
  }

  @Test
  void resolve_whenMacDaemon_expectDefaultSystemPaths() {
    // Arrange
    Map<String, String> env = new HashMap<>();
    ServiceDirs svc = new ServiceDirs(env, new AppEnv(env, "Mac OS X", "root"));

    // Act
    Resolved r = svc.resolve();

    // Assert
    assertTrue(
        norm(r.getConfigDir().toString())
            .startsWith("/Library/Application Support/Cryptad/config"));
    assertTrue(norm(r.getLogsDir().toString()).startsWith("/Library/Logs/Cryptad"));
  }

  @Test
  void expandAll_whenPlaceholderValuesPresent_expectResolvedDirectories() throws IOException {
    // Arrange
    Path root = tmp;
    Path home = root.resolve("home");
    ensureDir(home);
    Map<String, String> env = new HashMap<>();
    AppEnv ae = new AppEnv(env, "Linux", "tester", _ -> null);
    AppDirs dirs = new AppDirs(env, sysProps(home, root), new HashMap<>(), ae);
    Resolved r = dirs.resolve();
    String[] lines =
        new String[] {
          "node.install.cfgDir=${configDir}",
          "node.install.storeDir=stateDir", // leading token form
          "node.install.tempDir=cacheDir/tmp",
          "logger.dirname=${logsDir}",
          "End"
        };
    SimpleFieldSet sfs = new SimpleFieldSet(lines, true, true, false);

    // Act
    SimpleFieldSet out = CryptadConfig.expandAll(sfs, r, System.getProperties());

    // Assert
    String expandedConfigDir = out.get("node.install.cfgDir");
    String expandedTempDir = out.get("node.install.tempDir");
    System.out.println("DEBUG cfgDir expected=" + r.getConfigDir());
    System.out.println("DEBUG node.install.cfgDir actual=" + expandedConfigDir);
    assertNotNull(expandedConfigDir);
    assertTrue(expandedConfigDir.startsWith(r.getConfigDir().toString()));
    assertEquals(r.getDataDir().toString(), out.get("node.install.storeDir"));
    assertNotNull(expandedTempDir);
    assertTrue(expandedTempDir.startsWith(r.getCacheDir().toString()));
    System.out.println("DEBUG logsDir expected=" + r.getLogsDir());
    System.out.println("DEBUG logger.dirname actual=" + out.get("logger.dirname"));
    assertEquals(r.getLogsDir().toString(), out.get("logger.dirname"));
  }
}
