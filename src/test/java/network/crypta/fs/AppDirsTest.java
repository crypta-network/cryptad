package network.crypta.fs;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import network.crypta.config.CryptadConfig;
import network.crypta.support.SimpleFieldSet;
import org.jetbrains.annotations.NotNull;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class AppDirsTest {

  @Rule public TemporaryFolder tmp = new TemporaryFolder();

  private Map<String, String> sysProps(Path home, Path tmpdir) {
    Map<String, String> p = new HashMap<>();
    p.put("user.home", home.toString());
    p.put("java.io.tmpdir", tmpdir.toString());
    p.put("os.name", "Linux");
    return p;
  }

  @Test
  public void linuxXdgUnset_defaultsUnderHome() {
    Path home = tmp.getRoot().toPath().resolve("home");
    Path t = tmp.getRoot().toPath().resolve("t");
    home.toFile().mkdirs();
    t.toFile().mkdirs();
    Map<String, String> env = new HashMap<>();
    AppEnv ae = new AppEnv(env, "Linux", "tester");
    AppDirs dirs = new AppDirs(env, sysProps(home, t), new HashMap<>(), ae);
    Resolved r = dirs.resolve();
    assertTrue(r.getConfigDir().toString().contains(".config/cryptad/config"));
    assertTrue(r.getDataDir().toString().contains(".local/share/cryptad/data"));
    assertTrue(Files.exists(r.getConfigDir()));
  }

  @Test
  public void linuxXdgSet_respectsEnv() {
    Path root = tmp.getRoot().toPath();
    Path home = root.resolve("home");
    Path t = root.resolve("t");
    Path xdgConfig = root.resolve("xdg-config");
    Path xdgData = root.resolve("xdg-data");
    Path xdgCache = root.resolve("xdg-cache");
    home.toFile().mkdirs();
    t.toFile().mkdirs();
    xdgConfig.toFile().mkdirs();
    xdgData.toFile().mkdirs();
    xdgCache.toFile().mkdirs();
    Map<String, String> env = new HashMap<>();
    env.put("XDG_CONFIG_HOME", xdgConfig.toString());
    env.put("XDG_DATA_HOME", xdgData.toString());
    env.put("XDG_CACHE_HOME", xdgCache.toString());
    AppEnv ae = new AppEnv(env, "Linux", "tester");
    AppDirs dirs = new AppDirs(env, sysProps(home, t), new HashMap<>(), ae);
    Resolved r = dirs.resolve();
    assertTrue(r.getConfigDir().startsWith(xdgConfig));
    assertTrue(r.getDataDir().startsWith(xdgData));
    assertTrue(r.getCacheDir().startsWith(xdgCache));
  }

  @Test
  public void macNative_defaultsToLibrary() {
    Path home = tmp.getRoot().toPath().resolve("home");
    home.toFile().mkdirs();
    Map<String, String> env = new HashMap<>();
    AppEnv ae = new AppEnv(env, "Mac OS X", "user");
    Map<String, String> sp = sysProps(home, tmp.getRoot().toPath());
    sp.put("os.name", "Mac OS X");
    AppDirs dirs = new AppDirs(env, sp, new HashMap<>(), ae);
    Resolved r = dirs.resolve();
    assertTrue(r.getConfigDir().toString().contains("Library/Application Support/Cryptad/config"));
    assertTrue(r.getCacheDir().toString().contains("Library/Caches/Cryptad"));
  }

  @Test
  public void macRespectsXdgWhenSet() {
    Path home = tmp.getRoot().toPath().resolve("home");
    Path xdgConfig = tmp.getRoot().toPath().resolve("xdg");
    home.toFile().mkdirs();
    xdgConfig.toFile().mkdirs();
    Map<String, String> env = new HashMap<>();
    env.put("XDG_CONFIG_HOME", xdgConfig.toString());
    AppEnv ae = new AppEnv(env, "Mac OS X", "user");
    Map<String, String> sp = sysProps(home, tmp.getRoot().toPath());
    sp.put("os.name", "Mac OS X");
    AppDirs dirs = new AppDirs(env, sp, new HashMap<>(), ae);
    Resolved r = dirs.resolve();
    assertTrue(r.getConfigDir().startsWith(xdgConfig));
  }

  @Test
  public void snapStrict_usesCommonForData() {
    Path root = tmp.getRoot().toPath();
    Path home = root.resolve("home");
    Path common = root.resolve("snap-common");
    home.toFile().mkdirs();
    common.toFile().mkdirs();
    Map<String, String> env = new HashMap<>();
    env.put("SNAP", "/snap/app");
    env.put("SNAP_USER_COMMON", common.toString());
    env.put("SNAP_USER_DATA", home.toString());
    env.put("XDG_CONFIG_HOME", home.resolve(".config").toString());
    env.put("XDG_DATA_HOME", home.resolve(".local/share").toString());
    env.put("XDG_CACHE_HOME", home.resolve(".cache").toString());
    AppEnv ae = new AppEnv(env, "Linux", "user");
    AppDirs dirs = new AppDirs(env, sysProps(home, root), new HashMap<>(), ae);
    Resolved r = dirs.resolve();
    assertTrue(r.getDataDir().startsWith(common.resolve("cryptad")));
  }

  @Test
  public void snapWithoutCommon_usesXdgAndRuntimeUnderXdgRt() {
    Path root = tmp.getRoot().toPath();
    Path home = root.resolve("home");
    Path xdgConfig = root.resolve("xdg-config");
    Path xdgData = root.resolve("xdg-data");
    Path xdgCache = root.resolve("xdg-cache");
    Path xdgRt = root.resolve("xdg-rt");
    home.toFile().mkdirs();
    xdgConfig.toFile().mkdirs();
    xdgData.toFile().mkdirs();
    xdgCache.toFile().mkdirs();
    xdgRt.toFile().mkdirs();
    Map<String, String> env = new HashMap<>();
    env.put("SNAP", "/snap/app");
    env.put("XDG_CONFIG_HOME", xdgConfig.toString());
    env.put("XDG_DATA_HOME", xdgData.toString());
    env.put("XDG_CACHE_HOME", xdgCache.toString());
    env.put("XDG_RUNTIME_DIR", xdgRt.toString());
    AppEnv ae = new AppEnv(env, "Linux", "user");
    AppDirs dirs = new AppDirs(env, sysProps(home, root), new HashMap<>(), ae);
    Resolved r = dirs.resolve();
    assertTrue(r.getConfigDir().startsWith(xdgConfig.resolve("cryptad/config")));
    assertTrue(r.getDataDir().startsWith(xdgData.resolve("cryptad/data")));
    assertTrue(r.getCacheDir().startsWith(xdgCache.resolve("cryptad")));
    assertTrue(
        r.getRunDir().startsWith(xdgRt.resolve(network.crypta.fs.DirsKt.APP_RUNTIME_SUBPATH)));
  }

  @Test
  public void snapWithCommon_runtimeFallsBackToCacheWhenUnwritable() {
    Path root = tmp.getRoot().toPath();
    Path home = root.resolve("home");
    Path common = root.resolve("snap-common");
    Path xdgCache = common.resolve(".cache");
    home.toFile().mkdirs();
    common.toFile().mkdirs();
    xdgCache.toFile().mkdirs();
    Map<String, String> env = new HashMap<>();
    env.put("SNAP", "/snap/app");
    env.put("UID", "99999");
    env.put("SNAP_INSTANCE_NAME", "cryptad.test");
    env.put("SNAP_USER_COMMON", common.toString());
    // Do not set XDG_RUNTIME_DIR; computeSnapRuntime will attempt /run (unwritable in tests) and
    // fall back to cache/rt.
    AppEnv ae = new AppEnv(env, "Linux", "user");
    AppDirs dirs = new AppDirs(env, sysProps(home, root), new HashMap<>(), ae);
    Resolved r = dirs.resolve();
    assertTrue(r.getConfigDir().startsWith(common.resolve("cryptad/config")));
    assertTrue(r.getDataDir().startsWith(common.resolve("cryptad/data")));
    assertTrue(r.getCacheDir().startsWith(xdgCache.resolve("cryptad")));
    assertTrue(r.getRunDir().startsWith(xdgCache.resolve("rt")));
    assertTrue(r.getLogsDir().startsWith(common.resolve("cryptad/logs")));
  }

  @Test
  public void macXdgCasing_isLowercaseCryptad() {
    Path home = tmp.getRoot().toPath().resolve("home");
    Path xdgConfig = tmp.getRoot().toPath().resolve("xdg");
    home.toFile().mkdirs();
    xdgConfig.toFile().mkdirs();
    Map<String, String> env = new HashMap<>();
    env.put("XDG_CONFIG_HOME", xdgConfig.toString());
    AppEnv ae = new AppEnv(env, "Mac OS X", "user");
    Map<String, String> sp = sysProps(home, tmp.getRoot().toPath());
    sp.put("os.name", "Mac OS X");
    AppDirs dirs = new AppDirs(env, sp, new HashMap<>(), ae);
    Resolved r = dirs.resolve();
    assertTrue(r.getConfigDir().toString().contains("/cryptad/config"));
  }

  @Test
  public void windowsAppDirs_casingIsCryptad() {
    Path root = tmp.getRoot().toPath();
    Path home = root.resolve("home");
    Path roaming = home.resolve("AppData/Roaming");
    Path local = home.resolve("AppData/Local");
    roaming.toFile().mkdirs();
    local.toFile().mkdirs();
    Map<String, String> env = new HashMap<>();
    env.put("APPDATA", roaming.toString());
    env.put("LOCALAPPDATA", local.toString());
    AppEnv ae = new AppEnv(env, "Windows 10", "user");
    Map<String, String> sp = sysProps(home, root);
    sp.put("os.name", "Windows 10");
    AppDirs dirs = new AppDirs(env, sp, new HashMap<>(), ae);
    Resolved r = dirs.resolve();
    assertTrue(
        r.getConfigDir().toString().contains("Cryptad\\/config".replace("\\/", "/"))
            || r.getConfigDir().toString().contains("Cryptad/config"));
    assertTrue(r.getCacheDir().toString().contains("Cryptad"));
  }

  @Test
  public void xdgRuntimeMissing_fallsBackToCacheRt() {
    Path root = tmp.getRoot().toPath();
    Path home = root.resolve("home");
    Path xdgCache = root.resolve("xdg-cache");
    Path xdgConfig = root.resolve("xdg-config");
    Path xdgData = root.resolve("xdg-data");
    home.toFile().mkdirs();
    xdgCache.toFile().mkdirs();
    xdgConfig.toFile().mkdirs();
    xdgData.toFile().mkdirs();
    Map<String, String> env = new HashMap<>();
    env.put("XDG_CONFIG_HOME", xdgConfig.toString());
    env.put("XDG_DATA_HOME", xdgData.toString());
    env.put("XDG_CACHE_HOME", xdgCache.toString());
    AppEnv ae = new AppEnv(env, "Linux", "user");
    AppDirs dirs = new AppDirs(env, sysProps(home, root), new HashMap<>(), ae);
    Resolved r = dirs.resolve();
    // Without XDG_RUNTIME_DIR and without writable /run parent, runDir should be <cache>/rt
    assertTrue(r.getRunDir().startsWith(xdgCache.resolve("rt")));
  }

  @Test
  public void flatpakHonorsXdg() {
    Path root = tmp.getRoot().toPath();
    Path home = root.resolve("home");
    Path xdgConfig = root.resolve("xdg-config");
    Map<String, String> env = getStringStringMap(root, home, xdgConfig);
    AppEnv ae = new AppEnv(env, "Linux", "user");
    AppDirs dirs = new AppDirs(env, sysProps(home, root), new HashMap<>(), ae);
    Resolved r = dirs.resolve();
    assertTrue(r.getConfigDir().startsWith(xdgConfig));
    assertTrue(
        r.getRunDir()
            .toString()
            .contains("/app/org.example.Cryptad/" + network.crypta.fs.DirsKt.APP_RUNTIME_SUBPATH));
  }

  @NotNull
  private static Map<String, String> getStringStringMap(Path root, Path home, Path xdgConfig) {
    Path xdgData = root.resolve("xdg-data");
    Path xdgCache = root.resolve("xdg-cache");
    home.toFile().mkdirs();
    xdgConfig.toFile().mkdirs();
    xdgData.toFile().mkdirs();
    xdgCache.toFile().mkdirs();
    Map<String, String> env = new HashMap<>();
    env.put("FLATPAK_ID", "org.example.Cryptad");
    env.put("XDG_CONFIG_HOME", xdgConfig.toString());
    env.put("XDG_DATA_HOME", xdgData.toString());
    env.put("XDG_CACHE_HOME", xdgCache.toString());
    env.put("XDG_RUNTIME_DIR", root.resolve("xdg-rt").toString());
    return env;
  }

  @Test
  public void systemdService_usesExportedDirs() {
    Path root = tmp.getRoot().toPath();
    Map<String, String> env = new HashMap<>();
    env.put("CONFIGURATION_DIRECTORY", root.resolve("etc").toString());
    env.put("STATE_DIRECTORY", root.resolve("lib").toString());
    env.put("CACHE_DIRECTORY", root.resolve("cache").toString());
    env.put("LOGS_DIRECTORY", root.resolve("log").toString());
    env.put("RUNTIME_DIRECTORY", root.resolve("run").toString());
    ServiceDirs svc = new ServiceDirs(env, new AppEnv(env, "Linux", "root"));
    Resolved r = svc.resolve();
    assertTrue(r.getConfigDir().startsWith(root.resolve("etc")));
    assertTrue(r.getDataDir().startsWith(root.resolve("lib")));
    assertTrue(r.getLogsDir().startsWith(root.resolve("log")));
  }

  @Test
  public void windowsService_rootsUnderProgramData() {
    Path root = tmp.getRoot().toPath();
    Map<String, String> env = new HashMap<>();
    env.put("PROGRAMDATA", root.resolve("ProgramData").toString());
    ServiceDirs svc = new ServiceDirs(env, new AppEnv(env, "Windows 10", "SYSTEM"));
    Resolved r = svc.resolve();
    assertTrue(r.getConfigDir().toString().contains("ProgramData"));
    assertTrue(r.getLogsDir().toString().contains("ProgramData"));
  }

  @Test
  public void macDaemon_defaultsApply() {
    Map<String, String> env = new HashMap<>();
    ServiceDirs svc = new ServiceDirs(env, new AppEnv(env, "Mac OS X", "root"));
    Resolved r = svc.resolve();
    assertTrue(
        r.getConfigDir().toString().startsWith("/Library/Application Support/Cryptad/config"));
    assertTrue(r.getLogsDir().toString().startsWith("/Library/Logs/Cryptad"));
  }

  @Test
  public void placeholderExpansion_works() throws IOException {
    Path root = tmp.getRoot().toPath();
    Path home = root.resolve("home");
    home.toFile().mkdirs();
    Map<String, String> env = new HashMap<>();
    AppEnv ae = new AppEnv(env, "Linux", "tester", p -> null);
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
    SimpleFieldSet out = CryptadConfig.expandAll(sfs, r, System.getProperties());
    System.out.println("DEBUG cfgDir expected=" + r.getConfigDir());
    System.out.println("DEBUG node.install.cfgDir actual=" + out.get("node.install.cfgDir"));
    assertTrue(out.get("node.install.cfgDir").startsWith(r.getConfigDir().toString()));
    assertEquals(r.getDataDir().toString(), out.get("node.install.storeDir"));
    assertTrue(out.get("node.install.tempDir").startsWith(r.getCacheDir().toString()));
    System.out.println("DEBUG logsDir expected=" + r.getLogsDir());
    System.out.println("DEBUG logger.dirname actual=" + out.get("logger.dirname"));
    assertEquals(r.getLogsDir().toString(), out.get("logger.dirname"));
  }
}
