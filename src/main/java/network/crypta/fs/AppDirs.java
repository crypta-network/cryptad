package network.crypta.fs;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

/**
 * Computes directory locations for user-session (non-service) mode.
 *
 * <p>- Linux/XDG and macOS with XDG_* set: lowercase app dir name `cryptad`.
 *
 * <p>- macOS native (no XDG_*): `Cryptad` under Library conventions.
 *
 * <p>- Windows: `Cryptad` under `%APPDATA%`/`%LOCALAPPDATA%`.
 */
public final class AppDirs extends BaseDirs {
  private static final String APP_DIR_NAME = "Cryptad";
  private static final String APP_DIR_NAME_LOWER = "cryptad";

  public AppDirs(
      Map<String, String> env,
      Map<String, String> systemProperties,
      Map<String, String> cliOverrides,
      AppEnv appEnv) {
    super(env, systemProperties, cliOverrides, appEnv);
  }

  /** Zero-arg constructor for Java callers. */
  public AppDirs() {
    this(System.getenv(), currentSystemProperties(), Map.of(), new AppEnv(System.getenv()));
  }

  /** One-arg constructor (CLI overrides only) for Java callers. */
  public AppDirs(Map<String, String> cliOverrides) {
    this(
        System.getenv(),
        currentSystemProperties(),
        cliOverrides != null ? cliOverrides : Map.of(),
        new AppEnv(System.getenv()));
  }

  @Override
  protected Resolved computeBase() {
    boolean osxPrefersXdg =
        env.containsKey("XDG_CONFIG_HOME")
            || env.containsKey("XDG_DATA_HOME")
            || env.containsKey("XDG_CACHE_HOME");

    String appDirName =
        appEnv.isWindows() || (appEnv.isMac() && !osxPrefersXdg)
            ? APP_DIR_NAME
            : APP_DIR_NAME_LOWER;
    String home = systemProperties.getOrDefault(Dirs.USER_HOME, System.getProperty(Dirs.USER_HOME));

    if (appEnv.isWindows()) {
      String appData =
          env.getOrDefault("APPDATA", Paths.get(home, "AppData", "Roaming").toString());
      String localAppData =
          env.getOrDefault("LOCALAPPDATA", Paths.get(home, "AppData", "Local").toString());
      Dirs.Bases bases =
          new Dirs.Bases(
              Paths.get(appData), Paths.get(localAppData), Paths.get(localAppData, "Cache"));
      Path runtimeBase = Paths.get(localAppData, APP_DIR_NAME, "Run");
      Path logsBase = Paths.get(localAppData, APP_DIR_NAME, "Logs");
      return Dirs.buildResolved(bases, appDirName, runtimeBase, logsBase);
    }

    if (appEnv.isMac() && !osxPrefersXdg) {
      Path appSupport = Paths.get(home, Dirs.MACOS_LIBRARY_PATH, "Application Support");
      Dirs.Bases bases =
          new Dirs.Bases(
              appSupport, appSupport, Paths.get(home, Dirs.MACOS_LIBRARY_PATH, "Caches"));
      Path runtimeBase = bases.cache().resolve(APP_DIR_NAME).resolve("run");
      Path logsBase = Paths.get(home, Dirs.MACOS_LIBRARY_PATH, "Logs", APP_DIR_NAME);
      return Dirs.buildResolved(bases, appDirName, runtimeBase, logsBase);
    }

    Dirs.Bases bases = Dirs.xdgBases(env, home);
    if (appEnv.isSnap()) {
      String snapCommon = env.get("SNAP_USER_COMMON");
      if (!isBlank(snapCommon)) {
        Path snapCommonPath = Paths.get(snapCommon);
        bases = new Dirs.Bases(snapCommonPath, snapCommonPath, snapCommonPath.resolve(".cache"));
        Path runtimeBase = Dirs.computeSnapRuntime(env, bases.cache());
        Path logsBase = bases.data().resolve(appDirName).resolve("logs");
        return Dirs.buildResolved(bases, appDirName, runtimeBase, logsBase);
      }
    }
    Path runtimeBase = Dirs.computeStandardXdgRuntime(env, systemProperties, appEnv, bases.cache());
    Path logsBase = bases.data().resolve(appDirName).resolve("logs");
    return Dirs.buildResolved(bases, appDirName, runtimeBase, logsBase);
  }

  @Override
  protected Overrides envOverrides() {
    Overrides base =
        new Overrides(
            asPath(env.get("CRYPTAD_CONFIG_DIR")),
            asPath(env.get("CRYPTAD_DATA_DIR")),
            asPath(env.get("CRYPTAD_CACHE_DIR")),
            asPath(env.get("CRYPTAD_RUN_DIR")),
            asPath(env.get("CRYPTAD_LOGS_DIR")));

    if (!appEnv.isDocker()) {
      return base;
    }

    return new Overrides(
        coalesce(asPath(env.get("APP_CONFIG_DIR")), base.config()),
        coalesce(asPath(env.get("APP_DATA_DIR")), base.data()),
        coalesce(asPath(env.get("APP_CACHE_DIR")), base.cache()),
        base.run(),
        base.logs());
  }

  private static Path asPath(String value) {
    return value == null ? null : Paths.get(value);
  }

  private static boolean isBlank(String value) {
    return value == null || value.trim().isEmpty();
  }

  private static Path coalesce(Path first, Path fallback) {
    return first != null ? first : fallback;
  }
}
