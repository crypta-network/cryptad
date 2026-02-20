package network.crypta.fs;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

/**
 * Resolves Cryptad directory locations for user-session (non-service) execution modes.
 *
 * <p>This implementation selects platform-appropriate defaults for configuration, data, cache,
 * runtime, and logs paths while preserving expected naming conventions per operating system. It is
 * intended for regular interactive launches, not long-running system service installations.
 * Resolution starts from platform conventions, then applies environment-based overrides exposed by
 * {@link BaseDirs}. In containerized Docker scenarios it also honors shared generic override
 * variables so deployment tooling can provide paths without using Cryptad-specific names.
 *
 * <p>Platform behavior:
 *
 * <ul>
 *   <li>Linux/XDG and macOS with explicit XDG variables use lowercase app directory name {@code
 *       cryptad}.
 *   <li>Native macOS mode (without XDG variables) uses {@code Cryptad} under Library directories.
 *   <li>Windows uses {@code Cryptad} beneath {@code %APPDATA%} and {@code %LOCALAPPDATA%} roots.
 * </ul>
 */
public final class AppDirs extends BaseDirs {
  private static final String APP_DIR_NAME = "Cryptad";
  private static final String APP_DIR_NAME_LOWER = "cryptad";

  /**
   * Creates an {@code AppDirs} resolver with explicit environment and runtime context.
   *
   * <p>Use this constructor when tests or bootstrap code must control all inputs that influence
   * path resolution. The supplied maps and environment abstraction are passed to the base resolver
   * logic, which handles override precedence and platform-specific defaults.
   *
   * @param env process-like environment variables used to compute platform and override paths
   * @param systemProperties system property values used for home and runtime fallback resolution
   * @param cliOverrides command-line directory overrides that take precedence where supported
   * @param appEnv environment abstraction that reports platform and sandbox characteristics
   */
  public AppDirs(
      Map<String, String> env,
      Map<String, String> systemProperties,
      Map<String, String> cliOverrides,
      AppEnv appEnv) {
    super(env, systemProperties, cliOverrides, appEnv);
  }

  /**
   * Creates an {@code AppDirs} resolver using the current process environment and properties.
   *
   * <p>This convenience constructor is suitable for standard production startup where no explicit
   * command-line overrides are provided.
   */
  public AppDirs() {
    this(System.getenv(), currentSystemProperties(), Map.of(), new AppEnv(System.getenv()));
  }

  /**
   * Creates an {@code AppDirs} resolver with explicit command-line overrides.
   *
   * <p>Environment variables and system properties are read from the current process, while the
   * provided override map can replace selected directory outputs. A {@code null} argument is
   * treated as an empty map for predictable behavior.
   *
   * @param cliOverrides map of directory override values keyed by supported override names
   */
  public AppDirs(Map<String, String> cliOverrides) {
    this(
        System.getenv(),
        currentSystemProperties(),
        cliOverrides != null ? cliOverrides : Map.of(),
        new AppEnv(System.getenv()));
  }

  /** {@inheritDoc} */
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

  /** {@inheritDoc} */
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
