package network.crypta.fs;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

/**
 * Resolves directory layout for service-oriented Cryptad deployments.
 *
 * <p>This strategy targets operating-system service environments rather than interactive user
 * sessions. It provides platform-specific base roots for Windows Service, launchd-style macOS
 * deployments, and Linux/systemd installations, then allows service manager environment variables
 * to override those defaults where supported. The class is intentionally conservative when creating
 * directories: it avoids mutating non-native host filesystems during tests or cross-platform runs.
 *
 * <p>Resolution model:
 *
 * <ul>
 *   <li>Compute service defaults per target operating system.
 *   <li>Apply Linux service environment overrides when present.
 *   <li>Create directories only when runtime host and target OS families match.
 * </ul>
 */
public final class ServiceDirs extends BaseDirs {
  private static final String APP_DIR_NAME = "Cryptad";

  /**
   * Creates a service-directory resolver with fully injected environment inputs.
   *
   * <p>This constructor is intended for tests and startup paths that need explicit control over
   * environment variables, system properties, CLI overrides, and platform detection behavior.
   *
   * @param env environment variables used for service-directory and override detection
   * @param systemProperties JVM/system property snapshot used for fallback path resolution
   * @param cliOverrides command-line overrides that take the highest precedence when non-null
   * @param appEnv environment detector used for target-platform branching
   */
  public ServiceDirs(
      Map<String, String> env,
      Map<String, String> systemProperties,
      Map<String, String> cliOverrides,
      AppEnv appEnv) {
    super(env, systemProperties, cliOverrides, appEnv);
  }

  /**
   * Creates a service-directory resolver from the current process environment and system
   * properties.
   *
   * <p>This convenience constructor applies no explicit CLI overrides.
   */
  public ServiceDirs() {
    this(System.getenv(), currentSystemProperties(), Map.of(), new AppEnv(System.getenv()));
  }

  /**
   * Creates a service-directory resolver with explicit CLI overrides.
   *
   * <p>Environment variables and system properties are read from the current process. A {@code
   * null} override map is treated as empty.
   *
   * @param cliOverrides CLI-provided directory overrides keyed by logical directory names
   */
  public ServiceDirs(Map<String, String> cliOverrides) {
    this(
        System.getenv(),
        currentSystemProperties(),
        cliOverrides != null ? cliOverrides : Map.of(),
        new AppEnv(System.getenv()));
  }

  /**
   * Creates a service-directory resolver with explicit environment and detector dependencies.
   *
   * <p>This compatibility constructor is used by Java tests that previously passed only environment
   * values and an {@link AppEnv} instance. Missing arguments are replaced with safe defaults.
   *
   * @param env environment variables used for base path and override detection
   * @param appEnv environment detector used for target-platform decisions
   */
  public ServiceDirs(Map<String, String> env, AppEnv appEnv) {
    this(
        env != null ? env : Map.of(),
        currentSystemProperties(),
        Map.of(),
        appEnv != null ? appEnv : new AppEnv());
  }

  /** {@inheritDoc} */
  @Override
  protected Resolved computeBase() {
    if (appEnv.isWindows()) {
      String programData =
          env.getOrDefault(
              "PROGRAMDATA",
              Paths.get(
                      systemProperties.getOrDefault(
                          Dirs.USER_HOME, System.getProperty(Dirs.USER_HOME)),
                      "AppData",
                      "Local")
                  .toString());
      Path root = Paths.get(programData).resolve(APP_DIR_NAME);
      return new Resolved(
          root.resolve("config"),
          root.resolve("data"),
          root.resolve("cache"),
          root.resolve("run"),
          root.resolve("logs"));
    }

    if (appEnv.isMac()) {
      Path root = Paths.get("/" + Dirs.MACOS_LIBRARY_PATH, "Application Support", APP_DIR_NAME);
      return new Resolved(
          root.resolve("config"),
          root.resolve("data"),
          Paths.get("/" + Dirs.MACOS_LIBRARY_PATH, "Caches", APP_DIR_NAME),
          Paths.get("/" + Dirs.MACOS_LIBRARY_PATH, "Caches", APP_DIR_NAME, "run"),
          Paths.get("/" + Dirs.MACOS_LIBRARY_PATH, "Logs", APP_DIR_NAME));
    }

    return new Resolved(
        Paths.get("/etc/cryptad"),
        Paths.get("/var/lib/cryptad"),
        Paths.get("/var/cache/cryptad"),
        Paths.get("/run/cryptad"),
        Paths.get("/var/log/cryptad"));
  }

  /** {@inheritDoc} */
  @Override
  protected Overrides envOverrides() {
    if (!appEnv.isLinux()) {
      return new Overrides();
    }
    return new Overrides(
        asPath(env.get("CONFIGURATION_DIRECTORY")),
        asPath(env.get("STATE_DIRECTORY")),
        asPath(env.get("CACHE_DIRECTORY")),
        asPath(env.get("RUNTIME_DIRECTORY")),
        asPath(env.get("LOGS_DIRECTORY")));
  }

  /** {@inheritDoc} */
  @Override
  protected boolean shouldEnsureDirectories() {
    if (Dirs.isUnitTestRuntime()) {
      return false;
    }
    AppEnv.OsKind hostKind = new AppEnv().osKind();
    return (appEnv.isWindows() && hostKind == AppEnv.OsKind.WINDOWS)
        || (appEnv.isMac() && hostKind == AppEnv.OsKind.MAC)
        || (appEnv.isLinux() && hostKind == AppEnv.OsKind.LINUX);
  }

  private static Path asPath(String value) {
    return value == null ? null : Paths.get(value);
  }
}
