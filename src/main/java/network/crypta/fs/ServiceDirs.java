package network.crypta.fs;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

/** Service-aware directories based on systemd (Linux), launchd (macOS), and Windows Service. */
public final class ServiceDirs extends BaseDirs {
  public ServiceDirs(
      Map<String, String> env,
      Map<String, String> systemProperties,
      Map<String, String> cliOverrides,
      AppEnv appEnv) {
    super(env, systemProperties, cliOverrides, appEnv);
  }

  /** Zero-arg constructor for Java callers. */
  public ServiceDirs() {
    this(System.getenv(), currentSystemProperties(), Map.of(), new AppEnv(System.getenv()));
  }

  /** One-arg constructor (CLI overrides only) used by NodeStarter. */
  public ServiceDirs(Map<String, String> cliOverrides) {
    this(
        System.getenv(),
        currentSystemProperties(),
        cliOverrides != null ? cliOverrides : Map.of(),
        new AppEnv(System.getenv()));
  }

  /** Backward-compat constructor used from Java tests: (env, appEnv). */
  public ServiceDirs(Map<String, String> env, AppEnv appEnv) {
    this(
        env != null ? env : Map.of(),
        currentSystemProperties(),
        Map.of(),
        appEnv != null ? appEnv : new AppEnv());
  }

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
      Path root = Paths.get(programData).resolve("Cryptad");
      return new Resolved(
          root.resolve("config"),
          root.resolve("data"),
          root.resolve("cache"),
          root.resolve("run"),
          root.resolve("logs"));
    }

    if (appEnv.isMac()) {
      Path root = Paths.get("/" + Dirs.MACOS_LIBRARY_PATH, "Application Support", "Cryptad");
      return new Resolved(
          root.resolve("config"),
          root.resolve("data"),
          Paths.get("/" + Dirs.MACOS_LIBRARY_PATH, "Caches", "Cryptad"),
          Paths.get("/" + Dirs.MACOS_LIBRARY_PATH, "Caches", "Cryptad", "run"),
          Paths.get("/" + Dirs.MACOS_LIBRARY_PATH, "Logs", "Cryptad"));
    }

    return new Resolved(
        Paths.get("/etc/cryptad"),
        Paths.get("/var/lib/cryptad"),
        Paths.get("/var/cache/cryptad"),
        Paths.get("/run/cryptad"),
        Paths.get("/var/log/cryptad"));
  }

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
