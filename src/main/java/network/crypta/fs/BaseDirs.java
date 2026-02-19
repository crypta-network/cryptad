package network.crypta.fs;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public abstract class BaseDirs {
  protected final Map<String, String> env;
  protected final Map<String, String> systemProperties;
  protected final Map<String, String> cliOverrides;
  protected final AppEnv appEnv;

  protected BaseDirs(
      Map<String, String> env,
      Map<String, String> systemProperties,
      Map<String, String> cliOverrides,
      AppEnv appEnv) {
    this.env = Objects.requireNonNull(env);
    this.systemProperties = Objects.requireNonNull(systemProperties);
    this.cliOverrides = Objects.requireNonNull(cliOverrides);
    this.appEnv = Objects.requireNonNull(appEnv);
  }

  protected abstract Resolved computeBase();

  protected Overrides envOverrides() {
    return new Overrides();
  }

  /**
   * Whether to actually create the resolved directories on disk.
   *
   * <p>Defaults to true.
   */
  protected boolean shouldEnsureDirectories() {
    return true;
  }

  public final Resolved resolve() {
    Resolved base = computeBase();
    Overrides envO = envOverrides();
    Overrides cliO = cliOverrides();

    Path finalConfig = firstNonNull(cliO.getConfig(), envO.getConfig(), base.getConfigDir());
    Path finalData = firstNonNull(cliO.getData(), envO.getData(), base.getDataDir());
    Path finalCache = firstNonNull(cliO.getCache(), envO.getCache(), base.getCacheDir());
    Path finalRun = firstNonNull(cliO.getRun(), envO.getRun(), base.getRunDir());
    Path finalLogs = firstNonNull(cliO.getLogs(), envO.getLogs(), base.getLogsDir());

    if (shouldEnsureDirectories()) {
      Dirs.ensureDir(finalConfig, Dirs.PERM_USER_RWX);
      Dirs.ensureDir(finalData, Dirs.PERM_GROUP_RX);
      Dirs.ensureDir(finalCache, Dirs.PERM_GROUP_RX);
      Dirs.ensureDir(finalRun, Dirs.PERM_GROUP_RX);
      Dirs.ensureDir(finalLogs, Dirs.PERM_GROUP_RX);
    }
    return new Resolved(finalConfig, finalData, finalCache, finalRun, finalLogs);
  }

  static Map<String, String> currentSystemProperties() {
    Map<String, String> out = new LinkedHashMap<>();
    for (Map.Entry<Object, Object> entry : System.getProperties().entrySet()) {
      out.put(String.valueOf(entry.getKey()), String.valueOf(entry.getValue()));
    }
    return out;
  }

  private Overrides cliOverrides() {
    return new Overrides(
        asPath(cliOverrides.get("configDir")),
        asPath(cliOverrides.get("dataDir")),
        asPath(cliOverrides.get("cacheDir")),
        asPath(cliOverrides.get("runDir")),
        asPath(cliOverrides.get("logsDir")));
  }

  private static Path asPath(String value) {
    return value != null ? Paths.get(value) : null;
  }

  @SafeVarargs
  private static <T> T firstNonNull(T... values) {
    for (T value : values) {
      if (value != null) {
        return value;
      }
    }
    throw new IllegalStateException("Expected at least one non-null value");
  }
}
