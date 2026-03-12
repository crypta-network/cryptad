package network.crypta.fs;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Shared base implementation for resolving Cryptad directory layouts across runtime modes.
 *
 * <p>Concrete subclasses compute platform- or mode-specific base directories, while this class
 * centralizes override precedence and optional on-disk directory creation. Resolution combines
 * three inputs in deterministic order: command-line overrides, environment overrides, then subclass
 * base defaults. The resulting {@link Resolved} object is immutable and can be reused by startup
 * code for configuration, data, cache, runtime, and log paths.
 *
 * <p>Subclasses are expected to provide base values through {@link #computeBase()} and may refine
 * environment behavior through {@link #envOverrides()}. By default, resolved directories are
 * created eagerly; subclasses can opt out when they need discovery without filesystem mutation.
 *
 * <ul>
 *   <li>Encapsulates precedence between CLI, environment, and computed defaults.
 *   <li>Applies consistent directory permissions when creating resolved locations.
 *   <li>Keeps shared parsing logic for injected system properties and CLI path overrides.
 * </ul>
 */
public abstract class BaseDirs {
  /**
   * Environment variables used by subclasses and override resolution logic.
   *
   * <p>The map is injected to support deterministic tests and non-process environments.
   */
  protected final Map<String, String> env;

  /**
   * System property snapshot used for home/runtime fallback logic.
   *
   * <p>The values are captured as strings and treated as immutable input for resolution.
   */
  protected final Map<String, String> systemProperties;

  /**
   * Command-line directory overrides keyed by logical names such as {@code configDir}.
   *
   * <p>When present, these values have the highest precedence during the final resolution.
   */
  protected final Map<String, String> cliOverrides;

  /**
   * Runtime environment detector used by subclasses for platform and mode decisions.
   *
   * <p>This instance provides OS, sandbox, and service heuristics shared by directory strategies.
   */
  protected final AppEnv appEnv;

  /**
   * Creates the shared resolver base with injected environment and override sources.
   *
   * <p>All inputs are required and are stored as-is for deterministic resolution behavior in both
   * production and tests.
   *
   * @param env environment variables used for directory and mode derivation
   * @param systemProperties system property snapshot used for fallback path computation
   * @param cliOverrides command-line overrides that should take the highest precedence
   * @param appEnv environment detector used for OS and runtime-mode branching
   */
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

  /**
   * Computes base directories for the current strategy before overrides are applied.
   *
   * <p>Subclasses return mode-appropriate defaults for all required directory categories. The
   * returned object must contain non-null paths and should not perform side effects unrelated to
   * computing base values.
   *
   * @return base directory set used as the lowest-precedence resolution input
   */
  protected abstract Resolved computeBase();

  /**
   * Returns environment-derived directory overrides for this strategy.
   *
   * <p>The default implementation returns an empty override set. Subclasses can override to map
   * environment variables to concrete paths. These values are applied after CLI overrides and
   * before computed base values.
   *
   * @return environment override set, possibly empty but never {@code null}
   */
  protected Overrides envOverrides() {
    return new Overrides();
  }

  /**
   * Whether to actually create the resolved directories on disk.
   *
   * <p>Defaults to true.
   *
   * @return {@code true} when {@link #resolve()} should ensure directories exist on disk
   */
  protected boolean shouldEnsureDirectories() {
    return true;
  }

  /**
   * Resolves the final directory set by applying precedence and optional directory creation.
   *
   * <p>This method combines subclass base directories, environment overrides, and CLI overrides in
   * that order of increasing precedence. For each directory category, the first non-null value
   * wins. When {@link #shouldEnsureDirectories()} returns {@code true}, each resolved path is
   * created with the appropriate permission policy before returning.
   *
   * @return immutable resolved directory set for config, data, cache, runtime, and logs
   */
  public final Resolved resolve() {
    Resolved base = computeBase();
    Overrides envO = envOverrides();
    Overrides cliO = cliOverrides();

    Path finalConfig = firstNonNull(cliO.config(), envO.config(), base.configDir());
    Path finalData = firstNonNull(cliO.data(), envO.data(), base.dataDir());
    Path finalCache = firstNonNull(cliO.cache(), envO.cache(), base.cacheDir());
    Path finalRun = firstNonNull(cliO.run(), envO.run(), base.runDir());
    Path finalLogs = firstNonNull(cliO.logs(), envO.logs(), base.logsDir());

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
