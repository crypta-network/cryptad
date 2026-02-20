package network.crypta.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.regex.Pattern;
import network.crypta.fs.Resolved;
import network.crypta.support.SimpleFieldSet;

/**
 * Loads, expands, and normalizes Cryptad configuration values with directory-aware defaults.
 *
 * <p>This utility centralizes the configuration file lifecycle for the launcher and node startup
 * path. It can create a missing configuration file from an embedded template, parse values into a
 * {@link SimpleFieldSet}, expand placeholders such as {@code ${configDir}} and {@code ${dataDir}},
 * and materialize default directory settings when required keys are absent. Expansion applies
 * deterministic anchoring and normalization, so relative suffixes are resolved under known base
 * directories while protecting against directory traversal patterns.
 *
 * <p>Primary responsibilities:
 *
 * <ul>
 *   <li>Provide stable default configuration values for installation, cache, run, download, and log
 *       paths.
 *   <li>Translate placeholder-driven and shorthand path expressions into concrete normalized paths.
 *   <li>Create configured directory trees on a best-effort basis after expansion.
 * </ul>
 */
public final class CryptadConfig {
  private static final Pattern TRAVERSAL_PATTERN = Pattern.compile("(^|/)\\.\\.(/|$)");
  private static final String DATA_DIR_KEY = "dataDir";
  private static final String CACHE_DIR_KEY = "cacheDir";

  /**
   * Minimal default configuration template used for first-run file creation.
   *
   * <p>The template intentionally contains only baseline keys required for startup and updater
   * behavior, leaving directory and path keys to be derived during expansion. A trailing newline is
   * included so generated files follow standard text-file termination conventions.
   */
  public static final String DEFAULT_TEMPLATE =
      """
      # Cryptad config (auto-generated)
      logger.priority=NORMAL
      node.updater.enabled=true
      node.updater.autoupdate=false
      End

      """;

  private CryptadConfig() {}

  /**
   * Loads configuration from disk and expands placeholders using the current JVM system properties.
   *
   * <p>This convenience overload delegates to {@link #loadExpandingPlaceholders(Path, Resolved,
   * Properties)} and uses {@link System#getProperties()} as the source for values such as {@code
   * user.home} and {@code java.io.tmpdir}. Use this entry point when the runtime environment should
   * define home and temporary directories. The returned field set contains expanded values and
   * includes finalized defaults for required install and runtime keys.
   *
   * @param configFile path to the configuration file that should be loaded or created
   * @param dirs resolved directory set that supplies base locations for placeholders
   * @return expanded configuration values with final default keys applied
   * @throws IOException if parent directory creation, file creation, read, or write operations fail
   */
  @SuppressWarnings("unused")
  public static SimpleFieldSet loadExpandingPlaceholders(Path configFile, Resolved dirs)
      throws IOException {
    return loadExpandingPlaceholders(configFile, dirs, System.getProperties());
  }

  /**
   * Loads configuration, expands placeholders, and ensures required directories exist.
   *
   * <p>If the target file does not exist, this method creates parent directories as needed and
   * writes {@link #DEFAULT_TEMPLATE} using UTF-8. It then parses the file, expands placeholders and
   * leading-token shorthand through {@link #expandAll(SimpleFieldSet, Resolved, Properties)}, and
   * finally attempts to create all configured directories. Directory creation is best-effort, but
   * configuration file creation and parsing failures propagate to the caller.
   *
   * @param configFile path to the on-disk configuration file
   * @param dirs resolved directory set that defines placeholder base paths
   * @param systemProps property source used for home and temporary directory values
   * @return expanded configuration values ready for downstream startup usage
   * @throws IOException if file or parent directory creation, read, or initial write fails
   */
  public static SimpleFieldSet loadExpandingPlaceholders(
      Path configFile, Resolved dirs, Properties systemProps) throws IOException {
    Path parent = configFile.getParent();
    if (parent != null && !Files.exists(parent)) {
      Files.createDirectories(parent);
    }
    if (!Files.exists(configFile)) {
      Files.writeString(configFile, DEFAULT_TEMPLATE, StandardCharsets.UTF_8);
    }
    SimpleFieldSet sfs = SimpleFieldSet.readFrom(Files.newInputStream(configFile), true, true);
    SimpleFieldSet expanded = expandAll(sfs, dirs, systemProps);
    createAll(expanded);
    return expanded;
  }

  /**
   * Expands all values in a field set using the current JVM system properties.
   *
   * <p>This overload delegates to {@link #expandAll(SimpleFieldSet, Resolved, Properties)} and
   * supplies {@link System#getProperties()} for runtime-derived placeholders. It is useful when
   * configuration expansion should follow the ambient process environment without test-specific
   * overrides.
   *
   * @param input source configuration field set to copy and expand
   * @param dirs resolved directory set that provides fixed base path placeholders
   * @return a copied field set containing expanded values and defaulted required keys
   */
  @SuppressWarnings("unused")
  public static SimpleFieldSet expandAll(SimpleFieldSet input, Resolved dirs) {
    return expandAll(input, dirs, System.getProperties());
  }

  /**
   * Expands placeholders and shorthand directory tokens for every value in a field set.
   *
   * <p>This method builds a base placeholder map from resolved directories and selected system
   * properties, then processes each key/value pair through {@link #expandValue(String, Map)}.
   * Values that change are overwritten in the returned copy, leaving the original input untouched.
   * After expansion, final fallback values are applied for required install and runtime keys so
   * downstream components can assume the presence of essential paths.
   *
   * @param input source configuration field set that is copied before mutation
   * @param dirs resolved directory set used to seed config, data, cache, run, and log placeholders
   * @param systemProps property source that contributes home and temporary directory values
   * @return expanded copy of {@code input} with deterministic fallback defaults applied
   */
  public static SimpleFieldSet expandAll(
      SimpleFieldSet input, Resolved dirs, Properties systemProps) {
    String home = systemProps.getProperty("user.home");
    String tmp = systemProps.getProperty("java.io.tmpdir");
    Map<String, String> base =
        Map.of(
            "configDir",
            dirs.configDir().toString(),
            DATA_DIR_KEY,
            dirs.dataDir().toString(),
            "stateDir",
            dirs.dataDir().toString(),
            CACHE_DIR_KEY,
            dirs.cacheDir().toString(),
            "runDir",
            dirs.runDir().toString(),
            "logsDir",
            dirs.logsDir().toString(),
            "home",
            home,
            "tmp",
            tmp);

    SimpleFieldSet out = new SimpleFieldSet(input);
    Iterator<String> it = out.keyIterator();
    while (it.hasNext()) {
      String key = it.next();
      String value = out.get(key);
      if (value == null) {
        continue;
      }
      String newVal = expandValue(value, base);
      if (!Objects.equals(newVal, value)) {
        out.putOverwrite(key, newVal);
      }
    }
    ensureFinalDefaults(out, base);
    return out;
  }

  private static void ensureFinalDefaults(SimpleFieldSet sfs, Map<String, String> base) {
    String userDir = Path.of(base.get(DATA_DIR_KEY), "user").toString();
    setIfMissing(sfs, "node.install.cfgDir", base.get("configDir"));
    setIfMissing(sfs, "node.install.storeDir", base.get(DATA_DIR_KEY));
    setIfMissing(sfs, "node.install.userDir", userDir);
    setIfMissing(
        sfs,
        "node.install.pluginStoresDir",
        Path.of(base.get(DATA_DIR_KEY), "plugin-data").toString());
    setIfMissing(
        sfs, "node.install.pluginDir", Path.of(base.get(DATA_DIR_KEY), "plugins").toString());
    setIfMissing(sfs, "node.install.tempDir", Path.of(base.get(CACHE_DIR_KEY), "tmp").toString());
    setIfMissing(
        sfs,
        "node.install.persistentTempDir",
        Path.of(base.get(CACHE_DIR_KEY), "persistent-temp").toString());
    setIfMissing(sfs, "node.install.nodeDir", Path.of(base.get(DATA_DIR_KEY), "node").toString());
    setIfMissing(sfs, "node.install.runDir", base.get("runDir"));
    setIfMissing(sfs, "node.downloadsDir", Path.of(base.get(DATA_DIR_KEY), "downloads").toString());
    setIfMissing(sfs, "logger.dirname", base.get("logsDir"));
    setIfMissing(sfs, "node.masterKeyFile", Path.of(userDir, "master.keys").toString());
  }

  private static void setIfMissing(SimpleFieldSet sfs, String key, String value) {
    if (sfs.get(key) == null) {
      sfs.putSingle(key, value);
    }
  }

  /**
   * Expands and validates a single configuration value against known base directories.
   *
   * <p>The expansion pipeline applies placeholder replacement (for example {@code ${configDir}} and
   * {@code ${dataDir}}), resolves leading-token shorthand such as {@code dataDir/plugins}, and
   * normalizes anchored values beneath recognized base directories. When a normalized anchored
   * value escapes its base, or when unanchored substituted content still includes traversal
   * segments, expansion fails. Internal checked failures are rethrown via a sneaky-throw helper to
   * preserve existing call-site behavior.
   *
   * @param value raw configuration value that may contain placeholders or shorthand tokens
   * @param base mapping from placeholder keys to concrete base directory paths
   * @return expanded and normalized value after placeholder, shorthand, and traversal checks
   * @throws RuntimeException if traversal validation fails during expansion
   */
  public static String expandValue(String value, Map<String, String> base) {
    try {
      PlaceholderResult afterPlaceholders = replacePlaceholders(value, base);
      String afterLeadingToken = expandLeadingToken(afterPlaceholders.value, base);
      AnchorResult anchored = anchorAndNormalize(afterLeadingToken, base, value);
      validateUnanchoredTraversal(
          anchored.value, anchored.anchored, afterPlaceholders.replacedAny, value);
      return anchored.value;
    } catch (IOException ioe) {
      throw sneakyThrow(ioe);
    }
  }

  private static String normSep(String s) {
    return s.replace('\\', '/');
  }

  private static PlaceholderResult replacePlaceholders(String input, Map<String, String> base) {
    String out = input;
    boolean replacedAny = false;
    for (Map.Entry<String, String> e : base.entrySet()) {
      String placeholder = "${" + e.getKey() + "}";
      if (out.contains(placeholder)) {
        replacedAny = true;
      }
      out = out.replace(placeholder, e.getValue());
    }
    return new PlaceholderResult(out, replacedAny);
  }

  private static String expandLeadingToken(String input, Map<String, String> base) {
    String out = input;
    for (Map.Entry<String, String> e : base.entrySet()) {
      String key = e.getKey();
      String val = e.getValue();
      if (out.equals(key)) {
        out = val;
      } else if (out.startsWith(key + "/") || out.startsWith(key + "\\")) {
        String rem = out.substring(key.length() + 1);
        String remNorm = normSep(rem);
        out = Path.of(val, remNorm).toString();
      }
    }
    return out;
  }

  private static AnchorResult anchorAndNormalize(
      String input, Map<String, String> base, String original) throws IOException {
    String out = input;
    boolean anchored = false;
    String outNorm = normSep(out);

    for (String v : base.values()) {
      Path basePath = Path.of(v).normalize();
      String vNorm = normSep(v);
      while (vNorm.endsWith("/")) {
        vNorm = vNorm.substring(0, vNorm.length() - 1);
      }

      if (outNorm.equals(vNorm) || outNorm.equals(vNorm + "/")) {
        out = basePath.toString();
        anchored = true;
        continue;
      }

      String prefix = vNorm + "/";
      if (outNorm.startsWith(prefix)) {
        String remainder = outNorm.substring(prefix.length());
        Path resolved = basePath.resolve(remainder).normalize();
        if (!resolved.startsWith(basePath)) {
          throw new IOException(
              "Illegal path traversal in config value: '"
                  + original
                  + "' (resolved: '"
                  + resolved
                  + "')");
        }
        out = resolved.toString();
        anchored = true;
      }
    }
    return new AnchorResult(out, anchored);
  }

  private static void validateUnanchoredTraversal(
      String out, boolean anchored, boolean replacedAny, String original) throws IOException {
    if (replacedAny && !anchored) {
      String safe = normSep(out);
      if (TRAVERSAL_PATTERN.matcher(safe).find()) {
        throw new IOException(
            "Illegal path traversal in config value: '"
                + original
                + "' (unanchored with '..' segments)");
      }
    }
  }

  private static void createAll(SimpleFieldSet sfs) {
    List<String> keys =
        List.of(
            "node.install.cfgDir",
            "node.install.storeDir",
            "node.install.userDir",
            "node.install.pluginStoresDir",
            "node.install.pluginDir",
            "node.install.tempDir",
            "node.install.persistentTempDir",
            "node.install.nodeDir",
            "node.install.runDir",
            "node.downloadsDir",
            "logger.dirname");

    List<Path> dirs = new ArrayList<>();
    for (String key : keys) {
      String value = sfs.get(key);
      if (value != null) {
        dirs.add(Path.of(value));
      }
    }
    for (Path dir : dirs) {
      try {
        if (!Files.exists(dir)) {
          Files.createDirectories(dir);
        }
      } catch (Exception _) {
        // Best effort.
      }
    }
  }

  /**
   * Copies an existing file to a destination path only when the destination is missing.
   *
   * <p>This helper preserves existing destination files and performs no action when {@code dst}
   * already exists or {@code src} is absent. When a copy is needed, parent directories for the
   * destination are created first. File attributes are preserved through {@link
   * StandardCopyOption#COPY_ATTRIBUTES} to keep metadata aligned with the original file.
   *
   * @param src source path that is copied when it exists
   * @param dst destination path that is created only when currently missing
   * @throws IOException if creating destination parents or copying file contents fails
   */
  public static void copyIfMissing(Path src, Path dst) throws IOException {
    if (!Files.exists(dst) && Files.exists(src)) {
      Path parent = dst.getParent();
      if (parent != null && !Files.exists(parent)) {
        Files.createDirectories(parent);
      }
      Files.copy(src, dst, StandardCopyOption.COPY_ATTRIBUTES);
    }
  }

  private static RuntimeException sneakyThrow(Throwable t) {
    CryptadConfig.throwAny(t);
    throw new IllegalStateException("Unreachable");
  }

  @SuppressWarnings("unchecked")
  private static <T extends Throwable> void throwAny(Throwable t) throws T {
    throw (T) t;
  }

  private record PlaceholderResult(String value, boolean replacedAny) {}

  private record AnchorResult(String value, boolean anchored) {}
}
