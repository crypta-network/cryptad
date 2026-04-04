package network.crypta.launcher;

import java.awt.Image;
import java.io.File;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.imageio.ImageIO;
import network.crypta.config.CryptadConfig;
import network.crypta.fs.AppDirs;
import network.crypta.fs.AppEnv;
import network.crypta.fs.Resolved;
import network.crypta.fs.ServiceDirs;
import network.crypta.fs.readiness.LauncherReadinessFiles;

import static network.crypta.launcher.LauncherLog.logDebug;

/**
 * Utility methods shared by launcher runtime code and launcher-focused tests.
 *
 * <p>This class centralizes reusable logic that would otherwise be duplicated across controller,
 * startup, and test code paths. It includes parser helpers for launcher output and wrapper
 * configuration files, path resolution logic for locating scripts and jar files, small command-line
 * construction helpers, and icon resource loading utilities. Methods are static and side-effect
 * free where practical, so call sites can use them without owning additional state.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Resolving executable and wrapper locations from environment, classpath, and filesystem
 *       fallbacks.
 *   <li>Parsing runtime output and wrapper properties into structured values.
 *   <li>Building launcher command lines and loading platform-appropriate icon assets.
 * </ul>
 */
public final class LauncherUtils {
  private static final Pattern CONF_RE_1 = Pattern.compile("CONF=\"([^\"]*wrapper\\.conf)\"");
  private static final Pattern CONF_RE_2 = Pattern.compile("-c\\s+\"([^\"]*wrapper\\.conf)\"");
  private static final Pattern PATH_SPLITTER = Pattern.compile(Pattern.quote(File.pathSeparator));

  /**
   * Environment variable key used to explicitly override launcher script location.
   *
   * <p>When set, path resolution treats this value as highest-precedence input.
   */
  public static final String CRYPTAD_PATH_ENV = "CRYPTAD_PATH";

  private static final String CRYPTAD_SCRIPT = "cryptad";
  private static final String CRYPTAD_SCRIPT_WINDOWS = "cryptad.bat";
  private static final String CONFIG_FILE_NAME = "cryptad.ini";
  private static final String NODE_INSTALL_RUN_DIR_KEY = "node.install.runDir";
  private static final String LOGGER_DIRNAME_KEY = "logger.dirname";
  private static final String DAEMON_LOG_FILE_NAME = "crypta-latest.log";
  private static final String RUN_DIR_MARKER = "Run dir:";

  private LauncherUtils() {}

  /**
   * Parses a likely FProxy listening port from a legacy launcher log line.
   *
   * <p>The parser uses conservative heuristics and returns {@code null} unless the line appears to
   * describe FProxy startup and contains a plausible numeric tail after the last colon. The
   * launcher keeps this only as a narrow compatibility fallback when structured readiness-file
   * discovery is unavailable.
   *
   * @param line launcher output line to inspect
   * @return parsed port number when recognized, otherwise {@code null}
   */
  public static Integer parseFProxyPortFromLine(String line) {
    String lower = line.toLowerCase(Locale.ROOT);
    if (!(lower.contains("starting") && lower.contains("fproxy") && lower.contains("on "))) {
      return null;
    }
    int idx = line.lastIndexOf(':');
    if (idx <= 0 || idx + 1 >= line.length()) {
      return null;
    }
    String tail = line.substring(idx + 1).trim();
    int digits = 0;
    while (digits < tail.length() && Character.isDigit(tail.charAt(digits))) {
      digits++;
    }
    if (digits < 2 || digits > 5) {
      return null;
    }
    if (digits < tail.length() && !Character.isWhitespace(tail.charAt(digits))) {
      return null;
    }
    return parsePort(tail.substring(0, digits));
  }

  /**
   * Parses the daemon's resolved runtime directory from startup diagnostics.
   *
   * <p>The node logs a multi-line "Resolved directories" block during bootstrap. When a line
   * containing the resolved run directory is observed, the launcher can retarget readiness-file
   * polling to the daemon's actual runtime directory even if configuration or CLI overrides moved
   * it away from the launcher's default AppDirs or ServiceDirs path.
   *
   * @param line launcher output line to inspect
   * @return normalized run-directory path when present, otherwise {@code null}
   */
  public static Path parseResolvedRunDirFromLine(String line) {
    int idx = line.indexOf(RUN_DIR_MARKER);
    if (idx < 0) {
      return null;
    }
    String tail = line.substring(idx + RUN_DIR_MARKER.length()).trim();
    if (tail.isEmpty()) {
      return null;
    }
    try {
      return Path.of(tail).normalize();
    } catch (RuntimeException e) {
      logDebug("Failed parsing launcher runDir from line: " + line, e);
      return null;
    }
  }

  /**
   * Resolves the readiness file path the daemon is expected to use for this launcher process.
   *
   * <p>The launcher first resolves the default base directories from the current environment. If
   * the normal {@code cryptad.ini} exists under the resolved config directory, the launcher loads
   * it with the same placeholder expansion used by daemon startup so {@code node.install.runDir}
   * overrides are honored before startup begins. When the config file is missing or unreadable, the
   * default resolved run directory remains the fallback.
   *
   * @return readiness-file path for the configured or default daemon runtime directory
   */
  public static Path resolveConfiguredLauncherReadinessFile() {
    Resolved resolvedDirs = resolveCurrentProcessDirs();
    Path configFile = resolvedDirs.configDir().resolve(CONFIG_FILE_NAME);
    return resolveConfiguredLauncherReadinessFile(configFile, resolvedDirs);
  }

  static Path resolveConfiguredLauncherReadinessFile(Path configFile, Resolved resolvedDirs) {
    Path defaultReadinessFile = LauncherReadinessFiles.resolve(resolvedDirs.runDir());
    if (!Files.isRegularFile(configFile)) {
      return defaultReadinessFile;
    }
    try {
      String runDir =
          CryptadConfig.loadExpandingPlaceholders(configFile, resolvedDirs)
              .get(NODE_INSTALL_RUN_DIR_KEY);
      if (runDir == null || runDir.isBlank()) {
        return defaultReadinessFile;
      }
      return LauncherReadinessFiles.resolve(Path.of(runDir).normalize());
    } catch (Exception e) {
      logDebug(
          "Failed resolving launcher readiness path from " + configFile + "; using default runDir",
          e);
      return defaultReadinessFile;
    }
  }

  /**
   * Resolves the daemon log file path the launcher can watch for startup diagnostics.
   *
   * <p>The launcher uses the same placeholder-expanded {@code cryptad.ini} view as daemon startup
   * so configured {@code logger.dirname} values are honored before the process begins. When the
   * config file is missing or unreadable, the default resolved logs directory remains the fallback.
   *
   * @return expected path to the daemon's rolling startup log
   */
  public static Path resolveConfiguredLauncherDaemonLogFile() {
    Resolved resolvedDirs = resolveCurrentProcessDirs();
    Path configFile = resolvedDirs.configDir().resolve(CONFIG_FILE_NAME);
    return resolveConfiguredLauncherDaemonLogFile(configFile, resolvedDirs);
  }

  static Path resolveConfiguredLauncherDaemonLogFile(Path configFile, Resolved resolvedDirs) {
    Path logsDir = resolvedDirs.logsDir();
    if (Files.isRegularFile(configFile)) {
      try {
        String configuredLogDir =
            CryptadConfig.loadExpandingPlaceholders(configFile, resolvedDirs)
                .get(LOGGER_DIRNAME_KEY);
        if (configuredLogDir != null && !configuredLogDir.isBlank()) {
          logsDir = Path.of(configuredLogDir).normalize();
        }
      } catch (Exception e) {
        logDebug(
            "Failed resolving launcher daemon log path from "
                + configFile
                + "; using default logsDir",
            e);
      }
    }
    return logsDir.resolve(DAEMON_LOG_FILE_NAME);
  }

  private static Integer parsePort(String value) {
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException _) {
      return null;
    }
  }

  /**
   * Parses wrapper property lines into a key/value map.
   *
   * <p>Blank lines, comment lines, and malformed lines without a key/value separator are skipped.
   * Later duplicate keys overwrite earlier values in the insertion order.
   *
   * @param lines raw wrapper configuration lines
   * @return parsed properties in encounter order
   */
  public static Map<String, String> parseWrapperProperties(List<String> lines) {
    Map<String, String> props = new LinkedHashMap<>();
    for (String raw : lines) {
      String line = raw.trim();
      int idx = line.indexOf('=');
      if (line.isEmpty() || line.startsWith("#") || idx <= 0) {
        continue;
      }
      String key = line.substring(0, idx).trim();
      String value = line.substring(idx + 1).trim();
      props.put(key, value);
    }
    return props;
  }

  /**
   * Upserts one wrapper property line in a copy of the provided configuration lines.
   *
   * <p>The first existing occurrence of {@code key} is replaced when present; otherwise a new line
   * is appended at the end.
   *
   * @param lines existing wrapper configuration lines
   * @param key property key to update or insert
   * @param value property value to store
   * @return updated line list containing exactly one inserted or replaced property line
   */
  public static List<String> upsertWrapperProperty(List<String> lines, String key, String value) {
    String updatedLine = key + "=" + value;
    int existingIndex = -1;
    for (int i = 0; i < lines.size(); i++) {
      if (matchesWrapperKey(lines.get(i), key)) {
        existingIndex = i;
        break;
      }
    }

    List<String> updated = new ArrayList<>(lines);
    if (existingIndex >= 0) {
      updated.set(existingIndex, updatedLine);
    } else {
      updated.add(updatedLine);
    }
    return updated;
  }

  /**
   * Computes the effective wrapper log path.
   *
   * <p>When {@code logSpec} is missing, a default relative path is applied. Relative values are
   * resolved from the wrapper configuration directory.
   *
   * @param confPath wrapper configuration file path
   * @param logSpec configured log path string, absolute or relative
   * @return normalized absolute or relative filesystem path for wrapper logging
   */
  public static Path computeWrapperLogPath(Path confPath, String logSpec) {
    String spec = (logSpec == null || logSpec.isBlank()) ? "../logs/wrapper.log" : logSpec;
    Path path = Paths.get(spec);
    if (path.isAbsolute()) {
      return path;
    }
    return wrapperConfDirectory(confPath).resolve(path).normalize();
  }

  /**
   * Resolves a wrapper-declared file path using wrapper configuration context.
   *
   * <p>Absolute file specifications are normalized directly. Relative paths are resolved from the
   * wrapper configuration directory or the optional wrapper working directory when supplied.
   *
   * @param confPath wrapper configuration file path
   * @param fileSpec configured file path string to resolve
   * @param workingDirSpec optional wrapper working directory specification
   * @return normalized resolved path, or {@code null} when {@code fileSpec} is missing
   */
  public static Path computeWrapperFilePath(Path confPath, String fileSpec, String workingDirSpec) {
    if (fileSpec == null || fileSpec.isBlank()) {
      return null;
    }
    Path path = Paths.get(fileSpec);
    if (path.isAbsolute()) {
      return path.normalize();
    }

    Path confDir = wrapperConfDirectory(confPath);
    Path base = confDir;
    if (workingDirSpec != null && !workingDirSpec.isBlank()) {
      Path wd = Paths.get(workingDirSpec);
      base = wd.isAbsolute() ? wd.normalize() : confDir.resolve(wd).normalize();
    }
    return base.resolve(path).normalize();
  }

  private static Path wrapperConfDirectory(Path confPath) {
    Path parent = confPath.getParent();
    if (parent != null) {
      return parent;
    }
    Path normalized = confPath.toAbsolutePath().normalize();
    return normalized.getParent() != null ? normalized.getParent() : normalized;
  }

  /**
   * Guesses the wrapper configuration path associated with a cryptad wrapper script.
   *
   * <p>The method first checks the conventional relative configuration location. When the script is
   * readable, it scans the script header for explicit wrapper configuration assignments.
   *
   * @param cryptadPath path to the cryptad wrapper script
   * @return inferred wrapper configuration path, or {@code null} when script directory is
   *     unavailable
   */
  public static Path guessWrapperConfPathForCryptadScript(Path cryptadPath) {
    Path scriptDir = cryptadPath.getParent();
    if (scriptDir == null) {
      return null;
    }

    Path defaultConf = scriptDir.resolve("../conf/wrapper.conf").normalize();
    if (Files.isRegularFile(defaultConf)) {
      return defaultConf;
    }
    if (!Files.isRegularFile(cryptadPath)) {
      return defaultConf;
    }

    try {
      Path scanned = scanWrapperConfPath(Files.readAllLines(cryptadPath, StandardCharsets.UTF_8));
      return scanned != null ? scanned : defaultConf;
    } catch (Exception e) {
      logDebug("Failed reading cryptad script to locate wrapper.conf; using default", e);
      return defaultConf;
    }
  }

  /**
   * Scans script lines for explicit wrapper configuration references.
   *
   * <p>Only the first 200 lines are inspected to limit work on large scripts.
   *
   * @param lines script file lines to inspect
   * @return a normalized wrapper configuration path when discovered, otherwise {@code null}
   */
  public static Path scanWrapperConfPath(List<String> lines) {
    int max = Math.min(lines.size(), 200);
    for (int i = 0; i < max; i++) {
      String line = lines.get(i);
      Matcher m1 = CONF_RE_1.matcher(line);
      if (m1.find()) {
        return Paths.get(m1.group(1)).normalize();
      }
      Matcher m2 = CONF_RE_2.matcher(line);
      if (m2.find()) {
        return Paths.get(m2.group(1)).normalize();
      }
    }
    return null;
  }

  /**
   * Resolves cryptad launcher script path using the default working directory and process
   * environment.
   *
   * @return resolved script path according to configured fallback order
   */
  public static Path resolveCryptadPath() {
    return resolveCryptadPath(Paths.get(System.getProperty("user.dir")));
  }

  /**
   * Resolves cryptad launcher script path using an explicit working directory.
   *
   * <p>Resolution order checks environment override, runtime jar vicinity, and working-directory
   * fallbacks.
   *
   * @param cwd working directory used for relative fallback candidates
   * @return resolved script path according to configured fallback order
   */
  public static Path resolveCryptadPath(Path cwd) {
    return resolveCryptadPathWithEnv(cwd, System.getenv());
  }

  /**
   * Resolves cryptad launcher script path with injected environment values.
   *
   * <p>This overload is used by tests and deterministic callers that should not rely on ambient
   * process environment.
   *
   * @param cwd working directory used for relative fallback candidates
   * @param env environment variables used during path resolution
   * @return resolved script path according to configured fallback order
   */
  public static Path resolveCryptadPathWithEnv(Path cwd, Map<String, String> env) {
    Path fromEnv = resolveCryptadPathFromEnv(cwd, env);
    if (fromEnv != null) {
      return fromEnv;
    }

    boolean isWindows = new AppEnv().isWindows();
    Path fromJar = resolveCryptadPathFromJar(isWindows);
    if (fromJar != null) {
      return fromJar;
    }

    Path fromCwd = resolveCryptadPathFromCwd(cwd, isWindows);
    if (fromCwd != null) {
      return fromCwd;
    }
    return cwd.resolve(isWindows ? CRYPTAD_SCRIPT_WINDOWS : CRYPTAD_SCRIPT);
  }

  /**
   * Locates the currently running cryptad jar path.
   *
   * <p>The lookup first inspects the protection-domain code source, then falls back to scanning
   * current Java classpath entries.
   *
   * @return a normalized jar path when found, otherwise {@code null}
   */
  public static Path findCurrentCryptadJarPath() {
    try {
      var location = LauncherUtils.class.getProtectionDomain().getCodeSource();
      if (location != null) {
        Path decoded =
            Paths.get(
                URLDecoder.decode(
                    location.getLocation().toURI().getPath(), StandardCharsets.UTF_8));
        if (isCryptadJarFile(decoded)) {
          return decoded.normalize();
        }
      }
    } catch (Exception e) {
      logDebug("Failed to decode current jar path from protection domain", e);
    }

    return findCryptadJarInClassPath(System.getProperty("java.class.path", ""));
  }

  /**
   * Finds a cryptad jar entry inside a Java classpath string.
   *
   * @param classPath classpath string to scan using platform path separators
   * @return a normalized matching jar path when present, otherwise {@code null}
   */
  public static Path findCryptadJarInClassPath(String classPath) {
    if (classPath == null || classPath.isBlank()) {
      return null;
    }
    Pattern namePattern =
        Pattern.compile("^" + CRYPTAD_SCRIPT + "(?:[-.].*)?\\.jar$", Pattern.CASE_INSENSITIVE);
    for (String raw : PATH_SPLITTER.split(classPath, 0)) {
      Path jarPath = resolveCryptadJarFromClassPathEntry(raw, namePattern);
      if (jarPath != null) {
        return jarPath;
      }
    }
    return null;
  }

  private static Path resolveCryptadJarFromClassPathEntry(String raw, Pattern namePattern) {
    if (raw == null || raw.isBlank()) {
      return null;
    }
    try {
      Path path = Paths.get(raw);
      if (!Files.isRegularFile(path)) {
        return null;
      }
      Path fileName = path.getFileName();
      String name = fileName != null ? fileName.toString() : "";
      return namePattern.matcher(name).matches() ? path.normalize() : null;
    } catch (Exception e) {
      logDebug("Error scanning classpath entry for cryptad jar: '" + raw + "'", e);
      return null;
    }
  }

  private static boolean matchesWrapperKey(String raw, String key) {
    String trimmed = raw.trim();
    if (trimmed.isEmpty() || trimmed.startsWith("#")) {
      return false;
    }
    int idx = trimmed.indexOf('=');
    if (idx <= 0) {
      return false;
    }
    return trimmed.substring(0, idx).trim().equals(key);
  }

  private static Resolved resolveCurrentProcessDirs() {
    AppEnv env = new AppEnv();
    return env.isServiceMode() ? new ServiceDirs().resolve() : new AppDirs().resolve();
  }

  private static Path resolveCryptadPathFromEnv(Path cwd, Map<String, String> env) {
    String raw = env.get(CRYPTAD_PATH_ENV);
    if (raw == null || raw.isBlank()) {
      return null;
    }
    Path path = Paths.get(raw.trim());
    return (path.isAbsolute() ? path : cwd.resolve(path)).normalize();
  }

  private static Path resolveCryptadPathFromJar(boolean isWindows) {
    Path jar = findCurrentCryptadJarPath();
    if (jar == null) {
      return null;
    }
    Path jarDir = jar.getParent();
    if (jarDir == null) {
      return null;
    }

    List<Path> candidates = new ArrayList<>();
    if (isWindows) {
      candidates.add(jarDir.resolve(CRYPTAD_SCRIPT_WINDOWS).normalize());
      candidates.add(jarDir.resolve("../bin/" + CRYPTAD_SCRIPT_WINDOWS).normalize());
    }
    candidates.add(jarDir.resolve(CRYPTAD_SCRIPT).normalize());
    candidates.add(jarDir.resolve("../bin/" + CRYPTAD_SCRIPT).normalize());

    for (Path candidate : candidates) {
      if (isLaunchScriptCandidate(candidate, isWindows)) {
        return candidate;
      }
    }
    return null;
  }

  private static Path resolveCryptadPathFromCwd(Path cwd, boolean isWindows) {
    List<Path> candidates = new ArrayList<>();
    if (isWindows) {
      candidates.add(cwd.resolve("bin/" + CRYPTAD_SCRIPT_WINDOWS));
    }
    candidates.add(cwd.resolve("bin/" + CRYPTAD_SCRIPT));
    if (isWindows) {
      candidates.add(cwd.resolve(CRYPTAD_SCRIPT_WINDOWS));
    }
    candidates.add(cwd.resolve(CRYPTAD_SCRIPT));

    for (Path candidate : candidates) {
      if (isLaunchScriptCandidate(candidate, isWindows)) {
        return candidate;
      }
    }
    return null;
  }

  private static boolean isLaunchScriptCandidate(Path candidate, boolean isWindows) {
    if (!Files.isRegularFile(candidate)) {
      return false;
    }
    // Windows launch scripts are often .bat files where executable bit checks are unreliable.
    if (isWindows) {
      return true;
    }
    return Files.isExecutable(candidate);
  }

  private static boolean isCryptadJarFile(Path path) {
    if (!Files.isRegularFile(path)) {
      return false;
    }
    Path fileName = path.getFileName();
    String name = fileName != null ? fileName.toString() : "";
    return name.startsWith(CRYPTAD_SCRIPT) && name.endsWith(".jar");
  }

  /**
   * Builds the command line used to launch the daemon wrapper script.
   *
   * <p>On non-Windows platforms the method prefers invoking through {@code script} when available,
   * which improves output flushing behavior for wrapper-driven logs.
   *
   * @param cryptadPath resolved cryptad wrapper script path
   * @return immutable command token list suitable for {@link ProcessBuilder}
   */
  public static List<String> buildCryptadCommand(Path cryptadPath) {
    AppEnv env = new AppEnv();
    if (!env.isWindows()) {
      String script = findOnPath("script");
      if (script != null) {
        if (env.isLinux()) {
          return List.of(
              script, "-q", "-c", "exec " + shellQuote(cryptadPath.toString()), "/dev/null");
        }
        return List.of(script, "-q", "/dev/null", cryptadPath.toString());
      }
    }
    return List.of(cryptadPath.toString());
  }

  /**
   * Applies minimal POSIX-safe single-argument shell quoting.
   *
   * @param s raw argument string
   * @return quoted argument string suitable for single-token shell embedding
   */
  public static String shellQuote(String s) {
    if (s.isEmpty()) {
      return "''";
    }
    return "'" + s.replace("'", "'\"'\"'") + "'";
  }

  /**
   * Finds an executable command on the current process {@code PATH}.
   *
   * @param cmd executable command name to search
   * @return resolved executable path string when found, otherwise {@code null}
   */
  public static String findOnPath(String cmd) {
    String path = System.getenv("PATH");
    if (path == null) {
      return null;
    }
    for (String dir : PATH_SPLITTER.split(path, 0)) {
      try {
        Path candidate = Paths.get(dir).resolve(cmd);
        if (Files.isRegularFile(candidate) && Files.isExecutable(candidate)) {
          return candidate.toString();
        }
      } catch (Exception e) {
        logDebug("Error checking PATH entry '" + dir + "' for '" + cmd + "'", e);
      }
    }
    return null;
  }

  /**
   * Loads launcher icon image resources for the current platform.
   *
   * <p>The loader checks platform-priority classpath resources first and falls back to a docs image
   * file when packaged resources are unavailable.
   *
   * @return decoded icon image, or {@code null} when no readable image source is available
   */
  public static Image loadAppIconImage() {
    ClassLoader cl = Thread.currentThread().getContextClassLoader();
    AppEnv env = new AppEnv();
    List<String> candidates = new ArrayList<>();

    if (env.isMac()) {
      candidates.add("network/crypta/launcher/crypta-launcher-icon-macos.png");
    } else if (env.isWindows()) {
      candidates.add("network/crypta/launcher/crypta-launcher-icon-windows.png");
    } else {
      candidates.add("network/crypta/launcher/crypta-launcher-icon-macos.png");
      candidates.add("network/crypta/launcher/crypta-launcher-icon-windows.png");
    }

    for (String candidate : candidates) {
      try {
        var resource = cl.getResource(candidate);
        if (resource != null) {
          return ImageIO.read(resource);
        }
      } catch (Exception e) {
        logDebug("Failed to read icon resource '" + candidate + "'", e);
      }
    }

    try {
      Path fallback = Paths.get("docs/images/crypta_logo.png");
      if (Files.isRegularFile(fallback)) {
        return ImageIO.read(fallback.toFile());
      }
    } catch (Exception e) {
      logDebug("Failed reading fallback icon from docs/images/crypta_logo.png", e);
    }

    return null;
  }
}
