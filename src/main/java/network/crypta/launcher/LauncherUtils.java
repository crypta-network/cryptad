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
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.imageio.ImageIO;
import network.crypta.fs.AppEnv;

import static network.crypta.launcher.LauncherLog.logDebug;

/** Utility helpers shared by the launcher runtime and launcher-focused tests. */
public final class LauncherUtils {
  private static final Pattern PORT_RE =
      Pattern.compile(
          "Starting\\s+FProxy\\s+on\\s+.*:(\\d{2,5})(?:\\s*|$)", Pattern.CASE_INSENSITIVE);
  private static final Pattern CONF_RE_1 = Pattern.compile("CONF=\"([^\"]*wrapper\\.conf)\"");
  private static final Pattern CONF_RE_2 = Pattern.compile("-c\\s+\"([^\"]*wrapper\\.conf)\"");

  public static final String CRYPTAD_PATH_ENV = "CRYPTAD_PATH";

  private LauncherUtils() {}

  /** Parse the FProxy listen port from a launcher log line. */
  public static Integer parseFProxyPortFromLine(String line) {
    Matcher matcher = PORT_RE.matcher(line);
    if (matcher.find()) {
      return parsePort(matcher.group(1));
    }
    String lower = line.toLowerCase();
    if (lower.contains("starting") && lower.contains("fproxy") && lower.contains("on ")) {
      int idx = line.lastIndexOf(':');
      if (idx > 0 && idx + 1 < line.length()) {
        String tail = line.substring(idx + 1).trim();
        if (tail.length() >= 2 && tail.length() <= 5 && tail.chars().allMatch(Character::isDigit)) {
          return parsePort(tail);
        }
      }
    }
    return null;
  }

  private static Integer parsePort(String value) {
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException ignored) {
      return null;
    }
  }

  /** Parse key/value wrapper.conf lines, ignoring blank and comment lines. */
  public static Map<String, String> parseWrapperProperties(List<String> lines) {
    Map<String, String> props = new LinkedHashMap<>();
    for (String raw : lines) {
      String line = raw.trim();
      if (line.isEmpty() || line.startsWith("#")) {
        continue;
      }
      int idx = line.indexOf('=');
      if (idx <= 0) {
        continue;
      }
      String key = line.substring(0, idx).trim();
      String value = line.substring(idx + 1).trim();
      props.put(key, value);
    }
    return props;
  }

  /**
   * Upsert a single wrapper property line, replacing the first existing occurrence when present.
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

  /** Compute the effective wrapper log path relative to wrapper.conf when needed. */
  public static Path computeWrapperLogPath(Path confPath, String logSpec) {
    String spec = (logSpec == null || logSpec.isBlank()) ? "../logs/wrapper.log" : logSpec;
    Path path = Paths.get(spec);
    if (path.isAbsolute()) {
      return path;
    }
    return wrapperConfDirectory(confPath).resolve(path).normalize();
  }

  /** Resolve a wrapper-declared file path against wrapper.conf and wrapper.working.dir. */
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

  /** Guess wrapper.conf location for a cryptad wrapper script. */
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

  /** Scan script lines for explicit wrapper.conf assignment. */
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

  /** Resolve cryptad wrapper path using env override, classpath jar, then cwd fallbacks. */
  public static Path resolveCryptadPath() {
    return resolveCryptadPath(Paths.get(System.getProperty("user.dir")));
  }

  /** Resolve cryptad wrapper path using env override, classpath jar, then cwd fallbacks. */
  public static Path resolveCryptadPath(Path cwd) {
    return resolveCryptadPathWithEnv(cwd, System.getenv());
  }

  /** Testing helper that allows injecting custom environment variables. */
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
    return cwd.resolve(isWindows ? "cryptad.bat" : "cryptad");
  }

  /** Locate the running cryptad jar by protection domain or class path scan. */
  public static Path findCurrentCryptadJarPath() {
    try {
      var location = LauncherUtils.class.getProtectionDomain().getCodeSource();
      if (location != null) {
        Path decoded =
            Paths.get(URLDecoder.decode(location.getLocation().toURI().getPath(), "UTF-8"));
        if (isCryptadJarFile(decoded)) {
          return decoded.normalize();
        }
      }
    } catch (Exception e) {
      logDebug("Failed to decode current jar path from protection domain", e);
    }

    return findCryptadJarInClassPath(System.getProperty("java.class.path", ""));
  }

  /** Find a cryptad*.jar entry in a Java classpath string. */
  public static Path findCryptadJarInClassPath(String classPath) {
    if (classPath == null || classPath.isBlank()) {
      return null;
    }
    Pattern namePattern = Pattern.compile("^cryptad(?:[-.].*)?\\.jar$", Pattern.CASE_INSENSITIVE);
    for (String raw : classPath.split(Pattern.quote(File.pathSeparator))) {
      if (raw == null || raw.isBlank()) {
        continue;
      }
      try {
        Path path = Paths.get(raw);
        if (Files.isRegularFile(path)) {
          String name = path.getFileName() != null ? path.getFileName().toString() : "";
          if (namePattern.matcher(name).matches()) {
            return path.normalize();
          }
        }
      } catch (Exception e) {
        logDebug("Error scanning classpath entry for cryptad jar: '" + raw + "'", e);
      }
    }
    return null;
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
      candidates.add(jarDir.resolve("cryptad.bat").normalize());
      candidates.add(jarDir.resolve("../bin/cryptad.bat").normalize());
    }
    candidates.add(jarDir.resolve("cryptad").normalize());
    candidates.add(jarDir.resolve("../bin/cryptad").normalize());

    for (Path candidate : candidates) {
      if (Files.isRegularFile(candidate) && Files.isExecutable(candidate)) {
        return candidate;
      }
    }
    return null;
  }

  private static Path resolveCryptadPathFromCwd(Path cwd, boolean isWindows) {
    List<Path> candidates = new ArrayList<>();
    if (isWindows) {
      candidates.add(cwd.resolve("bin/cryptad.bat"));
    }
    candidates.add(cwd.resolve("bin/cryptad"));
    if (isWindows) {
      candidates.add(cwd.resolve("cryptad.bat"));
    }
    candidates.add(cwd.resolve("cryptad"));

    for (Path candidate : candidates) {
      if (Files.isRegularFile(candidate) && Files.isExecutable(candidate)) {
        return candidate;
      }
    }
    return null;
  }

  private static boolean isCryptadJarFile(Path path) {
    if (!Files.isRegularFile(path)) {
      return false;
    }
    String name = path.getFileName() != null ? path.getFileName().toString() : "";
    return name.startsWith("cryptad") && name.endsWith(".jar");
  }

  /** Build the process command line for launching the daemon wrapper script. */
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

  /** Minimal POSIX-safe shell quoting for a single argument. */
  public static String shellQuote(String s) {
    if (s.isEmpty()) {
      return "''";
    }
    return "'" + s.replace("'", "'\"'\"'") + "'";
  }

  /** Find a command on PATH and return the resolved executable path. */
  public static String findOnPath(String cmd) {
    String path = System.getenv("PATH");
    if (path == null) {
      return null;
    }
    for (String dir : path.split(Pattern.quote(File.pathSeparator))) {
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

  /** Load an application icon image from classpath resources or docs fallback. */
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
