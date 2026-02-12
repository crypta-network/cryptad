package network.crypta.launcher

import java.awt.Image
import java.io.File
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import javax.imageio.ImageIO
import network.crypta.fs.AppEnv

/**
 * Collection of small, mostly pure helper functions used by the launcher controller and tests.
 *
 * These utilities focus on log parsing, wrapper configuration parsing, filesystem path
 * normalization, and command construction for launching the daemon. Callers typically use them when
 * wiring the Swing launcher, resolving the wrapper configuration, or extracting the FProxy port
 * from log output. Most functions are deterministic and side-effect light; where they read
 * environment variables or system properties, results can vary with the process environment.
 */

// --- Port parsing ---

private val PORT_RE =
  Regex("""Starting\s+FProxy\s+on\s+.*:(\d{2,5})(?:\s*|$)""", RegexOption.IGNORE_CASE)

/**
 * Try to parse the FProxy HTTP port from a single log line.
 *
 * This function first searches for the canonical "Starting FProxy on ..." pattern and then falls
 * back to a lightweight heuristic that looks for a trailing `:<port>` segment. The port is accepted
 * only when it is 2–5 digits long to avoid matching short or malformed values. The operation is
 * idempotent and has no side effects; it simply returns a nullable port value.
 *
 * @param line raw log line to scan, typically emitted by the daemon or wrapper.
 * @return parsed port number when a match is found, or `null` when no valid port is present.
 */
fun parseFProxyPortFromLine(line: String): Int? {
  PORT_RE.find(line)?.let { m ->
    return m.groupValues[1].toIntOrNull()
  }
  if (
    line.contains("Starting", ignoreCase = true) &&
      line.contains("FProxy", ignoreCase = true) &&
      line.contains("on ", ignoreCase = true)
  ) {
    val idx = line.lastIndexOf(':')
    if (idx > 0 && idx + 1 < line.length) {
      val tail = line.substring(idx + 1).trim()
      if (tail.all { it.isDigit() } && tail.length in 2..5) return tail.toIntOrNull()
    }
  }
  return null
}

// --- wrapper.conf helpers ---

/**
 * Parse wrapper configuration lines into a `key=value` map.
 *
 * Blank lines and comment lines (those starting with `#` after trimming) are ignored. For matching
 * lines, the first `=` is treated as the delimiter and both key and value are trimmed. If a key
 * appears multiple times, the last value wins, which mirrors common configuration semantics.
 *
 * @param lines wrapper configuration lines, already split by newline.
 * @return map of property keys to values, excluding comments and blank lines.
 */
fun parseWrapperProperties(lines: List<String>): Map<String, String> = buildMap {
  lines.forEach { raw ->
    val line = raw.trim()
    if (line.isEmpty() || line.startsWith('#')) return@forEach
    val idx = line.indexOf('=')
    if (idx <= 0) return@forEach
    val k = line.substringBefore('=', "").trim()
    val v = line.substringAfter('=', "").trim()
    put(k, v)
  }
}

/**
 * Upsert a single `key=value` line in a wrapper configuration file.
 *
 * The first existing occurrence of `key` (ignoring leading/trailing whitespace and comments) is
 * replaced, and all other lines are preserved verbatim. If no matching key is found, a new line is
 * appended at the end. This function does not validate the key or value beyond simple matching and
 * does not alter comment or blank lines.
 *
 * @param lines original wrapper configuration lines in their existing order.
 * @param key property key to upsert; compared after trimming whitespace.
 * @param value property value to write as a single line after the `=` delimiter.
 * @return a new list of lines with the update applied, preserving unrelated content.
 */
fun upsertWrapperProperty(lines: List<String>, key: String, value: String): List<String> {
  val updatedLine = "$key=$value"
  val index = lines.indexOfFirst { matchesWrapperKey(it, key) }
  if (index >= 0) {
    val updated = ArrayList<String>(lines.size)
    for (i in lines.indices) {
      updated.add(if (i == index) updatedLine else lines[i])
    }
    return updated
  }
  val appended = ArrayList<String>(lines.size + 1)
  appended.addAll(lines)
  appended.add(updatedLine)
  return appended
}

/**
 * Compute the effective `wrapper.logfile` path.
 *
 * When the provided spec is blank or null, a default relative path of `../logs/wrapper.log` is
 * used. Relative paths are resolved against the parent directory of the wrapper configuration file,
 * and the result is normalized. Absolute paths are returned as-is (after normalization).
 *
 * @param confPath path to the wrapper configuration file used as the base for relative values.
 * @param logSpec value of `wrapper.logfile`, which may be null or blank.
 * @return resolved filesystem path where the wrapper log file is expected to be written.
 */
fun computeWrapperLogPath(confPath: Path, logSpec: String?): Path {
  val spec = logSpec?.takeUnless { it.isBlank() } ?: "../logs/wrapper.log"
  val p = Paths.get(spec)
  return if (p.isAbsolute) p else wrapperConfDirectory(confPath).resolve(p).normalize()
}

/**
 * Compute an effective file path declared in `wrapper.conf`.
 *
 * If `fileSpec` is relative, it is resolved against `wrapper.working.dir` when provided. A relative
 * working directory is itself resolved against the wrapper configuration directory. Absolute
 * `fileSpec` values are normalized and returned directly. If `fileSpec` is null or blank, this
 * function returns `null` to signal the absence of a configured file path.
 *
 * @param confPath path to the wrapper configuration file used as a base for relative paths.
 * @param fileSpec property value that may be absolute, relative, or blank.
 * @param workingDirSpec optional `wrapper.working.dir` value that influences relative resolution.
 * @return normalized path for the configured file, or `null` when no file spec is provided.
 */
fun computeWrapperFilePath(confPath: Path, fileSpec: String?, workingDirSpec: String?): Path? {
  val spec = fileSpec?.takeUnless { it.isBlank() } ?: return null
  val p = Paths.get(spec)
  if (p.isAbsolute) return p.normalize()
  val confDir = wrapperConfDirectory(confPath)
  val base =
    workingDirSpec
      ?.takeUnless { it.isBlank() }
      ?.let { wdRaw ->
        val wd = Paths.get(wdRaw)
        if (wd.isAbsolute) wd.normalize() else confDir.resolve(wd).normalize()
      } ?: confDir
  return base.resolve(p).normalize()
}

private fun wrapperConfDirectory(confPath: Path): Path {
  confPath.parent?.let {
    return it
  }
  val normalized = confPath.toAbsolutePath().normalize()
  return normalized.parent ?: normalized
}

/**
 * Guess the `wrapper.conf` path for a given `cryptad` wrapper script.
 *
 * The method prefers the conventional `../conf/wrapper.conf` location relative to the script
 * directory. If the script is present but the default file does not exist, it scans the first few
 * lines for an explicit `-c ".../wrapper.conf"` or `CONF=".../wrapper.conf"` declaration. When
 * reading the script fails, the default path is returned as a safe fallback.
 *
 * @param cryptadPath path to the wrapper script (`cryptad` or `cryptad.bat`).
 * @return resolved wrapper configuration path, or `null` if the script path has no parent.
 */
fun guessWrapperConfPathForCryptadScript(cryptadPath: Path): Path? {
  val scriptDir = cryptadPath.parent ?: return null
  val defaultConf = scriptDir.resolve("../conf/wrapper.conf").normalize()
  if (Files.isRegularFile(defaultConf)) return defaultConf
  if (!Files.isRegularFile(cryptadPath)) return defaultConf
  return try {
    scanWrapperConfPath(Files.readAllLines(cryptadPath, StandardCharsets.UTF_8)) ?: defaultConf
  } catch (e: Exception) {
    logDebug("Failed reading cryptad script to locate wrapper.conf; using default", e)
    defaultConf
  }
}

/**
 * Scan shell script lines for an explicit `wrapper.conf` path.
 *
 * Only two simple patterns are recognized: `CONF=".../wrapper.conf"` and `-c ".../wrapper.conf"`.
 * The scan stops after the first match and considers only the first 200 lines to keep parsing fast
 * and deterministic.
 *
 * @param lines raw script lines, typically from the wrapper launch script.
 * @return normalized path to `wrapper.conf` when found, or `null` when no match exists.
 */
fun scanWrapperConfPath(lines: List<String>): Path? {
  val re1 = Regex("""CONF="([^"]*wrapper\.conf)"""")
  val re2 = Regex("""-c\s+"([^"]*wrapper\.conf)"""")
  for (line in lines.take(200)) {
    re1.find(line)?.let {
      return Paths.get(it.groupValues[1]).normalize()
    }
    re2.find(line)?.let {
      return Paths.get(it.groupValues[1]).normalize()
    }
  }
  return null
}

/**
 * Resolve the default wrapper launcher path (`cryptad` on Unix, `cryptad.bat` on Windows).
 *
 * Resolution is ordered and stops at the first existing executable. If the `CRYPTAD_PATH`
 * environment variable is set, it is used first (absolute or resolved against `cwd`). Otherwise:
 * - From the currently running `cryptad.jar` location (same directory), then `../bin/`.
 * - From the current working directory: `bin/cryptad` (Unix) or `bin/cryptad.bat` (Windows), then
 *   `./cryptad` or `./cryptad.bat` respectively.
 *
 * This avoids relying on the user's home or working directory when launched from the assembled
 * distribution (bin/ + lib/).
 *
 * @param cwd base directory for relative path resolution, usually the current working directory.
 * @return best-effort path to the wrapper script, even if it does not exist.
 */
fun resolveCryptadPath(cwd: Path = Paths.get(System.getProperty("user.dir"))): Path =
  resolveCryptadPathWithEnv(cwd, System.getenv())

internal const val CRYPTAD_PATH_ENV: String = "CRYPTAD_PATH"

/** Internal helper that allows injecting an environment map (for tests). */
internal fun resolveCryptadPathWithEnv(
  cwd: Path = Paths.get(System.getProperty("user.dir")),
  env: Map<String, String> = System.getenv(),
): Path {
  // 0) Environment override (absolute or relative to cwd)
  resolveCryptadPathFromEnv(cwd, env)?.let {
    return it
  }

  // 1) Try to resolve relative to the currently running cryptad.jar (preferred)
  val isWindows = AppEnv().isWindows()
  resolveCryptadPathFromJar(isWindows)?.let {
    return it
  }

  // 2) Fallback to resolving from the working directory (legacy behavior)
  return resolveCryptadPathFromCwd(cwd, isWindows) ?: cwd.resolve("cryptad")
}

/** Attempt to locate the path to the currently running cryptad.jar. */
internal fun findCurrentCryptadJarPath(): Path? {
  // a) Use the protection domain of a class packaged inside cryptad.jar (the launcher lives there)
  val loc = LauncherController::class.java.protectionDomain?.codeSource?.location
  if (loc != null) {
    try {
      val uri = loc.toURI()
      val decoded = Paths.get(URLDecoder.decode(uri.path, "UTF-8"))
      if (isCryptadJarFile(decoded)) return decoded.normalize()
    } catch (e: Exception) {
      logDebug("Failed to decode current jar path from protection domain", e)
    }
  }

  // b) As a fallback (tests/dev), scan the java.class.path for a cryptad*.jar entry
  val cp = System.getProperty("java.class.path") ?: ""
  return findCryptadJarInClassPath(cp)
}

/** Find a `cryptad*.jar` on the given Java class path string. */
internal fun findCryptadJarInClassPath(classPath: String): Path? {
  if (classPath.isBlank()) return null
  val sep = File.pathSeparator
  val entries = classPath.split(sep)
  val re = Regex("^cryptad(?:[-.].*)?\\.jar$", RegexOption.IGNORE_CASE)
  for (raw in entries) {
    if (raw.isBlank()) continue
    try {
      val p = Paths.get(raw)
      if (Files.isRegularFile(p)) {
        val name = p.fileName?.toString() ?: continue
        if (re.matches(name)) return p.normalize()
      }
    } catch (e: Exception) {
      logDebug("Error scanning classpath entry for cryptad jar: '$raw'", e)
    }
  }
  return null
}

private fun matchesWrapperKey(raw: String, key: String): Boolean {
  val trimmed = raw.trim()
  if (trimmed.isEmpty() || trimmed.startsWith('#')) return false
  val idx = trimmed.indexOf('=')
  if (idx <= 0) return false
  val k = trimmed.substringBefore('=', "").trim()
  return k == key
}

private fun resolveCryptadPathFromEnv(cwd: Path, env: Map<String, String>): Path? {
  val raw = env[CRYPTAD_PATH_ENV] ?: return null
  val trimmed = raw.trim()
  if (trimmed.isEmpty()) return null
  val p = Paths.get(trimmed)
  return (if (p.isAbsolute) p else cwd.resolve(trimmed)).normalize()
}

private fun resolveCryptadPathFromJar(isWindows: Boolean): Path? {
  val jar = findCurrentCryptadJarPath() ?: return null
  val jarDir = jar.parent ?: return null
  val candidates = buildList {
    if (isWindows) {
      add(jarDir.resolve("cryptad.bat").normalize())
      add(jarDir.resolve("../bin/cryptad.bat").normalize())
    }
    add(jarDir.resolve("cryptad").normalize())
    add(jarDir.resolve("../bin/cryptad").normalize())
  }
  return candidates.firstOrNull { Files.isRegularFile(it) && Files.isExecutable(it) }
}

private fun resolveCryptadPathFromCwd(cwd: Path, isWindows: Boolean): Path? {
  val candidates = buildList {
    if (isWindows) add(cwd.resolve("bin/cryptad.bat"))
    add(cwd.resolve("bin/cryptad"))
    if (isWindows) add(cwd.resolve("cryptad.bat"))
    add(cwd.resolve("cryptad"))
  }
  return candidates.firstOrNull { Files.isRegularFile(it) && Files.isExecutable(it) }
}

private fun isCryptadJarFile(path: Path): Boolean {
  if (!Files.isRegularFile(path)) return false
  val name = path.fileName?.toString() ?: return false
  return name.endsWith(".jar") && name.startsWith("cryptad")
}

/**
 * Build the command line for starting the daemon, preserving the PTY optimization on Unix.
 *
 * On Unix-like systems, if `script(1)` is available, the command is wrapped to reduce line
 * buffering and preserve interactive behavior. Linux and BSD/macOS variants are handled separately
 * due to differing argument conventions. On Windows, or when `script` is not found, the command
 * line is a single-element list containing the wrapper script path.
 *
 * @param cryptadPath path to the wrapper script executable to invoke.
 * @return ordered command-line arguments suitable for `ProcessBuilder`.
 */
fun buildCryptadCommand(cryptadPath: Path): List<String> {
  val env = AppEnv()
  if (!env.isWindows()) {
    val script = findOnPath("script")
    if (script != null) {
      val isLinux = env.isLinux()
      return if (isLinux) {
        // util-linux script(1): use -c "cmd" FILE
        val cmd = "exec ${shellQuote(cryptadPath.toString())}"
        listOf(script, "-q", "-c", cmd, "/dev/null")
      } else {
        // BSD/macOS script(1): FILE [command ...]
        listOf(script, "-q", "/dev/null", cryptadPath.toString())
      }
    }
  }
  return listOf(cryptadPath.toString())
}

/** Minimal POSIX shell quoting for a single argument. */
internal fun shellQuote(s: String): String =
  if (s.isEmpty()) "''" else "'" + s.replace("'", "'\"'\"'") + "'"

/**
 * Search the current `PATH` for an executable.
 *
 * This helper scans the `PATH` environment variable in order and returns the first matching,
 * executable file. It does not expand file extensions, so callers should supply the exact command
 * name for the host platform.
 *
 * @param cmd command name to locate, without additional arguments.
 * @return absolute path to the first matching executable, or `null` when none is found.
 */
fun findOnPath(cmd: String): String? {
  val path = System.getenv("PATH") ?: return null
  val sep = File.pathSeparator
  path.split(sep).forEach { dir ->
    try {
      val f = Paths.get(dir).resolve(cmd)
      if (Files.isRegularFile(f) && Files.isExecutable(f)) return f.toString()
    } catch (e: Exception) {
      logDebug("Error checking PATH entry '$dir' for '$cmd'", e)
    }
  }
  return null
}

/**
 * Load the application icon image.
 *
 * OS-specific classpath resources are preferred, with macOS artwork used as a generic fallback for
 * non-macOS platforms when available. When running from source without packaged resources, the
 * README image under `docs/images/crypta_logo.png` is used as a development fallback. If no image
 * can be loaded, this function returns `null` and callers should skip icon configuration.
 *
 * @return decoded icon image, or `null` when no resource can be loaded.
 */
fun loadAppIconImage(): Image? {
  val cl = Thread.currentThread().contextClassLoader
  val env = AppEnv()

  val candidates = buildList {
    when {
      env.isMac() -> {
        add("network/crypta/launcher/crypta-launcher-icon-macos.png")
      }

      env.isWindows() -> {
        add("network/crypta/launcher/crypta-launcher-icon-windows.png")
      }

      else -> {
        // Prefer macOS artwork as a generic fallback for Linux/others if present
        add("network/crypta/launcher/crypta-launcher-icon-macos.png")
        add("network/crypta/launcher/crypta-launcher-icon-windows.png")
      }
    }
  }

  for (path in candidates) {
    val res = cl.getResource(path)
    if (res != null) {
      try {
        return ImageIO.read(res)
      } catch (e: Exception) {
        logDebug("Failed to read icon resource '$path'", e)
      }
    }
  }

  // Fallback for dev runs: use the README logo if present
  try {
    val fallback = Paths.get("docs/images/crypta_logo.png")
    if (Files.isRegularFile(fallback)) {
      return ImageIO.read(fallback.toFile())
    }
  } catch (e: Exception) {
    logDebug("Failed reading fallback icon from docs/images/crypta_logo.png", e)
  }
  return null
}
