package network.crypta.launcher

import java.io.File
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

/** Small pure helpers used by the launcher controller and tests. */

// --- Port parsing ---

private val PORT_RE =
  Regex("""Starting\s+FProxy\s+on\s+.*:(\d{2,5})(?:\s*|$)""", RegexOption.IGNORE_CASE)

/** Try to parse the FProxy HTTP port from a log line. */
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

/** Return `key=value` map from wrapper.conf content lines (ignores comments and blanks). */
fun parseWrapperProperties(lines: List<String>): Map<String, String> = buildMap {
  lines.forEach { raw ->
    val line = raw.trim()
    if (line.isEmpty() || line.startsWith('#')) return@forEach
    val idx = line.indexOf('=')
    if (idx <= 0) return@forEach
    val k = line.take(idx).trim()
    val v = line.substring(idx + 1).trim()
    put(k, v)
  }
}

/**
 * Pure helper to upsert (add or replace) a property line. Preserves existing file structure and
 * comments, modifying only the first occurrence or appending at the end.
 */
fun upsertWrapperProperty(lines: List<String>, key: String, value: String): List<String> {
  var replaced = false
  val out =
    lines
      .map { raw ->
        if (!replaced) {
          val trimmed = raw.trim()
          if (trimmed.isNotEmpty() && !trimmed.startsWith('#')) {
            val idx = trimmed.indexOf('=')
            if (idx > 0) {
              val k = trimmed.take(idx).trim()
              if (k == key) {
                replaced = true
                return@map "$key=$value"
              }
            }
          }
        }
        raw
      }
      .toMutableList()
  if (!replaced) out.add("$key=$value")
  return out
}

/** Compute the effective wrapper.logfile path given the wrapper.conf location and value. */
fun computeWrapperLogPath(confPath: Path, logSpec: String?): Path {
  val spec = logSpec?.takeUnless { it.isBlank() } ?: "../logs/wrapper.log"
  val p = Paths.get(spec)
  return if (p.isAbsolute) p else confPath.parent.resolve(p).normalize()
}

/**
 * Guess wrapper.conf path for a `cryptad` wrapper script path. Tries `../conf/wrapper.conf` and
 * also scans the script for an explicit `-c ".../wrapper.conf"` or `CONF=".../wrapper.conf"`.
 */
fun guessWrapperConfPathForCryptadScript(cryptadPath: Path): Path? {
  val scriptDir = cryptadPath.parent ?: return null
  val defaultConf = scriptDir.resolve("../conf/wrapper.conf").normalize()
  if (Files.isRegularFile(defaultConf)) return defaultConf
  if (!Files.isRegularFile(cryptadPath)) return defaultConf
  return try {
    scanWrapperConfPath(Files.readAllLines(cryptadPath, StandardCharsets.UTF_8)) ?: defaultConf
  } catch (_: Exception) {
    defaultConf
  }
}

/** Pure scan for wrapper.conf inside a shell script's lines. */
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
 * Resolve the default `cryptad` wrapper script path.
 *
 * If the `CRYPTAD_PATH` environment variable is set, that path is used first (absolute or resolved
 * relative to `cwd`). Otherwise the resolution order (first existing/executable wins):
 * - From the currently running `cryptad.jar` location (same directory), i.e. `<jarDir>/cryptad`.
 * - From the distribution layout relative to `cryptad.jar`, i.e. `<jarDir>/../bin/cryptad`.
 * - From the current working directory: `bin/cryptad`, then `./cryptad`.
 *
 * This avoids relying on the user's home or working directory when launched from the assembled
 * distribution (bin/ + lib/).
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
  env[CRYPTAD_PATH_ENV]?.let { raw ->
    val trimmed = raw.trim()
    if (trimmed.isNotEmpty()) {
      val p = Paths.get(trimmed)
      return (if (p.isAbsolute) p else cwd.resolve(trimmed)).normalize()
    }
  }

  // 1) Try to resolve relative to the currently running cryptad.jar (preferred)
  findCurrentCryptadJarPath()?.let { jar ->
    val jarDir = jar.parent
    if (jarDir != null) {
      val sameDir = jarDir.resolve("cryptad").normalize()
      if (Files.isRegularFile(sameDir) && Files.isExecutable(sameDir)) return sameDir

      val siblingBin = jarDir.resolve("../bin/cryptad").normalize()
      if (Files.isRegularFile(siblingBin) && Files.isExecutable(siblingBin)) return siblingBin
    }
  }

  // 2) Fallback to resolving from the working directory (legacy behavior)
  val bin = cwd.resolve("bin/cryptad")
  if (Files.isRegularFile(bin) && Files.isExecutable(bin)) return bin
  return cwd.resolve("cryptad")
}

/** Attempt to locate the path to the currently running cryptad.jar. */
internal fun findCurrentCryptadJarPath(): Path? {
  // a) Use the protection domain of a class packaged inside cryptad.jar (the launcher lives there)
  val loc = LauncherController::class.java.protectionDomain?.codeSource?.location
  if (loc != null) {
    try {
      val uri = loc.toURI()
      val decoded = Paths.get(URLDecoder.decode(uri.path, "UTF-8"))
      if (Files.isRegularFile(decoded) && decoded.fileName.toString().endsWith(".jar")) {
        // Typically .../lib/cryptad.jar in the assembled distribution
        if (decoded.fileName.toString().startsWith("cryptad")) return decoded.normalize()
      }
    } catch (_: Exception) {}
  }

  // b) As a fallback (tests/dev), scan the java.class.path for a cryptad*.jar entry
  val cp = System.getProperty("java.class.path") ?: ""
  return findCryptadJarInClassPath(cp)
}

/** Find a `cryptad*.jar` on the given Java class path string. */
internal fun findCryptadJarInClassPath(classPath: String): Path? {
  if (classPath.isBlank()) return null
  val sep = File.pathSeparator ?: ":"
  val entries = classPath.split(sep)
  val re = Regex("^cryptad(?:[-.].*)?\\.jar$", RegexOption.IGNORE_CASE)
  for (raw in entries) {
    if (raw.isBlank()) continue
    try {
      val p = Paths.get(raw)
      if (Files.isRegularFile(p)) {
        val name = p.fileName.toString()
        if (re.matches(name)) return p.normalize()
      }
    } catch (_: Exception) {}
  }
  return null
}

/** Build the command line for starting the daemon, keeping the PTY optimization for Unix. */
fun buildCryptadCommand(cryptadPath: Path): List<String> {
  val os = System.getProperty("os.name").lowercase()
  if (!os.contains("win")) {
    val script = findOnPath("script")
    if (script != null) {
      return listOf(script, "-q", "/dev/null", "sh", "-lc", cryptadPath.toString())
    }
  }
  return listOf(cryptadPath.toString())
}

fun findOnPath(cmd: String): String? {
  val path = System.getenv("PATH") ?: return null
  val sep = if (System.getProperty("os.name").lowercase().contains("win")) ";" else ":"
  path.split(sep).forEach { dir ->
    try {
      val f = Paths.get(dir).resolve(cmd)
      if (Files.isRegularFile(f) && Files.isExecutable(f)) return f.toString()
    } catch (_: Exception) {}
  }
  return null
}
