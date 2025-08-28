package network.crypta.launcher

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
    val k = line.substring(0, idx).trim()
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
              val k = trimmed.substring(0, idx).trim()
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
    Files.readAllLines(cryptadPath, StandardCharsets.UTF_8).let { scanWrapperConfPath(it) }
      ?: defaultConf
  } catch (_: Exception) {
    defaultConf
  }
}

/** Pure scan for wrapper.conf inside a shell script's lines. */
fun scanWrapperConfPath(lines: List<String>): Path? {
  val re1 = Regex("""CONF=\"([^\"]*wrapper\.conf)\"""")
  val re2 = Regex("""-c\s+\"([^\"]*wrapper\.conf)\"""")
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

/** Resolve the `cryptad` path relative to current working directory. */
fun resolveCryptadPath(cwd: Path = Paths.get(System.getProperty("user.dir"))): Path {
  val bin = cwd.resolve("bin/cryptad")
  if (Files.isRegularFile(bin) && Files.isExecutable(bin)) return bin
  return cwd.resolve("cryptad")
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
