package network.crypta.launcher

import java.io.PrintWriter
import java.io.StringWriter

/**
 * Minimal logging helpers for the launcher package.
 * - `logDebug()` prints only when the environment variable `CRYPTA_LAUNCHER_DEBUG` is set to a
 *   truthy value ("1", "true", "yes").
 * - `logWarn()` and `logError()` always print to stderr with a timestamped prefix.
 *
 * We keep this lightweight to avoid adding a logging framework dependency in the launcher.
 */
private enum class Lvl {
  DEBUG,
  @Suppress("unused") INFO,
  WARN,
  ERROR,
}

private val debugEnabled: Boolean by lazy {
  val v = System.getenv("CRYPTA_LAUNCHER_DEBUG")?.lowercase()?.trim()
  v == "1" || v == "true" || v == "yes" || v == "y" || v == "on"
}

private fun tsNow(): String =
  java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_TIME)

private fun emit(level: Lvl, msg: String, t: Throwable? = null) {
  if (level == Lvl.DEBUG && !debugEnabled) return
  val base = "${tsNow()} [Launcher/${level.name}] ${msg}"
  if (t == null) {
    System.err.println(base)
  } else {
    val sw = StringWriter()
    t.printStackTrace(PrintWriter(sw))
    System.err.println(base + "\n" + sw.toString())
  }
}

fun logDebug(msg: String, t: Throwable? = null) = emit(Lvl.DEBUG, msg, t)

fun logWarn(msg: String, t: Throwable? = null) = emit(Lvl.WARN, msg, t)

@Suppress("unused") fun logError(msg: String, t: Throwable? = null) = emit(Lvl.ERROR, msg, t)
