package network.crypta.support

import org.slf4j.LoggerFactory
import org.slf4j.event.Level

/**
 * SLF4J logging bootstrap utilities used by tests and tooling.
 *
 * Replaces the deprecated network.crypta.support.Logger facade. This helper configures logger
 * levels directly on the bound SLF4J backend when possible (Logback is expected in tests).
 */
object Logging {
  // Track which loggers we have overridden so we can revert them on the next bootstrap call.
  private val appliedLoggerNames = mutableSetOf<String>()

  /** Sets the root logger level and applies optional per-package overrides. */
  @JvmStatic
  fun bootstrap(level: Level, details: String?) {
    setRootLevel(level)
    applyDetails(details)
  }

  /** Sets the level for the named logger when running with Logback. */
  @JvmStatic
  fun setLevel(loggerName: String, level: Level) {
    val (ctx, logger) = resolveLogbackLogger(loggerName) ?: return
    logger.level = level.toLogback()
    ctx.resetTurboFilterList() // best-effort nudge
  }

  /** Sets the root logger level when running with Logback. */
  @JvmStatic
  fun setRootLevel(level: Level) {
    val (ctx, logger) = resolveLogbackLogger(org.slf4j.Logger.ROOT_LOGGER_NAME) ?: return
    logger.level = level.toLogback()
    ctx.resetTurboFilterList()
  }

  @Synchronized
  private fun applyDetails(details: String?) {
    val ctx = resolveLogbackLogger(org.slf4j.Logger.ROOT_LOGGER_NAME)?.first ?: return
    // Replace semantics: clear previous overrides first
    clearOverrides(ctx)
    if (details.isNullOrBlank()) return
    // Comma-separated "section:LEVEL" pairs
    details.split(',').forEach { rawToken ->
      val token = rawToken.trim()
      if (token.isEmpty() || !token.contains(':')) {
        return@forEach
      }
      val idx = token.indexOf(':')
      val section = token.take(idx)
      val lvl = token.substring(idx + 1).trim()
      val up = lvl.uppercase()
      if (up == "NONE" || up == "OFF") {
        setOff(section)
        appliedLoggerNames.add(section)
        return@forEach
      }
      val level = up.toSlf4jLevelOrNull() ?: return@forEach
      setLevel(section, level)
      appliedLoggerNames.add(section)
    }
  }

  private fun String.toSlf4jLevelOrNull(): Level? =
    when (this) {
      // Accept only standard SLF4J names
      "ERROR" -> Level.ERROR

      "WARN" -> Level.WARN

      "INFO" -> Level.INFO

      "DEBUG" -> Level.DEBUG

      "TRACE" -> Level.TRACE

      else -> null
    }

  private fun Level.toLogback(): ch.qos.logback.classic.Level =
    when (this) {
      Level.ERROR -> ch.qos.logback.classic.Level.ERROR
      Level.WARN -> ch.qos.logback.classic.Level.WARN
      Level.INFO -> ch.qos.logback.classic.Level.INFO
      Level.DEBUG -> ch.qos.logback.classic.Level.DEBUG
      Level.TRACE -> ch.qos.logback.classic.Level.TRACE
    }

  /** Sets a named logger to OFF when using Logback. */
  @JvmStatic
  fun setOff(loggerName: String) {
    val (ctx, logger) = resolveLogbackLogger(loggerName) ?: return
    logger.level = ch.qos.logback.classic.Level.OFF
    ctx.resetTurboFilterList()
  }

  private fun resolveLogbackLogger(
    name: String
  ): Pair<ch.qos.logback.classic.LoggerContext, ch.qos.logback.classic.Logger>? {
    val factory = LoggerFactory.getILoggerFactory()
    return if (factory is ch.qos.logback.classic.LoggerContext) {
      val logger = factory.getLogger(name)
      Pair(factory, logger)
    } else {
      null
    }
  }

  @Synchronized
  private fun clearOverrides(ctx: ch.qos.logback.classic.LoggerContext) {
    for (name in appliedLoggerNames) {
      val lgr = ctx.getLogger(name)
      lgr.level = null // inherit root level
    }
    appliedLoggerNames.clear()
  }
}
