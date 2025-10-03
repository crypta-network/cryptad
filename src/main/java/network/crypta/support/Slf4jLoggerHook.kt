package network.crypta.support

import network.crypta.support.Logger.LogLevel
import org.slf4j.LoggerFactory

/**
 * LoggerHook that forwards Crypta Logger events to SLF4J.
 *
 * Notes
 * - Filtering: The global LoggerHookChain already applies threshold/detail filtering via
 *   instanceShouldLog() before dispatch. We do not rely on per-hook filtering here; this hook emits
 *   whatever the chain passes through. Keeping a direct call avoids duplicating logic.
 * - Levels: MINIMAL→trace, MINOR/DEBUG→debug, NORMAL→info, WARNING→warn, ERROR→error, NONE→no-op.
 */
class Slf4jLoggerHook(threshold: LogLevel) : LoggerHook(threshold) {

  override fun log(
    o: Any?,
    source: Class<*>?,
    message: String?,
    e: Throwable?,
    priority: LogLevel,
  ) {
    // Respect this hook's current threshold and per-section detail rules
    if (!instanceShouldLog(priority, source)) return

    val clazz = source ?: o?.javaClass ?: Slf4jLoggerHook::class.java
    val log = LoggerFactory.getLogger(clazz)
    val msg = message ?: ""

    when (priority) {
      LogLevel.ERROR -> if (e != null) log.error(msg, e) else log.error(msg)
      LogLevel.WARNING -> if (e != null) log.warn(msg, e) else log.warn(msg)
      LogLevel.NORMAL -> if (e != null) log.info(msg, e) else log.info(msg)
      LogLevel.MINOR,
      LogLevel.DEBUG -> if (e != null) log.debug(msg, e) else log.debug(msg)
      LogLevel.MINIMAL -> if (e != null) log.trace(msg, e) else log.trace(msg)
      LogLevel.NONE -> {
        /* no-op */
      }
    }
  }
}
