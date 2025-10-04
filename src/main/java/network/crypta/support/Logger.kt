package network.crypta.support

import java.lang.ref.WeakReference
import java.lang.reflect.Field
import java.lang.reflect.Modifier
import network.crypta.support.LoggerHook.InvalidThresholdException

/**
 * Central logging facade used across the Crypta codebase.
 *
 * Provides static convenience methods (in the companion) and an abstract instance API which
 * concrete loggers and hook chains implement. The global logger defaults to a no-op [VoidLogger]
 * until replaced by [setupChain] or [setupStdoutLogging].
 */
abstract class Logger {

  /**
   * Log severity levels used to filter messages. Ordering matters: a level matches a threshold when
   * its ordinal is greater than or equal to the threshold's ordinal.
   */
  enum class LogLevel {
    MINIMAL,
    DEBUG,
    MINOR,
    NORMAL,
    WARNING,
    ERROR,
    NONE;

    /** Returns true if this level is at least the given [threshold]. */
    fun matchesThreshold(threshold: LogLevel) = this.ordinal >= threshold.ordinal

    companion object {
      // No deprecated helpers retained.
    }
  }

  companion object {
    /** Singleton global logger used by the static helpers. Defaults to [VoidLogger] (no-op). */
    @JvmField var logger: Logger = VoidLogger()

    @Synchronized
    @JvmStatic
    @Throws(InvalidThresholdException::class)
    /**
     * Installs a [LoggerHookChain] and an SLF4J sink with the given thresholds.
     *
     * @param level Global threshold applied to the chain and sink.
     * @param detail Optional detailed thresholds string understood by hooks (e.g. per package).
     * @throws InvalidThresholdException if [detail] contains invalid rules.
     */
    fun setupStdoutLogging(level: LogLevel, detail: String?) {
      // Initialize the chain thresholds, and add an SLF4J sink honoring the same thresholds.
      setupChain()
      logger.setThreshold(level)
      logger.setDetailedThresholds(detail)
      val hook = Slf4jLoggerHook(level)
      detail?.let { hook.setDetailedThresholds(it) }
      (logger as LoggerHookChain).addHook(hook)
    }

    @Synchronized
    @JvmStatic
    /** Replaces the global [logger] with a fresh [LoggerHookChain]. */
    fun setupChain() {
      logger = LoggerHookChain()
    }

    @Synchronized
    @JvmStatic
    /** Logs a DEBUG message attributed to [c]. */
    fun debug(c: Class<*>, s: String) {
      logger.log(c, s, LogLevel.DEBUG)
    }

    @Synchronized
    @JvmStatic
    /** Logs a DEBUG message and [t] attributed to [c]. */
    fun debug(c: Class<*>, s: String, t: Throwable?) {
      logger.log(c, s, t, LogLevel.DEBUG)
    }

    @Synchronized
    @JvmStatic
    /** Logs a DEBUG message attributed to [o]'s class. */
    fun debug(o: Any, s: String) {
      logger.log(o, s, LogLevel.DEBUG)
    }

    @Synchronized
    @JvmStatic
    /** Logs a DEBUG message and [t] attributed to [o]'s class. */
    fun debug(o: Any, s: String, t: Throwable?) {
      logger.log(o, s, t, LogLevel.DEBUG)
    }

    @Synchronized
    @JvmStatic
    /** Logs an ERROR message attributed to [c]. */
    fun error(c: Class<*>, s: String) {
      logger.log(c, s, LogLevel.ERROR)
    }

    @Synchronized
    @JvmStatic
    /** Logs an ERROR message and [t] attributed to [c]. */
    fun error(c: Class<*>, s: String, t: Throwable?) {
      logger.log(c, s, t, LogLevel.ERROR)
    }

    @Synchronized
    @JvmStatic
    /** Logs an ERROR message attributed to [o]'s class. */
    fun error(o: Any, s: String) {
      logger.log(o, s, LogLevel.ERROR)
    }

    @Synchronized
    @JvmStatic
    /** Logs an ERROR message and [e] attributed to [o]'s class. */
    fun error(o: Any, s: String, e: Throwable?) {
      logger.log(o, s, e, LogLevel.ERROR)
    }

    @Synchronized
    @JvmStatic
    /** Logs a MINOR message attributed to [c]. */
    fun minor(c: Class<*>, s: String) {
      logger.log(c, s, LogLevel.MINOR)
    }

    @Synchronized
    @JvmStatic
    /** Logs a MINOR message attributed to [o]'s class. */
    fun minor(o: Any, s: String) {
      logger.log(o, s, LogLevel.MINOR)
    }

    @Synchronized
    @JvmStatic
    /** Logs a MINOR message and [t] attributed to [o]'s class. */
    fun minor(o: Any, s: String, t: Throwable?) {
      logger.log(o, s, t, LogLevel.MINOR)
    }

    @Synchronized
    @JvmStatic
    /** Logs a MINOR message and [t] attributed to [c]. */
    fun minor(c: Class<*>, s: String, t: Throwable?) {
      logger.log(c, s, t, LogLevel.MINOR)
    }

    @Synchronized
    @JvmStatic
    /** Logs a NORMAL informational message attributed to [o]'s class. */
    fun normal(o: Any, s: String) {
      logger.log(o, s, LogLevel.NORMAL)
    }

    @Synchronized
    @JvmStatic
    /** Logs a NORMAL informational message and [t] attributed to [o]'s class. */
    fun normal(o: Any, s: String, t: Throwable?) {
      logger.log(o, s, t, LogLevel.NORMAL)
    }

    @Synchronized
    @JvmStatic
    /** Logs a NORMAL informational message attributed to [c]. */
    fun normal(c: Class<*>, s: String) {
      logger.log(c, s, LogLevel.NORMAL)
    }

    @Synchronized
    @JvmStatic
    /** Logs a NORMAL informational message and [t] attributed to [c]. */
    fun normal(c: Class<*>, s: String, t: Throwable?) {
      logger.log(c, s, t, LogLevel.NORMAL)
    }

    @Synchronized
    @JvmStatic
    /** Logs a WARNING message attributed to [c]. */
    fun warning(c: Class<*>, s: String) {
      logger.log(c, s, LogLevel.WARNING)
    }

    @Synchronized
    @JvmStatic
    /** Logs a WARNING message and [t] attributed to [c]. */
    fun warning(c: Class<*>, s: String, t: Throwable?) {
      logger.log(c, s, t, LogLevel.WARNING)
    }

    @Synchronized
    @JvmStatic
    /** Logs a WARNING message attributed to [o]'s class. */
    fun warning(o: Any, s: String) {
      logger.log(o, s, LogLevel.WARNING)
    }

    @Synchronized
    @JvmStatic
    /** Logs a WARNING message and [e] attributed to [o]'s class. */
    fun warning(o: Any, s: String, e: Throwable?) {
      logger.log(o, s, e, LogLevel.WARNING)
    }

    @Synchronized
    @JvmStatic
    /** Logs a message at [prio] attributed to [o]'s class. */
    fun logStatic(o: Any, s: String, prio: LogLevel) {
      logger.log(o, s, prio)
    }

    @Synchronized
    @JvmStatic
    /** Logs a message and [e] at [prio] attributed to [o]'s class. */
    fun logStatic(o: Any, s: String, e: Throwable?, prio: LogLevel) {
      logger.log(o, s, e, prio)
    }

    @JvmStatic
    /** Fast-path check: returns whether [priority] would be emitted for [c]. */
    fun shouldLog(priority: LogLevel, c: Class<*>?): Boolean = logger.instanceShouldLog(priority, c)

    @JvmStatic
    /** Convenience overload of [shouldLog] for an instance. */
    fun shouldLog(priority: LogLevel, o: Any?): Boolean = shouldLog(priority, o?.javaClass)

    @JvmStatic
    /** Registers a callback notified when thresholds change. */
    fun registerLogThresholdCallback(ltc: LogThresholdCallback) {
      logger.instanceRegisterLogThresholdCallback(ltc)
    }

    @JvmStatic
    /** Unregisters a previously registered threshold callback. */
    fun unregisterLogThresholdCallback(ltc: LogThresholdCallback) {
      logger.instanceUnregisterLogThresholdCallback(ltc)
    }

    @JvmStatic
    /**
     * Registers [clazz] so its optional static `logMINOR`/`logDEBUG` fields mirror thresholds.
     * Missing fields are ignored.
     */
    fun registerClass(clazz: Class<*>) {
      val ltc =
        object : LogThresholdCallback {
          private val ref = WeakReference(clazz)

          override fun shouldUpdate() {
            val c =
              ref.get()
                ?: run {
                  unregisterLogThresholdCallback(this)
                  return
                }
            var done = false
            try {
              val field: Field = c.getDeclaredField("logMINOR")
              if (Modifier.isStatic(field.modifiers)) {
                field.isAccessible = true
                // Sonar: prefer indexed accessor over direct set() call
                field[null] = shouldLog(LogLevel.MINOR, c)
              }
              done = true
            } catch (_: Exception) {
              // Intentionally ignore: class may not declare optional log fields
            }
            try {
              val field: Field = c.getDeclaredField("logDEBUG")
              if (Modifier.isStatic(field.modifiers)) {
                field.isAccessible = true
                // Sonar: prefer indexed accessor over direct set() call
                field[null] = shouldLog(LogLevel.DEBUG, c)
              }
              done = true
            } catch (_: Exception) {
              // Intentionally ignore: class may not declare optional log fields
            }
            if (!done) error(this, "No log level field for $c")
          }
        }
      registerLogThresholdCallback(ltc)
    }

    @Synchronized
    @JvmStatic
    /** Adds [logger2] to the global [LoggerHookChain], creating a chain if needed. */
    fun globalAddHook(logger2: LoggerHook) {
      if (logger is VoidLogger) setupChain()
      (logger as LoggerHookChain).addHook(logger2)
    }

    @Synchronized
    @JvmStatic
    /** Sets the global logging threshold to [i]. */
    fun globalSetThreshold(i: LogLevel) {
      logger.setThreshold(i)
    }

    /** Returns the current global logging threshold. */
    @Synchronized @JvmStatic fun globalGetThresholdNew(): LogLevel = logger.getThresholdNew()

    @Synchronized
    @JvmStatic
    /** Removes [hook] from the active [LoggerHookChain], if present. */
    fun globalRemoveHook(hook: LoggerHook) {
      if (logger is LoggerHookChain) {
        (logger as LoggerHookChain).removeHook(hook)
      } else {
        System.err.println("Cannot remove hook: $hook global logger is $logger")
      }
    }

    @Synchronized
    @JvmStatic
    /** Reverts to [VoidLogger] when the active chain has no hooks. */
    fun destroyChainIfEmpty() {
      if (logger is VoidLogger) return
      if (logger is LoggerHookChain && (logger as LoggerHookChain).getHooks().isEmpty()) {
        logger = VoidLogger()
      }
    }

    @Synchronized
    @JvmStatic
    /**
     * Returns the global [LoggerHookChain], promoting the current logger to a chain if needed. A
     * single existing [LoggerHook] is preserved as the first hook in the new chain.
     */
    fun getChain(): LoggerHookChain {
      return if (logger is LoggerHookChain) {
        logger as LoggerHookChain
      } else {
        val oldLogger = logger
        if (oldLogger !is VoidLogger) {
          check(oldLogger is LoggerHook) {
            "The old logger is not a VoidLogger and is not a LoggerHook either!"
          }
        }
        setupChain()
        if (oldLogger !is VoidLogger) {
          (logger as LoggerHookChain).addHook(oldLogger as LoggerHook)
        }
        logger as LoggerHookChain
      }
    }
  }

  /** Logs [message] attributed to [source] with optional [e] at [priority]. */
  abstract fun log(o: Any?, source: Class<*>?, message: String?, e: Throwable?, priority: LogLevel)

  /** Logs [message] attributed to [source] at [priority]. */
  abstract fun log(source: Any?, message: String?, priority: LogLevel)

  /** Logs [message] attributed to [o] with [e] at [priority]. */
  abstract fun log(o: Any?, message: String?, e: Throwable?, priority: LogLevel)

  /** Logs [message] attributed to class [c] at [priority]. */
  abstract fun log(c: Class<*>, message: String?, priority: LogLevel)

  /** Logs [message] and [e] attributed to class [c] at [priority]. */
  abstract fun log(c: Class<*>, message: String?, e: Throwable?, priority: LogLevel)

  /** Returns whether a message at [priority] for class [c] should be emitted. */
  abstract fun instanceShouldLog(priority: LogLevel, c: Class<*>?): Boolean

  /** Convenience overload of [instanceShouldLog] for an instance [o]. */
  abstract fun instanceShouldLog(prio: LogLevel, o: Any?): Boolean

  /** Sets the global logging threshold for this logger. */
  abstract fun setThreshold(thresh: LogLevel)

  /**
   * Sets the logging threshold from a symbolic string (e.g. "DEBUG").
   *
   * @throws InvalidThresholdException if the value cannot be parsed.
   */
  @Throws(InvalidThresholdException::class) abstract fun setThreshold(symbolicThreshold: String)

  /** Returns the current logging threshold. */
  abstract fun getThresholdNew(): LogLevel

  /**
   * Applies detailed threshold overrides described by [details] (implementation-defined format).
   *
   * @throws InvalidThresholdException if the rules are invalid.
   */
  @Throws(InvalidThresholdException::class) abstract fun setDetailedThresholds(details: String?)

  /** Registers a threshold change callback for this logger instance. */
  abstract fun instanceRegisterLogThresholdCallback(ltc: LogThresholdCallback)

  /** Unregisters a threshold change callback for this logger instance. */
  abstract fun instanceUnregisterLogThresholdCallback(ltc: LogThresholdCallback)
}
