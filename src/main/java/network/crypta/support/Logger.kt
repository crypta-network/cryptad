package network.crypta.support

import java.lang.ref.WeakReference
import java.lang.reflect.Field
import java.lang.reflect.Modifier
import network.crypta.support.LoggerHook.InvalidThresholdException

abstract class Logger {
  // Removed legacy OSThread helpers which were no-ops and unused.

  enum class LogLevel {
    MINIMAL,
    DEBUG,
    MINOR,
    NORMAL,
    WARNING,
    ERROR,
    NONE;

    fun matchesThreshold(threshold: LogLevel) = this.ordinal >= threshold.ordinal

    companion object {
      // No deprecated helpers retained.
    }
  }

  companion object {
    @JvmField var logger: Logger = VoidLogger()

    @Synchronized
    @JvmStatic
    @Throws(InvalidThresholdException::class)
    fun setupStdoutLogging(level: LogLevel, detail: String?) {
      // Initialize the chain thresholds, and add an SLF4J sink honoring the same thresholds.
      setupChain()
      logger.setThreshold(level)
      logger.setDetailedThresholds(detail)
      val hook = Slf4jLoggerHook(level)
      detail?.let { hook.setDetailedThresholds(it) }
      (logger as LoggerHookChain).addHook(hook)
    }

    // Removed deprecated Int-based setup overload.

    @Synchronized
    @JvmStatic
    fun setupChain() {
      logger = LoggerHookChain()
    }

    @Synchronized
    @JvmStatic
    fun debug(c: Class<*>, s: String) {
      logger.log(c, s, LogLevel.DEBUG)
    }

    @Synchronized
    @JvmStatic
    fun debug(c: Class<*>, s: String, t: Throwable?) {
      logger.log(c, s, t, LogLevel.DEBUG)
    }

    @Synchronized
    @JvmStatic
    fun debug(o: Any, s: String) {
      logger.log(o, s, LogLevel.DEBUG)
    }

    @Synchronized
    @JvmStatic
    fun debug(o: Any, s: String, t: Throwable?) {
      logger.log(o, s, t, LogLevel.DEBUG)
    }

    @Synchronized
    @JvmStatic
    fun error(c: Class<*>, s: String) {
      logger.log(c, s, LogLevel.ERROR)
    }

    @Synchronized
    @JvmStatic
    fun error(c: Class<*>, s: String, t: Throwable?) {
      logger.log(c, s, t, LogLevel.ERROR)
    }

    @Synchronized
    @JvmStatic
    fun error(o: Any, s: String) {
      logger.log(o, s, LogLevel.ERROR)
    }

    @Synchronized
    @JvmStatic
    fun error(o: Any, s: String, e: Throwable?) {
      logger.log(o, s, e, LogLevel.ERROR)
    }

    @Synchronized
    @JvmStatic
    fun minor(c: Class<*>, s: String) {
      logger.log(c, s, LogLevel.MINOR)
    }

    @Synchronized
    @JvmStatic
    fun minor(o: Any, s: String) {
      logger.log(o, s, LogLevel.MINOR)
    }

    @Synchronized
    @JvmStatic
    fun minor(o: Any, s: String, t: Throwable?) {
      logger.log(o, s, t, LogLevel.MINOR)
    }

    @Synchronized
    @JvmStatic
    fun minor(c: Class<*>, s: String, t: Throwable?) {
      logger.log(c, s, t, LogLevel.MINOR)
    }

    @Synchronized
    @JvmStatic
    fun normal(o: Any, s: String) {
      logger.log(o, s, LogLevel.NORMAL)
    }

    @Synchronized
    @JvmStatic
    fun normal(o: Any, s: String, t: Throwable?) {
      logger.log(o, s, t, LogLevel.NORMAL)
    }

    @Synchronized
    @JvmStatic
    fun normal(c: Class<*>, s: String) {
      logger.log(c, s, LogLevel.NORMAL)
    }

    @Synchronized
    @JvmStatic
    fun normal(c: Class<*>, s: String, t: Throwable?) {
      logger.log(c, s, t, LogLevel.NORMAL)
    }

    @Synchronized
    @JvmStatic
    fun warning(c: Class<*>, s: String) {
      logger.log(c, s, LogLevel.WARNING)
    }

    @Synchronized
    @JvmStatic
    fun warning(c: Class<*>, s: String, t: Throwable?) {
      logger.log(c, s, t, LogLevel.WARNING)
    }

    @Synchronized
    @JvmStatic
    fun warning(o: Any, s: String) {
      logger.log(o, s, LogLevel.WARNING)
    }

    @Synchronized
    @JvmStatic
    fun warning(o: Any, s: String, e: Throwable?) {
      logger.log(o, s, e, LogLevel.WARNING)
    }

    @Synchronized
    @JvmStatic
    fun logStatic(o: Any, s: String, prio: LogLevel) {
      logger.log(o, s, prio)
    }

    @Synchronized
    @JvmStatic
    fun logStatic(o: Any, s: String, e: Throwable?, prio: LogLevel) {
      logger.log(o, s, e, prio)
    }

    // Removed deprecated Int-based logStatic overload.

    @JvmStatic
    fun shouldLog(priority: LogLevel, c: Class<*>?): Boolean = logger.instanceShouldLog(priority, c)

    // Removed deprecated Int-based shouldLog overload.

    @JvmStatic
    fun shouldLog(priority: LogLevel, o: Any?): Boolean = shouldLog(priority, o?.javaClass)

    // Removed deprecated Int-based shouldLog overload.

    @JvmStatic
    fun registerLogThresholdCallback(ltc: LogThresholdCallback) {
      logger.instanceRegisterLogThresholdCallback(ltc)
    }

    @JvmStatic
    fun unregisterLogThresholdCallback(ltc: LogThresholdCallback) {
      logger.instanceUnregisterLogThresholdCallback(ltc)
    }

    @JvmStatic
    fun registerClass(clazz: Class<*>) {
      val ltc =
        object : LogThresholdCallback() {
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
            if (!done) error(this, "No log level field for " + c)
          }
        }
      registerLogThresholdCallback(ltc)
    }

    @Synchronized
    @JvmStatic
    fun globalAddHook(logger2: LoggerHook) {
      if (logger is VoidLogger) setupChain()
      (logger as LoggerHookChain).addHook(logger2)
    }

    @Synchronized
    @JvmStatic
    fun globalSetThreshold(i: LogLevel) {
      logger.setThreshold(i)
    }

    // Removed deprecated Int-based globalSetThreshold overload.

    @Synchronized @JvmStatic fun globalGetThresholdNew(): LogLevel = logger.getThresholdNew()

    // Removed deprecated Int-based globalGetThreshold overload.

    @Synchronized
    @JvmStatic
    fun globalRemoveHook(hook: LoggerHook) {
      if (logger is LoggerHookChain) {
        (logger as LoggerHookChain).removeHook(hook)
      } else {
        System.err.println("Cannot remove hook: $hook global logger is $logger")
      }
    }

    @Synchronized
    @JvmStatic
    fun destroyChainIfEmpty() {
      if (logger is VoidLogger) return
      if (logger is LoggerHookChain && (logger as LoggerHookChain).getHooks().isEmpty()) {
        logger = VoidLogger()
      }
    }

    @Synchronized
    @JvmStatic
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

  abstract fun log(o: Any?, source: Class<*>?, message: String?, e: Throwable?, priority: LogLevel)

  abstract fun log(source: Any?, message: String?, priority: LogLevel)

  abstract fun log(o: Any?, message: String?, e: Throwable?, priority: LogLevel)

  abstract fun log(c: Class<*>, message: String?, priority: LogLevel)

  abstract fun log(c: Class<*>, message: String?, e: Throwable?, priority: LogLevel)

  abstract fun instanceShouldLog(priority: LogLevel, c: Class<*>?): Boolean

  abstract fun instanceShouldLog(prio: LogLevel, o: Any?): Boolean

  abstract fun setThreshold(thresh: LogLevel)

  @Throws(InvalidThresholdException::class) abstract fun setThreshold(symbolicThreshold: String)

  abstract fun getThresholdNew(): LogLevel

  @Throws(InvalidThresholdException::class) abstract fun setDetailedThresholds(details: String?)

  abstract fun instanceRegisterLogThresholdCallback(ltc: LogThresholdCallback)

  abstract fun instanceUnregisterLogThresholdCallback(ltc: LogThresholdCallback)
}
