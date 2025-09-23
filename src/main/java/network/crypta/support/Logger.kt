package network.crypta.support

import java.lang.ref.WeakReference
import java.lang.reflect.Field
import java.lang.reflect.Modifier
import network.crypta.support.FileLoggerHook.IntervalParseException
import network.crypta.support.LoggerHook.InvalidThresholdException

abstract class Logger {
  @Deprecated("unused")
  class OSThread {
    companion object {
      @Deprecated("always returns -1") @JvmStatic fun getPID(o: Any?): Int = -1

      @Deprecated("always returns -1") @JvmStatic fun getPPID(o: Any?): Int = -1

      @Deprecated("always returns null")
      @JvmStatic
      fun getFieldFromProcSelfStat(fieldNumber: Int, o: Any?): String? = null

      @Deprecated("always returns -1") @JvmStatic fun getPIDFromProcSelfStat(o: Any?): Int = -1

      @Deprecated("always returns -1") @JvmStatic fun getPPIDFromProcSelfStat(o: Any?): Int = -1

      @Deprecated("always returns -1") @JvmStatic fun logPID(o: Any?): Int = -1

      @Deprecated("always returns -1") @JvmStatic fun logPPID(o: Any?): Int = -1
    }
  }

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
      @Deprecated("use enum constant")
      @JvmStatic
      fun fromOrdinal(ordinal: Int): LogLevel {
        for (level in values()) {
          if (level.ordinal == ordinal) return level
        }
        throw RuntimeException("Invalid ordinal: $ordinal")
      }
    }
  }

  companion object {
    @Deprecated("use LogLevel constants") @JvmField val ERROR: Int = LogLevel.ERROR.ordinal

    @Deprecated("use LogLevel constants") @JvmField val WARNING: Int = LogLevel.WARNING.ordinal

    @Deprecated("use LogLevel constants") @JvmField val NORMAL: Int = LogLevel.NORMAL.ordinal

    @Deprecated("use LogLevel constants") @JvmField val MINOR: Int = LogLevel.MINOR.ordinal

    @Deprecated("use LogLevel constants") @JvmField val DEBUG: Int = LogLevel.DEBUG.ordinal

    @Deprecated("use LogLevel constants") @JvmField val INTERNAL: Int = LogLevel.NONE.ordinal

    @JvmField var logger: Logger = VoidLogger()

    @Synchronized
    @JvmStatic
    @Throws(InvalidThresholdException::class)
    fun setupStdoutLogging(level: LogLevel, detail: String?): FileLoggerHook {
      setupChain()
      logger.setThreshold(level)
      logger.setDetailedThresholds(detail)
      val fh: FileLoggerHook =
        try {
          FileLoggerHook(System.out, "d (c, t, p): m", "MMM dd, yyyy HH:mm:ss:SSS", level.name)
        } catch (e: IntervalParseException) {
          throw Error(e)
        }
      detail?.let { fh.setDetailedThresholds(it) }
      (logger as LoggerHookChain).addHook(fh)
      fh.start()
      return fh
    }

    @Deprecated("use other overload")
    @Synchronized
    @JvmStatic
    @Throws(InvalidThresholdException::class)
    fun setupStdoutLogging(level: Int, detail: String?): FileLoggerHook =
      setupStdoutLogging(LogLevel.entries.getOrNull(level) ?: LogLevel.NORMAL, detail)

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

    @Deprecated("use LogLevel version")
    @Synchronized
    @JvmStatic
    fun logStatic(o: Any, s: String, prio: Int) {
      logStatic(o, s, LogLevel.entries.getOrNull(prio) ?: LogLevel.NORMAL)
    }

    @JvmStatic
    fun shouldLog(priority: LogLevel, c: Class<*>?): Boolean = logger.instanceShouldLog(priority, c)

    @Deprecated("use LogLevel version")
    @JvmStatic
    fun shouldLog(priority: Int, c: Class<*>?): Boolean =
      shouldLog(LogLevel.entries.getOrNull(priority) ?: LogLevel.NORMAL, c)

    @JvmStatic
    fun shouldLog(priority: LogLevel, o: Any?): Boolean = shouldLog(priority, o?.javaClass)

    @Deprecated("use LogLevel version")
    @JvmStatic
    fun shouldLog(priority: Int, o: Any?): Boolean =
      shouldLog(LogLevel.entries.getOrNull(priority) ?: LogLevel.NORMAL, o)

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
                field.set(null, shouldLog(LogLevel.MINOR, c))
              }
              done = true
            } catch (_: Exception) {}
            try {
              val field: Field = c.getDeclaredField("logDEBUG")
              if (Modifier.isStatic(field.modifiers)) {
                field.isAccessible = true
                field.set(null, shouldLog(LogLevel.DEBUG, c))
              }
              done = true
            } catch (_: Exception) {}
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

    @Deprecated("use LogLevel version")
    @Synchronized
    @JvmStatic
    fun globalSetThreshold(i: Int) {
      logger.setThreshold(LogLevel.entries.getOrNull(i) ?: LogLevel.NORMAL)
    }

    @Synchronized @JvmStatic fun globalGetThresholdNew(): LogLevel = logger.getThresholdNew()

    @Deprecated("use LogLevel version")
    @Synchronized
    @JvmStatic
    fun globalGetThreshold(): Int = globalGetThresholdNew().ordinal

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
          if (oldLogger !is LoggerHook) {
            throw IllegalStateException(
              "The old logger is not a VoidLogger and is not a LoggerHook either!"
            )
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
