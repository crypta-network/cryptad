package network.crypta.support

import java.util.ArrayList

/** A logger that distributes log events to a set of LoggerHook instances. */
class LoggerHookChain : LoggerHook {
  private var hooks: Array<LoggerHook>

  constructor() : super(LogLevel.NORMAL) {
    hooks = emptyArray()
  }

  constructor(threshold: LogLevel) : super(threshold) {
    hooks = emptyArray()
  }

  @Throws(InvalidThresholdException::class)
  constructor(threshold: String) : super(threshold) {
    hooks = emptyArray()
  }

  @Synchronized
  override fun log(
    o: Any?,
    source: Class<*>?,
    message: String?,
    e: Throwable?,
    priority: LogLevel,
  ) {
    for (hook in hooks) {
      hook.log(o, source, message, e, priority)
    }
  }

  @Synchronized
  fun addHook(lh: LoggerHook) {
    hooks = hooks + lh
  }

  @Synchronized
  fun removeHook(lh: LoggerHook) {
    val hooksLength = hooks.size
    if (hooksLength == 0) return
    val newHooks = ArrayList<LoggerHook>(hooksLength - 1)
    for (h in hooks) if (h !== lh) newHooks.add(h)
    if (newHooks.size != hooksLength) hooks = newHooks.toTypedArray()
  }

  @Synchronized fun getHooks(): Array<LoggerHook> = hooks

  @Throws(InvalidThresholdException::class)
  override fun setDetailedThresholds(details: String?) {
    super.setDetailedThresholds(details)
  }

  override fun setThreshold(thresh: LogLevel) {
    super.setThreshold(thresh)
  }
}
