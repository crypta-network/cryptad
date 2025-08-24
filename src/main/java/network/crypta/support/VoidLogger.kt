package network.crypta.support

/** A Logger implementation that discards all messages. */
class VoidLogger : Logger() {
  override fun log(
    o: Any?,
    source: Class<*>?,
    message: String?,
    e: Throwable?,
    priority: LogLevel,
  ) {}

  override fun log(source: Any?, message: String?, priority: LogLevel) {}

  override fun log(o: Any?, message: String?, e: Throwable?, priority: LogLevel) {}

  override fun log(c: Class<*>, message: String?, priority: LogLevel) {}

  override fun log(c: Class<*>, message: String?, e: Throwable?, priority: LogLevel) {}

  override fun instanceShouldLog(priority: LogLevel, c: Class<*>?): Boolean = false

  override fun instanceShouldLog(prio: LogLevel, o: Any?): Boolean = false

  override fun setThreshold(thresh: LogLevel) {}

  override fun getThresholdNew(): LogLevel = LogLevel.NONE

  override fun setThreshold(symbolicThreshold: String) {}

  override fun setDetailedThresholds(details: String?) {}

  override fun instanceRegisterLogThresholdCallback(ltc: LogThresholdCallback) {}

  override fun instanceUnregisterLogThresholdCallback(ltc: LogThresholdCallback) {}
}
