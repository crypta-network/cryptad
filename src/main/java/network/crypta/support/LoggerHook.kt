package network.crypta.support

import java.util.ArrayList
import java.util.StringTokenizer
import java.util.concurrent.CopyOnWriteArrayList

abstract class LoggerHook : Logger {
  protected lateinit var thresholdValue: LogLevel

  class DetailedThreshold(val section: String, val dThreshold: LogLevel)

  protected constructor(thresh: LogLevel) : super() {
    this.thresholdValue = thresh
  }

  constructor(thresh: String) : super() {
    this.thresholdValue = parseThreshold(thresh.uppercase())
  }

  @JvmField var detailedThresholds: Array<DetailedThreshold> = emptyArray()
  private val thresholdsCallbacks = CopyOnWriteArrayList<LogThresholdCallback>()

  abstract override fun log(
    o: Any?,
    source: Class<*>?,
    message: String?,
    e: Throwable?,
    priority: LogLevel,
  )

  override fun log(source: Any?, message: String?, priority: LogLevel) {
    if (!instanceShouldLog(priority, source)) return
    log(source, source?.javaClass, message, null, priority)
  }

  override fun log(o: Any?, message: String?, e: Throwable?, priority: LogLevel) {
    if (!instanceShouldLog(priority, o)) return
    log(o, o?.javaClass, message, e, priority)
  }

  override fun log(c: Class<*>, message: String?, priority: LogLevel) {
    if (!instanceShouldLog(priority, c)) return
    log(null, c, message, null, priority)
  }

  override fun log(c: Class<*>, message: String?, e: Throwable?, priority: LogLevel) {
    if (!instanceShouldLog(priority, c)) return
    log(null, c, message, e, priority)
  }

  fun acceptPriority(prio: LogLevel) = prio.matchesThreshold(thresholdValue)

  override fun setThreshold(thresh: LogLevel) {
    thresholdValue = thresh
    notifyLogThresholdCallbacks()
  }

  override fun getThresholdNew(): LogLevel = thresholdValue

  @Throws(InvalidThresholdException::class)
  private fun parseThreshold(threshold: String?): LogLevel {
    if (threshold == null) throw InvalidThresholdException(threshold)
    return try {
      LogLevel.valueOf(threshold.uppercase())
    } catch (e: IllegalArgumentException) {
      throw InvalidThresholdException(threshold)
    }
  }

  @Throws(InvalidThresholdException::class)
  override fun setThreshold(symbolicThreshold: String) {
    setThreshold(parseThreshold(symbolicThreshold))
  }

  @Throws(InvalidThresholdException::class)
  override fun setDetailedThresholds(details: String?) {
    if (details == null) return
    val st = StringTokenizer(details, ",", false)
    val stuff = ArrayList<DetailedThreshold>()
    while (st.hasMoreTokens()) {
      val token = st.nextToken()
      if (token.isEmpty()) continue
      val x = token.indexOf(':')
      if (x < 0 || x == token.length - 1) continue
      val section = token.substring(0, x)
      val value = token.substring(x + 1)
      stuff.add(DetailedThreshold(section, parseThreshold(value.uppercase())))
    }
    val newThresholds = stuff.toTypedArray()
    synchronized(this) { detailedThresholds = newThresholds }
    notifyLogThresholdCallbacks()
  }

  fun getDetailedThresholds(): String {
    val thresh: Array<DetailedThreshold>
    synchronized(this) { thresh = detailedThresholds }
    if (thresh.isEmpty()) return ""
    val sb = StringBuilder()
    for (t in thresh) {
      sb.append(t.section).append(':').append(t.dThreshold).append(',')
    }
    sb.deleteCharAt(sb.length - 1)
    return sb.toString()
  }

  class InvalidThresholdException(msg: String?) : Exception(msg)

  override fun instanceShouldLog(priority: LogLevel, c: Class<*>?): Boolean {
    val thresholds: Array<DetailedThreshold>
    var thresh: LogLevel
    synchronized(this) {
      thresholds = detailedThresholds
      thresh = thresholdValue
    }
    if (c != null && thresholds.isNotEmpty()) {
      val cname = c.name
      for (dt in thresholds) {
        if (cname.startsWith(dt.section)) thresh = dt.dThreshold
      }
    }
    return priority.matchesThreshold(thresh)
  }

  final override fun instanceShouldLog(prio: LogLevel, o: Any?): Boolean =
    instanceShouldLog(prio, o?.javaClass)

  final override fun instanceRegisterLogThresholdCallback(ltc: LogThresholdCallback) {
    thresholdsCallbacks.add(ltc)
    ltc.shouldUpdate()
  }

  final override fun instanceUnregisterLogThresholdCallback(ltc: LogThresholdCallback) {
    thresholdsCallbacks.remove(ltc)
  }

  private fun notifyLogThresholdCallbacks() {
    for (ltc in thresholdsCallbacks) ltc.shouldUpdate()
  }
}
