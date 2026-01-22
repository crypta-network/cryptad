package network.crypta.launcher

import java.io.Closeable
import java.util.concurrent.CopyOnWriteArraySet
import java.util.concurrent.atomic.AtomicBoolean
import java.util.function.Consumer
import org.freedesktop.dbus.annotations.DBusInterfaceName
import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder
import org.freedesktop.dbus.exceptions.DBusConnectionException
import org.freedesktop.dbus.exceptions.DBusExecutionException
import org.freedesktop.dbus.interfaces.DBusInterface
import org.freedesktop.dbus.messages.DBusSignal
import org.freedesktop.dbus.types.UInt32
import org.freedesktop.dbus.types.Variant

/**
 * Portal-backed theme detector that reads the XDG Desktop Portal color scheme setting.
 *
 * This implementation connects to the session D-Bus and queries `org.freedesktop.portal.Settings`
 * for the `org.freedesktop.appearance/color-scheme` key. It is intended for environments where a
 * portal is available (for example, inside Flatpak), and it provides a minimal adapter that the
 * launcher can use without pulling in UI logic. Callers typically construct the detector once, call
 * [isDark] when a value is needed, and optionally register a listener to receive updates when the
 * portal signals a change.
 *
 * The detector treats failures conservatively: if a read fails, it reports a non-dark preference
 * and keeps the connection open to allow later reads or signals to succeed. Listener callbacks are
 * invoked from the D-Bus signal handler, so callers should keep work lightweight and thread-safe.
 * <ul>
 * <li>Reads the portal value on demand and maps it to a boolean preference.</li>
 * <li>Registers a single signal handler that fan-outs notifications to listeners.</li>
 * <li>Closes the D-Bus connection on [close] as a best-effort cleanup.</li>
 * </ul>
 */
class PortalThemeDetectorImpl : Closeable {
  private val conn by lazy { DBusConnectionBuilder.forSessionBus().build() }
  private val settings by lazy {
    conn.getRemoteObject(DESKTOP_PORTAL, DESKTOP_PATH, PortalSettings::class.java)
  }

  private val listeners = CopyOnWriteArraySet<Consumer<Boolean>>()
  private val signalRegistered = AtomicBoolean(false)

  init {
    // Validate portal availability early so callers can fall back if needed.
    try {
      try {
        settings.ReadOne(APPEARANCE, COLOR_SCHEME)
      } catch (_: DBusExecutionException) {
        settings.Read(APPEARANCE, COLOR_SCHEME)
      }
    } catch (t: Throwable) {
      // Propagate to the factory so it can choose the upstream detector
      throw t
    }
  }

  /**
   * Returns whether the portal reports a preference for a dark theme.
   *
   * This call reads the current value of the portal `color-scheme` key and maps known values to a
   * boolean. A value of `1` is treated as a dark preference, while other values are interpreted as
   * not dark. If the portal cannot be reached or returns an unexpected payload, this method returns
   * {@code false} and does not throw. The result is a snapshot of the current portal state; callers
   * that need updates should also register a listener.
   *
   * @return `true` when the portal reports a dark preference; `false` otherwise.
   */
  fun isDark(): Boolean =
    try {
      val v =
        try {
          settings.ReadOne(APPEARANCE, COLOR_SCHEME)
        } catch (_: DBusExecutionException) {
          settings.Read(APPEARANCE, COLOR_SCHEME)
        }
      mapVariantToDark(v)
    } catch (_: Throwable) {
      false
    }

  /**
   * Registers a listener notified when the portal reports a theme change.
   *
   * The listener is stored in a thread-safe set and will be invoked whenever the portal emits a
   * `SettingChanged` signal for the appearance color scheme. The first call to this method
   * registers a single D-Bus signal handler; later calls only add listeners. Listener callbacks are
   * best-effort and any runtime exception thrown by a listener is ignored, so other listeners
   * continue to receive updates.
   *
   * @param darkThemeListener consumer receiving `true` for dark preference, `false` otherwise;
   *   non-null.
   */
  fun registerListener(darkThemeListener: Consumer<Boolean>) {
    listeners.add(darkThemeListener)
    if (signalRegistered.compareAndSet(false, true)) {
      try {
        conn.addSigHandler(PortalSettings.SettingChanged::class.java) { sig ->
          if (sig.namespace == APPEARANCE && sig.key == COLOR_SCHEME) {
            val isDark = mapVariantToDark(sig.value)
            listeners.forEach { l ->
              try {
                l.accept(isDark)
              } catch (_: RuntimeException) {
                // Ignore listener exceptions to keep notifications flowing.
              }
            }
          }
        }
      } catch (_: DBusConnectionException) {
        // ignore, no live updates
      }
    }
  }

  /**
   * Removes a previously registered listener from the notification set.
   *
   * Passing `null` is a no-op. The D-Bus signal handler remains registered after removal so that
   * other listeners can continue to receive updates. This method does not close the connection; use
   * [close] when the detector is no longer needed.
   *
   * @param darkThemeListener listener to remove; `null` leaves the set unchanged.
   */
  fun removeListener(darkThemeListener: Consumer<Boolean>?) {
    if (darkThemeListener != null) listeners.remove(darkThemeListener)
    // Keep handler registered; connection is closed on process exit.
  }

  private fun mapVariantToDark(v: Variant<*>): Boolean {
    val code =
      when (val raw = unwrap(v)) {
        is UInt32 -> raw.toInt()
        is Number -> raw.toInt()
        is String -> raw.toIntOrNull() ?: 0
        else -> 0
      }
    val dark = code == 1 // 1 = prefer-dark, 2 = prefer-light, 0 = no preference
    return dark
  }

  override fun close() {
    try {
      if (conn.isConnected) conn.close()
    } catch (_: Exception) {
      // Ignore shutdown failures; connection is best-effort.
    }
  }

  private tailrec fun unwrap(any: Any?): Any? =
    when (any) {
      is Variant<*> -> unwrap(any.value)
      else -> any
    }

  companion object {
    private const val DESKTOP_PORTAL = "org.freedesktop.portal.Desktop"
    private const val DESKTOP_PATH = "/org/freedesktop/portal/desktop"
    private const val APPEARANCE = "org.freedesktop.appearance"
    private const val COLOR_SCHEME = "color-scheme"
  }
}

@Suppress("FunctionName")
@DBusInterfaceName("org.freedesktop.portal.Settings")
private interface PortalSettings : DBusInterface {
  fun Read(namespace: String, key: String): Variant<*>

  fun ReadOne(namespace: String, key: String): Variant<*>

  @Suppress("unused") fun ReadAll(namespace: String): Map<String, Variant<*>>

  // dbus-java expects signal classes to be declared as members of a class
  // implementing DBusInterface and present in a named package.
  @DBusInterfaceName("org.freedesktop.portal.Settings")
  class SettingChanged(
    path: String,
    val namespace: String,
    val key: String,
    val value: Variant<*>,
  ) : DBusSignal(path, namespace, key, value)
}
