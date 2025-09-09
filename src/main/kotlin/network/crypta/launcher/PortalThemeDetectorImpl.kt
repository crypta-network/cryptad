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
 * Portal-backed implementation of OsThemeDetector that queries the XDG Desktop Portal
 * (org.freedesktop.portal.Settings) for org.freedesktop.appearance/color-scheme. Works inside
 * Flatpak and on host desktops. Fallback selection is handled by the factory.
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
      // Propagate to factory so it can choose the upstream detector
      throw t
    }
  }

  fun isDark(): Boolean {
    return try {
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
  }

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
              } catch (_: RuntimeException) {}
            }
          }
        }
      } catch (_: DBusConnectionException) {
        /* ignore, no live updates */
      }
    }
  }

  fun removeListener(darkThemeListener: Consumer<Boolean>?) {
    if (darkThemeListener != null) listeners.remove(darkThemeListener)
    // Keep handler registered; connection is closed on process exit.
  }

  override fun close() {
    try {
      if (conn.isConnected) conn.close()
    } catch (_: Exception) {}
  }

  private fun mapVariantToDark(v: Variant<*>): Boolean {
    val raw = unwrap(v)
    val code =
      when (raw) {
        is UInt32 -> raw.toInt()
        is Number -> raw.toInt()
        is String -> raw.toIntOrNull() ?: 0
        else -> 0
      }
    val dark = code == 1 // 1 = prefer-dark, 2 = prefer-light, 0 = no preference
    return dark
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

@DBusInterfaceName("org.freedesktop.portal.Settings")
private interface PortalSettings : DBusInterface {
  fun Read(namespace: String, key: String): Variant<*>

  fun ReadOne(namespace: String, key: String): Variant<*>

  fun ReadAll(namespace: String): Map<String, Variant<*>>

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
