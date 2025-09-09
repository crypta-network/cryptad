package com.jthemedetecor

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
import org.slf4j.LoggerFactory

/**
 * Portal-backed implementation of {@link OsThemeDetector} that queries the XDG Desktop Portal
 * (org.freedesktop.portal.Settings) for org.freedesktop.appearance/color-scheme. This works in
 * Flatpak sandboxes and on the host desktop. Falls back is handled by the factory outside.
 */
class PortalThemeDetector : OsThemeDetector(), Closeable {
  private val log = LoggerFactory.getLogger(PortalThemeDetector::class.java)

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

  override fun isDark(): Boolean {
    return try {
      val v =
        try {
          settings.ReadOne(APPEARANCE, COLOR_SCHEME)
        } catch (_: DBusExecutionException) {
          settings.Read(APPEARANCE, COLOR_SCHEME)
        }
      mapVariantToDark(v)
    } catch (t: Throwable) {
      log.debug("Portal Read failed: ${t.javaClass.simpleName}: ${t.message}")
      false
    }
  }

  override fun registerListener(darkThemeListener: Consumer<Boolean>) {
    listeners.add(darkThemeListener)
    if (signalRegistered.compareAndSet(false, true)) {
      try {
        conn.addSigHandler(SettingChanged::class.java) { sig ->
          if (sig.namespace == APPEARANCE && sig.key == COLOR_SCHEME) {
            val isDark = mapVariantToDark(sig.value)
            listeners.forEach { l ->
              try {
                l.accept(isDark)
              } catch (e: RuntimeException) {
                log.warn("Listener threw: ${e.message}")
              }
            }
          }
        }
      } catch (e: DBusConnectionException) {
        log.debug("Failed to register portal signal handler: ${e.message}")
      }
    }
  }

  override fun removeListener(darkThemeListener: Consumer<Boolean>?) {
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
    return code == 1 // 1 = prefer-dark, 2 = prefer-light, 0 = no preference
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
}

@DBusInterfaceName("org.freedesktop.portal.Settings")
private class SettingChanged(
  path: String,
  val namespace: String,
  val key: String,
  val value: Variant<*>,
) : DBusSignal(path, namespace, key, value)
