package network.crypta.launcher

import com.jthemedetecor.OsThemeDetector
import org.slf4j.LoggerFactory

/**
 * Flatpak/portal-aware OS theme detector.
 *
 * It prefers reading the XDG Desktop Portal settings (org.freedesktop.appearance/color-scheme)
 * which is available inside Flatpak sandboxes and on host desktops. When the portal is not
 * reachable, it falls back to the upstream jSystemThemeDetector implementation.
 */
object FlatpakAwareOsThemeDetector {
  private val log = LoggerFactory.getLogger("FlatpakAwareOsThemeDetector")

  /** Factory that returns a portal-backed detector when possible, else upstream detector. */
  fun getDetector(): OsThemeDetector {
    val portal = tryCreatePortalDetector()
    return portal ?: OsThemeDetector.getDetector()
  }

  private fun tryCreatePortalDetector(): OsThemeDetector? {
    if (!isLinux()) return null
    return try {
      com.jthemedetecor.PortalThemeDetector().also { /* ok */ }
    } catch (t: Throwable) {
      // Any failure (no bus, portal absent, missing transport) → fall back
      log.debug("Portal detector not available: ${t.javaClass.simpleName}: ${t.message}")
      null
    }
  }

  private fun isLinux(): Boolean =
    try {
      System.getProperty("os.name").lowercase().contains("linux")
    } catch (_: Exception) {
      false
    }
}
