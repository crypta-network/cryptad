package network.crypta.launcher

import com.jthemedetecor.OsThemeDetector

/**
 * Flatpak/portal-aware OS theme detector.
 *
 * It prefers reading the XDG Desktop Portal settings (org.freedesktop.appearance/color-scheme)
 * which is available inside Flatpak sandboxes and on host desktops. When the portal is not
 * reachable, it falls back to the upstream jSystemThemeDetector implementation.
 */
object FlatpakAwareOsThemeDetector {

  /** Factory that returns a portal-backed detector when possible, else upstream detector. */
  fun getDetector(): OsThemeDetector {
    val portal = tryCreatePortalDetector()
    if (portal != null) return portal
    return OsThemeDetector.getDetector()
  }

  private fun tryCreatePortalDetector(): OsThemeDetector? {
    if (!isLinux()) return null
    return try {
      com.jthemedetecor.PortalThemeDetector()
    } catch (t: Throwable) {
      logDebug("XDG portal theme detector unavailable; falling back to upstream detector", t)
      null
    }
  }

  private fun isLinux(): Boolean =
    try {
      System.getProperty("os.name").lowercase().contains("linux")
    } catch (e: Exception) {
      logDebug("Failed to read os.name property for isLinux()", e)
      false
    }
}
