package network.crypta.launcher

import com.formdev.flatlaf.FlatDarkLaf
import com.formdev.flatlaf.FlatLaf
import com.formdev.flatlaf.FlatLightLaf
import com.formdev.flatlaf.themes.FlatMacDarkLaf
import com.formdev.flatlaf.themes.FlatMacLightLaf
import com.jthemedetecor.OsThemeDetector
import java.util.function.Consumer
import javax.swing.SwingUtilities
import javax.swing.UIManager
import javax.swing.plaf.FontUIResource

/**
 * Installs FlatLaf matching the current OS theme and switches live on changes. Uses
 * jSystemThemeDetector (OsThemeDetector) for cross‑platform OS theme detection.
 */
object ThemeSwitcher {
  @Volatile private var detector: OsThemeDetector? = null
  @Volatile private var listener: Consumer<Boolean>? = null

  /** Initialize OS theme detection and apply the matching FlatLaf before UI creation. */
  fun install() {
    // macOS: ensure the system appearance is reported to Java/Swing
    try {
      System.setProperty("apple.awt.application.appearance", "system")
    } catch (_: Exception) {}

    val det = OsThemeDetector.getDetector()
    detector = det

    // Apply current theme synchronously (must happen before any Swing components are created)
    applyFor(det.isDark, synchronous = true)

    // Listen for changes and switch LAF live
    val consumer = Consumer<Boolean> { isDark -> applyFor(isDark) }
    listener = consumer
    det.registerListener(consumer)
  }

  /** Stop OS theme change reporting (call on shutdown to avoid leaks). */
  fun shutdown() {
    val det = detector
    val c = listener
    if (det != null && c != null) det.removeListener(c)
    detector = null
    listener = null
  }

  private fun applyFor(useDark: Boolean, synchronous: Boolean = false) {
    val mac = isMac()
    val laf =
      if (mac) {
        if (useDark) FlatMacDarkLaf() else FlatMacLightLaf()
      } else {
        if (useDark) FlatDarkLaf() else FlatLightLaf()
      }

    val apply: () -> Unit = {
      try {
        if (mac) {
          // Work around JDK-8355079: set a sane default logical font on macOS
          UIManager.put("defaultFont", FontUIResource("SansSerif", java.awt.Font.PLAIN, 13))
        }
        FlatLaf.setup(laf)
        if (!mac) FlatLaf.setUseNativeWindowDecorations(true)
        // For live switches after startup, refresh UI
        if (!synchronous) FlatLaf.updateUI()
      } catch (_: Exception) {}
    }

    if (synchronous) apply() else SwingUtilities.invokeLater(apply)
  }

  private fun isMac(): Boolean =
    try {
      System.getProperty("os.name").lowercase().contains("mac")
    } catch (_: Exception) {
      false
    }
}
