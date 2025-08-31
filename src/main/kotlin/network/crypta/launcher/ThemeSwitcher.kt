package network.crypta.launcher

import com.formdev.flatlaf.FlatDarkLaf
import com.formdev.flatlaf.FlatLaf
import com.formdev.flatlaf.FlatLightLaf
import com.formdev.flatlaf.themes.FlatMacDarkLaf
import com.formdev.flatlaf.themes.FlatMacLightLaf
import com.github.weisj.darklaf.platform.preferences.SystemPreferencesManager
import com.github.weisj.darklaf.theme.spec.ColorToneRule
import com.github.weisj.darklaf.theme.spec.PreferredThemeStyle
import javax.swing.SwingUtilities
import javax.swing.UIManager
import javax.swing.plaf.FontUIResource

/**
 * Installs FlatLaf matching the current OS theme and switches live on changes. Uses Darklaf's
 * platform-preferences module for cross-platform OS theme detection.
 */
object ThemeSwitcher {
  @Volatile private var manager: SystemPreferencesManager? = null

  /** Initialize OS theme detection and apply the matching FlatLaf before UI creation. */
  fun install() {
    // macOS: ensure the system appearance is reported to Java/Swing
    try {
      System.setProperty("apple.awt.application.appearance", "system")
    } catch (_: Exception) {}

    val mgr = SystemPreferencesManager()
    manager = mgr

    // Apply current theme synchronously (must happen before any Swing components are created)
    applyFor(mgr.preferredThemeStyle, synchronous = true)

    // Listen for changes and switch LAF live
    mgr.addListener { style -> applyFor(style) }
    mgr.enableReporting(true)
  }

  /** Stop OS theme change reporting (call on shutdown to avoid leaks). */
  fun shutdown() {
    manager?.enableReporting(false)
    manager = null
  }

  private fun applyFor(style: PreferredThemeStyle?, synchronous: Boolean = false) {
    val mac = isMac()
    val useDark = style?.colorToneRule == ColorToneRule.DARK
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
