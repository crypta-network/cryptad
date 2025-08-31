package network.crypta.launcher

import com.formdev.flatlaf.FlatDarkLaf
import com.formdev.flatlaf.FlatLaf
import com.formdev.flatlaf.FlatLightLaf
import com.github.weisj.darklaf.platform.preferences.SystemPreferencesManager
import com.github.weisj.darklaf.theme.spec.ColorToneRule
import com.github.weisj.darklaf.theme.spec.PreferredThemeStyle
import javax.swing.SwingUtilities

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

    // Apply current theme synchronously
    applyFor(mgr.preferredThemeStyle)

    // Listen for changes and switch LAF live
    mgr.addListener { style -> applyFor(style) }
    mgr.enableReporting(true)
  }

  /** Stop OS theme change reporting (call on shutdown to avoid leaks). */
  fun shutdown() {
    manager?.enableReporting(false)
    manager = null
  }

  private fun applyFor(style: PreferredThemeStyle?) {
    val useDark = style?.colorToneRule == ColorToneRule.DARK
    val laf = if (useDark) FlatDarkLaf() else FlatLightLaf()

    // Switch on EDT; update all open windows
    SwingUtilities.invokeLater {
      try {
        FlatLaf.setup(laf)
        // Prefer native window decorations where supported (kept idempotent across switches)
        if (!isMac()) FlatLaf.setUseNativeWindowDecorations(true)
        FlatLaf.updateUI()
      } catch (_: Exception) {}
    }
  }

  private fun isMac(): Boolean =
    try {
      System.getProperty("os.name").lowercase().contains("mac")
    } catch (_: Exception) {
      false
    }
}
