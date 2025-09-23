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
import network.crypta.fs.AppEnv

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
    } catch (e: Exception) {
      logDebug("Failed to set macOS appearance system property", e)
    }
    try {
      if (AppEnv().isLinux()) {
        javax.swing.JFrame.setDefaultLookAndFeelDecorated(true)
        javax.swing.JDialog.setDefaultLookAndFeelDecorated(true)
      }
    } catch (t: Throwable) {
      logDebug("Failed to enable client decorations on Linux/Flatpak", t)
    }
    val det = FlatpakAwareOsThemeDetector.getDetector()
    detector = det

    // Apply current theme synchronously (must happen before any Swing components are created)
    val initialDark = det.isDark
    applyFor(initialDark, synchronous = true)

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
    val mac = AppEnv().isMac()
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
        // Use FlatLaf client decorations on Linux/Flatpak to avoid light server-side title bars
        val inFlatpak = System.getenv("FLATPAK_ID")?.isNotEmpty() == true
        val useNativeDeco = AppEnv().isMac().not() && !inFlatpak
        FlatLaf.setUseNativeWindowDecorations(useNativeDeco)
        // Apply LAF explicitly via UIManager to catch errors, then let FlatLaf do extra setup
        try {
          UIManager.setLookAndFeel(laf)
        } catch (t: Throwable) {
          logDebug("UIManager.setLookAndFeel() failed", t)
        }
        // Also set swing.defaultlaf so the EDT initialization cannot override us to GTK
        try {
          System.setProperty("swing.defaultlaf", laf.javaClass.name)
        } catch (t: Throwable) {
          logDebug("Failed to set swing.defaultlaf system property", t)
        }
        FlatLaf.setup(laf)
        // For live switches after startup, refresh UI
        if (!synchronous) FlatLaf.updateUI()
      } catch (e: Exception) {
        logWarn("Failed to apply FlatLaf theme", e)
      }
    }

    if (synchronous) {
      if (SwingUtilities.isEventDispatchThread()) {
        apply()
      } else {
        try {
          SwingUtilities.invokeAndWait(apply)
        } catch (e: Exception) {
          logDebug("invokeAndWait failed; applying LAF synchronously on caller thread", e)
          apply()
        }
      }
    } else {
      SwingUtilities.invokeLater(apply)
    }
  }
}
