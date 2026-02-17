package network.crypta.launcher

import com.formdev.flatlaf.FlatDarkLaf
import com.formdev.flatlaf.FlatLaf
import com.formdev.flatlaf.FlatLightLaf
import com.formdev.flatlaf.themes.FlatMacDarkLaf
import com.formdev.flatlaf.themes.FlatMacLightLaf
import com.jthemedetecor.OsThemeDetector
import java.util.function.Consumer
import javax.swing.LookAndFeel
import javax.swing.SwingUtilities
import javax.swing.UIManager
import javax.swing.plaf.FontUIResource
import network.crypta.fs.AppEnv

/**
 * Applies a FlatLaf look-and-feel that tracks the operating system theme and keeps Swing components
 * synchronized as the OS preference changes.
 *
 * This singleton is designed for early application startup: call [install] before any Swing
 * components are created so the initial look-and-feel is consistent and does not flash from a
 * default theme. It selects a platform-appropriate FlatLaf variant, configures window decorations
 * for Linux/Flatpak, and wires an [OsThemeDetector] listener so later OS theme changes update the
 * UI. The implementation keeps the minimal mutable state needed to unregister the listener in
 * [shutdown], and it is safe to call from any thread because internal dispatch uses the EDT.
 *
 * Notable behaviors:
 * <ul>
 * <li>Initial theme application is synchronous to avoid UI creation races.</li>
 * <li>Live switches refresh the UI on the EDT.</li>
 * <li>macOS applies a default logical font to avoid JDK-8355079.</li>
 * </ul>
 *
 * @see FlatpakAwareOsThemeDetector
 * @see FlatLaf
 * @see AppEnv
 */
object ThemeSwitcher {
  private class ThemeDetectionState {
    @Volatile var detector: OsThemeDetector? = null

    @Volatile var listener: Consumer<Boolean>? = null
  }

  private val state = ThemeDetectionState()

  /**
   * Initialize OS theme detection and apply the matching FlatLaf before UI creation.
   *
   * Call this once during application startup, before any Swing component is constructed, so the
   * initial theme is applied synchronously on the EDT and remains stable. The method configures
   * platform-specific details (macOS appearance hint and Linux client decorations), creates a
   * detector via [FlatpakAwareOsThemeDetector], applies the current theme immediately, and then
   * registers a listener for later OS theme changes. Repeated calls replace the stored detector
   * reference, but the intent is a single early call to avoid redundant listeners.
   */
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
    state.detector = det

    // Apply the current theme synchronously (must happen before any Swing components are created)
    val initialDark = det.isDark
    applyFor(initialDark, synchronous = true)

    // Listen for changes and switch LAF live
    val consumer = Consumer<Boolean> { isDark -> applyFor(isDark) }
    state.listener = consumer
    det.registerListener(consumer)
  }

  /**
   * Stop OS theme change reporting and release any registered listener.
   *
   * This is intended for application shutdown to avoid leaks or spurious callbacks after the UI is
   * torn down. If [install] was never called, this method is a no-op. It clears the cached detector
   * and listener references after attempting to unregister them, and it does not touch the current
   * look-and-feel state.
   */
  fun shutdown() {
    val det = state.detector
    val c = state.listener
    if (det != null && c != null) det.removeListener(c)
    state.detector = null
    state.listener = null
  }

  private fun applyFor(useDark: Boolean, synchronous: Boolean = false) {
    val mac = AppEnv().isMac()
    val laf = createLaf(useDark, mac)
    applyLaf(laf, mac, synchronous)
  }

  private fun createLaf(useDark: Boolean, mac: Boolean): LookAndFeel =
    if (mac) {
      if (useDark) FlatMacDarkLaf() else FlatMacLightLaf()
    } else {
      if (useDark) FlatDarkLaf() else FlatLightLaf()
    }

  private fun applyLaf(laf: LookAndFeel, mac: Boolean, synchronous: Boolean) {
    val apply: () -> Unit = { applyLafInternal(laf, mac, synchronous) }

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

  private fun applyLafInternal(laf: LookAndFeel, mac: Boolean, synchronous: Boolean) {
    try {
      if (mac) {
        // Work around JDK-8355079: set a sane default logical font on macOS
        UIManager.put("defaultFont", FontUIResource("SansSerif", java.awt.Font.PLAIN, 13))
      }
      configureWindowDecorations()
      applyLookAndFeel(laf)
      setDefaultLafProperty(laf)
      FlatLaf.setup(laf)
      // For live switches after startup, refresh UI
      if (!synchronous) FlatLaf.updateUI()
    } catch (e: Exception) {
      logWarn("Failed to apply FlatLaf theme", e)
    }
  }

  private fun configureWindowDecorations() {
    // Use FlatLaf client decorations on Linux/Flatpak to avoid light server-side title bars
    val inFlatpak = System.getenv("FLATPAK_ID")?.isNotEmpty() == true
    val useNativeDeco = AppEnv().isMac().not() && !inFlatpak
    FlatLaf.setUseNativeWindowDecorations(useNativeDeco)
  }

  private fun applyLookAndFeel(laf: LookAndFeel) {
    // Apply LAF explicitly via UIManager to catch errors, then let FlatLaf do extra setup
    try {
      UIManager.setLookAndFeel(laf)
    } catch (t: Throwable) {
      logDebug("UIManager.setLookAndFeel() failed", t)
    }
  }

  private fun setDefaultLafProperty(laf: LookAndFeel) {
    // Also set swing.defaultlaf so the EDT initialization cannot override us to GTK
    try {
      System.setProperty("swing.defaultlaf", laf.javaClass.name)
    } catch (t: Throwable) {
      logDebug("Failed to set swing.defaultlaf system property", t)
    }
  }
}
