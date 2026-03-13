package network.crypta.launcher;

import com.formdev.flatlaf.FlatDarkLaf;
import com.formdev.flatlaf.FlatLaf;
import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.themes.FlatMacDarkLaf;
import com.formdev.flatlaf.themes.FlatMacLightLaf;
import com.jthemedetecor.OsThemeDetector;
import java.awt.Font;
import java.util.function.Consumer;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.LookAndFeel;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.plaf.FontUIResource;
import network.crypta.fs.AppEnv;

import static network.crypta.launcher.LauncherLog.logDebug;
import static network.crypta.launcher.LauncherLog.logWarn;

/**
 * Applies and maintains FlatLaf theme selection based on the current operating-system appearance.
 *
 * <p>This class bridges OS theme detection with Swing look-and-feel updates for the launcher UI. It
 * performs initial one-time setup, selects a platform-appropriate FlatLaf variant, and registers a
 * listener so theme changes propagate while the application is running. Updates are marshaled onto
 * the Swing event dispatch thread to keep the UI state consistent with Swing threading rules. The
 * implementation also includes platform nuances, such as macOS appearance hints and Flatpak-aware
 * native decoration toggles.
 *
 * <p>Key behaviors:
 *
 * <ul>
 *   <li>Uses portal-aware theme detection when available, with fallback detector behavior.
 *   <li>Prefers synchronous initial LAF application to avoid startup flicker.
 *   <li>Supports clean listener shutdown to prevent stale callback retention.
 * </ul>
 */
public final class ThemeSwitcher {
  private static OsThemeDetector detector;
  private static Consumer<Boolean> listener;

  private ThemeSwitcher() {}

  /**
   * Installs launcher look-and-feel based on the current OS theme and registers change tracking.
   *
   * <p>The initial theme is applied immediately, then an OS theme listener is attached, so the
   * following dark/light transitions update the active look-and-feel.
   */
  public static synchronized void install() {
    try {
      System.setProperty("apple.awt.application.appearance", "system");
    } catch (Exception e) {
      logDebug("Failed to set macOS appearance system property", e);
    }

    try {
      if (new AppEnv().isLinux()) {
        JFrame.setDefaultLookAndFeelDecorated(true);
        JDialog.setDefaultLookAndFeelDecorated(true);
      }
    } catch (Exception e) {
      logDebug("Failed to enable client decorations on Linux", e);
    }

    OsThemeDetector osThemeDetector = FlatpakAwareOsThemeDetector.getDetector();
    detector = osThemeDetector;
    applyFor(osThemeDetector.isDark(), true);

    Consumer<Boolean> newListener = isDark -> applyFor(Boolean.TRUE.equals(isDark), false);
    listener = newListener;
    osThemeDetector.registerListener(newListener);
  }

  /**
   * Unregisters the active OS theme listener and clears retained detector references.
   *
   * <p>This method is safe to call multiple times and is intended for orderly launcher shutdown.
   */
  public static synchronized void shutdown() {
    if (detector != null && listener != null) {
      detector.removeListener(listener);
      if (detector instanceof AutoCloseable closeable) {
        try {
          closeable.close();
        } catch (Exception e) {
          logDebug("Failed to close OS theme detector", e);
        }
      }
    }
    detector = null;
    listener = null;
  }

  private static void applyFor(boolean useDark, boolean synchronous) {
    boolean mac = new AppEnv().isMac();
    LookAndFeel laf = createLaf(useDark, mac);
    applyLaf(laf, mac, synchronous);
  }

  private static LookAndFeel createLaf(boolean useDark, boolean mac) {
    if (mac) {
      return useDark ? new FlatMacDarkLaf() : new FlatMacLightLaf();
    }
    return useDark ? new FlatDarkLaf() : new FlatLightLaf();
  }

  private static void applyLaf(LookAndFeel laf, boolean mac, boolean synchronous) {
    Runnable apply = () -> applyLafInternal(laf, mac, synchronous);
    if (synchronous) {
      if (SwingUtilities.isEventDispatchThread()) {
        apply.run();
      } else {
        try {
          SwingUtilities.invokeAndWait(apply);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          logDebug("invokeAndWait failed; applying LAF on caller thread", e);
          apply.run();
        } catch (Exception e) {
          logDebug("invokeAndWait failed; applying LAF on caller thread", e);
          apply.run();
        }
      }
      return;
    }
    SwingUtilities.invokeLater(apply);
  }

  private static void applyLafInternal(LookAndFeel laf, boolean mac, boolean synchronous) {
    try {
      if (mac) {
        UIManager.put("defaultFont", new FontUIResource("SansSerif", Font.PLAIN, 13));
      }
      boolean inFlatpak = !System.getenv().getOrDefault("FLATPAK_ID", "").isEmpty();
      FlatLaf.setUseNativeWindowDecorations(!mac && !inFlatpak);
      UIManager.setLookAndFeel(laf);
      System.setProperty("swing.defaultlaf", laf.getClass().getName());
      FlatLaf.setup(laf);
      if (!synchronous) {
        FlatLaf.updateUI();
      }
    } catch (Exception e) {
      logWarn("Failed to apply FlatLaf theme", e);
    }
  }
}
