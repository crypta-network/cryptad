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

/** Simple FlatLaf theme switcher with OS theme listener support. */
public final class ThemeSwitcher {
  private static OsThemeDetector detector;
  private static Consumer<Boolean> listener;

  private ThemeSwitcher() {}

  /** Install a theme matching the current OS preference and register for changes. */
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

  /** Remove any registered detector listener. */
  public static synchronized void shutdown() {
    if (detector != null && listener != null) {
      detector.removeListener(listener);
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
