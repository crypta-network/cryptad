package network.crypta.launcher;

import com.jthemedetecor.OsThemeDetector;
import network.crypta.fs.AppEnv;

/**
 * Flatpak/portal-aware OS theme detector.
 *
 * <p>It prefers reading XDG Desktop Portal settings, which is available inside Flatpak sandboxes
 * and on host desktops. When the portal is not reachable, it falls back to the upstream detector.
 */
public final class FlatpakAwareOsThemeDetector {
  private FlatpakAwareOsThemeDetector() {}

  /** Factory that returns a portal-backed detector when possible, else upstream detector. */
  public static OsThemeDetector getDetector() {
    OsThemeDetector portal = tryCreatePortalDetector();
    if (portal != null) {
      return portal;
    }
    return OsThemeDetector.getDetector();
  }

  private static OsThemeDetector tryCreatePortalDetector() {
    if (!new AppEnv().isLinux()) {
      return null;
    }
    try {
      return new com.jthemedetecor.PortalThemeDetector();
    } catch (Throwable t) {
      LauncherLog.logDebug(
          "XDG portal theme detector unavailable; falling back to upstream detector", t);
      return null;
    }
  }
}
