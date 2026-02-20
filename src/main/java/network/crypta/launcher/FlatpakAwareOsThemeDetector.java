package network.crypta.launcher;

import com.jthemedetecor.OsThemeDetector;
import network.crypta.fs.AppEnv;

/**
 * Provides theme detection that prefers XDG Desktop Portal integration on Linux.
 *
 * <p>This launcher helper selects an {@link OsThemeDetector} implementation that works reliably in
 * sandboxed and desktop-hosted Linux environments. It first attempts to use a portal-backed
 * detector, which can read desktop appearance settings through XDG Desktop Portal APIs even when
 * the process is running inside Flatpak. If portal access is unavailable or detector construction
 * fails, it falls back to the upstream default detector implementation.
 *
 * <p>Behavior highlights:
 *
 * <ul>
 *   <li>Only attempts portal-backed detection on Linux-family platforms.
 *   <li>Fails opening by returning the upstream detector when portal setup is unavailable.
 *   <li>Logs debug information when portal initialization throws.
 * </ul>
 */
public final class FlatpakAwareOsThemeDetector {
  private FlatpakAwareOsThemeDetector() {}

  /**
   * Returns a theme detector, preferring a portal-backed implementation when available.
   *
   * <p>The method attempts to create a Linux portal detector first. When that attempt returns
   * {@code null}, it delegates to {@link OsThemeDetector#getDetector()} to preserve default
   * behavior. This keeps theme detection resilient across both sandboxed and non-sandboxed
   * runtimes.
   *
   * @return portal-backed detector when successfully created, otherwise the upstream fallback
   */
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
    } catch (Exception t) {
      LauncherLog.logDebug(
          "XDG portal theme detector unavailable; falling back to upstream detector", t);
      return null;
    }
  }
}
