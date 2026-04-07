package network.crypta.fs.readiness;

import java.net.URI;
import java.util.Objects;

/**
 * Versioned launcher readiness payload persisted under the resolved runtime directory.
 *
 * <p>The launcher needs only a small amount of structured state to discover when the daemon's UI is
 * actually ready for normal use. This record deliberately keeps the contract narrow and stable:
 * protocol version, readiness state, and the UI endpoint details required to open the browser
 * without parsing human-facing log output.
 *
 * @param version protocol version carried by the readiness file
 * @param state readiness state token
 * @param uiPort local HTTP port where the UI is reachable
 * @param uiRoot root path for the launcher-opened UI URL
 */
public record LauncherReadinessInfo(int version, String state, int uiPort, String uiRoot) {
  /** Current readiness-file protocol version. */
  public static final int VERSION_1 = 1;

  /** Ready state token written once the HTTP shell is fully usable. */
  public static final String READY_STATE = "ready";

  /** Default UI root path used by the current launcher/browser flow. */
  public static final String DEFAULT_UI_ROOT = "/";

  /**
   * Creates a validated readiness payload.
   *
   * <p>The v1 contract currently supports only the {@value #READY_STATE} state because the launcher
   * consumes the file purely as a ready signal rather than a broader lifecycle stream.
   */
  public LauncherReadinessInfo {
    if (version <= 0) {
      throw new IllegalArgumentException("version must be positive");
    }
    Objects.requireNonNull(state);
    if (!READY_STATE.equals(state)) {
      throw new IllegalArgumentException("unsupported readiness state: " + state);
    }
    if (uiPort < 1 || uiPort > 65_535) {
      throw new IllegalArgumentException("uiPort must be between 1 and 65535");
    }
    Objects.requireNonNull(uiRoot);
    if (!isValidUiRoot(uiRoot)) {
      throw new IllegalArgumentException("uiRoot must be a valid absolute URI path");
    }
  }

  /**
   * Creates the current ready payload for the supplied UI port.
   *
   * @param uiPort HTTP port exposed by the daemon's UI shell
   * @return v1 ready payload for the default UI root
   */
  public static LauncherReadinessInfo ready(int uiPort) {
    return ready(uiPort, DEFAULT_UI_ROOT);
  }

  /**
   * Creates the current ready payload for the supplied UI port and root path.
   *
   * @param uiPort HTTP port exposed by the daemon's UI shell
   * @param uiRoot primary browser-facing root path exposed by that shell
   * @return v1 ready payload for the supplied UI route
   */
  public static LauncherReadinessInfo ready(int uiPort, String uiRoot) {
    return new LauncherReadinessInfo(VERSION_1, READY_STATE, uiPort, uiRoot);
  }

  /**
   * Indicates whether the supplied UI root is safe to embed directly as a raw URI path.
   *
   * <p>The readiness protocol carries only browser route paths, not query strings or fragments. A
   * valid root must therefore be absolute, non-blank, and parse as the raw path portion of an HTTP
   * URI without adding query or fragment components.
   *
   * @param uiRoot candidate readiness UI root
   * @return {@code true} when the value is a safe absolute raw URI path
   */
  public static boolean isValidUiRoot(String uiRoot) {
    if (uiRoot == null || uiRoot.isBlank() || uiRoot.charAt(0) != '/') {
      return false;
    }
    try {
      URI uri = URI.create("http://localhost" + uiRoot);
      return uiRoot.equals(uri.getRawPath())
          && uri.getRawQuery() == null
          && uri.getRawFragment() == null;
    } catch (IllegalArgumentException _) {
      return false;
    }
  }

  /**
   * Indicates whether this payload represents a ready UI.
   *
   * @return {@code true} when the state equals {@value #READY_STATE}
   */
  public boolean isReady() {
    return READY_STATE.equals(state);
  }
}
