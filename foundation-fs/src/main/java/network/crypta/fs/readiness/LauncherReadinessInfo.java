package network.crypta.fs.readiness;

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
    if (uiRoot.isBlank() || uiRoot.charAt(0) != '/') {
      throw new IllegalArgumentException("uiRoot must start with '/'");
    }
  }

  /**
   * Creates the current ready payload for the supplied UI port.
   *
   * @param uiPort HTTP port exposed by the daemon's UI shell
   * @return v1 ready payload for the default UI root
   */
  public static LauncherReadinessInfo ready(int uiPort) {
    return new LauncherReadinessInfo(VERSION_1, READY_STATE, uiPort, DEFAULT_UI_ROOT);
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
