package network.crypta.platform.appui;

/**
 * Browser-origin policy used when serving an installed static app UI.
 *
 * <p>The mode describes the intended browser trust boundary, not the AppHost process sandbox.
 * Static app UI code can run either on the legacy local-admin origin for compatibility or on a
 * loopback-only per-app origin. Platform API authorization remains server-side in both modes.
 *
 * <p>Mode values are serialized in bootstrap JSON, app summaries, audit-adjacent diagnostics, and
 * documentation. They are deliberately stable, lower-case strings because operators may compare
 * summaries from different nodes or release builds. Runtime availability is reported separately by
 * {@link AppUiOriginStatus}; a mode says what policy was selected, while a status says whether that
 * policy is currently active, degraded, unsupported, or stopped.
 */
public enum AppUiOriginMode {
  /**
   * Legacy compatibility mode where the app UI is served below {@code /apps/{appId}/} on the local
   * admin origin.
   *
   * <p>This mode preserves Phase 5 behavior for first-party compatibility, development, and
   * diagnostics. It is not the preferred trust boundary for third-party static apps when an
   * isolated loopback origin can be allocated.
   */
  SAME_ORIGIN_FALLBACK("same-origin-fallback"),

  /**
   * Preferred mode where one static app UI is served from its own loopback HTTP origin.
   *
   * <p>Each installed static app receives a distinct browser origin, normally by using a distinct
   * {@code 127.0.0.1} port. Browser sessions issued in this mode are expected to be bound to that
   * app id and origin.
   */
  ISOLATED_LOOPBACK("isolated-loopback"),

  /**
   * Strict mode where the static app UI must not fall back to the local-admin origin.
   *
   * <p>The current implementation can expose this policy in data models before all callers require
   * it. A binding using this mode should report a non-active status instead of silently serving the
   * app on the admin origin when loopback isolation is unavailable.
   */
  ISOLATED_LOOPBACK_REQUIRED("isolated-loopback-required");

  private final String jsonValue;

  AppUiOriginMode(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the stable JSON/documentation value for this mode.
   *
   * <p>The returned value is the wire-facing spelling. It should be used for JSON summaries and
   * docs rather than {@link #name()}, which is a Java enum identifier.
   *
   * @return lower-case hyphenated mode value
   */
  public String jsonValue() {
    return jsonValue;
  }
}
