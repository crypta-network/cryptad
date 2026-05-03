package network.crypta.platform.appui;

/**
 * Runtime status for an app UI browser origin assignment.
 *
 * <p>The status is intentionally small and operator-facing. It tells summaries and bootstrap
 * payloads whether the preferred isolated origin is usable or whether the app is running through a
 * compatibility path.
 *
 * <p>Status values are paired with {@link AppUiOriginMode}. The mode describes the selected policy;
 * this enum describes the current outcome of trying to serve that policy. Keeping the two concepts
 * separate lets Web Shell show a stable policy while API callers still detect transient listener
 * failures, unsupported app UI modes, and explicit same-origin fallback.
 */
public enum AppUiOriginStatus {
  /**
   * The isolated loopback origin is currently active and browser-openable.
   *
   * <p>Bindings with this status can be used for Web Shell launch URLs, CORS origin approval, and
   * origin-bound browser-session verification.
   */
  ACTIVE("active"),

  /**
   * The app UI is using the legacy same-origin compatibility route.
   *
   * <p>Fallback keeps development and diagnostic routes working, but it is not an active isolated
   * origin and should not be approved as an app CORS origin.
   */
  FALLBACK("fallback"),

  /**
   * Origin isolation could not be provided on this node or for this app.
   *
   * <p>This status is appropriate for process-only apps, invalid UI declarations, or environments
   * where the local loopback listener cannot be allocated. A binding may include a warning string
   * with the operator-facing reason.
   */
  UNSUPPORTED("unsupported"),

  /**
   * A previously assigned origin is not currently serving requests.
   *
   * <p>Stopped indicates a runtime lifecycle state rather than a manifest problem. Callers should
   * refresh the binding before reusing any launch URL or CORS decision derived from it.
   */
  STOPPED("stopped");

  private final String jsonValue;

  AppUiOriginStatus(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the stable JSON/documentation value for this status.
   *
   * <p>The returned value is the wire-facing spelling used in app summaries and bootstrap metadata.
   * It should be preferred over {@link #name()} outside Java-only diagnostics.
   *
   * @return lower-case hyphenated status value
   */
  public String jsonValue() {
    return jsonValue;
  }
}
