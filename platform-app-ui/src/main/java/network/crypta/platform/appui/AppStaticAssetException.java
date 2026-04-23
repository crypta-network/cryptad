package network.crypta.platform.appui;

/**
 * Client-visible failure while parsing or resolving an app-owned static UI path.
 *
 * <p>The app UI resolver throws this exception for request problems that are meaningful to an HTTP
 * adapter but should not expose implementation details. Typical examples are malformed percent
 * encoding, decoded path traversal, encoded separators, and symbolic-link escapes found while
 * walking an installed bundle. Ordinary misses such as a missing app or missing asset are normally
 * returned as an empty {@code Optional}; this exception is reserved for paths that should be
 * treated as client errors.
 *
 * <p>The status code is deliberately HTTP-shaped but transport-neutral. Legacy toadlets, future
 * adapters, and tests can map the code to their own response type while reusing the same
 * filesystem-neutral message. Messages must remain safe to send to a browser; they should describe
 * the class of failure rather than include local absolute paths.
 */
public final class AppStaticAssetException extends Exception {
  /**
   * HTTP-style status code that the adapter should use for the client response.
   *
   * <p>The current resolver emits client-side values such as {@code 400} for unsafe paths and
   * {@code 404} for app id parsing failures that should not reveal whether an app exists.
   */
  private final int statusCode;

  /**
   * Creates a static asset resolution failure.
   *
   * <p>The constructor stores the supplied values without rewriting the message. Callers are
   * responsible for choosing a stable, user-safe message because the HTTP adapter can forward it or
   * use it when classifying the response.
   *
   * @param statusCode HTTP-style status code to return to the client for this failure
   * @param message stable, filesystem-neutral failure description suitable for logs or responses
   */
  public AppStaticAssetException(int statusCode, String message) {
    super(message);
    this.statusCode = statusCode;
  }

  /**
   * Returns the HTTP-style status code for this resolution failure.
   *
   * @return status code such as {@code 400} or {@code 404} for adapter mapping
   */
  public int statusCode() {
    return statusCode;
  }
}
