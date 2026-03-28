package network.crypta.compat.bandwidth;

/**
 * Signals that automatic bandwidth detection is unavailable for the current runtime context.
 *
 * <p>Callers should treat this as a recoverable condition and continue with manual bandwidth
 * configuration paths rather than aborting the surrounding flow. This exception is intentionally
 * narrow: it distinguishes “detection cannot run here” from “detection ran but produced unusable
 * values,” which is reported through validation exceptions such as {@link
 * network.crypta.support.IllegalValueException}. That separation lets setup and alerting code
 * preserve the legacy fallback behavior while moving the shared detection logic out of the HTTP
 * wizard package.
 *
 * <p>The message should describe the missing capability or runtime limitation in plain terms. When
 * a lower-level failure is available, callers can chain it as the cause for diagnostics without
 * changing the higher-level recovery path.
 */
public class BandwidthDetectionUnavailableException extends Exception {

  /**
   * Creates an exception with a human-readable reason.
   *
   * <p>Use this overload when there is no underlying throwable to preserve, and the surrounding
   * code only needs a clear explanation for why automatic detection is unavailable.
   *
   * @param message explanatory text describing the unavailable detection condition in terms that a
   *     caller or operator can act on
   */
  public BandwidthDetectionUnavailableException(String message) {
    super(message);
  }

  /**
   * Creates an exception with a reason message and the originating failure cause.
   *
   * <p>Use this overload when a lower-level checked or runtime exception explains the
   * unavailability in more detail and should remain attached for logging or troubleshooting.
   *
   * @param message explanatory text describing the unavailable detection condition in a stable,
   *     high-level form
   * @param cause underlying exception that prevented automatic bandwidth detection and should be
   *     retained as the causal chain
   */
  public BandwidthDetectionUnavailableException(String message, Throwable cause) {
    super(message, cause);
  }
}
