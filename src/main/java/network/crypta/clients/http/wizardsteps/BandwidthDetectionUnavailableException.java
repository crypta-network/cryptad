package network.crypta.clients.http.wizardsteps;

/**
 * Signals that automatic bandwidth detection is unavailable for the current runtime context.
 *
 * <p>The first-time wizard uses this checked exception to indicate that it cannot produce a
 * measured upload/download estimate from platform capabilities or current node state. Callers
 * should treat this as a recoverable condition and continue with manual bandwidth configuration
 * paths rather than aborting the wizard flow.
 *
 * <p>The type is intentionally lightweight and immutable. It carries explanatory text and, when
 * available, an originating cause to preserve debugging context without defining any
 * wizard-specific recovery policy inside the exception itself.
 *
 * <ul>
 *   <li><b>When thrown:</b> probing logic cannot obtain a valid runtime estimate.
 *   <li><b>Expected handling:</b> fall back to manual rate selection UI.
 * </ul>
 */
public class BandwidthDetectionUnavailableException extends Exception {
  /**
   * Creates an exception with a human-readable reason describing why detection is unavailable.
   *
   * <p>Use this constructor when there is no lower-level throwable to propagate, but you still want
   * to provide user-facing or diagnostic context for the fallback decision in the wizard flow.
   *
   * @param message explanatory text describing the unavailable detection condition
   */
  public BandwidthDetectionUnavailableException(String message) {
    super(message);
  }

  /**
   * Creates an exception with a reason message and the originating failure cause.
   *
   * <p>Use this constructor when detection failed due to an underlying checked or runtime error and
   * the original throwable should be retained for logging, troubleshooting, or chained exception
   * inspection by upstream callers.
   *
   * @param message explanatory text describing the unavailable detection condition
   * @param cause underlying exception that prevented automatic bandwidth detection
   */
  @SuppressWarnings("unused")
  public BandwidthDetectionUnavailableException(String message, Throwable cause) {
    super(message, cause);
  }
}
