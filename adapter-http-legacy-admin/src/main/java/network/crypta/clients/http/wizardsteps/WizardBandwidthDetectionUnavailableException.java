package network.crypta.clients.http.wizardsteps;

/**
 * Compatibility shim for the legacy HTTP wizard layer while delegating the shared exception
 * contract to {@code foundation-compat}.
 *
 * <p>This type exists so the HTTP wizard package can preserve its historical checked-exception API
 * while the underlying detection logic lives in the leaf-owned compatibility module. Callers in the
 * legacy wizard code can continue to refer to a wizard-local exception name, but the actual
 * recovery semantics come from the shared {@link
 * network.crypta.compat.bandwidth.BandwidthDetectionUnavailableException} superclass.
 *
 * <p>The wrapper adds no behavior of its own. It is used only to keep package boundaries stable
 * during the decoupling work and to carry optional causes back to the legacy HTTP entry points.
 */
public class WizardBandwidthDetectionUnavailableException
    extends network.crypta.compat.bandwidth.BandwidthDetectionUnavailableException {
  /**
   * Creates an exception with a human-readable reason describing why detection is unavailable.
   *
   * <p>Use this constructor when there is no lower-level throwable to propagate, but you still want
   * to provide user-facing or diagnostic context for the fallback decision in the wizard flow.
   *
   * @param message explanatory text describing the unavailable detection condition
   */
  @SuppressWarnings("unused")
  public WizardBandwidthDetectionUnavailableException(String message) {
    super(message);
  }

  /**
   * Creates an exception with a reason message and the originating failure cause.
   *
   * <p>Use this constructor when detection failed due to an underlying checked or runtime error,
   * and the original throwable should be retained for logging, troubleshooting, or chained
   * exception inspection by upstream callers.
   *
   * @param message explanatory text describing the unavailable detection condition
   * @param cause underlying exception that prevented automatic bandwidth detection
   */
  @SuppressWarnings("unused")
  public WizardBandwidthDetectionUnavailableException(String message, Throwable cause) {
    super(message, cause);
  }
}
