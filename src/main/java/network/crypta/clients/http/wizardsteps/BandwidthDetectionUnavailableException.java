package network.crypta.clients.http.wizardsteps;

/** Indicates that runtime bandwidth auto-detection cannot be performed. */
public class BandwidthDetectionUnavailableException extends Exception {
  public BandwidthDetectionUnavailableException(String message) {
    super(message);
  }

  public BandwidthDetectionUnavailableException(String message, Throwable cause) {
    super(message, cause);
  }
}
