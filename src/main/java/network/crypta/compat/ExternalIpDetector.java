package network.crypta.compat;

/** Provides external/public IP detections used by {@code NodeIPDetector}. */
public interface ExternalIpDetector {
  DetectedIP[] getAddress();

  boolean hasDirectlyDetectedIP();

  default void terminate() {
    // Optional lifecycle hook for providers with background activity.
  }
}
