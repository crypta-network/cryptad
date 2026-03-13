package network.crypta.compat;

/**
 * Supplies externally observed IP reachability snapshots to node detection logic.
 *
 * <p>Implementations act as adapters between concrete discovery mechanisms and the core detector
 * manager. A provider may use STUN-like techniques, system network APIs, or other out-of-band
 * probing to infer public address and NAT characteristics, then expose those results as
 * compatibility-layer {@link DetectedIP} records. The interface is intentionally small to isolate
 * provider-specific complexity from node policy code.
 *
 * <p>Callers should treat results as best-effort observations rather than strict guarantees: values
 * can become stale as network topology changes. Implementations are expected to be non-throwing in
 * normal operation and to return empty or null-equivalent results when no detection is available.
 *
 * <ul>
 *   <li><b>Primary responsibility:</b> provide public-address/NAT observations.
 *   <li><b>Lifecycle hook:</b> optionally release provider resources via {@link #terminate()}.
 * </ul>
 */
public interface ExternalIpDetector {
  /**
   * Performs a detection pass and returns zero or more observed public connectivity records.
   *
   * <p>Each returned {@link DetectedIP} entry may include a public address, NAT category code, and
   * MTU hint. Implementations may return multiple candidates when they observe distinct reachable
   * endpoints. Callers should handle null or empty results as "no usable observation right now"
   * rather than as a hard failure.
   *
   * @return array of detected connectivity observations, or an empty result when none are available
   */
  DetectedIP[] getAddress();

  /**
   * Reports whether this provider currently has directly detected public addressing information.
   *
   * <p>This boolean is used as an optimization hint when scheduling detection runs. Returning
   * {@code false} does not imply permanent absence of direct detection support; providers may
   * transition as network conditions evolve.
   *
   * @return {@code true} when direct public-address detection is currently available
   */
  @SuppressWarnings("unused")
  boolean hasDirectlyDetectedIP();

  /**
   * Requests provider shutdown and cleanup of background resources.
   *
   * <p>The default implementation is a no-op so simple, stateless detectors do not need lifecycle
   * code. Providers that maintain threads, sockets, or scheduled tasks should override this method
   * and release those resources promptly.
   */
  default void terminate() {
    // Optional lifecycle hook for providers with background activity.
  }
}
