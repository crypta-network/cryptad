package network.crypta.pluginmanager;

/**
 * Supplies externally detected network reachability information to the node.
 *
 * <p>Implement this interface when a plugin can determine the node's externally visible IP address
 * and (optionally) its NAT/firewall characteristics. The node uses these results as an input to its
 * own IP detection and reachability logic: the plugin is asked to perform a detection run and to
 * return one or more {@link DetectedIP} records describing the observed public address and a coarse
 * NAT type classification.
 *
 * <p>Implementations are expected to be resilient and to fail safely. The node treats this as a
 * plugin boundary and may call the detector asynchronously; therefore keep execution time bounded,
 * avoid blocking indefinitely, and avoid mutating shared state without appropriate synchronization.
 * Returning {@code null} or an empty array is interpreted as “no result”.
 *
 * <ul>
 *   <li><b>Address discovery:</b> Provide one or more candidate public addresses.
 *   <li><b>NAT classification:</b> Populate {@link DetectedIP#natType} when the plugin can infer
 *       it.
 *   <li><b>Signal lack of connectivity:</b> Use {@link DetectedIP#NO_UDP} when there is no UDP.
 * </ul>
 */
public interface FredPluginIPDetector {

  /**
   * Performs an IP detection pass and returns the plugin's current view of public connectivity.
   *
   * <p>The node calls this method to obtain a snapshot of detected connectivity. Each returned
   * {@link DetectedIP} describes a candidate public address and a NAT type classification (see the
   * {@code DetectedIP.*} constants). The method may return multiple entries when the detector
   * observes multiple viable public addresses. If the plugin cannot determine a usable address, it
   * should return {@code null} or an empty array.
   *
   * <pre>{@code
   * DetectedIP[] ips = detector.getAddress();
   * if (ips != null) {
   *   for (DetectedIP ip : ips) {
   *     // Inspect ip.publicAddress and ip.natType.
   *   }
   * }
   * }</pre>
   *
   * @return an array of detected public IP observations, or {@code null} when no result is
   *     available
   */
  DetectedIP[] getAddress();
}
