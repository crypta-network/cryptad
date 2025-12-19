package network.crypta.pluginmanager;

import java.util.Map;

/**
 * Receives status updates from a port-forwarding plugin.
 *
 * <p>This callback is used by the plugin manager to decouple the mechanics of performing NAT
 * traversal and port mapping (which may involve external libraries and platform-specific behavior)
 * from the node code that consumes the results. A port-forwarding plugin calls {@link
 * #portForwardStatus(Map)} whenever it has new information about the outcome of one or more
 * port-forward attempts.
 *
 * <p>Implementations typically translate these updates into node-visible state (for example,
 * recording what was successfully mapped and which attempts failed) and may trigger follow-up
 * actions such as scheduling retries, changing advertised connectivity, or updating UI/status
 * reporting. Callers may invoke this callback multiple times over the lifetime of a plugin instance
 * and may do so from arbitrary threads, so implementations should avoid long-running work and
 * ensure appropriate thread-safety.
 *
 * <p><b>Responsibilities</b>
 *
 * <ul>
 *   <li>Accept per-port status information as a single batch update.
 *   <li>Handle partial updates (one or many ports) without assuming completeness.
 *   <li>Remain robust in the presence of failures reported by the plugin.
 * </ul>
 *
 * @author toad
 */
public interface ForwardPortCallback {

  /**
   * Reports the current status for one or more forwarded ports.
   *
   * <p>The provided map associates a {@link ForwardPort} (the requested mapping) with a {@link
   * ForwardPortStatus} describing the state as observed by the port-forwarding plugin. A single
   * call may cover one port or multiple ports, and repeated calls are allowed as a plugin's view of
   * the environment changes over time.
   *
   * <p>Callers should provide a non-null map; implementations should tolerate an empty map and
   * treat it as a no-op update.
   *
   * <pre>{@code
   * callback.portForwardStatus(Map.of(port, status));
   * }</pre>
   *
   * @param statuses mapping from {@link ForwardPort} to {@link ForwardPortStatus}; expected
   *     non-null, may be empty
   */
  void portForwardStatus(Map<ForwardPort, ForwardPortStatus> statuses);
}
