package network.crypta.pluginmanager;

import java.util.Set;

/**
 * Port-forwarding plugin extension point.
 *
 * <p>Implementations receive notifications whenever the node's externally reachable listening ports
 * change (and once during plugin startup), and are expected to attempt to make those ports
 * reachable from outside the local network (for example, by configuring a NAT gateway or firewall).
 *
 * <p>The node provides a set of {@link ForwardPort} requests and a {@link ForwardPortCallback} for
 * reporting outcomes. Implementations typically translate each request into one or more platform-
 * or device-specific operations (e.g., UPnP, NAT-PMP, PCP, or local firewall rules) and then report
 * per-port success or failure through the callback.
 *
 * <p>Threading is implementation-defined: callbacks may be invoked synchronously during {@link
 * #onChangePublicPorts(Set, ForwardPortCallback)} or asynchronously at a later time. Callers should
 * not assume a specific thread, and implementations should avoid blocking the caller for
 * long-running network discovery and control operations.
 *
 * <p><b>Responsibilities</b>
 *
 * <ul>
 *   <li>Attempt forwarding for each provided port request.
 *   <li>Report progress and final status via the provided callback.
 *   <li>Handle partial success: some ports may forward while others fail.
 * </ul>
 *
 * @see ForwardPort
 * @see ForwardPortCallback
 * @author toad
 */
public interface FredPluginPortForward {

  /**
   * Notifies the plugin that the node's set of public listening ports has changed.
   *
   * <p>This method is called when the node has determined a new set of ports that should be
   * reachable from outside the local network (and also once immediately after the plugin is
   * loaded). Implementations should treat {@code ports} as the desired set to forward at this point
   * in time, and should report a result for each requested port through {@code cb}.
   *
   * <p>Calls may occur multiple times over the life of a node as configuration changes or as the
   * network environment changes. Implementations should therefore be tolerant of repeated calls and
   * of sets that overlap with previous notifications. If forwarding is probabilistic (for example,
   * due to gateway behavior or lease expiry), it is acceptable to report best-effort outcomes and
   * retry internally as appropriate.
   *
   * <pre>{@code
   * // Example: apply the latest node port set.
   * plugin.onChangePublicPorts(ports, callback);
   * }</pre>
   *
   * @param ports the desired set of public ports to forward, as {@link ForwardPort} requests.
   * @param cb callback invoked with per-port success or failure results, possibly asynchronously.
   */
  void onChangePublicPorts(Set<ForwardPort> ports, ForwardPortCallback cb);
}
