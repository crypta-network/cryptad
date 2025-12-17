package network.crypta.pluginmanager;

/**
 * Provides plugin-reported bandwidth capability information to the node.
 *
 * <p>This interface is intended for plugins that can estimate or discover the maximum upstream and
 * downstream throughput available to the local node (for example, via router introspection,
 * measurement, or environment heuristics). The node uses these values as advisory signals;
 * implementations should treat them as best-effort estimates rather than strict guarantees.
 *
 * <p>Both methods may perform I/O or computation and are therefore allowed to block. Callers should
 * avoid invoking them from latency-sensitive threads, and implementations should avoid holding
 * global locks while computing the result. A return value of {@code -1} indicates that the
 * information is not currently available.
 *
 * <p><b>Notable behaviors</b>
 *
 * <ul>
 *   <li>Values are expressed in bits per second (bps), not bytes per second.
 *   <li>{@code -1} signals "unknown" rather than "zero bandwidth".
 * </ul>
 */
public interface FredPluginBandwidthIndicator {

  /**
   * Returns the maximum upstream bit rate reported by the plugin.
   *
   * <p>This value is an advisory estimate of the currently achievable upstream throughput.
   * Implementations may compute it on demand and may block while querying external state. If the
   * plugin cannot determine a value, it returns {@code -1}.
   *
   * <pre>{@code
   * int up = indicator.getUpstreamMaxBitRate();
   * }</pre>
   *
   * @return maximum upstream throughput in bits per second, or {@code -1} when unavailable to the
   *     plugin
   */
  int getUpstreamMaxBitRate();

  /**
   * Returns the maximum downstream bit rate reported by the plugin.
   *
   * <p>This value is an advisory estimate of the currently achievable downstream throughput.
   * Implementations may compute it on demand and may block while querying external state. If the
   * plugin cannot determine a value, it returns {@code -1}.
   *
   * <pre>{@code
   * int down = indicator.getDownstreamMaxBitRate();
   * }</pre>
   *
   * @return maximum downstream throughput in bits per second, or {@code -1} when unavailable to the
   *     plugin
   */
  int getDownstreamMaxBitRate();
}
