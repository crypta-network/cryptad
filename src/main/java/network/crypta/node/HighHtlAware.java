package network.crypta.node;

/**
 * Indicates that an object can report whether it is handling a request with a high Hops-To-Live
 * (HTL) value.
 *
 * <p>HTL is the per-request hop budget used by the router when forwarding requests across the
 * network. "High HTL" refers to values near the upper bound permitted by the current node or
 * routing configuration—commonly the maximum HTL or one below it. Implementations define the exact
 * threshold relative to the active routing context.
 *
 * <p>This signal is typically used by routing or scheduling code that adjusts behavior (for
 * example, backoff, logging, or prioritization) while a request is still near the network edge.
 */
public interface HighHtlAware {

  /**
   * Returns whether the current request is at a high HTL.
   *
   * @return {@code true} if the request's HTL is at or above the implementation's high-HTL
   *     threshold (often the maximum HTL or one less); {@code false} otherwise.
   */
  boolean isHighHtl();
}
