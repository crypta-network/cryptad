package network.crypta.node;

/**
 * Provides timeout information for peers that have recently failed requests.
 *
 * <p>Implementations answer when a failure-table based timeout for a peer ends so routing and
 * request-quenching code can decide whether it is acceptable to route to that peer. The concrete
 * key or request context is supplied by the caller's surrounding logic.
 *
 * @author toad
 */
public interface TimedOutNodesList {

  /**
   * Returns the wall-clock time at which the timeout for the given peer ends under the supplied
   * thresholds and mode.
   *
   * <p>Mode selection:
   *
   * <ul>
   *   <li>{@code forPerNodeFailureTables == true}: compute the timeout used by per-node failure
   *       tables (conservative routing decision).
   *   <li>{@code forPerNodeFailureTables == false}: compute the timeout used by {@code
   *       RecentlyFailed} request quenching (more permissive).
   * </ul>
   *
   * @param peer the non-null peer that may be routed to
   * @param htl the Hops-To-Live (HTL) threshold; timeouts recorded with an HTL lower than this
   *     value are ignored
   * @param now current time in milliseconds since the epoch, typically from {@link
   *     System#currentTimeMillis()}
   * @param forPerNodeFailureTables when {@code true}, use per-node failure-table semantics; when
   *     {@code false}, use {@code RecentlyFailed} quenching semantics
   * @return a millisecond timestamp (epoch) at which the timeout ends; {@code -1} if no timeout
   *     applies under the provided parameters
   */
  long getTimeoutTime(PeerNode peer, short htl, long now, boolean forPerNodeFailureTables);
}
