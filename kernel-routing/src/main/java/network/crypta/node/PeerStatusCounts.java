package network.crypta.node;

/**
 * Immutable snapshot of the peer status bucket counts for a node at a single point in time.
 *
 * <p>This record groups the counts that are routinely computed from peer manager status snapshots
 * so HTTP toadlets, status loggers, and field exporters can pass a single value object instead of
 * long parameter lists. It is intended for short-lived snapshots created during request handling or
 * periodic logging; the record carries only integers and has no back-references to peer objects.
 * Because it is immutable and contains only primitive values, it is thread-safe, inexpensive to
 * copy, and safe to cache within a request scope when the underlying peer set is not expected to
 * change mid-render.
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>Counts represent mutually exclusive status buckets as defined by the peer manager.
 *   <li>Seed server/client counts may be zero when not tracked by the caller.
 *   <li>{@link #notConnected()} summarizes the non-connected buckets for display.
 * </ul>
 *
 * @param connected number of peers currently connected and exchanging traffic.
 * @param routingBackedOff a number of peers temporarily backed off from routing.
 * @param tooNew a number of peers rejected due to being too new.
 * @param tooOld a number of peers rejected due to being too old.
 * @param disconnected number of peers known but currently disconnected.
 * @param neverConnected a number of peers configured but never connected.
 * @param disabled number of peers explicitly disabled by configuration.
 * @param bursting the number of peers temporarily exceeding throughput allowances.
 * @param listening number of peers accepting inbound connections.
 * @param listenOnly number of peers listed but not accepting inbound connections.
 * @param seedServers number of seed servers tracked for diagnostics.
 * @param seedClients number of seed clients tracked for diagnostics.
 * @param routingDisabled a number of peers prevented from routing traffic.
 * @param clockProblem number of peers flagged for clock synchronization issues.
 * @param connError number of peers whose last connection attempt failed.
 * @param disconnecting number of peers transitioning away from active connections.
 * @param noLoadStats number of peers missing current load statistics.
 */
public record PeerStatusCounts(
    int connected,
    int routingBackedOff,
    int tooNew,
    int tooOld,
    int disconnected,
    int neverConnected,
    int disabled,
    int bursting,
    int listening,
    int listenOnly,
    int seedServers,
    int seedClients,
    int routingDisabled,
    int clockProblem,
    int connError,
    int disconnecting,
    int noLoadStats) {

  /**
   * Returns the total count of peers that are not currently connected.
   *
   * <p>This method sums the bucket values that represent known peers without an active connection,
   * including peers that are too new, too old, disabled, or otherwise not connected. It performs a
   * simple arithmetic aggregation over immutable fields, so it is deterministic, side-effect free,
   * and safe to call repeatedly while rendering UI summaries. Callers typically use the result to
   * render concise totals or to decide whether a detailed breakdown should be displayed.
   *
   * @return total number of peers in non-connected status buckets at the snapshot time.
   */
  public int notConnected() {
    return tooNew
        + tooOld
        + noLoadStats
        + disconnected
        + neverConnected
        + disabled
        + bursting
        + listening
        + listenOnly
        + clockProblem
        + connError;
  }
}
