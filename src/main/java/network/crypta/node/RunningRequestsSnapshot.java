package network.crypta.node;

import network.crypta.node.RequestTracker.CountedRequests;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Snapshot of running request counts and estimated transfer liabilities at a point in time.
 *
 * <p>This type aggregates counts for CHK and SSK operations and exposes them as immutable fields,
 * along with derived totals and transfer-weighted estimates. Instances are created from a {@link
 * RequestTracker} when the node wants a live view of activity, or from {@link PeerLoadStats} when a
 * peer advertises its own counters. The snapshot is intentionally lightweight: it does not retain
 * references to mutable trackers, and it does not attempt to update itself once built.
 *
 * <p>Source-restarted requests can be tracked separately; some constructors subtract them from the
 * main totals while keeping the {@code *SR} fields for limit adjustments. Logging treats negative
 * values as an error signal, which helps detect inconsistent upstream accounting. Instances are
 * immutable and thread-safe because all fields are final.
 *
 * <ul>
 *   <li>Captures counts and estimated transfers for CHK/SSK operations.
 *   <li>Optionally separates source-restarted requests for limit calculations.
 *   <li>Provides lightweight logging and byte-estimate helpers.
 * </ul>
 *
 * @see RequestTracker
 * @see PeerLoadStats
 */
class RunningRequestsSnapshot {
  /** Logger for snapshot diagnostics, used only by the {@code log(...)} helpers. */
  private static final Logger LOG = LoggerFactory.getLogger(RunningRequestsSnapshot.class);

  /** Formatting fragment appended when logging a specific peer context. */
  private static final String TEXT_FOR = " for ";

  // Look plausible from my node-throttle.dat stats as of 01/11/2010.
  /**
   * Output bytes required for an inbound transfer. Includes e.g. sending the request in the first
   * place.
   */
  private static final int TRANSFER_IN_OUT_OVERHEAD = 256;

  /** Input bytes required for an outbound transfer. Includes e.g. sending the insert etc. */
  private static final int TRANSFER_OUT_IN_OVERHEAD = 256;

  /**
   * Expected outgoing CHK transfers for this snapshot, adjusted by constructor rules.
   *
   * <p>The value represents a count of transfers, not bytes. It may exclude source-restarted
   * transfers when the snapshot is built for requests originating from a peer.
   */
  final int expectedTransfersOutCHK;

  /**
   * Expected incoming CHK transfers for this snapshot, adjusted by constructor rules.
   *
   * <p>The value represents a count of transfers. It reflects the live RequestTracker view or a
   * peer-reported value when constructed from {@link PeerLoadStats}.
   */
  final int expectedTransfersInCHK;

  /**
   * Expected outgoing SSK transfers for this snapshot, adjusted by constructor rules.
   *
   * <p>The value is a transfer count and may differ from the source-restarted totals, depending on
   * the constructor used to build the snapshot.
   */
  final int expectedTransfersOutSSK;

  /**
   * Expected incoming SSK transfers for this snapshot, adjusted by constructor rules.
   *
   * <p>The value is a transfer count rather than a byte estimate. It may be negative only if the
   * upstream counters are inconsistent.
   */
  final int expectedTransfersInSSK;

  /**
   * Total number of requests represented by this snapshot.
   *
   * <p>When constructed from {@link PeerLoadStats}, the value may be {@code -1} to indicate that
   * the peer did not provide a total count.
   */
  final int totalRequests;

  /**
   * Expected outgoing CHK transfers for source-restarted requests, when tracked separately.
   *
   * <p>When source-restarted requests are not relevant, this value is zero.
   */
  final int expectedTransfersOutCHKSR;

  /**
   * Expected incoming CHK transfers for source-restarted requests, when tracked separately.
   *
   * <p>When source-restarted requests are not relevant, this value is zero.
   */
  final int expectedTransfersInCHKSR;

  /**
   * Expected outgoing SSK transfers for source-restarted requests, when tracked separately.
   *
   * <p>When source-restarted requests are not relevant, this value is zero.
   */
  final int expectedTransfersOutSSKSR;

  /**
   * Expected incoming SSK transfers for source-restarted requests, when tracked separately.
   *
   * <p>When source-restarted requests are not relevant, this value is zero.
   */
  final int expectedTransfersInSSKSR;

  /**
   * Total number of source-restarted requests represented by this snapshot.
   *
   * <p>When source-restarted requests are not tracked, the value is zero.
   */
  final int totalRequestsSR;

  /**
   * Average outgoing transfers assumed per insert when counting transfer liabilities.
   *
   * <p>This is a heuristic input to the request tracker and is not derived from observed transfers.
   */
  final int averageTransfersPerInsert;

  /**
   * Indicates whether this snapshot covers real-time traffic ({@code true}) or bulk traffic.
   *
   * <p>The flag is passed through from the constructor parameters or peer-reported stats.
   */
  final boolean realTimeFlag;

  /**
   * Create a snapshot of all running requests regardless of peer ownership.
   *
   * <p>This constructor asks the {@link RequestTracker} to count both CHK and SSK requests across
   * all categories (local, remote, insert, request, and offer). Source-restarted requests are
   * included in the main totals, and their contributions are also captured in the {@code *SR}
   * fields. The resulting snapshot is immutable and safe to share across threads.
   *
   * <p>Use this variant when computing global limits or producing aggregate diagnostics rather than
   * when evaluating a single peer's resource usage.
   *
   * @param tracker Request tracker supplying current counts; must not be {@code null}.
   * @param ignoreLocalVsRemote If {@code true}, treat local requests as remote for estimates.
   * @param transfersPerInsert Average transfers per insert used for estimation; non-negative.
   * @param realTimeFlag {@code true} to count real-time requests, {@code false} for bulk.
   */
  RunningRequestsSnapshot(
      RequestTracker tracker,
      boolean ignoreLocalVsRemote,
      int transfersPerInsert,
      boolean realTimeFlag) {
    this.averageTransfersPerInsert = transfersPerInsert;
    this.realTimeFlag = realTimeFlag;
    CountedRequests countCHK = new CountedRequests();
    CountedRequests countSSK = new CountedRequests();
    CountedRequests countCHKSR = new CountedRequests();
    CountedRequests countSSKSR = new CountedRequests();
    tracker.countRequests(
        true,
        false,
        false,
        false,
        realTimeFlag,
        transfersPerInsert,
        ignoreLocalVsRemote,
        countCHK,
        countCHKSR);
    tracker.countRequests(
        true,
        true,
        false,
        false,
        realTimeFlag,
        transfersPerInsert,
        ignoreLocalVsRemote,
        countSSK,
        countSSKSR);
    tracker.countRequests(
        true,
        false,
        true,
        false,
        realTimeFlag,
        transfersPerInsert,
        ignoreLocalVsRemote,
        countCHK,
        countCHKSR);
    tracker.countRequests(
        true,
        true,
        true,
        false,
        realTimeFlag,
        transfersPerInsert,
        ignoreLocalVsRemote,
        countSSK,
        countSSKSR);
    tracker.countRequests(
        false,
        false,
        false,
        false,
        realTimeFlag,
        transfersPerInsert,
        ignoreLocalVsRemote,
        countCHK,
        countCHKSR);
    tracker.countRequests(
        false,
        true,
        false,
        false,
        realTimeFlag,
        transfersPerInsert,
        ignoreLocalVsRemote,
        countSSK,
        countSSKSR);
    tracker.countRequests(
        false,
        false,
        true,
        false,
        realTimeFlag,
        transfersPerInsert,
        ignoreLocalVsRemote,
        countCHK,
        countCHKSR);
    tracker.countRequests(
        false,
        true,
        true,
        false,
        realTimeFlag,
        transfersPerInsert,
        ignoreLocalVsRemote,
        countSSK,
        countSSKSR);
    tracker.countRequests(
        false,
        false,
        false,
        true,
        realTimeFlag,
        transfersPerInsert,
        ignoreLocalVsRemote,
        countCHK,
        countCHKSR);
    tracker.countRequests(
        false,
        true,
        false,
        true,
        realTimeFlag,
        transfersPerInsert,
        ignoreLocalVsRemote,
        countSSK,
        countSSKSR);
    this.expectedTransfersInCHK = countCHK.expectedTransfersIn();
    this.expectedTransfersInSSK = countSSK.expectedTransfersIn();
    this.expectedTransfersOutCHK = countCHK.expectedTransfersOut();
    this.expectedTransfersOutSSK = countSSK.expectedTransfersOut();
    this.totalRequests = countCHK.total() + countSSK.total();
    this.expectedTransfersInCHKSR = countCHKSR.expectedTransfersIn();
    this.expectedTransfersInSSKSR = countSSKSR.expectedTransfersIn();
    this.expectedTransfersOutCHKSR = countCHKSR.expectedTransfersOut();
    this.expectedTransfersOutSSKSR = countSSKSR.expectedTransfersOut();
    this.totalRequestsSR = countCHKSR.total() + countSSKSR.total();
  }

  /**
   * Create a snapshot for traffic originating from or routed to a specific peer.
   *
   * <p>When {@code requestsToNode} is {@code false}, source-restarted requests are counted into the
   * {@code *SR} fields and subtracted from the primary totals so that callers can adjust limits
   * separately. When {@code requestsToNode} is {@code true}, source-restarted accounting is
   * irrelevant and the {@code *SR} counters are zeroed. For requests routed to a peer, local
   * transfers are treated as remote regardless of the supplied {@code ignoreLocalVsRemote}
   * argument, because the peer experiences them as remote usage.
   *
   * <p>Use this constructor when enforcing per-peer limits or when communicating current load to a
   * connected peer.
   *
   * @param tracker Request tracker supplying current counts; must not be {@code null}.
   * @param source Peer whose requests are counted; may be {@code null} for adopted requests.
   * @param requestsToNode {@code true} to count requests routed to the peer, otherwise from it.
   * @param ignoreLocalVsRemote If {@code true}, treat local requests as remote in estimates.
   * @param transfersPerInsert Average transfers per insert used for estimation; non-negative.
   * @param realTimeFlag {@code true} to count real-time requests, {@code false} for bulk.
   */
  RunningRequestsSnapshot(
      RequestTracker tracker,
      PeerNode source,
      boolean requestsToNode,
      boolean ignoreLocalVsRemote,
      int transfersPerInsert,
      boolean realTimeFlag) {
    this.averageTransfersPerInsert = transfersPerInsert;
    this.realTimeFlag = realTimeFlag;
    // We are calculating what part of their resources we use. Therefore, we have
    // to see it from their point of view - meaning all the requests are remote.
    if (requestsToNode) ignoreLocalVsRemote = true;
    CountedRequests countCHK = new CountedRequests();
    CountedRequests countSSK = new CountedRequests();
    CountedRequests countCHKSR = null;
    CountedRequests countSSKSR = null;
    if (!requestsToNode) {
      // No point counting if it's requests to the node.
      // Restarted only matters for requests from a node.
      countCHKSR = new CountedRequests();
      countSSKSR = new CountedRequests();
    }
    tracker.countRequests(
        source,
        requestsToNode,
        true,
        false,
        false,
        false,
        realTimeFlag,
        transfersPerInsert,
        ignoreLocalVsRemote,
        countCHK,
        countCHKSR);
    tracker.countRequests(
        source,
        requestsToNode,
        true,
        true,
        false,
        false,
        realTimeFlag,
        transfersPerInsert,
        ignoreLocalVsRemote,
        countSSK,
        countSSKSR);
    tracker.countRequests(
        source,
        requestsToNode,
        true,
        false,
        true,
        false,
        realTimeFlag,
        transfersPerInsert,
        ignoreLocalVsRemote,
        countCHK,
        countCHKSR);
    tracker.countRequests(
        source,
        requestsToNode,
        true,
        true,
        true,
        false,
        realTimeFlag,
        transfersPerInsert,
        ignoreLocalVsRemote,
        countSSK,
        countSSKSR);
    tracker.countRequests(
        source,
        requestsToNode,
        false,
        false,
        false,
        false,
        realTimeFlag,
        transfersPerInsert,
        ignoreLocalVsRemote,
        countCHK,
        countCHKSR);
    tracker.countRequests(
        source,
        requestsToNode,
        false,
        true,
        false,
        false,
        realTimeFlag,
        transfersPerInsert,
        ignoreLocalVsRemote,
        countSSK,
        countSSKSR);
    tracker.countRequests(
        source,
        requestsToNode,
        false,
        false,
        true,
        false,
        realTimeFlag,
        transfersPerInsert,
        ignoreLocalVsRemote,
        countCHK,
        countCHKSR);
    tracker.countRequests(
        source,
        requestsToNode,
        false,
        true,
        true,
        false,
        realTimeFlag,
        transfersPerInsert,
        ignoreLocalVsRemote,
        countSSK,
        countSSKSR);
    tracker.countRequests(
        source,
        requestsToNode,
        false,
        false,
        false,
        true,
        realTimeFlag,
        transfersPerInsert,
        ignoreLocalVsRemote,
        countCHK,
        countCHKSR);
    tracker.countRequests(
        source,
        requestsToNode,
        false,
        true,
        false,
        true,
        realTimeFlag,
        transfersPerInsert,
        ignoreLocalVsRemote,
        countSSK,
        countSSKSR);
    if (!requestsToNode) {
      this.expectedTransfersInCHKSR = countCHKSR.expectedTransfersIn();
      this.expectedTransfersInSSKSR = countSSKSR.expectedTransfersIn();
      this.expectedTransfersOutCHKSR = countCHKSR.expectedTransfersOut();
      this.expectedTransfersOutSSKSR = countSSKSR.expectedTransfersOut();
      this.totalRequestsSR = countCHKSR.total() + countSSKSR.total();
      this.expectedTransfersInCHK = countCHK.expectedTransfersIn() - expectedTransfersInCHKSR;
      this.expectedTransfersInSSK = countSSK.expectedTransfersIn() - expectedTransfersInSSKSR;
      this.expectedTransfersOutCHK = countCHK.expectedTransfersOut() - expectedTransfersOutCHKSR;
      this.expectedTransfersOutSSK = countSSK.expectedTransfersOut() - expectedTransfersOutSSKSR;
      this.totalRequests = (countCHK.total() + countSSK.total()) - totalRequestsSR;
    } else {
      this.expectedTransfersInCHK = countCHK.expectedTransfersIn();
      this.expectedTransfersInSSK = countSSK.expectedTransfersIn();
      this.expectedTransfersOutCHK = countCHK.expectedTransfersOut();
      this.expectedTransfersOutSSK = countSSK.expectedTransfersOut();
      this.totalRequests = countCHK.total() + countSSK.total();
      this.expectedTransfersInCHKSR = 0;
      this.expectedTransfersInSSKSR = 0;
      this.expectedTransfersOutCHKSR = 0;
      this.expectedTransfersOutSSKSR = 0;
      this.totalRequestsSR = 0;
    }
  }

  /**
   * Create a snapshot from peer-reported load statistics.
   *
   * <p>This constructor copies the expected transfer counts from {@link PeerLoadStats} and assumes
   * they already represent remote usage. Source-restarted counters are set to zero because the peer
   * report does not expose them. The {@code totalRequests} value is taken as-is, which may be
   * {@code -1} when the peer omits the total.
   *
   * @param stats Peer-provided load statistics; must not be {@code null}.
   */
  RunningRequestsSnapshot(PeerLoadStats stats) {
    this.realTimeFlag = stats.realTime;
    // Assume they are all remote.
    this.expectedTransfersInCHK = stats.expectedTransfersInCHK;
    this.expectedTransfersInSSK = stats.expectedTransfersInSSK;
    this.expectedTransfersOutCHK = stats.expectedTransfersOutCHK;
    this.expectedTransfersOutSSK = stats.expectedTransfersOutSSK;
    this.totalRequests = stats.totalRequests;
    this.averageTransfersPerInsert = stats.averageTransfersOutPerInsert;
    this.expectedTransfersInCHKSR = 0;
    this.expectedTransfersInSSKSR = 0;
    this.expectedTransfersOutCHKSR = 0;
    this.expectedTransfersOutSSKSR = 0;
    this.totalRequestsSR = 0;
  }

  /**
   * Log the current snapshot without associating it with a specific peer.
   *
   * <p>The message includes CHK/SSK transfer counts, total requests, and whether the snapshot
   * covers real-time or bulk traffic. If any transfer count is negative, the message is logged at
   * error level to highlight inconsistent accounting; otherwise it is emitted at debug level when
   * enabled. The method has no side effects beyond logging.
   */
  void log() {
    log(null);
  }

  /**
   * Log the current snapshot, optionally annotated with the peer context.
   *
   * <p>The same formatting and severity rules as {@link #log()} are applied. When {@code source} is
   * non-null, its string representation is appended to the log message to aid diagnostics. The
   * method performs no allocation beyond message construction and does not mutate state.
   *
   * @param source Peer to include in the log line; {@code null} for a global message.
   */
  void log(PeerNode source) {
    String message =
        "Running (adjusted): CHK in: "
            + expectedTransfersInCHK
            + " out: "
            + expectedTransfersOutCHK
            + " SSK in: "
            + expectedTransfersInSSK
            + " out: "
            + expectedTransfersOutSSK
            + " total="
            + totalRequests
            + (source == null ? "" : (TEXT_FOR + source))
            + (realTimeFlag ? " (realtime)" : " (bulk)");
    if (expectedTransfersInCHK < 0
        || expectedTransfersOutCHK < 0
        || expectedTransfersInSSK < 0
        || expectedTransfersOutSSK < 0) LOG.error(message);
    else if (LOG.isDebugEnabled()) LOG.debug(message);
  }

  /**
   * Calculate a byte-weighted liability estimate for non-source-restarted requests.
   *
   * <p>The result is computed from the expected transfer counts using fixed per-transfer sizes for
   * CHK and SSK plus the inbound/outbound overhead constants. The {@code input} flag selects which
   * direction of bandwidth to estimate. The {@code ignoreLocalVsRemoteBandwidthLiability} parameter
   * is currently ignored but retained for API symmetry with callers.
   *
   * @param ignoreLocalVsRemoteBandwidthLiability Unused flag preserved for API compatibility.
   * @param input {@code true} to compute an inbound estimate; {@code false} for outbound.
   * @return Byte-weighted estimate derived from the expected transfer counters.
   */
  double calculate(boolean ignoreLocalVsRemoteBandwidthLiability, boolean input) {
    use(ignoreLocalVsRemoteBandwidthLiability);

    if (input)
      return this.expectedTransfersInCHK * (32768d + 256d)
          + this.expectedTransfersInSSK * (2048d + 256d)
          + this.expectedTransfersOutCHK * (double) TRANSFER_OUT_IN_OVERHEAD
          + this.expectedTransfersOutSSK * (double) TRANSFER_OUT_IN_OVERHEAD;
    else
      return this.expectedTransfersOutCHK * (32768d + 256d)
          + this.expectedTransfersOutSSK * (2048d + 256d)
          + expectedTransfersInCHK * (double) TRANSFER_IN_OUT_OVERHEAD
          + expectedTransfersInSSK * (double) TRANSFER_IN_OUT_OVERHEAD;
  }

  /**
   * Calculate a byte-weighted liability estimate for source-restarted requests.
   *
   * <p>This mirrors {@link #calculate(boolean, boolean)} but uses the {@code *SR} counters. When
   * source-restarted requests are not tracked, the counters are zero and the result is {@code 0}.
   * The {@code ignoreLocalVsRemoteBandwidthLiability} parameter is currently unused and retained
   * only to match the calling pattern.
   *
   * @param ignoreLocalVsRemoteBandwidthLiability Unused flag preserved for API compatibility.
   * @param input {@code true} to compute an inbound estimate; {@code false} for outbound.
   * @return Byte-weighted estimate derived from the source-restarted counters.
   */
  double calculateSR(boolean ignoreLocalVsRemoteBandwidthLiability, boolean input) {
    use(ignoreLocalVsRemoteBandwidthLiability);

    if (input)
      return this.expectedTransfersInCHKSR * (32768d + 256d)
          + this.expectedTransfersInSSKSR * (2048d + 256d)
          + this.expectedTransfersOutCHKSR * (double) TRANSFER_OUT_IN_OVERHEAD
          + this.expectedTransfersOutSSKSR * (double) TRANSFER_OUT_IN_OVERHEAD;
    else
      return this.expectedTransfersOutCHKSR * (32768d + 256d)
          + this.expectedTransfersOutSSKSR * (2048d + 256d)
          + expectedTransfersInCHKSR * (double) TRANSFER_IN_OUT_OVERHEAD
          + expectedTransfersInSSKSR * (double) TRANSFER_IN_OUT_OVERHEAD;
  }

  /**
   * Return the number of requests represented by this snapshot.
   *
   * <p>A value of {@code -1} indicates the total is unknown, typically because a peer did not
   * provide a total when reporting its load.
   *
   * @return The number of requests, or {@code -1} when the count is unavailable.
   */
  int totalRequests() {
    return totalRequests;
  }

  /**
   * Return the total expected outgoing transfers for CHK and SSK.
   *
   * <p>The value is derived from the non-source-restarted counters, which may exclude
   * source-restarted transfers depending on the constructor used.
   *
   * @return Sum of {@code expectedTransfersOutCHK} and {@code expectedTransfersOutSSK}.
   */
  int totalOutTransfers() {
    return expectedTransfersOutCHK + expectedTransfersOutSSK;
  }

  /**
   * No-op helper to acknowledge unused parameters without altering control flow.
   *
   * <p>Doclint expects private members to be documented when {@code -private} is used.
   *
   * @param ignored Placeholder parameter array; values are ignored by design.
   */
  @SuppressWarnings("java:S1172")
  private static void use(boolean... ignored) {
    // Intentionally no-op: acknowledge parameter usage without jumps
  }
}
