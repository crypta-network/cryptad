package network.crypta.node;

import network.crypta.node.RequestTracker.CountedRequests;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class RunningRequestsSnapshot {
  private static final Logger LOG = LoggerFactory.getLogger(RunningRequestsSnapshot.class);
  private static final String TEXT_FOR = " for ";

  // Look plausible from my node-throttle.dat stats as of 01/11/2010.
  /**
   * Output bytes required for an inbound transfer. Includes e.g. sending the request in the first
   * place.
   */
  private static final int TRANSFER_IN_OUT_OVERHEAD = 256;

  /** Input bytes required for an outbound transfer. Includes e.g. sending the insert etc. */
  private static final int TRANSFER_OUT_IN_OVERHEAD = 256;

  final int expectedTransfersOutCHK;
  final int expectedTransfersInCHK;
  final int expectedTransfersOutSSK;
  final int expectedTransfersInSSK;
  final int totalRequests;
  final int expectedTransfersOutCHKSR;
  final int expectedTransfersInCHKSR;
  final int expectedTransfersOutSSKSR;
  final int expectedTransfersInSSKSR;
  final int totalRequestsSR;
  final int averageTransfersPerInsert;
  final boolean realTimeFlag;

  /**
   * Create a snapshot of all requests running. Because this isn't for any particular peer, it
   * includes all requests, even those which are SourceRestarted.
   *
   * @param tracker The RequestTracker for the Node.
   * @param ignoreLocalVsRemote If true, pretend that the request is remote even if it's local (that
   *     is, count imaginary onward transfers etc. depending on the request type).
   * @param transfersPerInsert Assume that any insert will cause this many outgoing transfers. This
   *     is not predictable, so we use an average.
   * @param realTimeFlag If true, count real-time requests, if false, count bulk requests.
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
   * Create a snapshot of either the requests from a node, or the requests routed to a node. If we
   * are counting requests from a node, we also fill in the *SR counters with the counts for
   * requests which have sourceRestarted() i.e. the requests where the peer has reconnected after a
   * timeout but the requests are still running. These are only counted in the *SR totals, they are
   * not in the basic totals. The caller will reduce the limits according to the *SR totals, and
   * only consider the non-SR requests when deciding whether the peer is over the limit. The updated
   * limits are sent to the downstream node so that it can send the right number of requests.
   *
   * @param tracker Request tracker used to count relevant requests.
   * @param source The peer we are interested in.
   * @param requestsToNode If true, count requests sent to the node and currently running. If false,
   *     count requests originated by the node.
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

  void log() {
    log(null);
  }

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
   * @return The number of requests running or -1 if not known (remote doesn't tell us).
   */
  int totalRequests() {
    return totalRequests;
  }

  int totalOutTransfers() {
    return expectedTransfersOutCHK + expectedTransfersOutSSK;
  }

  @SuppressWarnings("java:S1172")
  private static void use(boolean... ignored) {
    // Intentionally no-op: acknowledge parameter usage without jumps
  }
}
