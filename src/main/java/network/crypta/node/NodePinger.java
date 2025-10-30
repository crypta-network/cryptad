package network.crypta.node;

import static java.util.concurrent.TimeUnit.DAYS;

import java.util.Arrays;
import network.crypta.node.NodeStats.PeerLoadStats;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Periodically samples connected peers to maintain latency and capacity summaries.
 *
 * <p>This component computes the median round-trip time (RTT) across currently connected peers and
 * derives capacity quartiles for realtime and bulk directions (input/output) using the latest
 * {@link PeerLoadStats} advertised by each peer. Results are stored in volatile fields so readers
 * see the most recent values without additional synchronization.
 *
 * <p>Threading and scheduling: {@link #run()} executes on the node's ticker/executor. It grabs a
 * snapshot of the connected peers under {@code PeerManager}'s lock and then performs all
 * calculations without holding locks.
 */
public class NodePinger implements Runnable {
  private static final Logger LOG = LoggerFactory.getLogger(NodePinger.class);

  private final Node node;
  private volatile double meanPing = 0;

  /** One year in milliseconds; used by callers as an upper sanity bound for ping. */
  public static final double CRAZY_MAX_PING_TIME = 365.25 * DAYS.toMillis(1);

  NodePinger(Node n) {
    this.node = n;
  }

  // Starts a single sampling pass immediately; callers typically schedule via the ticker.
  void start() {
    run();
  }

  @Override
  public void run() {
    try {
      PeerNode[] peers;
      synchronized (node.getPeers()) {
        peers = node.getPeers().connectedPeers();
      }
      if (peers == null || peers.length == 0) return;

      // Operate on the snapshot without holding PeerManager locks
      recalculateMean(peers);
      capacityInputRealtime.calculate(peers);
      capacityInputBulk.calculate(peers);
      capacityOutputRealtime.calculate(peers);
      capacityOutputBulk.calculate(peers);
    } finally {
      // Requeue after work completes to avoid exacerbating overload
      node.getTicker().queueTimedJob(this, 200);
    }
  }

  /**
   * Recomputes the median RTT from the provided peer snapshot.
   *
   * @param peers snapshot of connected peers; must not be modified while in use
   */
  private void recalculateMean(PeerNode[] peers) {
    if (peers.length == 0) return;
    meanPing = calculateMedianPing(peers);
    if (LOG.isDebugEnabled()) LOG.debug("Median ping (ms): {}", meanPing);
  }

  /**
   * Returns the upper-median RTT in milliseconds.
   *
   * <p>For an even number of samples, the element at {@code length/2} after sorting is used.
   */
  private double calculateMedianPing(PeerNode[] peers) {
    double[] allPeers = new double[peers.length];
    for (int i = 0; i < peers.length; i++) {
      PeerNode peer = peers[i];
      allPeers[i] = peer.averagePingTime();
    }

    Arrays.sort(allPeers);
    return allPeers[peers.length / 2];
  }

  /**
   * Gets the current median RTT across connected peers.
   *
   * @return median ping in milliseconds; {@code 0} until the first calculation completes
   */
  public double averagePingTime() {
    return meanPing;
  }

  final CapacityChecker capacityInputRealtime = new CapacityChecker(true, true);
  final CapacityChecker capacityInputBulk = new CapacityChecker(true, false);
  final CapacityChecker capacityOutputRealtime = new CapacityChecker(false, true);
  final CapacityChecker capacityOutputBulk = new CapacityChecker(false, false);

  /**
   * Maintains capacity quartiles for a given direction and class (input/output × realtime/bulk).
   *
   * <p>Values come from {@link PeerLoadStats#peerLimit(boolean)} of peers that provided a recent
   * load status for the selected class. Units are the same as reported by peers.
   */
  class CapacityChecker {
    final boolean isInput;
    final boolean isRealtime;
    private double min;
    private double median;
    private double firstQuartile;
    private double lastQuartile;
    private double max;

    CapacityChecker(boolean input, boolean realtime) {
      isInput = input;
      isRealtime = realtime;
    }

    // Updates quartiles from the given peer snapshot. Ignores peers without recent load stats.
    void calculate(PeerNode[] peers) {
      double[] allPeers = new double[peers.length];
      int x = 0;
      for (PeerNode peer : peers) {
        PeerLoadStats stats = peer.outputLoadTracker(isRealtime).getLastIncomingLoadStats();
        if (stats == null) continue;
        allPeers[x++] = stats.peerLimit(isInput);
      }
      if (x != peers.length) {
        allPeers = Arrays.copyOf(allPeers, x);
      }
      Arrays.sort(allPeers);
      if (x == 0) return;
      synchronized (this) {
        min = allPeers[0];
        median = allPeers[x / 2];
        firstQuartile = allPeers[x / 4];
        lastQuartile = allPeers[(x * 3) / 4];
        max = allPeers[x - 1];
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Peer capacity quartiles: {}{}{}",
              isInput ? "input " : "output ",
              isRealtime ? "realtime: " : "bulk: ",
              Arrays.toString(getQuartiles()));
      }
    }

    /** Returns a snapshot of quartiles in ascending order: min, Q1, median, Q3, max. */
    synchronized double[] getQuartiles() {
      return new double[] {min, firstQuartile, median, lastQuartile, max};
    }

    /** Returns {@code min(median/2, firstQuartile)} for fair sharing thresholding. */
    synchronized double getThreshold() {
      return Math.min(median / 2, firstQuartile);
    }
  }

  /**
   * Gets the per-class capacity threshold derived from peer quartiles.
   *
   * @param isRealtime whether to use realtime ({@code true}) or bulk ({@code false}) metrics
   * @param isInput whether to use input ({@code true}) or output ({@code false}) metrics
   * @return threshold equal to {@code min(median/2, Q1)} in peer-reported units
   */
  public double capacityThreshold(boolean isRealtime, boolean isInput) {
    return capacityChecker(isRealtime, isInput).getThreshold();
  }

  private CapacityChecker capacityChecker(boolean isRealtime, boolean isInput) {
    if (isRealtime) {
      return isInput ? capacityInputRealtime : capacityOutputRealtime;
    } else {
      return isInput ? capacityInputBulk : capacityOutputBulk;
    }
  }
}
