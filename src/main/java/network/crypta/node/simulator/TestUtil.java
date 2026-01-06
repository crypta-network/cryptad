package network.crypta.node.simulator;

import network.crypta.node.Node;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Test utility helpers for simulator-oriented node initialization checks.
 *
 * <p>This class provides blocking helpers that poll a running {@link Node} until a minimum number
 * of opennet connections is observed. It is intended for simulator-style tests that need the
 * network to form before assertions can run, and it favors simple, predictable behavior over
 * advanced scheduling or asynchronous callbacks. The methods are synchronous and sleep between
 * samples, so callers should invoke them from test threads rather than time-sensitive execution
 * paths. The class is stateless; all state lives in the caller's {@code Node} instance and the
 * local loop variables.
 *
 * <p>Notable behaviors include a fixed ten-minute upper bound, periodic progress logging, and a
 * boolean success result rather than throwing on timeout. Concurrency-wise, it performs read-only
 * queries against the node and does not synchronize; it is safe to call from multiple threads
 * provided the underlying {@code Node} supports concurrent reads.
 *
 * <ul>
 *   <li>Polls peer counts and connection counts with a one-second cadence.
 *   <li>Logs progress on each sample and a warning if the timeout is reached.
 *   <li>Does not mutate node state or manage node lifecycle.
 * </ul>
 *
 * @see Node
 */
public class TestUtil {
  private static final Logger LOG = LoggerFactory.getLogger(TestUtil.class);

  private TestUtil() {
    throw new IllegalStateException("Utility class");
  }

  static boolean waitForNodes(Node node) throws InterruptedException {
    int targetPeers = node.network().opennet().getAnnouncementThreshold();
    // Wait until the opennet connection count reaches the configured threshold.
    int seconds = 0;
    boolean success = false;
    while (seconds < 600) {
      Thread.sleep(1000);
      int seeds = node.network().peers().countSeednodes();
      int seedConns =
          node.network().peers().seedPeers().getConnectedSeedServerPeersVector(null).size();
      int opennetPeers = node.network().peers().countValidPeers();
      int opennetConns = node.network().peers().countConnectedOpennetPeers();
      LOG.info(
          "{} : seeds: {}, connected: {} opennet: peers: {}, connected: {}",
          seconds,
          seeds,
          seedConns,
          opennetPeers,
          opennetConns);
      seconds++;
      if (opennetConns >= targetPeers) {
        success = true;
        break;
      }
    }
    if (!success) {
      LOG.warn("Failed to reach target peers count {} in 10 minutes.", targetPeers);
    }
    return success;
  }
}
