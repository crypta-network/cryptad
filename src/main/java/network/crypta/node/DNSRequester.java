package network.crypta.node;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashSet;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Background worker that periodically resolves DNS for unconnected peers to refresh handshake
 * endpoints.
 *
 * <p>The worker selects at most one unconnected peer per cycle and spreads queries using randomized
 * delays to avoid bursts. Recently checked peers are tracked by their location and skipped until
 * roughly 81% of the remaining unconnected set has been visited, which reduces duplicated lookups
 * while still making progress across the pool.
 *
 * <p>Lifecycle: {@link #start()} schedules this instance on the node's executor; {@link #run()}
 * loops until the thread is interrupted. Non-fatal throwables are logged and the loop continues.
 * Call {@link #forceRun()} to wake the worker early.
 *
 * @author amphibian
 */
public class DNSRequester implements Runnable {
  private static final Logger LOG = LoggerFactory.getLogger(DNSRequester.class);

  final Node node;
  private long lastLogTime;
  private final Set<Double> recentNodeIdentitySet = new HashSet<>();
  private final Deque<Double> recentNodeIdentityQueue = new ArrayDeque<>();
  // For simulations/tests only; may be set by external harnesses when supported.
  static boolean disable = false;
  private boolean wakeRequested;

  DNSRequester(Node node) {
    this.node = node;
  }

  void start() {
    LOG.info("Starting DNSRequester");
    // Schedule the worker on the node's executor with a descriptive thread name.
    node.getExecutor().execute(this, "DNSRequester thread for " + node.getDarknetPortNumber());
  }

  /**
   * Executes the background loop and returns only when the worker thread is interrupted.
   *
   * <p>Fatal JVM conditions ({@link VirtualMachineError}) are rethrown to allow higher-level
   * handlers to terminate the process. Other throwables are caught and logged so the worker can
   * continue.
   */
  @Override
  @SuppressWarnings("java:S1181")
  public void run() {
    while (!Thread.currentThread().isInterrupted()) {
      try {
        realRun();
      } catch (VirtualMachineError fatal) {
        // Propagate truly fatal JVM conditions; do not attempt to keep the worker alive. We avoid
        // logging here to prevent duplicate stack traces when uncaught handlers also log.
        throw fatal;
      } catch (Throwable t) {
        // Keep the background worker alive on non-fatal throwables.
        LOG.error("Caught in DNSRequester: {}", t, t);
      }
    }
  }

  private void realRun() {
    // Resolve DNS for unconnected peers that were not checked recently. This avoids repeatedly
    // selecting the same locations (coupon collector effect) and spreads lookups over time.
    PeerNode[] nodesToCheck =
        Arrays.stream(node.getPeers().myPeers())
            .filter(peerNode -> !peerNode.isConnected())
            // Identify recent peers by location rather than identity. Double equality is used only
            // for exact-match deduplication; ordering/approximation is not required here.
            .filter(peerNode -> !recentNodeIdentitySet.contains(peerNode.getLocation()))
            .toArray(PeerNode[]::new);

    if (LOG.isDebugEnabled()) {
      long now = System.currentTimeMillis();
      if ((now - lastLogTime) > 100) {
        // Rate-limit debug logs to at most once every ~100 ms.
        LOG.debug("Processing DNS Requests (log rate-limited)");
      }
      lastLogTime = now;
    }

    int unconnectedNodesLength = nodesToCheck.length;
    if (unconnectedNodesLength > 0) {
      // Check a randomly chosen unconnected peer that has not been visited recently to avoid
      // bursts of DNS requests.
      PeerNode pn = nodesToCheck[node.getFastWeakRandom().nextInt(unconnectedNodesLength)];
      if (unconnectedNodesLength < 5) {
        // For tiny eligible sets, clear recent-selection state for simplicity.
        recentNodeIdentitySet.clear();
        recentNodeIdentityQueue.clear();
      } else {
        // Defer rechecking this location until ~81% of the other unconnected peers have been
        // visited. This reduces duplicate lookups while maintaining coverage.
        recentNodeIdentitySet.add(pn.getLocation());
        recentNodeIdentityQueue.offerFirst(pn.getLocation());
        while (recentNodeIdentityQueue.size() > (0.81 * unconnectedNodesLength)) {
          recentNodeIdentitySet.remove(recentNodeIdentityQueue.removeLast());
        }
      }
      // Attempt a DNS refresh for the chosen peer.
      pn.maybeUpdateHandshakeIPs(false);
    }

    int nextMaxWaitTime = 1000 + node.getFastWeakRandom().nextInt(60000);
    try {
      synchronized (this) {
        // Randomized sleep (1s..61s) to spread queries and avoid synchronized bursts across nodes.
        long deadline = System.currentTimeMillis() + nextMaxWaitTime;
        while (!wakeRequested) {
          long remaining = deadline - System.currentTimeMillis();
          if (remaining <= 0) break;
          wait(remaining); // Sleep up to the remaining time or until notified.
        }
        // Consume any pending wake so subsequent waits block as expected.
        wakeRequested = false;
      }
    } catch (InterruptedException _) {
      // Restore interrupt status so callers can act accordingly.
      Thread.currentThread().interrupt();
    }
  }

  /**
   * Wakes the worker if it is currently waiting.
   *
   * <p>Signals the internal wait/notify gate so a pending sleep ends early and the next lookup
   * cycle can begin sooner. Safe to call from any thread.
   */
  public void forceRun() {
    synchronized (this) {
      wakeRequested = true;
      notifyAll();
    }
  }
}
