package network.crypta.node.simulator;

import java.util.concurrent.locks.LockSupport;
import network.crypta.crypt.RandomSource;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import network.crypta.node.FSParseException;
import network.crypta.node.Location;
import network.crypta.node.Node;
import network.crypta.node.NodeInitException;
import network.crypta.node.NodeStats;
import network.crypta.node.PeerNode;
import network.crypta.node.PeerTooOldException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides shared utilities and test helpers for the RealNode* test suite.
 *
 * <p>This abstract base class centralizes logic that repeatedly appears when driving simulation
 * tests against a live {@link Node} graph. It focuses on building deterministic synthetic
 * topologies, performing symmetric peer connections, and waiting for connectivity to stabilize
 * while capturing telemetry that is useful for debugging. The helpers here favor clarity and
 * repeatability over performance; they assume tests run in a controlled environment and use
 * predictable inputs such as an explicit {@link RandomSource}. The class does not own state beyond
 * logging constants and uses static methods to keep call sites concise and free of side effects.
 *
 * <p>Thread-safety is inherited from the underlying node implementation. The utilities themselves
 * are stateless, but they may block while waiting for peer handshakes to converge, and they read
 * live node statistics. Callers should use them from test threads that can tolerate waiting, and
 * they should not assume idempotency when node state changes concurrently.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Assigning idealized locations and constructing Kleinberg-like networks.
 *   <li>Connecting peers with consistent trust and visibility defaults.
 *   <li>Polling connectivity and logging progress with latency summaries.
 * </ul>
 *
 * @author toad
 * @author robert
 * @see Node
 */
public abstract class RealNodeTest {
  private static final Logger LOG = LoggerFactory.getLogger(RealNodeTest.class);
  private static final long CONNECTION_WAIT_NANOS = 1_000_000_000L;

  static final int EXIT_BASE = NodeInitException.EXIT_NODE_UPPER_LIMIT;
  static final int EXIT_CANNOT_DELETE_OLD_DATA = EXIT_BASE + 3;
  static final int EXIT_PING_TARGET_NOT_REACHED = EXIT_BASE + 4;
  static final int EXIT_INSERT_FAILED = EXIT_BASE + 5;
  static final int EXIT_BAD_DATA = EXIT_BASE + 7;

  static final FRIEND_TRUST trust = FRIEND_TRUST.LOW;
  static final FRIEND_VISIBILITY visibility = FRIEND_VISIBILITY.NO;

  /**
   * Creates the base helper for RealNode* tests with no instance state.
   *
   * <p>This constructor exists to let subclasses inherit the shared static utilities without
   * requiring any initialization parameters. It performs no work and does not allocate resources,
   * so it is safe to invoke from any test setup path. Subclasses typically rely on the static
   * helpers directly, but the protected constructor keeps the type extensible while preventing
   * direct instantiation outside the test hierarchy.
   */
  protected RealNodeTest() {}

  /* Because we start a whole bunch of nodes at once, we will get many "Not reusing
   * tracker, so wiping old trackers" messages. This is normal, all the nodes start
   * handshaking straight off, they all send JFK(1)s, and we get race conditions. */

  /*
  Borrowed from mrogers simulation code (February 6, 2008)
  --
  Note: May not generate good networks. Presumably this is because the arrays are always scanned
         [0..n], some nodes tend to have *much* higher connections than the degree (the first few),
         starving the latter ones.
  */
  static void makeKleinbergNetwork(
      Node[] nodes,
      boolean idealLocations,
      int degree,
      boolean forceNeighbourConnections,
      RandomSource random) {
    if (idealLocations) {
      assignIdealLocations(nodes);
    }
    if (forceNeighbourConnections) {
      connectNeighbourNodes(nodes);
    }
    for (Node a : nodes) {
      double norm = calculateDistanceNormalization(a, nodes);
      connectWithProbability(a, nodes, norm, degree, random);
    }
  }

  private static void assignIdealLocations(Node[] nodes) {
    // First set the locations up so we don't spend a long time swapping just to stabilize each
    // network.
    double div = 1.0 / nodes.length;
    double loc = 0.0;
    for (Node node : nodes) {
      node.network().setLocation(loc);
      loc += div;
    }
  }

  private static void connectNeighbourNodes(Node[] nodes) {
    for (int i = 0; i < nodes.length; i++) {
      int next = (i + 1) % nodes.length;
      connect(nodes[i], nodes[next]);
    }
  }

  private static double calculateDistanceNormalization(Node node, Node[] nodes) {
    double norm = 0.0;
    for (Node other : nodes) {
      if (node.network().location() == other.network().location()) continue;
      norm += 1.0 / distance(node, other);
    }
    return norm;
  }

  private static void connectWithProbability(
      Node node, Node[] nodes, double normalization, int degree, RandomSource random) {
    // Create degree/2 outgoing connections
    for (Node other : nodes) {
      if (node.network().location() == other.network().location()) continue;
      double p = 1.0 / distance(node, other) / normalization;
      for (int n = 0; n < degree / 2; n++) {
        if (random.nextFloat() < p) {
          connect(node, other);
          break;
        }
      }
    }
  }

  static void connect(Node a, Node b) {
    try {
      a.network().connect(b, trust, visibility);
      b.network().connect(a, trust, visibility);
    } catch (FSParseException e) {
      LOG.error("cannot connect!!!!", e);
    } catch (PeerParseException e) {
      LOG.error("cannot connect #2!!!!", e);
    } catch (ReferenceSignatureVerificationException e) {
      LOG.error("cannot connect #3!!!!", e);
    } catch (PeerTooOldException e) {
      LOG.error("cannot connect #4!!!!", e);
    }
  }

  static double distance(Node a, Node b) {
    double aL = a.network().location();
    double bL = b.network().location();
    return Location.distance(aL, bL);
  }

  static String getPortNumber(PeerNode p) {
    if (p == null || p.getPeer() == null) return "null";
    return Integer.toString(p.getPeer().getPort());
  }

  static String getPortNumber(Node n) {
    if (n == null) return "null";
    return Integer.toString(n.network().darknetPortNumber());
  }

  static void waitForAllConnected(Node[] nodes) throws InterruptedException {
    long tStart = System.currentTimeMillis();
    while (true) {
      ConnectionStats stats = ConnectionStats.capture(nodes);
      if (stats.isFullyConnected(nodes.length)) {
        LOG.info("All nodes fully connected");
        return;
      }
      logWaitingForConnections(stats, nodes.length, tStart);
      waitForNextCheck();
    }
  }

  private static void waitForNextCheck() throws InterruptedException {
    LockSupport.parkNanos(CONNECTION_WAIT_NANOS);
    if (Thread.interrupted()) {
      throw new InterruptedException();
    }
  }

  private static void logWaitingForConnections(ConnectionStats stats, int nodeCount, long tStart) {
    long tDelta = (System.currentTimeMillis() - tStart) / 1000;
    LOG.info(
        "Waiting for nodes to be fully connected: {} / {} ({} / {} connections total partial {}"
            + " compatible {}) - backed off {} ping min/avg/max {}/{}/{} at {}s",
        stats.countFullyConnected,
        nodeCount,
        stats.totalConnections,
        stats.totalPeers,
        stats.totalPartialConnections,
        stats.totalCompatibleConnections,
        stats.totalBackedOff,
        (int) stats.minPingTime,
        (int) stats.averagePingTime(nodeCount),
        (int) stats.maxPingTime,
        tDelta);
  }

  private static final class ConnectionStats {
    private int countFullyConnected;
    private int countReallyConnected;
    private int totalPeers;
    private int totalConnections;
    private int totalPartialConnections;
    private int totalCompatibleConnections;
    private int totalBackedOff;
    private double totalPingTime;
    private double maxPingTime;
    private double minPingTime = Double.MAX_VALUE;

    private static ConnectionStats capture(Node[] nodes) {
      ConnectionStats stats = new ConnectionStats();
      for (Node node : nodes) {
        stats.recordNode(node);
      }
      return stats;
    }

    private void recordNode(Node node) {
      int countConnected = node.network().peers().countConnectedDarknetPeers();
      int countAlmostConnected = node.network().peers().countAlmostConnectedDarknetPeers();
      int countTotal = node.network().peers().countValidPeers();
      int countBackedOff = node.network().peers().countBackedOffPeers(false);
      int countCompatible = node.network().peers().countCompatibleDarknetPeers();
      totalPeers += countTotal;
      totalConnections += countConnected;
      totalPartialConnections += countAlmostConnected;
      totalCompatibleConnections += countCompatible;
      totalBackedOff += countBackedOff;
      double pingTime = node.network().stats().getNodeAveragePingTime();
      totalPingTime += pingTime;
      if (pingTime > maxPingTime) maxPingTime = pingTime;
      if (pingTime < minPingTime) minPingTime = pingTime;
      if (countConnected == countTotal) {
        countFullyConnected++;
        if (countBackedOff == 0) countReallyConnected++;
      } else {
        logConnectionCount(node, countConnected, countAlmostConnected);
      }
      logBackedOff(node, countBackedOff);
    }

    private boolean isFullyConnected(int nodeCount) {
      return countFullyConnected == nodeCount
          && countReallyConnected == nodeCount
          && totalBackedOff == 0
          && minPingTime < NodeStats.DEFAULT_SUB_MAX_PING_TIME
          && maxPingTime < NodeStats.DEFAULT_SUB_MAX_PING_TIME
          && averagePingTime(nodeCount) < NodeStats.DEFAULT_SUB_MAX_PING_TIME;
    }

    private double averagePingTime(int nodeCount) {
      return totalPingTime / nodeCount;
    }

    private void logConnectionCount(Node node, int countConnected, int countAlmostConnected) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Connection count for {} : {} partial {}", node, countConnected, countAlmostConnected);
      }
    }

    private void logBackedOff(Node node, int countBackedOff) {
      if (LOG.isDebugEnabled() && countBackedOff > 0) {
        LOG.debug("Backed off: {} : {}", node, countBackedOff);
      }
    }
  }
}
