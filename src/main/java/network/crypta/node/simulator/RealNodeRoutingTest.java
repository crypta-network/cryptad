package network.crypta.node.simulator;

import java.io.File;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.RandomSource;
import network.crypta.node.LocationManager;
import network.crypta.node.Node;
import network.crypta.node.NodeInitException;
import network.crypta.node.NodeStarter;
import network.crypta.support.PooledExecutor;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.io.FileUtil;
import network.crypta.support.math.BootstrappingDecayingRunningAverage;
import network.crypta.support.math.RunningAverage;
import network.crypta.support.math.SimpleRunningAverage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

/**
 * Runs a deterministic routing simulation across a small in-process darknet mesh.
 *
 * <p>This class creates a fixed-size set of real nodes, wires them into a Kleinberg-style topology,
 * and repeatedly issues routed pings until the observed success rate reaches target accuracy. It is
 * intended for manual, long-running experiments that compare routing behavior under different
 * configuration knobs, rather than for unit-test execution. The harness keeps the random seed
 * stable so that routing changes can be compared across runs, while still allowing natural timing
 * variance from the threaded node runtime.
 *
 * <p>State is managed entirely in a temporary working directory, and the simulation terminates by
 * calling {@link System#exit(int)} with a process status. The test is not thread-safe to embed in
 * other frameworks because it owns process lifecycle and uses shared static counters from {@link
 * LocationManager}.
 *
 * <ul>
 *   <li>Creates a reproducible mesh with known ports and deterministic locations.
 *   <li>Starts all nodes, waits for connectivity, and runs routed pings in cycles.
 *   <li>Logs swap statistics, path-length averages, and final accuracy summaries.
 * </ul>
 *
 * @author amphibian
 */
public class RealNodeRoutingTest extends RealNodeTest {
  private static final Logger LOG = LoggerFactory.getLogger(RealNodeRoutingTest.class);

  static final int NUMBER_OF_NODES = 100;
  static final int DEGREE = 10;
  static final short MAX_HTL = (short) 5;
  static final boolean START_WITH_IDEAL_LOCATIONS = true;
  static final boolean FORCE_NEIGHBOUR_CONNECTIONS = true;
  static final int MAX_PINGS = 2000;
  static final boolean ENABLE_SWAPPING = false;
  static final boolean ENABLE_SWAP_QUEUEING = false;
  static final boolean ENABLE_FOAF = true;

  private static final int DARKNET_PORT_BASE = 10_000 + NUMBER_OF_NODES;

  /**
   * Last darknet port reserved for the simulated node range, inclusive.
   *
   * <p>This value is derived from the base port and {@link #NUMBER_OF_NODES} so that the simulator
   * can allocate a contiguous range without scanning. It is constant for a given run and is a
   * read-only configuration used when setting up external tooling or log filters.
   */
  public static final int DARKNET_PORT_END = DARKNET_PORT_BASE + NUMBER_OF_NODES;

  private static final int PINGS_PER_CYCLE = 10;

  /**
   * Starts the routing simulation and blocks until the target accuracy is achieved or the run
   * fails.
   *
   * <p>The method deletes and recreates a working directory, seeds the deterministic random source,
   * constructs {@link Node} instances, and starts them on distinct darknet ports. It then waits for
   * the network to connect and performs routed pings in cycles, logging location swaps and hop
   * statistics. The process exits with a non-zero status if it cannot prepare the working directory
   * or if the accuracy target is not reached within the configured maximum tests. This entry point
   * is not intended to be idempotent because it wipes the prior state on each run.
   *
   * <pre>{@code
   * // Example: run the routing simulator from the command line.
   * RealNodeRoutingTest.main(new String[0]);
   * }</pre>
   *
   * @throws NodeInitException if node initialization fails while creating the test nodes
   * @throws InterruptedException if the thread is interrupted while waiting for connectivity
   */
  static void main() throws NodeInitException, InterruptedException {
    LOG.info("Routing test using real nodes:");
    LOG.info("");
    String dir = "realNodeRequestInsertTest";
    File wd = new File(dir);
    if (!FileUtil.removeAll(wd)) {
      LOG.error("Mass delete failed, test may not be accurate.");
      System.exit(EXIT_CANNOT_DELETE_OLD_DATA);
    }
    if (!wd.mkdir() && !wd.isDirectory()) {
      LOG.error("Working directory could not be created: {}", wd.getAbsolutePath());
      System.exit(EXIT_CANNOT_DELETE_OLD_DATA);
    }
    // NOTE: globalTestInit returns in an ignored random source
    NodeStarter.globalTestInit(wd, false, Level.ERROR, "", true, null);
    // Make the network reproducible so we can easily compare different routing options by
    // specifying a seed.
    DummyRandomSource random = new DummyRandomSource(3142);
    Node[] nodes = new Node[NUMBER_OF_NODES];
    LOG.info("Creating nodes...");
    PriorityAwareExecutor executor = new PooledExecutor();
    for (int i = 0; i < NUMBER_OF_NODES; i++) {
      LOG.info("Creating node {}", i);
      NodeStarter.TestNodeParameters params = new NodeStarter.TestNodeParameters();
      params.setPort(DARKNET_PORT_BASE + i);
      params.setOpennetPort(0);
      params.setBaseDirectory(wd);
      params.setDisableProbabilisticHTLs(true);
      params.setMaxHTL(MAX_HTL);
      params.setRandom(random);
      params.setExecutor(executor);
      params.setThreadLimit(500 * NUMBER_OF_NODES);
      params.setStoreSize(65_536L);
      params.setRamStore(true);
      params.setEnableSwapping(ENABLE_SWAPPING);
      params.setEnableSwapQueueing(ENABLE_SWAP_QUEUEING);
      params.setEnablePacketCoalescing(true);
      params.setEnableFOAF(ENABLE_FOAF);
      params.setLongPingTimes(true);
      nodes[i] = NodeStarter.createTestNode(params);
      LOG.info("Created node {}", i);
    }
    LOG.info("Created " + NUMBER_OF_NODES + " nodes");
    // Now link them up
    makeKleinbergNetwork(
        nodes, START_WITH_IDEAL_LOCATIONS, DEGREE, FORCE_NEIGHBOUR_CONNECTIONS, random);

    LOG.info("Added random links");

    for (int i = 0; i < NUMBER_OF_NODES; i++) {
      LOG.info("Starting node {}", i);
      nodes[i].start(false);
    }

    waitForAllConnected(nodes);

    // Make the choice of nodes to ping to and from deterministic too.
    // There is timing noise because of all the nodes, but the network
    // and the choice of nodes to start and finish are deterministic, so
    // the overall result should be more or less deterministic.
    waitForPingAverage(0.98, nodes, new DummyRandomSource(3143), MAX_PINGS, 5000);
    System.exit(0);
  }

  static void waitForPingAverage(
      double accuracy, Node[] nodes, RandomSource random, int maxTests, int sleepTime)
      throws InterruptedException {
    PingCounters counters = new PingCounters();
    int cycleNumber = 0;
    int lastSwaps = 0;
    int lastNoSwaps = 0;
    RunningAverage avg = new SimpleRunningAverage(100, 0.0);
    RunningAverage avg2 = new BootstrappingDecayingRunningAverage(0.0, 0.0, 1.0, 100, null);
    for (int total = 0; total < maxTests; total++) {
      cycleNumber++;
      sleepOrThrow(sleepTime);
      logNodeLocations(cycleNumber, nodes);
      SwapSnapshot swaps = logSwapStats(nodes, lastSwaps, lastNoSwaps);
      lastNoSwaps = swaps.noSwaps();

      waitForAllConnected(nodes);

      lastSwaps = swaps.newSwaps();
      // Do some (routed) test-pings
      runPingBatch(nodes, random, sleepTime, avg, avg2, counters);
      logAveragePathLength(counters);
      if (hasReachedAccuracy(accuracy, avg, counters)) {
        logAccuracySummary(nodes, accuracy, counters);
        return;
      }
    }
    System.exit(EXIT_PING_TARGET_NOT_REACHED);
  }

  private static void sleepOrThrow(int sleepTime) throws InterruptedException {
    try {
      Thread.sleep(sleepTime);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw e;
    }
  }

  private static void logNodeLocations(int cycleNumber, Node[] nodes) {
    for (int i = 0; i < nodes.length; i++) {
      LOG.info("Cycle {} node {}: {}", cycleNumber, i, nodes[i].network().location());
    }
  }

  private static SwapSnapshot logSwapStats(Node[] nodes, int lastSwaps, int lastNoSwaps) {
    int newSwaps = LocationManager.getSwaps();
    int totalStarted = LocationManager.getStartedSwaps();
    int noSwaps = LocationManager.getNoSwaps();
    LOG.info("Swaps: {}", newSwaps - lastSwaps);
    LOG.info(
        "Total swaps: Started*2: {}, succeeded: {}, last minute failures: {}, ratio {}, early"
            + " failures: {}",
        totalStarted * 2,
        newSwaps,
        noSwaps,
        (double) noSwaps / (double) newSwaps,
        (totalStarted * 2) - (noSwaps + newSwaps));
    LOG.info(
        "This cycle ratio: {}",
        ((double) (noSwaps - lastNoSwaps)) / ((double) (newSwaps - lastSwaps)));
    LOG.info(
        "Swaps rejected (already locked): {}", LocationManager.getSwapsRejectedAlreadyLocked());
    LOG.info("Swaps rejected (nowhere to go): {}", LocationManager.getSwapsRejectedNowhereToGo());
    LOG.info("Swaps rejected (rate limit): {}", LocationManager.getSwapsRejectedRateLimit());
    LOG.info("Swaps rejected (recognized ID):{}", LocationManager.getSwapsRejectedRecognizedID());
    LOG.info("Swaps failed:{}", LocationManager.getNoSwaps());
    LOG.info("Swaps succeeded:{}", LocationManager.getSwaps());

    logSwapAverages(nodes);
    return new SwapSnapshot(newSwaps, noSwaps);
  }

  private static void logSwapAverages(Node[] nodes) {
    double totalSwapInterval = 0.0;
    double totalSwapTime = 0.0;
    for (Node node : nodes) {
      totalSwapInterval += node.network().locationManager().getSendSwapInterval();
      totalSwapTime += node.network().locationManager().getAverageSwapTime();
    }
    LOG.info("Average swap time: {}", totalSwapTime / nodes.length);
    LOG.info("Average swap sender interval: {}", totalSwapInterval / nodes.length);
  }

  private static void runPingBatch(
      Node[] nodes,
      RandomSource random,
      int sleepTime,
      RunningAverage avg,
      RunningAverage avg2,
      PingCounters counters)
      throws InterruptedException {
    for (int i = 0; i < PINGS_PER_CYCLE; i++) {
      sleepOrThrow(sleepTime);
      try {
        Node randomNode = nodes[random.nextInt(nodes.length)];
        Node randomNode2 = randomNode;
        while (randomNode2 == randomNode) {
          randomNode2 = nodes[random.nextInt(nodes.length)];
        }
        double loc2 = randomNode2.network().location();
        LOG.info(
            "Pinging {} @ {} from {} @ {}",
            randomNode2.network().darknetPortNumber(),
            loc2,
            randomNode.network().darknetPortNumber(),
            randomNode.network().location());

        int hopsTaken =
            randomNode.network().routedPing(loc2, randomNode2.network().darknetPubKeyHash());
        counters.pings++;
        if (hopsTaken < 0) {
          counters.failures++;
          avg.report(0.0);
          avg2.report(0.0);
          double ratio =
              (double) counters.successes / ((double) (counters.failures + counters.successes));
          LOG.warn(
              "Routed ping {} FAILED from {} to {} (long:{}, short:{}, vague:{})",
              counters.pings,
              randomNode.network().darknetPortNumber(),
              randomNode2.network().darknetPortNumber(),
              ratio,
              avg.currentValue(),
              avg2.currentValue());
        } else {
          counters.totalHopsTaken += hopsTaken;
          counters.successes++;
          avg.report(1.0);
          avg2.report(1.0);
          double ratio =
              (double) counters.successes / ((double) (counters.failures + counters.successes));
          LOG.info(
              "Routed ping {} success: {} {} to {} (long:{}, short:{}, vague:{})",
              counters.pings,
              hopsTaken,
              randomNode.network().darknetPortNumber(),
              randomNode2.network().darknetPortNumber(),
              ratio,
              avg.currentValue(),
              avg2.currentValue());
        }
      } catch (Exception e) {
        LOG.error("Caught {}", e, e);
      }
    }
  }

  private static void logAveragePathLength(PingCounters counters) {
    LOG.info(
        "Average path length for successful requests: {}",
        ((double) counters.totalHopsTaken) / counters.successes);
  }

  private static boolean hasReachedAccuracy(
      double accuracy, RunningAverage avg, PingCounters counters) {
    return counters.pings > 10
        && avg.currentValue() > accuracy
        && ((double) counters.successes / ((double) (counters.failures + counters.successes))
            > accuracy);
  }

  private static void logAccuracySummary(Node[] nodes, double accuracy, PingCounters counters) {
    LOG.info("");
    LOG.info("Reached {}% accuracy.", accuracy * 100);
    LOG.info("");
    LOG.info("Network size: {}", nodes.length);
    LOG.info("Maximum HTL: {}", MAX_HTL);
    LOG.info(
        "Average path length for successful requests: {}",
        counters.totalHopsTaken / counters.successes);
    LOG.info("Total started swaps: {}", LocationManager.getStartedSwaps());
    LOG.info(
        "Total rejected swaps (already locked): {}",
        LocationManager.getSwapsRejectedAlreadyLocked());
    LOG.info(
        "Total swaps rejected (nowhere to go): {}", LocationManager.getSwapsRejectedNowhereToGo());
    LOG.info("Total swaps rejected (rate limit): {}", LocationManager.getSwapsRejectedRateLimit());
    LOG.info(
        "Total swaps rejected (recognized ID):{}", LocationManager.getSwapsRejectedRecognizedID());
    LOG.info("Total swaps failed:{}", LocationManager.getNoSwaps());
    LOG.info("Total swaps succeeded:{}", LocationManager.getSwaps());
  }

  private record SwapSnapshot(int newSwaps, int noSwaps) {}

  private static final class PingCounters {
    private int totalHopsTaken;
    private int failures;
    private int successes;
    private int pings;
  }
}
