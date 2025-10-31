package network.crypta.node.simulator;

import java.io.File;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.RandomSource;
import network.crypta.node.LocationManager;
import network.crypta.node.Node;
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
 * @author amphibian
 *     <p>Create a mesh of nodes and let them sort out their locations.
 *     <p>Then run some node-to-node searches.
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

  public static int DARKNET_PORT_BASE = RealNodeRequestInsertTest.DARKNET_PORT_END;
  public static final int DARKNET_PORT_END = DARKNET_PORT_BASE + NUMBER_OF_NODES;

  public static void main(String[] args) throws Exception {
    System.out.println("Routing test using real nodes:");
    System.out.println();
    String dir = "realNodeRequestInsertTest";
    File wd = new File(dir);
    if (!FileUtil.removeAll(wd)) {
      System.err.println("Mass delete failed, test may not be accurate.");
      System.exit(EXIT_CANNOT_DELETE_OLD_DATA);
    }
    wd.mkdir();
    // NOTE: globalTestInit returns in ignored random source
    NodeStarter.globalTestInit(wd, false, Level.ERROR, "", true, null);
    // Make the network reproducible so we can easily compare different routing options by
    // specifying a seed.
    DummyRandomSource random = new DummyRandomSource(3142);
    // DiffieHellman.init(random);
    Node[] nodes = new Node[NUMBER_OF_NODES];
    LOG.info("Creating nodes...");
    PriorityAwareExecutor executor = new PooledExecutor();
    for (int i = 0; i < NUMBER_OF_NODES; i++) {
      System.err.println("Creating node " + i);
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
      LOG.info("Created node " + i);
    }
    LOG.info("Created " + NUMBER_OF_NODES + " nodes");
    // Now link them up
    makeKleinbergNetwork(
        nodes, START_WITH_IDEAL_LOCATIONS, DEGREE, FORCE_NEIGHBOUR_CONNECTIONS, random);

    LOG.info("Added random links");

    for (int i = 0; i < NUMBER_OF_NODES; i++) {
      System.err.println("Starting node " + i);
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
    int totalHopsTaken = 0;
    int cycleNumber = 0;
    int lastSwaps = 0;
    int lastNoSwaps = 0;
    int failures = 0;
    int successes = 0;
    RunningAverage avg = new SimpleRunningAverage(100, 0.0);
    RunningAverage avg2 = new BootstrappingDecayingRunningAverage(0.0, 0.0, 1.0, 100, null);
    int pings = 0;
    for (int total = 0; total < maxTests; total++) {
      cycleNumber++;
      try {
        Thread.sleep(sleepTime);
      } catch (InterruptedException e) {
        // Ignore
      }
      for (int i = 0; i < nodes.length; i++) {
        System.err.println("Cycle " + cycleNumber + " node " + i + ": " + nodes[i].getLocation());
      }
      int newSwaps = LocationManager.getSwaps();
      int totalStarted = LocationManager.getStartedSwaps();
      int noSwaps = LocationManager.getNoSwaps();
      System.err.println("Swaps: " + (newSwaps - lastSwaps));
      System.err.println(
          "\nTotal swaps: Started*2: "
              + totalStarted * 2
              + ", succeeded: "
              + newSwaps
              + ", last minute failures: "
              + noSwaps
              + ", ratio "
              + (double) noSwaps / (double) newSwaps
              + ", early failures: "
              + ((totalStarted * 2) - (noSwaps + newSwaps)));
      System.err.println(
          "This cycle ratio: "
              + ((double) (noSwaps - lastNoSwaps)) / ((double) (newSwaps - lastSwaps)));
      lastNoSwaps = noSwaps;
      System.err.println(
          "Swaps rejected (already locked): " + LocationManager.getSwapsRejectedAlreadyLocked());
      System.err.println(
          "Swaps rejected (nowhere to go): " + LocationManager.getSwapsRejectedNowhereToGo());
      System.err.println(
          "Swaps rejected (rate limit): " + LocationManager.getSwapsRejectedRateLimit());
      System.err.println(
          "Swaps rejected (recognized ID):" + LocationManager.getSwapsRejectedRecognizedID());
      System.err.println("Swaps failed:" + LocationManager.getNoSwaps());
      System.err.println("Swaps succeeded:" + LocationManager.getSwaps());

      double totalSwapInterval = 0.0;
      double totalSwapTime = 0.0;
      for (int i = 0; i < nodes.length; i++) {
        totalSwapInterval += nodes[i].getLocationManager().getSendSwapInterval();
        totalSwapTime += nodes[i].getLocationManager().getAverageSwapTime();
      }
      System.err.println("Average swap time: " + (totalSwapTime / nodes.length));
      System.err.println("Average swap sender interval: " + (totalSwapInterval / nodes.length));

      waitForAllConnected(nodes);

      lastSwaps = newSwaps;
      // Do some (routed) test-pings
      for (int i = 0; i < 10; i++) {
        try {
          Thread.sleep(sleepTime);
        } catch (InterruptedException e1) {
        }
        try {
          Node randomNode = nodes[random.nextInt(nodes.length)];
          Node randomNode2 = randomNode;
          while (randomNode2 == randomNode) {
            randomNode2 = nodes[random.nextInt(nodes.length)];
          }
          double loc2 = randomNode2.getLocation();
          LOG.info(
              "Pinging "
                  + randomNode2.getDarknetPortNumber()
                  + " @ "
                  + loc2
                  + " from "
                  + randomNode.getDarknetPortNumber()
                  + " @ "
                  + randomNode.getLocation());

          int hopsTaken = randomNode.routedPing(loc2, randomNode2.getDarknetPubKeyHash());
          pings++;
          if (hopsTaken < 0) {
            failures++;
            avg.report(0.0);
            avg2.report(0.0);
            double ratio = (double) successes / ((double) (failures + successes));
            System.err.println(
                "Routed ping "
                    + pings
                    + " FAILED from "
                    + randomNode.getDarknetPortNumber()
                    + " to "
                    + randomNode2.getDarknetPortNumber()
                    + " (long:"
                    + ratio
                    + ", short:"
                    + avg.currentValue()
                    + ", vague:"
                    + avg2.currentValue()
                    + ')');
          } else {
            totalHopsTaken += hopsTaken;
            successes++;
            avg.report(1.0);
            avg2.report(1.0);
            double ratio = (double) successes / ((double) (failures + successes));
            System.err.println(
                "Routed ping "
                    + pings
                    + " success: "
                    + hopsTaken
                    + ' '
                    + randomNode.getDarknetPortNumber()
                    + " to "
                    + randomNode2.getDarknetPortNumber()
                    + " (long:"
                    + ratio
                    + ", short:"
                    + avg.currentValue()
                    + ", vague:"
                    + avg2.currentValue()
                    + ')');
          }
        } catch (Throwable t) {
          LOG.error("Caught " + t, t);
        }
      }
      System.err.println(
          "Average path length for successful requests: " + ((double) totalHopsTaken) / successes);
      if (pings > 10
          && avg.currentValue() > accuracy
          && ((double) successes / ((double) (failures + successes)) > accuracy)) {
        System.err.println();
        System.err.println("Reached " + (accuracy * 100) + "% accuracy.");
        System.err.println();
        System.err.println("Network size: " + nodes.length);
        System.err.println("Maximum HTL: " + MAX_HTL);
        System.err.println(
            "Average path length for successful requests: " + totalHopsTaken / successes);
        System.err.println("Total started swaps: " + LocationManager.getStartedSwaps());
        System.err.println(
            "Total rejected swaps (already locked): "
                + LocationManager.getSwapsRejectedAlreadyLocked());
        System.err.println(
            "Total swaps rejected (nowhere to go): "
                + LocationManager.getSwapsRejectedNowhereToGo());
        System.err.println(
            "Total swaps rejected (rate limit): " + LocationManager.getSwapsRejectedRateLimit());
        System.err.println(
            "Total swaps rejected (recognized ID):"
                + LocationManager.getSwapsRejectedRecognizedID());
        System.err.println("Total swaps failed:" + LocationManager.getNoSwaps());
        System.err.println("Total swaps succeeded:" + LocationManager.getSwaps());
        return;
      }
    }
    System.exit(EXIT_PING_TARGET_NOT_REACHED);
  }
}
