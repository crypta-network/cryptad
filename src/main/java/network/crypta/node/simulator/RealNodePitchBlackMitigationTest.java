package network.crypta.node.simulator;

import static java.util.concurrent.TimeUnit.MINUTES;

import java.io.File;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.stream.Collectors;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.RandomSource;
import network.crypta.node.LocationManager;
import network.crypta.node.Node;
import network.crypta.node.NodeStarter;
import network.crypta.node.PeerNode;
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
 * @author ArneBab
 *     <p>This test spins uf Freenet nodes and simulates a pitch black attack and defense. It moves
 *     fake days forward to simulate the defense despite limited swapping speed.
 *     <p>It spins up NUMBER_OF_NODES freenet nodes with DEEGREE.
 *     <p>MIN_PINGS and MAX_PINGS give the minimum and maximum runtime.
 *     <p>Adjust the variables NUMBER_OF_NODES, DEGREE, and PINGS_PER_ITERATION to adjust test
 *     parameters.
 *     <p>Set PITCH_BLACK_ATTACK_MEAN_LOCATION and PITCH_BLACK_ATTACK_JITTER to select the location
 *     to attack. PITCH_BLACK_ATTACK_JITTER is necessary to prevent existind heuristics from
 *     deticting the naive attack with exactly one location.
 *     <p>Set BETWEEN_PING_SLEEP_TIME to give the nodes time to swap between logging.
 *     <p>PITCH_BLACK_MITIGATION_FREQUENCY_ONE_DAY gives the time between triggering a mitigation
 *     (usually it is just one per day). It abvances the fake time by one day per period.
 *     <p>Just grep the test output to get test results. Example Gnuplot calls to evaluate:
 *     <p>set title "Average peer locations during pitch black mitigation" set xlabel "Time / Cycle"
 *     set ylabel "node / index" set cblabel "location / position in ring" plot "<(grep Cycle
 *     real-node-pitch-black-mitigation-test-results-11.log | grep ' node ' | sed 's/Cycle //;s/
 *     node / /;s/: .*average=/ /;s/, .*$//;s/,/./g')" using 1:2:3 palette pt 5 ps 1.5 lw 1 title
 *     "RealNodePitchBlackMitigationTest"
 *     <p>set title "Average path length of successful pings" set xlabel "Time / Cycle" set ylabel
 *     "average path lenth / hops" plot "<(grep 'Average path length'
 *     real-node-pitch-black-mitigation-test-results-11.log | sed 's/.*: //')" using 0:1 pt 5 ps 1.5
 *     lw 1 title "RealNodePitchBlackMitigationTest"
 *     <p>set title "Ping-Statistics" set xlabel "Time / Ping Number" set ylabel "fraction /
 *     unitless" set cblabel "path / hops needed" plot "<(grep 'Routed ping'
 *     real-node-pitch-black-mitigation-test-results-11.log | grep success | sed 's/Routed ping
 *     //;s/ success: / /g')" using 1:(($0+1)/$1):2 palette pt 3 ps 1 lw 1 title "succeeded",
 *     "<(grep 'Routed ping' real-node-pitch-black-mitigation-test-results-11.log | grep FAILED |
 *     sed 's/Routed ping //;s/FAILED from//')" using 1:(($0+1)/$1) pt 6 ps 1 lw 1 title "FAILED"
 */
public class RealNodePitchBlackMitigationTest extends RealNodeTest {
  private static final Logger LOG = LoggerFactory.getLogger(RealNodePitchBlackMitigationTest.class);

  static final int NUMBER_OF_NODES = 300;
  static final int DEGREE = 4;
  static final short MAX_HTL = (short) 10;
  static final boolean START_WITH_IDEAL_LOCATIONS = true;
  static final boolean FORCE_NEIGHBOUR_CONNECTIONS = true;
  static final int MIN_PINGS = 420;
  static final int MAX_PINGS = 840;
  static final boolean ENABLE_SWAPPING = true;
  static final boolean ENABLE_SWAP_QUEUEING = true;
  static final boolean ENABLE_FOAF = true;
  static final boolean ACTIVE_PITCH_BLACK_ATTACK = false;
  static final boolean INITIAL_PITCH_BLACK_ATTACK = true;
  public static final long PITCH_BLACK_MITIGATION_STARTUP_DELAY = MINUTES.toMillis(1);
  public static final long PITCH_BLACK_MITIGATION_FREQUENCY_ONE_DAY = MINUTES.toMillis(30);
  public static final int PINGS_PER_ITERATION = 10;

  public static int DARKNET_PORT_BASE = RealNodeRequestInsertTest.DARKNET_PORT_END;
  public static final int DARKNET_PORT_END = DARKNET_PORT_BASE + NUMBER_OF_NODES;
  public static final double PITCH_BLACK_ATTACK_JITTER = 0.001;
  public static final double PITCH_BLACK_ATTACK_MEAN_LOCATION = 0.5;
  public static final int BETWEEN_PING_SLEEP_TIME = 500000;

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
      params.setStoreSize(4_000_000L);
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

    // force a disrupted network
    if (INITIAL_PITCH_BLACK_ATTACK) {
      for (int i = 0; i < NUMBER_OF_NODES; i++) {
        Node nodeToAttack = nodes[i];
        attackSpecificNode(
            PITCH_BLACK_ATTACK_MEAN_LOCATION, PITCH_BLACK_ATTACK_JITTER, nodeToAttack, i);
      }
    }

    // enable warning logging to see pitch black defense lo
    network.crypta.support.Logging.setRootLevel(org.slf4j.event.Level.WARN);

    // set the time to yesterday to have pitch black information
    LocationManager.setClockForTesting(
        Clock.offset(Clock.systemDefaultZone(), Duration.ofDays(-1)));
    // shift forward one day per 5 minutes
    Runnable dayIncrementingJob =
        new Runnable() {
          @Override
          public void run() {
            nodes[0].getTicker().queueTimedJob(this, PITCH_BLACK_MITIGATION_FREQUENCY_ONE_DAY);
            LocationManager.setClockForTesting(
                Clock.offset(LocationManager.getClockForTesting(), Duration.ofDays(1)));
          }
        };
    nodes[0]
        .getTicker()
        .queueTimedJob(dayIncrementingJob, PITCH_BLACK_MITIGATION_FREQUENCY_ONE_DAY);

    // start the nodes and adjust mitigation times
    LocationManager.setPitchBlackMitigationFrequencyOneDay(
        PITCH_BLACK_MITIGATION_FREQUENCY_ONE_DAY);
    LocationManager.setPitchBlackMitigationStartupDelay(PITCH_BLACK_MITIGATION_STARTUP_DELAY);
    for (int i = 0; i < NUMBER_OF_NODES; i++) {
      System.err.println("Starting node " + i);
      nodes[i].start(false);
    }

    waitForAllConnected(nodes);

    // Make the choice of nodes to ping to and from deterministic too.
    // There is timing noise because of all the nodes, but the network
    // and the choice of nodes to start and finish are deterministic, so
    // the overall result should be more or less deterministic.
    waitForPingAverage(
        0.98, nodes, new DummyRandomSource(3143), MAX_PINGS, BETWEEN_PING_SLEEP_TIME);
    System.exit(0);
  }

  public static void attackSpecificNode(
      double pitchBlackAttackMeanLocation,
      double pitchBlackAttackJitter,
      Node nodeToAttack,
      int indexOfNode) {
    double pitchBlackFakeLocation =
        pitchBlackAttackMeanLocation
            + (nodeToAttack.getFastWeakRandom().nextDouble() * pitchBlackAttackJitter);
    System.err.println(
        "Pitch-Black-Attack on node "
            + indexOfNode
            + " using mean "
            + pitchBlackAttackMeanLocation
            + " with jitter "
            + pitchBlackAttackJitter
            + ": "
            + pitchBlackFakeLocation);
    nodeToAttack.setLocation(pitchBlackFakeLocation);
    System.err.println("New location of node " + indexOfNode + ": " + nodeToAttack.getLocation());
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
      if (ACTIVE_PITCH_BLACK_ATTACK) {
        for (int i = 0; i < NUMBER_OF_NODES; i++) {
          Node nodeToAttack = nodes[i];
          // attack 2% of the nodes per round
          if (nodeToAttack.getFastWeakRandom().nextFloat() < 0.98) {
            continue;
          }
          attackSpecificNode(
              PITCH_BLACK_ATTACK_MEAN_LOCATION, PITCH_BLACK_ATTACK_JITTER, nodeToAttack, i);
        }
      }
      try {
        Thread.sleep(sleepTime);
      } catch (InterruptedException e) {
        // Ignore
      }
      for (int i = 0; i < nodes.length; i++) {
        System.err.println(
            "Cycle "
                + cycleNumber
                + " node "
                + i
                + ": "
                + nodes[i].getLocation()
                + " degree: "
                + nodes[i].getPeerNodes().length
                + " locs: "
                + Arrays.stream(nodes[i].getPeerNodes())
                    .map(PeerNode::getLocation)
                    .collect(Collectors.summarizingDouble(d -> d)));
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
      for (int i = 0; i < PINGS_PER_ITERATION; i++) {
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
      if (pings > MAX_PINGS
          || pings > MIN_PINGS
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
