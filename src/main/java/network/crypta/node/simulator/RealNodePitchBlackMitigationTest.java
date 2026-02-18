package network.crypta.node.simulator;

import java.io.File;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneId;
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

import static java.util.concurrent.TimeUnit.MINUTES;

/**
 * Simulates a pitch black attack and mitigation sequence using real node instances.
 *
 * <p>This long-running test harness builds a deterministic network of {@link Node} instances,
 * advances a fake clock to trigger mitigation cycles, and continuously routes pings to measure how
 * the routing layer behaves under disrupted locations. It is intended for manual, repeatable
 * experiments rather than unit-test execution. Configuration lives in the class constants, so a run
 * can be reproduced by keeping the same node count, degree, random seed, and ping cadence.
 *
 * <p>The class writes detailed metrics to logs; a typical workflow is to parse those logs into
 * plots after the run completes. This class relies on static configuration and background threads
 * spawned by {@link Node}, so it is not thread-safe for concurrent runs in the same JVM.
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>Constructs a Kleinberg-style network topology before starting nodes.
 *   <li>Optionally applies a location-shifting attack to all nodes.
 *   <li>Advances the simulated day every mitigation interval to exercise mitigation timers.
 * </ul>
 *
 * <p>Example Gnuplot snippets for evaluating output logs:
 *
 * <pre>{@code
 * set title "Average peer locations during pitch black mitigation"
 * set xlabel "Time / Cycle"
 * set ylabel "node / index"
 * set cblabel "location / position in ring"
 * plot "<(grep Cycle real-node-pitch-black-mitigation-test-results-11.log | grep ' node ' | \
 *   sed 's/Cycle //;s/ node / /;s/: .*average=/ /;s/, .*$//;s/,/./g')" \
 *   using 1:2:3 palette pt 5 ps 1.5 lw 1 title "RealNodePitchBlackMitigationTest"
 * }</pre>
 *
 * <pre>{@code
 * set title "Average path length of successful pings"
 * set xlabel "Time / Cycle"
 * set ylabel "average path length / hops"
 * plot "<(grep 'Average path length' real-node-pitch-black-mitigation-test-results-11.log | \
 *   sed 's/.*: //')" using 0:1 pt 5 ps 1.5 lw 1 title "RealNodePitchBlackMitigationTest"
 * }</pre>
 *
 * <pre>{@code
 * set title "Ping-Statistics"
 * set xlabel "Time / Ping Number"
 * set ylabel "fraction / unitless"
 * set cblabel "path / hops needed"
 * plot "<(grep 'Routed ping' real-node-pitch-black-mitigation-test-results-11.log | grep success | \
 *   sed 's/Routed ping //;s/ success: / /g')" using 1:(($0+1)/$1):2 palette pt 3 ps 1 lw 1 \
 *   title "succeeded", \
 *   "<(grep 'Routed ping' real-node-pitch-black-mitigation-test-results-11.log | grep FAILED | \
 *   sed 's/Routed ping //;s/FAILED from//')" using 1:(($0+1)/$1) pt 6 ps 1 lw 1 title "FAILED"
 * }</pre>
 *
 * @author ArneBab
 * @see LocationManager
 * @see RealNodeTest
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

  /**
   * Startup delay before the first mitigation cycle runs, in milliseconds of simulated time.
   *
   * <p>This value is applied once after the nodes start, allowing initial connections to stabilize
   * before mitigation timers begin firing. The constant is expressed in minutes and converted to
   * milliseconds for the scheduler APIs.
   */
  public static final long PITCH_BLACK_MITIGATION_STARTUP_DELAY = MINUTES.toMillis(1);

  /**
   * Time between mitigation cycles, in milliseconds, used to advance the fake day counter.
   *
   * <p>The simulation advances the {@link LocationManager} clock by one day for every interval, so
   * this value governs both mitigation triggering and the noticeable passage of time.
   */
  public static final long PITCH_BLACK_MITIGATION_FREQUENCY_ONE_DAY = MINUTES.toMillis(30);

  /**
   * Number of routed pings attempted per iteration of the main simulation loop.
   *
   * <p>Each cycle performs this many ping attempts, collecting success/failure metrics that are
   * later logged and used to decide whether the target accuracy has been reached.
   */
  public static final int PINGS_PER_ITERATION = 10;

  private static final int DARKNET_PORT_BASE = RealNodeRequestInsertTest.DARKNET_PORT_END;

  /**
   * Random jitter added to the pitch black attack target, expressed in ring-location units.
   *
   * <p>The jitter avoids a perfectly fixed target location, which would make the attack trivial to
   * detect. The offset is sampled from the node's weak RNG and added to the mean location.
   */
  public static final double PITCH_BLACK_ATTACK_JITTER = 0.001;

  /**
   * Mean location around which pitch black attacks are centered, in ring-location units.
   *
   * <p>This value is combined with {@link #PITCH_BLACK_ATTACK_JITTER} to derive a per-node
   * destination location. Values are typically within the normalized location ring.
   */
  public static final double PITCH_BLACK_ATTACK_MEAN_LOCATION = 0.5;

  /**
   * Sleep time between pings and log samples, in milliseconds.
   *
   * <p>The delay gives nodes time to swap and for log output to reflect a new cycle. The value is
   * passed directly to {@link Thread#sleep(long)} and therefore uses millisecond granularity.
   */
  public static final int BETWEEN_PING_SLEEP_TIME = 500000;

  /**
   * Creates a new test harness instance with the default static configuration.
   *
   * <p>This constructor performs no explicit initialization beyond the implicit default constructor
   * behavior, and it exists solely to provide Javadoc for doclint. All behavior is configured
   * through the class constants and the {@link #main(String[])} entry point.
   */
  public RealNodePitchBlackMitigationTest() {
    // Empty by design: configuration and behavior are driven by static constants and main().
  }

  /**
   * Runs the pitch black mitigation simulation with deterministic configuration and logging.
   *
   * <p>This entry point initializes a working directory, creates {@link Node} instances, links them
   * into a Kleinberg-style topology, and optionally performs an initial pitch black attack. It then
   * advances the {@link LocationManager} clock on a timer to simulate days passing while pings are
   * routed and metrics are emitted. The run terminates once the configured accuracy threshold is
   * reached or the maximum number of pings is exceeded.
   *
   * <pre>{@code
   * RealNodePitchBlackMitigationTest.main(new String[0]);
   * }</pre>
   *
   * @param args command-line arguments; unused but accepted for standard entry-point semantics
   * @throws Exception if node initialization or startup fails before the simulation can begin
   */
  public static void main(@SuppressWarnings("unused") String[] args) throws Exception {
    LOG.info("Routing test using real nodes:");
    LOG.info("");
    String dir = "realNodeRequestInsertTest";
    File wd = new File(dir);
    if (!FileUtil.removeAll(wd)) {
      LOG.error("Mass delete failed, test may not be accurate.");
      System.exit(EXIT_CANNOT_DELETE_OLD_DATA);
    }
    if (!wd.mkdir() && !wd.isDirectory()) {
      LOG.warn("Failed to create working directory {}", wd.getAbsolutePath());
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
      LOG.warn("Creating node {}", i);
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
      LOG.info("Created node {}", i);
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

    // enable warning logging to see pitch black defense logs
    network.crypta.support.Logging.setRootLevel(org.slf4j.event.Level.WARN);

    // set the time yesterday to have pitch black information
    LocationManager.setClockForTesting(
        Clock.offset(Clock.system(ZoneId.systemDefault()), Duration.ofDays(-1)));
    // shift forward one day per 5 minutes
    Runnable dayIncrementingJob =
        new Runnable() {
          @Override
          public void run() {
            nodes[0]
                .network()
                .ticker()
                .queueTimedJob(this, PITCH_BLACK_MITIGATION_FREQUENCY_ONE_DAY);
            LocationManager.setClockForTesting(
                Clock.offset(LocationManager.getClockForTesting(), Duration.ofDays(1)));
          }
        };
    nodes[0]
        .network()
        .ticker()
        .queueTimedJob(dayIncrementingJob, PITCH_BLACK_MITIGATION_FREQUENCY_ONE_DAY);

    // start the nodes and adjust mitigation times
    LocationManager.setPitchBlackMitigationFrequencyOneDay(
        PITCH_BLACK_MITIGATION_FREQUENCY_ONE_DAY);
    LocationManager.setPitchBlackMitigationStartupDelay(PITCH_BLACK_MITIGATION_STARTUP_DELAY);
    for (int i = 0; i < NUMBER_OF_NODES; i++) {
      LOG.warn("Starting node {}", i);
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

  /**
   * Applies a pitch black attack location to a single node and logs the change.
   *
   * <p>The new location is computed as the mean attack location plus a random jitter sampled from
   * the node's weak RNG. The method logs the computed location and updates the node's stored
   * location in-place. It is safe to call repeatedly; each call overwrites the node's location with
   * a newly sampled value.
   *
   * @param pitchBlackAttackMeanLocation base ring location used as the attack center, unitless
   * @param pitchBlackAttackJitter jitter magnitude added to the mean location, unitless
   * @param nodeToAttack node instance to modify; must be non-null and initialized
   * @param indexOfNode stable index for logging, typically the node's position in the array
   */
  public static void attackSpecificNode(
      double pitchBlackAttackMeanLocation,
      double pitchBlackAttackJitter,
      Node nodeToAttack,
      int indexOfNode) {
    double pitchBlackFakeLocation =
        pitchBlackAttackMeanLocation
            + (nodeToAttack.bootstrap().fastWeakRandom().nextDouble() * pitchBlackAttackJitter);
    LOG.warn(
        "Pitch-Black-Attack on node {} using mean {} with jitter {}: {}",
        indexOfNode,
        pitchBlackAttackMeanLocation,
        pitchBlackAttackJitter,
        pitchBlackFakeLocation);
    nodeToAttack.network().setLocation(pitchBlackFakeLocation);
    LOG.warn("New location of node {}: {}", indexOfNode, nodeToAttack.network().location());
  }

  static void waitForPingAverage(
      double accuracy, Node[] nodes, RandomSource random, int maxTests, int sleepTime)
      throws InterruptedException {
    PingStats stats = new PingStats();
    int cycleNumber = 0;
    int lastSwaps = 0;
    int lastNoSwaps = 0;
    stats.avg = new SimpleRunningAverage(100, 0.0);
    stats.avg2 = new BootstrappingDecayingRunningAverage(0.0, 0.0, 1.0, 100, null);
    for (int total = 0; total < maxTests; total++) {
      cycleNumber++;
      applyActivePitchBlackAttack(nodes);
      sleepSilently(sleepTime);
      logNodeLocations(cycleNumber, nodes);
      SwapStats swapStats = logSwapStats(lastSwaps, lastNoSwaps);
      lastNoSwaps = swapStats.noSwaps;
      logAverageSwapMetrics(nodes);

      waitForAllConnected(nodes);

      lastSwaps = swapStats.newSwaps;
      runPingBatch(nodes, random, sleepTime, stats);
      LOG.warn(
          "Cycle avg path length for successful requests: {}",
          ((double) stats.totalHopsTaken) / stats.successes);
      if (shouldStopPinging(accuracy, stats)) {
        LOG.warn("");
        LOG.warn("Reached {}% accuracy.", accuracy * 100);
        LOG.warn("");
        LOG.warn("Network size: {}", nodes.length);
        LOG.warn("Maximum HTL: {}", MAX_HTL);
        LOG.warn(
            "Final avg path length for successful requests: {}",
            stats.totalHopsTaken / stats.successes);
        LOG.warn("Total started swaps: {}", LocationManager.getStartedSwaps());
        LOG.warn(
            "Final swaps rejected (already locked): {}",
            LocationManager.getSwapsRejectedAlreadyLocked());
        LOG.warn(
            "Final swaps rejected (nowhere to go): {}",
            LocationManager.getSwapsRejectedNowhereToGo());
        LOG.warn(
            "Final swaps rejected (rate limit): {}", LocationManager.getSwapsRejectedRateLimit());
        LOG.warn(
            "Final swaps rejected (recognized ID): {}",
            LocationManager.getSwapsRejectedRecognizedID());
        LOG.warn("Final swaps failed: {}", LocationManager.getNoSwaps());
        LOG.warn("Final swaps succeeded: {}", LocationManager.getSwaps());
        return;
      }
    }
    System.exit(EXIT_PING_TARGET_NOT_REACHED);
  }

  private static void applyActivePitchBlackAttack(Node[] nodes) {
    if (!ACTIVE_PITCH_BLACK_ATTACK) {
      return;
    }
    for (int i = 0; i < NUMBER_OF_NODES; i++) {
      Node nodeToAttack = nodes[i];
      // attack 2% of the nodes per round
      if (nodeToAttack.bootstrap().fastWeakRandom().nextFloat() < 0.98) {
        continue;
      }
      attackSpecificNode(
          PITCH_BLACK_ATTACK_MEAN_LOCATION, PITCH_BLACK_ATTACK_JITTER, nodeToAttack, i);
    }
  }

  private static void sleepSilently(int sleepTime) {
    try {
      Thread.sleep(sleepTime);
    } catch (InterruptedException _) {
      Thread.currentThread().interrupt();
    }
  }

  private static void logNodeLocations(int cycleNumber, Node[] nodes) {
    for (int i = 0; i < nodes.length; i++) {
      LOG.warn(
          "Cycle {} node {}: {} degree: {} locs: {}",
          cycleNumber,
          i,
          nodes[i].network().location(),
          nodes[i].network().peerNodes().length,
          Arrays.stream(nodes[i].network().peerNodes())
              .map(PeerNode::getLocation)
              .collect(Collectors.summarizingDouble(d -> d)));
    }
  }

  private static SwapStats logSwapStats(int lastSwaps, int lastNoSwaps) {
    int newSwaps = LocationManager.getSwaps();
    int totalStarted = LocationManager.getStartedSwaps();
    int noSwaps = LocationManager.getNoSwaps();
    LOG.warn("Swaps: {}", newSwaps - lastSwaps);
    LOG.warn(
        "Total swaps: Started*2: {}, succeeded: {}, last minute failures: {}, ratio {}, early"
            + " failures: {}",
        totalStarted * 2,
        newSwaps,
        noSwaps,
        (double) noSwaps / (double) newSwaps,
        (totalStarted * 2) - (noSwaps + newSwaps));
    LOG.warn(
        "This cycle ratio: {}",
        ((double) (noSwaps - lastNoSwaps)) / ((double) (newSwaps - lastSwaps)));
    LOG.warn(
        "Cycle swaps rejected (already locked): {}",
        LocationManager.getSwapsRejectedAlreadyLocked());
    LOG.warn(
        "Cycle swaps rejected (nowhere to go): {}", LocationManager.getSwapsRejectedNowhereToGo());
    LOG.warn("Cycle swaps rejected (rate limit): {}", LocationManager.getSwapsRejectedRateLimit());
    LOG.warn(
        "Cycle swaps rejected (recognized ID): {}", LocationManager.getSwapsRejectedRecognizedID());
    LOG.warn("Cycle swaps failed: {}", LocationManager.getNoSwaps());
    LOG.warn("Cycle swaps succeeded: {}", LocationManager.getSwaps());
    return new SwapStats(newSwaps, noSwaps);
  }

  private static void logAverageSwapMetrics(Node[] nodes) {
    double totalSwapInterval = 0.0;
    double totalSwapTime = 0.0;
    for (Node node : nodes) {
      totalSwapInterval += node.network().locationManager().getSendSwapInterval();
      totalSwapTime += node.network().locationManager().getAverageSwapTime();
    }
    LOG.warn("Average swap time: {}", totalSwapTime / nodes.length);
    LOG.warn("Average swap sender interval: {}", totalSwapInterval / nodes.length);
  }

  private static void runPingBatch(
      Node[] nodes, RandomSource random, int sleepTime, PingStats stats) {
    for (int i = 0; i < PINGS_PER_ITERATION; i++) {
      sleepSilently(sleepTime);
      try {
        PingAttempt attempt = createPingAttempt(nodes, random);
        int hopsTaken =
            attempt.from.network().routedPing(attempt.targetLocation, attempt.targetKeyHash);
        stats.pings++;
        if (hopsTaken < 0) {
          recordFailure(stats, attempt);
        } else {
          recordSuccess(stats, attempt, hopsTaken);
        }
      } catch (Exception e) {
        LOG.error("Caught {}", e, e);
      }
    }
  }

  private static PingAttempt createPingAttempt(Node[] nodes, RandomSource random) {
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
    return new PingAttempt(randomNode, randomNode2, loc2);
  }

  private static void recordFailure(PingStats stats, PingAttempt attempt) {
    stats.failures++;
    stats.avg.report(0.0);
    stats.avg2.report(0.0);
    double ratio = successRatio(stats);
    LOG.warn(
        "Routed ping {} FAILED from {} to {} (long:{}, short:{}, vague:{})",
        stats.pings,
        attempt.from.network().darknetPortNumber(),
        attempt.to.network().darknetPortNumber(),
        ratio,
        stats.avg.currentValue(),
        stats.avg2.currentValue());
  }

  private static void recordSuccess(PingStats stats, PingAttempt attempt, int hopsTaken) {
    stats.totalHopsTaken += hopsTaken;
    stats.successes++;
    stats.avg.report(1.0);
    stats.avg2.report(1.0);
    double ratio = successRatio(stats);
    LOG.warn(
        "Routed ping {} success: {} {} to {} (long:{}, short:{}, vague:{})",
        stats.pings,
        hopsTaken,
        attempt.from.network().darknetPortNumber(),
        attempt.to.network().darknetPortNumber(),
        ratio,
        stats.avg.currentValue(),
        stats.avg2.currentValue());
  }

  private static boolean shouldStopPinging(double accuracy, PingStats stats) {
    if (stats.pings > MAX_PINGS) {
      return true;
    }
    return stats.pings > MIN_PINGS
        && stats.avg.currentValue() > accuracy
        && successRatio(stats) > accuracy;
  }

  private static double successRatio(PingStats stats) {
    return (double) stats.successes / ((double) (stats.failures + stats.successes));
  }

  private record SwapStats(int newSwaps, int noSwaps) {}

  private static final class PingAttempt {
    private final Node from;
    private final Node to;
    private final double targetLocation;
    private final byte[] targetKeyHash;

    private PingAttempt(Node from, Node to, double targetLocation) {
      this.from = from;
      this.to = to;
      this.targetLocation = targetLocation;
      this.targetKeyHash = to.network().darknetPubKeyHash();
    }
  }

  private static final class PingStats {
    private int totalHopsTaken;
    private int failures;
    private int successes;
    private int pings;
    private RunningAverage avg;
    private RunningAverage avg2;
  }
}
