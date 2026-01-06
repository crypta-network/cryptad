package network.crypta.node.simulator;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.CHKEncodeException;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.keys.ClientKSK;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.InsertableClientSSK;
import network.crypta.keys.Key;
import network.crypta.keys.KeyDecodeException;
import network.crypta.keys.SSKEncodeException;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.LowLevelPutException;
import network.crypta.node.Node;
import network.crypta.node.NodeInitException;
import network.crypta.node.NodeStarter;
import network.crypta.node.NodeStarter.TestNodeParameters;
import network.crypta.support.PooledExecutor;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.compress.Compressor;
import network.crypta.support.compress.InvalidCompressionCodecException;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.FileUtil;
import network.crypta.support.math.RunningAverage;
import network.crypta.support.math.SimpleRunningAverage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

/**
 * Exercises insert-and-fetch behavior against a simulated real-node network.
 *
 * <p>This harness bootstraps a fixed-size darknet topology, inserts a small payload on a randomly
 * selected node, and attempts to fetch the same data from another node until a target number of
 * successful fetches is reached. It is intended for manual or batch execution to observe routing
 * health and basic data integrity in a controlled environment. The class owns all test state,
 * including node instances, request counters, and success tracking, and it is not thread-safe; run
 * it from a single driver thread and avoid sharing instances across concurrent tests.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Constructing and starting a deterministic network topology.
 *   <li>Generating insert/fetch keys and recording success ratios.
 *   <li>Reporting running request identifiers to aid debugging.
 * </ul>
 *
 * @author amphibian
 * @see RealNodeRoutingTest
 */
public class RealNodeRequestInsertTest extends RealNodeRoutingTest {
  private static final Logger LOG = LoggerFactory.getLogger(RealNodeRequestInsertTest.class);

  static final int NUMBER_OF_NODES = 100;
  static final int DEGREE = 10;
  static final short MAX_HTL = (short) 5;
  static final boolean START_WITH_IDEAL_LOCATIONS = true;
  static final boolean FORCE_NEIGHBOUR_CONNECTIONS = true;
  static final boolean ENABLE_SWAPPING = false;
  static final boolean ENABLE_ULPRS = false;
  static final boolean ENABLE_PER_NODE_FAILURE_TABLES = false;
  static final boolean ENABLE_SWAP_QUEUEING = false;
  static final boolean ENABLE_PACKET_COALESCING = true;
  static final boolean ENABLE_FOAF = true;
  static final boolean FORK_ON_CACHEABLE = false;
  static final boolean DISABLE_PROBABILISTIC_HTLS = true;
  // Set to true to cache everything. This depends on security level.
  static final boolean USE_SLASHDOT_CACHE = false;
  static final boolean REAL_TIME_FLAG = false;

  static final int TARGET_SUCCESSES = 20;

  // High bwlimit makes the "other" requests not affect the test requests.
  // Real solution is to get rid of the "other" requests.
  static final int BWLIMIT = 1000 * 1024;

  /**
   * Base TCP port used when assigning per-node darknet listener ports.
   *
   * <p>This value anchors the deterministic port allocation for the simulated nodes. Each node
   * receives {@code DARKNET_PORT_BASE + index}, so keep this range clear of other services when
   * running the harness on a shared host.
   */
  public static final int DARKNET_PORT_BASE = 10000;

  /**
   * Exclusive upper bound for the per-node darknet port range derived from {@link
   * #DARKNET_PORT_BASE}.
   *
   * <p>The range is {@code [DARKNET_PORT_BASE, DARKNET_PORT_END)}, sized to the number of nodes in
   * the simulated network. Keep this aligned with {@link #NUMBER_OF_NODES} to avoid port reuse.
   */
  public static final int DARKNET_PORT_END = DARKNET_PORT_BASE + NUMBER_OF_NODES;

  /**
   * Launches the insert-and-fetch exercise using an on-disk working directory.
   *
   * <p>This entry point clears any previous working directory, initializes the test nodes with a
   * deterministic random seed, links them into a Kleinberg-style topology, and then drives repeated
   * insert and fetch operations until success criteria are met or a failure exit code is produced.
   * The method is not idempotent because it deletes and recreates the working directory on each
   * run. It is intended to be executed from the command line in a controlled environment.
   *
   * @param args command-line arguments; unused and expected to be empty or ignored
   * @throws CHKEncodeException if CHK key generation fails for the test payload
   * @throws NodeInitException if node initialization fails during test setup
   * @throws InterruptedException if the test thread is interrupted while waiting
   */
  public static void main(String[] args)
      throws CHKEncodeException, NodeInitException, InterruptedException {
    String name = "realNodeRequestInsertTest";
    File wd = new File(name);
    if (!FileUtil.removeAll(wd)) {
      LOG.error("Mass delete failed, test may not be accurate.");
      System.exit(EXIT_CANNOT_DELETE_OLD_DATA);
    }
    if (!wd.mkdir() && !wd.isDirectory()) {
      LOG.error("Working directory {} could not be created.", wd.getAbsolutePath());
      System.exit(EXIT_CANNOT_DELETE_OLD_DATA);
    }
    DummyRandomSource random = new DummyRandomSource(3142);
    NodeStarter.globalTestInit(wd, false, Level.ERROR, "", true, random);
    LOG.info("Insert/retrieve test");
    DummyRandomSource topologyRandom = new DummyRandomSource(3143);
    Node[] nodes = new Node[NUMBER_OF_NODES];
    LOG.info("Creating nodes...");
    PriorityAwareExecutor executor = new PooledExecutor();
    for (int i = 0; i < NUMBER_OF_NODES; i++) {
      final int port = DARKNET_PORT_BASE + i;
      TestNodeParameters params =
          TestNodeParameterFactory.create(
              wd,
              random,
              executor,
              p -> {
                p.setPort(port);
                p.setOpennetPort(0);
                p.setDisableProbabilisticHTLs(DISABLE_PROBABILISTIC_HTLS);
                p.setMaxHTL(MAX_HTL);
                p.setDropProb(20);
                p.setThreadLimit(500 * NUMBER_OF_NODES);
                p.setStoreSize(256L * 1024);
                p.setRamStore(true);
                p.setEnableSwapping(ENABLE_SWAPPING);
                p.setEnableARKs(false);
                p.setEnableULPRs(ENABLE_ULPRS);
                p.setEnablePerNodeFailureTables(ENABLE_PER_NODE_FAILURE_TABLES);
                p.setEnableSwapQueueing(ENABLE_SWAP_QUEUEING);
                p.setEnablePacketCoalescing(ENABLE_PACKET_COALESCING);
                p.setOutputBandwidthLimit(BWLIMIT);
                p.setEnableFOAF(ENABLE_FOAF);
                p.setConnectToSeednodes(false);
                p.setLongPingTimes(true);
                p.setUseSlashdotCache(USE_SLASHDOT_CACHE);
                p.setEnableFCP(false);
              });
      nodes[i] = NodeStarter.createTestNode(params);
      LOG.info("Created node {}", i);
    }

    // Now link them up
    makeKleinbergNetwork(
        nodes, START_WITH_IDEAL_LOCATIONS, DEGREE, FORCE_NEIGHBOUR_CONNECTIONS, topologyRandom);

    LOG.info("Added random links");

    for (int i = 0; i < NUMBER_OF_NODES; i++) {
      nodes[i].start(false);
      LOG.info("Started node {}/{}", i, nodes.length);
    }

    waitForAllConnected(nodes);

    waitForPingAverage(0.5, nodes, new DummyRandomSource(3143), MAX_PINGS, 1000);

    random = new DummyRandomSource(3144);

    LOG.info("Ping average > 95%, lets do some inserts/requests");

    RealNodeRequestInsertTest tester =
        new RealNodeRequestInsertTest(nodes, random, TARGET_SUCCESSES);

    int status = -1;
    while (status == -1) {
      try {
        waitForAllConnected(nodes);
        status = tester.insertRequestTest();
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw e;
      } catch (Exception e) {
        LOG.error("Caught {}", e, e);
      }
    }
    System.exit(status);
  }

  /**
   * Creates a test harness bound to a fixed node set and success target.
   *
   * <p>The caller supplies the already-started nodes and a deterministic random source used for
   * selecting insert/fetch participants. The {@code targetSuccesses} parameter determines when the
   * harness will report overall success and return an exit code of {@code 0}. Instances are mutable
   * and track request state, so a single instance should be used for one run only.
   *
   * @param nodes node instances that participate in inserts and fetches
   * @param random deterministic random source used for node selection
   * @param targetSuccesses number of successful fetches required to succeed
   */
  public RealNodeRequestInsertTest(Node[] nodes, DummyRandomSource random, int targetSuccesses) {
    this.nodes = nodes;
    this.random = random;
    this.targetSuccesses = targetSuccesses;
  }

  private final Node[] nodes;
  private final RandomSource random;
  private int requestNumber = 0;
  private final RunningAverage requestsAvg = new SimpleRunningAverage(100, 0.0);
  private final String baseString = System.currentTimeMillis() + " ";
  private int insertAttempts = 0;
  private int fetchSuccesses = 0;
  private final int targetSuccesses;

  /**
   * Executes a single insert and fetch attempt, updating success tracking.
   *
   * <p>The method selects a random insert node, generates an SSK-based key pair and encoded block,
   * inserts the block, then selects a distinct fetch node and attempts to retrieve and decode the
   * data. It returns {@code -1} to indicate the harness should continue, or a non-negative exit
   * code when a terminal success or failure condition is reached. Each call increments the request
   * counter and updates the running success average for reporting.
   *
   * @return {@code -1} to continue, or a non-negative terminal exit code
   * @throws CHKEncodeException if CHK encoding fails while building the test block
   * @throws InvalidCompressionCodecException if compression metadata is invalid for the block
   * @throws SSKEncodeException if SSK encoding fails while creating insertable keys
   * @throws IOException if encoding requires I/O and the bucket operation fails
   * @throws KeyDecodeException if the fetched block cannot be decoded to bytes
   */
  int insertRequestTest()
      throws CHKEncodeException,
          InvalidCompressionCodecException,
          SSKEncodeException,
          IOException,
          KeyDecodeException {

    requestNumber++;
    try {
      Thread.sleep(100);
    } catch (InterruptedException e1) {
      Thread.currentThread().interrupt();
      LOG.warn("Interrupted while pausing before insert attempt {}", requestNumber, e1);
    }
    String dataString = baseString + requestNumber;
    // Pick random node to insert to
    int node1 = random.nextInt(NUMBER_OF_NODES);
    Node randomNode = nodes[node1];

    boolean isSSK = true;

    byte[] buf = dataString.getBytes(StandardCharsets.UTF_8);
    InsertKeys keys = createKeys(dataString, buf, isSSK);
    ClientKeyBlock block = keys.block;

    Key fetchNodeKey = keys.fetchKey.getNodeKey(false);
    LOG.info("Created random test key {} = {}", keys.testKey, fetchNodeKey);

    byte[] data = dataString.getBytes(StandardCharsets.UTF_8);
    String decoded = new String(block.memoryDecode(), StandardCharsets.UTF_8);
    LOG.debug("Decoded: {}", decoded);
    LOG.info("Insert Key: {}", keys.insertKey.getURI());
    LOG.info("Fetch Key: {}", keys.fetchKey.getURI());
    try {
      insertAttempts++;
      randomNode
          .services()
          .clientCore()
          .getTransfers()
          .realPut(block.getBlock(), false, FORK_ON_CACHEABLE, false, false, REAL_TIME_FLAG);
      LOG.error("Inserted to {}", node1);
    } catch (LowLevelPutException putEx) {
      LOG.error("Insert failed", putEx);
      return EXIT_INSERT_FAILED;
    }
    // Pick random node to request from
    int node2;
    do {
      node2 = random.nextInt(NUMBER_OF_NODES);
    } while (node2 == node1);
    Node fetchNode = nodes[node2];
    try {
      block =
          fetchNode
              .services()
              .clientCore()
              .getTransfers()
              .realGetKey(keys.fetchKey, false, false, false, REAL_TIME_FLAG);
    } catch (LowLevelGetException _) {
      block = null;
    }
    int result = handleFetchResult(block, data, node2);
    if (result != -1) {
      return result;
    }
    logRunningUids();
    return -1;
  }

  private InsertKeys createKeys(String dataString, byte[] buf, boolean isSSK)
      throws CHKEncodeException, InvalidCompressionCodecException, SSKEncodeException, IOException {
    FreenetURI testKey;
    ClientKey insertKey;
    ClientKey fetchKey;
    ClientKeyBlock block;
    if (isSSK) {
      testKey = new FreenetURI("KSK", dataString);

      insertKey = InsertableClientSSK.create(testKey);
      fetchKey = ClientKSK.create(testKey);

      block =
          ((InsertableClientSSK) insertKey)
              .encode(
                  new ArrayBucket(buf),
                  false,
                  false,
                  (short) -1,
                  buf.length,
                  Compressor.DEFAULT_COMPRESSORDESCRIPTOR);
    } else {
      block =
          ClientCHKBlock.encode(
              buf, false, false, (short) -1, buf.length, Compressor.DEFAULT_COMPRESSORDESCRIPTOR);
      insertKey = block.getClientKey();
      fetchKey = insertKey;
      testKey = insertKey.getURI();
    }
    return new InsertKeys(testKey, insertKey, fetchKey, block);
  }

  private int handleFetchResult(ClientKeyBlock block, byte[] data, int node2)
      throws KeyDecodeException {
    if (block == null) {
      int percentSuccess = 100 * fetchSuccesses / insertAttempts;
      LOG.error("Fetch #{} FAILED ({}%); from {}", requestNumber, percentSuccess, node2);
      requestsAvg.report(0.0);
      return -1;
    }

    byte[] results = block.memoryDecode();
    requestsAvg.report(1.0);
    if (!Arrays.equals(results, data)) {
      String resultsString = new String(results, StandardCharsets.UTF_8);
      LOG.error("Returned invalid data!: {}", resultsString);
      return EXIT_BAD_DATA;
    }

    fetchSuccesses++;
    int percentSuccess = 100 * fetchSuccesses / insertAttempts;
    String resultsString = new String(results, StandardCharsets.UTF_8);
    LOG.error(
        "Fetch #{} from node {} succeeded ({}%): {}",
        requestNumber, node2, percentSuccess, resultsString);
    if (fetchSuccesses == targetSuccesses) {
      LOG.info("Succeeded, {} successful fetches", targetSuccesses);
      return 0;
    }
    return -1;
  }

  private void logRunningUids() {
    StringBuilder load = new StringBuilder("Running UIDs for nodes: ");
    int totalRunningUIDsAlt = 0;
    List<Long> runningUIDsList = new ArrayList<>();
    for (int i = 0; i < nodes.length; i++) {
      load.append(i);
      load.append(':');
      nodes[i].routing().tracker().addRunningUIDs(runningUIDsList);
      int runningUIDsAlt = nodes[i].routing().tracker().getTotalRunningUIDsAlt();
      totalRunningUIDsAlt += runningUIDsAlt;
      load.append(totalRunningUIDsAlt);
      if (i != nodes.length - 1) {
        load.append(' ');
      }
    }
    LOG.info("Running UIDs for nodes: {}", load);
    if (totalRunningUIDsAlt != 0) {
      LOG.info("Still running UIDs (alt): {}", totalRunningUIDsAlt);
    }
    if (!runningUIDsList.isEmpty()) {
      LOG.info("List of running UIDs: {}", runningUIDsList);
    }
  }

  private record InsertKeys(
      FreenetURI testKey, ClientKey insertKey, ClientKey fetchKey, ClientKeyBlock block) {}
}
