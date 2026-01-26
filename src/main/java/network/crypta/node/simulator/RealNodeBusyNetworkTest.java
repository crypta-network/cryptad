package network.crypta.node.simulator;

import static java.util.concurrent.TimeUnit.DAYS;

import java.io.File;
import java.nio.charset.StandardCharsets;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.CHKDecodeException;
import network.crypta.keys.CHKEncodeException;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.node.LowLevelPutException;
import network.crypta.node.Node;
import network.crypta.node.NodeInitException;
import network.crypta.node.NodeStarter;
import network.crypta.node.RequestStarter;
import network.crypta.support.Fields;
import network.crypta.support.HexUtil;
import network.crypta.support.PooledExecutor;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.compress.Compressor;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

/**
 * Simulation harness that stresses a busy, bandwidth-limited network of real nodes.
 *
 * <p>This test configures a fixed-size node mesh, links it into a Kleinberg-style topology, and
 * then exercises bulk insert and prefetch behavior under constrained bandwidth settings. It
 * performs a single end-to-end run: it deletes any existing working directory, creates test nodes
 * with in-memory stores, starts the nodes, waits for connectivity and a high ping success rate,
 * inserts a fixed number of keys into random nodes, and finally queues prefetch requests for every
 * node. The process exits once all queued requests drain, so it is intended as a one-shot stress
 * run rather than a reusable fixture.
 *
 * <p>The harness itself executes on the main thread, while node activity happens inside each node's
 * executor. Completion is detected by polling queued request counts with a timed wait, which favors
 * test stability over strict real-time scheduling.
 *
 * <ul>
 *   <li>Builds a deterministic network using {@link DummyRandomSource} and fixed constants.
 *   <li>Applies bandwidth limits and optional feature toggles for repeatability.
 *   <li>Logs progress and exits with explicit codes for setup or insert failures.
 * </ul>
 *
 * @author toad
 * @see RealNodeRoutingTest
 */
public class RealNodeBusyNetworkTest extends RealNodeRoutingTest {
  private static final Logger LOG = LoggerFactory.getLogger(RealNodeBusyNetworkTest.class);
  private static final Object COMPLETION_MONITOR = new Object();

  static final int NUMBER_OF_NODES = 25;
  static final int DEGREE = 5;
  static final short MAX_HTL = (short) 8;
  static final int INSERT_KEYS = 50;
  static final boolean START_WITH_IDEAL_LOCATIONS = true;
  static final boolean FORCE_NEIGHBOUR_CONNECTIONS = true;
  static final boolean ENABLE_SWAPPING = false;
  static final boolean ENABLE_ULPRS = false;
  static final boolean ENABLE_PER_NODE_FAILURE_TABLES = false;
  static final boolean ENABLE_SWAP_QUEUEING = false;
  static final boolean ENABLE_PACKET_COALESCING = true;
  static final boolean ENABLE_FOAF = true;
  static final boolean FORK_ON_CACHEABLE = false;
  static final boolean REAL_TIME_FLAG = false;

  static final int DARKNET_PORT_BASE = 5008;
  static final int DARKNET_PORT_END = DARKNET_PORT_BASE + NUMBER_OF_NODES;

  /**
   * Creates an instance of the test harness with no instance state.
   *
   * <p>This class is designed to be used through its static entry point, but the default
   * constructor remains public for tools that require reflective instantiation. The constructor
   * performs no initialization and does not allocate resources; all state used by the test is
   * created within {@link #main(String[])} and released when the process exits.
   */
  public RealNodeBusyNetworkTest() {
    // Intentionally empty: this harness is driven by static entry points.
  }

  /**
   * Runs the busy-network simulation from setup through completion and then terminates the process.
   *
   * <p>The method creates or recreates the working directory, initializes test nodes with fixed
   * topology and bandwidth settings, and waits for a healthy ping average before inserting keys. It
   * then queues prefetch requests for every inserted key across every node and blocks until all
   * queued requests finish. The method is not idempotent: it deletes prior data, consumes ports,
   * and calls {@link System#exit(int)} on failure or normal completion.
   *
   * @param args command-line arguments that are currently ignored by this test harness
   * @throws Exception if node initialization, startup, or waiting is interrupted or fails
   */
  public static void main(@SuppressWarnings("unused") String[] args) throws Exception {
    String name = "realNodeRequestInsertTest";
    File wd = new File(name);
    prepareWorkingDirectory(wd);
    NodeStarter.globalTestInit(new File(name), false, Level.ERROR, "", true, null);
    LOG.info(
        "event=busy-network.start Busy network test (inserts/retrieves in quantity/stress test)");
    DummyRandomSource random = new DummyRandomSource();
    Node[] nodes = createNodes(wd, random);

    // Now link them up
    makeKleinbergNetwork(
        nodes, START_WITH_IDEAL_LOCATIONS, DEGREE, FORCE_NEIGHBOUR_CONNECTIONS, random);

    LOG.info("event=topology.links Added random links");

    startNodes(nodes);

    waitForAllConnected(nodes);

    waitForPingAverage(0.95, nodes, random, MAX_PINGS, 1000);

    LOG.info("event=ping.threshold Ping average > 95%, lets do some inserts/requests");

    HighLevelSimpleClient[] clients = createClients(nodes);

    // Insert 100 keys into random nodes

    ClientCHK[] keys = insertKeys(nodes, random);

    // Now queue requests for each key on every node.
    queueRequests(clients, nodes, keys);

    // Now wait until finished. How???

    waitForCompletion(nodes);
    System.exit(0);
  }

  /**
   * Removes any existing working directory and recreates it for a fresh test run.
   *
   * @param workingDirectory location that is deleted and recreated for this test run
   */
  private static void prepareWorkingDirectory(File workingDirectory) {
    if (!FileUtil.removeAll(workingDirectory)) {
      LOG.warn("event=workspace.delete-failed Mass delete failed, test may not be accurate.");
      System.exit(EXIT_CANNOT_DELETE_OLD_DATA);
    }
    if (!workingDirectory.mkdir() && !workingDirectory.isDirectory()) {
      LOG.warn(
          "event=workspace.mkdir-failed Failed to create working directory: {}",
          workingDirectory.getAbsolutePath());
      System.exit(EXIT_CANNOT_DELETE_OLD_DATA);
    }
  }

  /**
   * Builds the configured test nodes backed by the shared working directory.
   *
   * @param workingDirectory base directory shared by all nodes for test storage
   * @param random deterministic random source used for node configuration choices
   * @return the initialized nodes, in creation order, with configured test parameters
   * @throws NodeInitException if a node fails to initialize with the provided parameters
   */
  private static Node[] createNodes(File workingDirectory, DummyRandomSource random)
      throws NodeInitException {
    Node[] nodes = new Node[NUMBER_OF_NODES];
    LOG.info("event=nodes.create Creating nodes...");
    PriorityAwareExecutor executor = new PooledExecutor();
    for (int i = 0; i < NUMBER_OF_NODES; i++) {
      NodeStarter.TestNodeParameters params = new NodeStarter.TestNodeParameters();
      params.setPort(DARKNET_PORT_BASE + i);
      params.setOpennetPort(0);
      params.setBaseDirectory(workingDirectory);
      params.setDisableProbabilisticHTLs(false);
      params.setMaxHTL(MAX_HTL);
      params.setDropProb(20);
      params.setRandom(random);
      params.setExecutor(executor);
      params.setThreadLimit(500 * NUMBER_OF_NODES);
      params.setStoreSize((CHKBlock.DATA_LENGTH + CHKBlock.TOTAL_HEADERS_LENGTH) * 100L);
      params.setRamStore(true);
      params.setEnableSwapping(ENABLE_SWAPPING);
      params.setEnableULPRs(ENABLE_ULPRS);
      params.setEnablePerNodeFailureTables(ENABLE_PER_NODE_FAILURE_TABLES);
      params.setEnableSwapQueueing(ENABLE_SWAP_QUEUEING);
      params.setEnablePacketCoalescing(ENABLE_PACKET_COALESCING);
      params.setOutputBandwidthLimit(8000);
      params.setEnableFOAF(ENABLE_FOAF);
      params.setLongPingTimes(true);
      nodes[i] = NodeStarter.createTestNode(params);
      LOG.info("event=nodes.created Created node {}", i);
    }
    return nodes;
  }

  /**
   * Starts all nodes in order and logs progress.
   *
   * @param nodes nodes to start in index order for deterministic startup logging
   * @throws NodeInitException if any node fails to start successfully
   */
  private static void startNodes(Node[] nodes) throws NodeInitException {
    for (int i = 0; i < nodes.length; i++) {
      nodes[i].start(false);
      LOG.info("event=nodes.started Started node {}/{}", i, nodes.length);
    }
  }

  /**
   * Creates a client per node using the immediate splitfile priority class.
   *
   * @param nodes nodes that provide the client cores used to create clients
   * @return one client per node, aligned by index with the {@code nodes} array
   */
  private static HighLevelSimpleClient[] createClients(Node[] nodes) {
    HighLevelSimpleClient[] clients = new HighLevelSimpleClient[nodes.length];
    for (int i = 0; i < clients.length; i++) {
      clients[i] =
          nodes[i]
              .services()
              .clientCore()
              .makeClient(RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS, false, false);
    }
    return clients;
  }

  /**
   * Inserts the configured number of keys into random nodes.
   *
   * @param nodes nodes that receive randomly selected inserts during the run
   * @param random random source used to pick which node receives each insert
   * @return client keys corresponding to each inserted block, in insert order
   * @throws CHKEncodeException if encoding a client block fails for the input data
   * @throws CHKDecodeException if decoding a client block fails for logging output
   */
  private static ClientCHK[] insertKeys(Node[] nodes, DummyRandomSource random)
      throws CHKEncodeException, CHKDecodeException {
    ClientCHK[] keys = new ClientCHK[INSERT_KEYS];
    String baseString = System.currentTimeMillis() + " ";
    for (int i = 0; i < INSERT_KEYS; i++) {
      LOG.info("event=insert.progress Inserting {} of {}", i, INSERT_KEYS);
      int nodeIndex = random.nextInt(NUMBER_OF_NODES);
      Node randomNode = nodes[nodeIndex];
      ClientCHKBlock block = createBlock(baseString, i);
      ClientCHK chk = block.getClientKey();
      CHKBlock chkBlock = block.getBlock();
      keys[i] = chk;
      logBlockDetails(block, chkBlock);
      try {
        randomNode
            .services()
            .clientCore()
            .getTransfers()
            .realPut(chkBlock, false, FORK_ON_CACHEABLE, false, false, REAL_TIME_FLAG);
        LOG.error("event=insert.complete Inserted to {}", nodeIndex);
        logBlockPayloadDetails(chkBlock);
      } catch (LowLevelPutException putEx) {
        LOG.error("event=insert.failed Insert failed: {}", String.valueOf(putEx));
        System.exit(EXIT_INSERT_FAILED);
      }
    }
    return keys;
  }

  /**
   * Encodes a single block from the base string and index.
   *
   * @param baseString prefix for the content that is combined with the index
   * @param index numeric suffix appended to the base string before encoding
   * @return encoded client block containing the UTF-8 bytes of the composed string
   * @throws CHKEncodeException if the block cannot be encoded with the chosen parameters
   */
  private static ClientCHKBlock createBlock(String baseString, int index)
      throws CHKEncodeException {
    String dataString = baseString + index;
    byte[] data = dataString.getBytes(StandardCharsets.UTF_8);
    return ClientCHKBlock.encode(
        data, false, false, (short) -1, 0, Compressor.DEFAULT_COMPRESSORDESCRIPTOR);
  }

  /**
   * Logs decoded and header details for a block when debug logging is enabled.
   *
   * @param block client block providing the decoded payload and client key
   * @param chkBlock encoded block containing the headers that are logged
   * @throws CHKDecodeException if the block payload cannot be decoded for logging
   */
  private static void logBlockDetails(ClientCHKBlock block, CHKBlock chkBlock)
      throws CHKDecodeException {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "event=block.decoded Decoded: {}",
          new String(block.memoryDecode(), StandardCharsets.UTF_8));
      LOG.debug("event=block.headers Headers: {}", HexUtil.bytesToHex(chkBlock.getHeaders()));
    }
    LOG.info("event=block.key CHK: {}", block.getClientKey().getURI());
  }

  /**
   * Logs hashed payload details for a block when debug logging is enabled.
   *
   * @param chkBlock encoded block containing the payload and headers to hash
   */
  private static void logBlockPayloadDetails(CHKBlock chkBlock) {
    if (LOG.isDebugEnabled()) {
      byte[] encData = chkBlock.getData();
      byte[] encHeaders = chkBlock.getHeaders();
      LOG.debug(
          "event=block.payload Data: {}, Headers: {}",
          Fields.hashCode(encData),
          Fields.hashCode(encHeaders));
    }
  }

  /**
   * Queues prefetch requests for all keys from all clients and logs queue depth.
   *
   * @param clients clients that issue prefetch requests for every key
   * @param nodes nodes used only to count running requests for progress logging
   * @param keys keys to prefetch, queued across every client in index order
   */
  private static void queueRequests(
      HighLevelSimpleClient[] clients, Node[] nodes, ClientCHK[] keys) {
    for (int i = 0; i < keys.length; i++) {
      ClientCHK key = keys[i];
      LOG.info("event=prefetch.queue Progress {} of {}", i, keys.length);
      for (HighLevelSimpleClient client : clients) {
        client.prefetch(key.getURI(), DAYS.toMillis(1), 32768, null);
      }
      LOG.info("event=prefetch.queue-depth Running requests: {}", countRunningRequests(nodes));
    }
  }

  /**
   * Waits until all queued requests are complete.
   *
   * @param nodes nodes whose queued requests are polled for completion
   * @throws InterruptedException if the waiting thread is interrupted
   */
  private static void waitForCompletion(Node[] nodes) throws InterruptedException {
    while (true) {
      long totalRunningRequests = countRunningRequests(nodes);
      LOG.info("event=prefetch.await Running requests: {}", totalRunningRequests);
      if (totalRunningRequests == 0) {
        break;
      }
      synchronized (COMPLETION_MONITOR) {
        COMPLETION_MONITOR.wait(1000);
      }
    }
  }

  /**
   * Totals the number of queued requests across all nodes.
   *
   * @param nodes nodes whose queued requests are summed for reporting
   * @return total number of queued requests observed across all nodes
   */
  private static long countRunningRequests(Node[] nodes) {
    long totalRunningRequests = 0;
    for (Node node : nodes) {
      totalRunningRequests += node.services().clientCore().countQueuedRequests();
    }
    return totalRunningRequests;
  }
}
