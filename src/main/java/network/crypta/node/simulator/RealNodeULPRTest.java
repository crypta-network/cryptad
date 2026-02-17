package network.crypta.node.simulator;

import java.io.File;
import java.io.IOException;
import java.util.Objects;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.keys.BlockEncodeParams;
import network.crypta.keys.CHKEncodeException;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.InsertableClientSSK;
import network.crypta.keys.Key;
import network.crypta.keys.SSKEncodeException;
import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import network.crypta.node.FSParseException;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.Node;
import network.crypta.node.NodeDispatcher.NodeDispatcherCallback;
import network.crypta.node.NodeInitException;
import network.crypta.node.NodeStarter;
import network.crypta.node.NodeStarter.TestNodeParameters;
import network.crypta.node.PeerTooOldException;
import network.crypta.store.KeyCollisionException;
import network.crypta.support.HexUtil;
import network.crypta.support.PooledExecutor;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.compress.Compressor;
import network.crypta.support.compress.InvalidCompressionCodecException;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

/**
 * Runs an end-to-end ULPR propagation simulation using real nodes and live routing.
 *
 * <p>This executable harness builds a small darknet, triggers negative fetches for a randomly
 * generated key, inserts the data on one node, and then waits until every node has acquired the
 * block. It is intended for manual or CI-style validation of ULPR behavior under realistic node
 * scheduling rather than for deterministic unit testing. The run relies on per-node failure tables
 * to diversify routing while ULPRs replicate content to nodes that previously requested it.
 *
 * <p>The simulation starts nodes with their own background threads and uses a simple polling loop
 * with a one-second tick to measure propagation time. It is not designed to be run concurrently on
 * the same JVM because it exits the process on failure and uses shared static configuration.
 *
 * <p><b>Responsibilities:</b>
 *
 * <ul>
 *   <li>Initialize a reproducible node set with fixed ports and settings.
 *   <li>Issue fetch requests before insertion to populate failure tables.
 *   <li>Measure propagation time until all nodes hold the key.
 * </ul>
 *
 * @see RealNodeTest
 * @see RealNodePingTest
 */
public class RealNodeULPRTest extends RealNodeTest {
  private static final Logger LOG = LoggerFactory.getLogger(RealNodeULPRTest.class);

  private static final String NODE_LABEL = "Node ";
  private static final Object PROPAGATION_WAIT_LOCK = new Object();

  /**
   * Base port assigned to the first node in this simulation.
   *
   * <p>This value is derived from {@link RealNodePingTest#DARKNET_PORT_END} so the ULPR test can
   * run alongside other simulator tests without colliding on port assignments. Nodes are assigned
   * to consecutive ports starting at this base, so the range is deterministic across runs.
   */
  public static final int DARKNET_PORT_BASE = RealNodePingTest.DARKNET_PORT_END;

  /**
   * Creates a new ULPR test harness instance.
   *
   * <p>The class is typically used via its {@link #main()} entry point, but a public constructor is
   * provided to satisfy doclint requirements for public types. The constructor is intentionally
   * side-effect-free: it does not allocate nodes, create files, or start background threads.
   * Callers are expected to invoke static setup routines explicitly rather than relying on instance
   * initialization.
   */
  public RealNodeULPRTest() {
    // Intentionally empty: the harness is driven via static entry points.
  }

  /**
   * Entry point that executes the ULPR propagation simulation end to end.
   *
   * <p>The method prepares a working directory, initializes nodes with test parameters, connects a
   * ring plus randomized links, and then loops through a series of randomized keys. For each key,
   * all nodes attempt a fetch before the key is inserted, which primes failure tables and drives
   * ULPR-based replication once the data is stored. The method logs progress, computes propagation
   * timings, and terminates the JVM with an exit code on success or failure.
   *
   * <pre>{@code
   * public static void main(String[] args) throws Exception {
   *   RealNodeULPRTest.main();
   * }
   * }</pre>
   *
   * @throws FSParseException if a node reference cannot be parsed during linking
   * @throws PeerParseException if a peer record is malformed while connecting nodes
   * @throws CHKEncodeException if a CHK block cannot be encoded for the test key
   * @throws NodeInitException if node initialization fails or startup cannot complete
   * @throws ReferenceSignatureVerificationException if a darknet reference signature is invalid
   * @throws KeyCollisionException if insertion collides with an existing key in the store
   * @throws SSKEncodeException if an SSK block cannot be encoded for the test key
   * @throws IOException if key material cannot be created or stored on disk
   * @throws InterruptedException if the propagation wait loop is interrupted
   * @throws InvalidCompressionCodecException if the default compression descriptor is unsupported
   * @throws PeerTooOldException if a peer is rejected due to an incompatible version
   */
  public static void main()
      throws FSParseException,
          PeerParseException,
          CHKEncodeException,
          NodeInitException,
          ReferenceSignatureVerificationException,
          KeyCollisionException,
          SSKEncodeException,
          IOException,
          InterruptedException,
          InvalidCompressionCodecException,
          PeerTooOldException {
    LOG.info("ULPR test");
    String testName = "realNodeULPRTest";
    File wd = new File(testName);
    prepareWorkingDirectory(wd);

    DummyRandomSource random = new DummyRandomSource();

    NodeStarter.globalTestInit(
        wd,
        false,
        Level.ERROR,
        "network.crypta.node.Location:INFO,network.crypta.node.simulator"
            + ".RealNodeRoutingTest:INFO,network.crypta.node"
            + ".NodeDispatcher:INFO,network.crypta.node.FailureTable:DEBUG,"
            + "network.crypta.node.Node:DEBUG,network.crypta.node.Request:DEBUG,"
            + "network.crypta.io.comm.MessageCore:DEBUG,network.crypta.node"
            + ".PeerNode:DEBUG,network.crypta.node.DarknetPeerNode:DEBUG,network"
            + ".crypta.io.xfer.PacketThrottle:DEBUG,network.crypta.node"
            + ".PeerManager:DEBUG,network.crypta.client.async:DEBUG",
        true,
        null);
    Node[] nodes = createNodes(wd, random, new PooledExecutor());
    exportDarknetRefs(nodes);
    connectRing(nodes);
    addRandomLinks(nodes, random);
    startNodes(nodes);

    int successfulTests = 0;
    long totalPropagationTime = 0;
    for (int totalCount = 0; totalCount < NUMBER_OF_TESTS; totalCount++) {
      boolean isSSK = (totalCount & 0x1) == 1;
      KeyTestData keyData = createTestKey(random, isSSK);
      LOG.error(
          "Starting ULPR test #{}: {} = {} = {}",
          successfulTests,
          keyData.testKey,
          keyData.fetchKey,
          keyData.nodeKey);
      waitForAllConnected(nodes);
      boolean[] visited = trackVisitedNodes(nodes, isSSK, keyData.nodeKey);
      requestKeyFromAllNodes(nodes, keyData.fetchKey);
      logVisitedNodes(visited);
      long propagationTime =
          storeAndWaitForPropagation(nodes, keyData.block, keyData.fetchKey, successfulTests);
      successfulTests++;
      totalPropagationTime += propagationTime;
      LOG.info("Average propagation time: {}ms", totalPropagationTime / successfulTests);
    }
    LOG.info("Overall average propagation time: {}ms", totalPropagationTime / successfulTests);
    System.exit(0);
  }

  private static void prepareWorkingDirectory(File wd) {
    if (!FileUtil.removeAll(wd)) {
      LOG.warn("Mass delete failed, test may not be accurate.");
      System.exit(EXIT_CANNOT_DELETE_OLD_DATA);
    }
    if (!wd.mkdir() && !wd.isDirectory()) {
      LOG.warn("Failed to create working directory at {}", wd.getAbsolutePath());
      System.exit(EXIT_CANNOT_DELETE_OLD_DATA);
    }
  }

  private static Node[] createNodes(
      File wd, DummyRandomSource random, PriorityAwareExecutor executor) throws NodeInitException {
    Node[] nodes = new Node[NUMBER_OF_NODES];
    LOG.info("Creating nodes...");
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
                p.setDisableProbabilisticHTLs(true);
                p.setMaxHTL(MAX_HTL);
                p.setDropProb(20);
                p.setThreadLimit(500 * NUMBER_OF_NODES);
                p.setStoreSize(1024L * 1024L);
                p.setRamStore(true);
                p.setEnableSwapping(ENABLE_SWAPPING);
                p.setEnableULPRs(ENABLE_ULPRS);
                p.setEnablePerNodeFailureTables(ENABLE_PER_NODE_FAILURE_TABLES);
                p.setEnableSwapQueueing(true);
                p.setEnablePacketCoalescing(true);
                p.setOutputBandwidthLimit(0);
                p.setEnableFOAF(ENABLE_FOAF);
                p.setConnectToSeednodes(false);
                p.setLongPingTimes(true);
              });
      nodes[i] = NodeStarter.createTestNode(params);
      LOG.info("Created node {}", i);
    }
    LOG.info("Created {} nodes", NUMBER_OF_NODES);
    return nodes;
  }

  private static void exportDarknetRefs(Node[] nodes) {
    for (int i = 0; i < NUMBER_OF_NODES; i++) {
      nodes[i].network().exportDarknetPublicFieldSet();
    }
    LOG.info("Exported darknet public references");
  }

  private static void connectRing(Node[] nodes)
      throws FSParseException,
          PeerParseException,
          ReferenceSignatureVerificationException,
          PeerTooOldException {
    for (int i = 0; i < NUMBER_OF_NODES; i++) {
      int next = (i + 1) % NUMBER_OF_NODES;
      int prev = (i + NUMBER_OF_NODES - 1) % NUMBER_OF_NODES;
      nodes[i].network().connect(nodes[next], trust, visibility);
      nodes[i].network().connect(nodes[prev], trust, visibility);
    }
    LOG.info("Connected nodes");
  }

  private static void addRandomLinks(Node[] nodes, DummyRandomSource random)
      throws FSParseException,
          PeerParseException,
          ReferenceSignatureVerificationException,
          PeerTooOldException {
    for (int i = 0; i < NUMBER_OF_NODES * 5; i++) {
      if (i % NUMBER_OF_NODES == 0) {
        LOG.info("Added {} random links so far", i);
      }
      int length = (int) Math.pow(NUMBER_OF_NODES, random.nextDouble());
      int nodeA = random.nextInt(NUMBER_OF_NODES);
      int nodeB = (nodeA + length) % NUMBER_OF_NODES;
      Node a = nodes[nodeA];
      Node b = nodes[nodeB];
      a.network().connect(b, trust, visibility);
      b.network().connect(a, trust, visibility);
    }
    LOG.info("Added random links");
  }

  private static void startNodes(Node[] nodes) throws NodeInitException {
    for (Node node : nodes) {
      node.start(false);
    }
  }

  private static KeyTestData createTestKey(DummyRandomSource random, boolean isSSK)
      throws CHKEncodeException, SSKEncodeException, InvalidCompressionCodecException, IOException {
    byte[] buf = new byte[32];
    random.nextBytes(buf);
    String keyName = HexUtil.bytesToHex(buf);

    FreenetURI testKey;
    ClientKey fetchKey;
    ClientKeyBlock block;

    if (isSSK) {
      testKey = new FreenetURI("KSK", keyName);
      InsertableClientSSK insertKey = InsertableClientSSK.create(testKey);
      fetchKey = InsertableClientSSK.create(testKey);
      block =
          insertKey.encode(
              new BlockEncodeParams(
                  new ArrayBucket(buf),
                  false,
                  false,
                  (short) -1,
                  buf.length,
                  Compressor.DEFAULT_COMPRESSORDESCRIPTOR));
    } else {
      block =
          ClientCHKBlock.encode(
              buf, false, false, (short) -1, buf.length, Compressor.DEFAULT_COMPRESSORDESCRIPTOR);
      fetchKey = block.getClientKey();
      testKey = fetchKey.getURI();
    }
    Key nodeKey = fetchKey.getNodeKey(false);
    LOG.info("Created random test key {} = {}", testKey, nodeKey);
    return new KeyTestData(testKey, fetchKey, block, nodeKey);
  }

  private static boolean[] trackVisitedNodes(Node[] nodes, boolean isSSK, Key nodeKey) {
    boolean[] visited = new boolean[nodes.length];
    NodeDispatcherCallback cb =
        (m, n) -> {
          if ((!isSSK && Objects.equals(m.getSpec(), DMT.FNPCHKDataRequest))
              || (isSSK && Objects.equals(m.getSpec(), DMT.FNPSSKDataRequest))) {
            Key key = (Key) m.getObject(DMT.FREENET_ROUTING_KEY);
            if (key.equals(nodeKey)) {
              visited[n.network().darknetPortNumber() - DARKNET_PORT_BASE] = true;
            }
          }
        };

    for (Node node : nodes) {
      node.network().setDispatcherHook(cb);
    }
    return visited;
  }

  private static void requestKeyFromAllNodes(Node[] nodes, ClientKey fetchKey) {
    for (int i = 0; i < nodes.length; i++) {
      LOG.info("Searching from node {}", i);
      try {
        nodes[i % nodes.length]
            .services()
            .clientCore()
            .getTransfers()
            .realGetKey(fetchKey, false, false, false, REAL_TIME_FLAG);
        LOG.error("TEST FAILED: KEY ALREADY PRESENT!!!");
        System.exit(EXIT_KEY_EXISTS);
      } catch (LowLevelGetException e) {
        handleFetchFailure(e, i, nodes.length);
      }
    }
  }

  private static void handleFetchFailure(LowLevelGetException exception, int index, int length) {
    switch (exception.code) {
      case LowLevelGetException.DATA_NOT_FOUND, LowLevelGetException.ROUTE_NOT_FOUND ->
          LOG.info("{}{} : key not found (expected behaviour)", NODE_LABEL, index % length);
      case LowLevelGetException.RECENTLY_FAILED ->
          LOG.info(
              "{}{} : recently failed (expected behaviour on later tests)",
              NODE_LABEL,
              index % length);
      default -> {
        LOG.error("{}{} : UNEXPECTED ERROR", NODE_LABEL, index % length, exception);
        System.exit(EXIT_UNKNOWN_ERROR_CHECKING_KEY_NOT_EXIST);
      }
    }
  }

  private static void logVisitedNodes(boolean[] visited) {
    int visitedCount = 0;
    StringBuilder sb = new StringBuilder(3 * visited.length + 1);
    boolean first = true;
    for (int i = 0; i < visited.length; i++) {
      if (!visited[i]) {
        continue;
      }
      visitedCount++;
      if (!first) {
        sb.append(' ');
      }
      first = false;
      sb.append(i);
    }
    LOG.info("Nodes which were asked for the key by another node: {} : {}", visitedCount, sb);
  }

  private static long storeAndWaitForPropagation(
      Node[] nodes, ClientKeyBlock block, ClientKey fetchKey, int testIndex)
      throws InterruptedException, KeyCollisionException {
    LOG.info("Inserting to node {}", nodes.length - 1);
    long tStart = System.currentTimeMillis();
    nodes[nodes.length - 1].storage().store(block.getBlock(), false, false, true, false);
    LOG.info("Inserted to node {}", nodes.length - 1);

    int x = -1;
    while (true) {
      x++;
      waitForPropagationTick();
      int count = countNodesWithKey(nodes, fetchKey);
      LOG.info("T={} : {}/{} have the data on test {}.", x, count, nodes.length, testIndex);
      if (x > 300) {
        LOG.error("TEST FAILED");
        System.exit(EXIT_TEST_FAILED);
      }
      if (count == nodes.length) {
        long propagationTime = System.currentTimeMillis() - tStart;
        LOG.info("SUCCESSFUL TEST in {}ms!!!", propagationTime);
        return propagationTime;
      }
      if (x % nodes.length == 0 && LOG.isInfoEnabled()) {
        LOG.info("Nodes that do have the data: {}", nodesWithKey(nodes, fetchKey));
      }
    }
  }

  private static int countNodesWithKey(Node[] nodes, ClientKey fetchKey) {
    int count = 0;
    for (Node node : nodes) {
      if (node.storage().hasKey(fetchKey.getNodeKey(false), true, true)) {
        count++;
      }
    }
    return count;
  }

  private static void waitForPropagationTick() throws InterruptedException {
    synchronized (PROPAGATION_WAIT_LOCK) {
      long deadline = System.currentTimeMillis() + 1000;
      while (true) {
        long remaining = deadline - System.currentTimeMillis();
        if (remaining <= 0) {
          break;
        }
        PROPAGATION_WAIT_LOCK.wait(remaining);
      }
    }
  }

  private static String nodesWithKey(Node[] nodes, ClientKey fetchKey) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < nodes.length; i++) {
      if (nodes[i].storage().hasKey(fetchKey.getNodeKey(false), true, true)) {
        if (!sb.isEmpty()) {
          sb.append(' ');
        }
        sb.append(i);
      }
    }
    return sb.toString();
  }

  private record KeyTestData(
      FreenetURI testKey, ClientKey fetchKey, ClientKeyBlock block, Key nodeKey) {}

  // Exit codes
  static final int EXIT_BASE = NodeInitException.EXIT_NODE_UPPER_LIMIT;
  static final int EXIT_KEY_EXISTS = EXIT_BASE + 1;
  static final int EXIT_UNKNOWN_ERROR_CHECKING_KEY_NOT_EXIST = EXIT_BASE + 2;
  static final int EXIT_TEST_FAILED = EXIT_BASE + 4;
  static final int NUMBER_OF_NODES = 10;

  /**
   * Port value immediately after the last node in the simulation.
   *
   * <p>Nodes are assigned ports in the half-open range {@code [DARKNET_PORT_BASE,
   * DARKNET_PORT_END)}, which makes this value an exclusive upper bound for the test's port
   * allocation. Keeping a dedicated end marker simplifies derived ranges in other simulator tests.
   */
  public static final int DARKNET_PORT_END = DARKNET_PORT_BASE + NUMBER_OF_NODES;

  // We don't explicitly subscribe, so each node must be routed through.
  // However, per-node failure tables should ensure the node doesn't make the same mistake twice so
  // visits every node.
  static final short MAX_HTL = 10;
  static final int NUMBER_OF_TESTS = 100;
  static final boolean ENABLE_SWAPPING = true;
  static final boolean ENABLE_ULPRS = true;
  // This is the point of the test, but it's probably a good idea to be able to do a comparison
  // if we want to
  static final boolean ENABLE_PER_NODE_FAILURE_TABLES = true;
  static final boolean ENABLE_FOAF = true;
  static final boolean REAL_TIME_FLAG = false;
  static final FRIEND_TRUST trust = FRIEND_TRUST.LOW;
  static final FRIEND_VISIBILITY visibility = FRIEND_VISIBILITY.NO;
}
