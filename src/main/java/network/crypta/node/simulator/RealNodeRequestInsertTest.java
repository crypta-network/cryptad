package network.crypta.node.simulator;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.RandomSource;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.keys.CHKEncodeException;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.keys.ClientKSK;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.InsertableClientSSK;
import network.crypta.keys.KeyDecodeException;
import network.crypta.keys.SSKEncodeException;
import network.crypta.node.FSParseException;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.LowLevelPutException;
import network.crypta.node.Node;
import network.crypta.node.NodeInitException;
import network.crypta.node.NodeStarter;
import network.crypta.node.NodeStarter.TestNodeParameters;
import network.crypta.support.PooledExecutor;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.compress.InvalidCompressionCodecException;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.FileUtil;
import network.crypta.support.math.RunningAverage;
import network.crypta.support.math.SimpleRunningAverage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

/**
 * @author amphibian
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
  // static final int NUMBER_OF_NODES = 50;
  // static final short MAX_HTL = 10;

  // FIXME: HACK: High bwlimit makes the "other" requests not affect the test requests.
  // Real solution is to get rid of the "other" requests!!
  static final int BWLIMIT = 1000 * 1024;

  // public static final int DARKNET_PORT_BASE = RealNodePingTest.DARKNET_PORT2+1;
  public static final int DARKNET_PORT_BASE = 10000;
  public static final int DARKNET_PORT_END = DARKNET_PORT_BASE + NUMBER_OF_NODES;

  public static void main(String[] args)
      throws FSParseException,
          PeerParseException,
          CHKEncodeException,
          NodeInitException,
          ReferenceSignatureVerificationException,
          InterruptedException {
    String name = "realNodeRequestInsertTest";
    File wd = new File(name);
    if (!FileUtil.removeAll(wd)) {
      System.err.println("Mass delete failed, test may not be accurate.");
      System.exit(EXIT_CANNOT_DELETE_OLD_DATA);
    }
    wd.mkdir();
    DummyRandomSource random = new DummyRandomSource(3142);
    // NOTE: globalTestInit returns in ignored random source
    // NodeStarter.globalTestInit(name, false, LogLevel.ERROR,
    // "freenet.node.Location:normal,freenet.node.simulator.RealNode:minor,freenet.node.Insert:MINOR,freenet.node.Request:MINOR,freenet.node.Node:MINOR");
    // NodeStarter.globalTestInit(name, false, LogLevel.ERROR,
    // "freenet.node.Location:MINOR,freenet.io.comm:MINOR,freenet.node.NodeDispatcher:MINOR,freenet.node.simulator:MINOR,freenet.node.PeerManager:MINOR,freenet.node.RequestSender:MINOR");
    // NodeStarter.globalTestInit(name, false, LogLevel.ERROR,
    // "freenet.node.FNP:MINOR,freenet.node.Packet:MINOR,freenet.io.comm:MINOR,freenet.node.PeerNode:MINOR,freenet.node.DarknetPeerNode:MINOR");
    NodeStarter.globalTestInit(wd, false, Level.ERROR, "", true, random);
    System.out.println("Insert/retrieve test");
    System.out.println();
    DummyRandomSource topologyRandom = new DummyRandomSource(3143);
    // DiffieHellman.init(random);
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
      LOG.info("Created node " + i);
    }

    // Now link them up
    makeKleinbergNetwork(
        nodes, START_WITH_IDEAL_LOCATIONS, DEGREE, FORCE_NEIGHBOUR_CONNECTIONS, topologyRandom);

    LOG.info("Added random links");

    for (int i = 0; i < NUMBER_OF_NODES; i++) {
      nodes[i].start(false);
      System.err.println("Started node " + i + "/" + nodes.length);
    }

    waitForAllConnected(nodes);

    waitForPingAverage(0.5, nodes, new DummyRandomSource(3143), MAX_PINGS, 1000);

    random = new DummyRandomSource(3144);

    System.out.println();
    System.out.println("Ping average > 95%, lets do some inserts/requests");
    System.out.println();

    RealNodeRequestInsertTest tester =
        new RealNodeRequestInsertTest(nodes, random, TARGET_SUCCESSES);

    while (true) {
      try {
        waitForAllConnected(nodes);
        int status = tester.insertRequestTest();
        if (status == -1) continue;
        System.exit(status);
      } catch (Throwable t) {
        LOG.error("Caught " + t, t);
      }
    }
  }

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
   * @param nodes
   * @param random
   * @return -1 to continue or an exit code (0 or positive for an error).
   * @throws CHKEncodeException
   * @throws InvalidCompressionCodecException
   * @throws SSKEncodeException
   * @throws IOException
   * @throws KeyDecodeException
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
    }
    String dataString = baseString + requestNumber;
    // Pick random node to insert to
    int node1 = random.nextInt(NUMBER_OF_NODES);
    Node randomNode = nodes[node1];
    // LOG.error("Inserting: \""+dataString+"\" to "+node1);

    // boolean isSSK = requestNumber % 2 == 1;
    boolean isSSK = true;

    FreenetURI testKey;
    ClientKey insertKey;
    ClientKey fetchKey;
    ClientKeyBlock block;

    byte[] buf = dataString.getBytes(StandardCharsets.UTF_8);
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
                  COMPRESSOR_TYPE.DEFAULT_COMPRESSORDESCRIPTOR);
    } else {
      block =
          ClientCHKBlock.encode(
              buf,
              false,
              false,
              (short) -1,
              buf.length,
              COMPRESSOR_TYPE.DEFAULT_COMPRESSORDESCRIPTOR);
      insertKey = fetchKey = block.getClientKey();
      testKey = insertKey.getURI();
    }

    System.err.println();
    System.err.println("Created random test key " + testKey + " = " + fetchKey.getNodeKey(false));
    System.err.println();

    byte[] data = dataString.getBytes(StandardCharsets.UTF_8);
    LOG.debug("Decoded: " + new String(block.memoryDecode(), StandardCharsets.UTF_8));
    LOG.info("Insert Key: " + insertKey.getURI());
    LOG.info("Fetch Key: " + fetchKey.getURI());
    try {
      insertAttempts++;
      randomNode
          .getClientCore()
          .realPut(block.getBlock(), false, FORK_ON_CACHEABLE, false, false, REAL_TIME_FLAG);
      LOG.error("Inserted to " + node1);
    } catch (LowLevelPutException putEx) {
      LOG.error("Insert failed: " + putEx);
      System.err.println("Insert failed: " + putEx);
      return EXIT_INSERT_FAILED;
    }
    // Pick random node to request from
    int node2;
    do {
      node2 = random.nextInt(NUMBER_OF_NODES);
    } while (node2 == node1);
    Node fetchNode = nodes[node2];
    try {
      block = fetchNode.getClientCore().realGetKey(fetchKey, false, false, false, REAL_TIME_FLAG);
    } catch (LowLevelGetException e) {
      block = null;
    }
    if (block == null) {
      int percentSuccess = 100 * fetchSuccesses / insertAttempts;
      LOG.error("Fetch #" + requestNumber + " FAILED (" + percentSuccess + "%); from " + node2);
      System.err.println(
          "Fetch #" + requestNumber + " FAILED (" + percentSuccess + "%); from " + node2);
      requestsAvg.report(0.0);
    } else {
      byte[] results = block.memoryDecode();
      requestsAvg.report(1.0);
      if (Arrays.equals(results, data)) {
        fetchSuccesses++;
        int percentSuccess = 100 * fetchSuccesses / insertAttempts;
        LOG.error(
            "Fetch #"
                + requestNumber
                + " from node "
                + node2
                + " succeeded ("
                + percentSuccess
                + "%): "
                + new String(results));
        System.err.println(
            "Fetch #"
                + requestNumber
                + " succeeded ("
                + percentSuccess
                + "%): \""
                + new String(results)
                + '\"');
        if (fetchSuccesses == targetSuccesses) {
          System.err.println("Succeeded, " + targetSuccesses + " successful fetches");
          return 0;
        }
      } else {
        LOG.error("Returned invalid data!: " + new String(results));
        System.err.println("Returned invalid data!: " + new String(results));
        return EXIT_BAD_DATA;
      }
    }
    StringBuilder load = new StringBuilder("Running UIDs for nodes: ");
    int totalRunningUIDsAlt = 0;
    List<Long> runningUIDsList = new ArrayList<>();
    for (int i = 0; i < nodes.length; i++) {
      load.append(i);
      load.append(':');
      nodes[i].getTracker().addRunningUIDs(runningUIDsList);
      int runningUIDsAlt = nodes[i].getTracker().getTotalRunningUIDsAlt();
      totalRunningUIDsAlt += runningUIDsAlt;
      load.append(totalRunningUIDsAlt);
      if (i != nodes.length - 1) load.append(' ');
    }
    System.err.println(load);
    if (totalRunningUIDsAlt != 0)
      System.err.println("Still running UIDs (alt): " + totalRunningUIDsAlt);
    if (!runningUIDsList.isEmpty()) {
      System.err.println("List of running UIDs: " + Arrays.toString(runningUIDsList.toArray()));
    }
    return -1;
  }
}
