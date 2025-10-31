package network.crypta.node.simulator;

import static java.util.concurrent.TimeUnit.DAYS;

import java.io.File;
import java.nio.charset.StandardCharsets;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.node.LowLevelPutException;
import network.crypta.node.Node;
import network.crypta.node.NodeStarter;
import network.crypta.node.RequestStarter;
import network.crypta.support.*;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

/**
 * Test a busy, bandwidth limited network. Hopefully this should reveal any serious problems with
 * load limiting and block transfer.
 *
 * @author toad
 */
public class RealNodeBusyNetworkTest extends RealNodeRoutingTest {
  private static final Logger LOG = LoggerFactory.getLogger(RealNodeBusyNetworkTest.class);

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

  // static final int NUMBER_OF_NODES = 50;
  // static final short MAX_HTL = 10;

  static final int DARKNET_PORT_BASE = 5008;
  static final int DARKNET_PORT_END = DARKNET_PORT_BASE + NUMBER_OF_NODES;

  public static void main(String[] args) throws Exception {
    String name = "realNodeRequestInsertTest";
    File wd = new File(name);
    if (!FileUtil.removeAll(wd)) {
      System.err.println("Mass delete failed, test may not be accurate.");
      System.exit(EXIT_CANNOT_DELETE_OLD_DATA);
    }
    wd.mkdir();
    // NOTE: globalTestInit returns in ignored random source
    // NodeStarter.globalTestInit(name, false, LogLevel.ERROR,
    // "freenet.node.Location:normal,freenet.node.simulator.RealNode:minor,freenet.node.Insert:MINOR,freenet.node.Request:MINOR,freenet.node.Node:MINOR");
    // NodeStarter.globalTestInit(name, false, LogLevel.ERROR,
    // "freenet.node.Location:MINOR,freenet.io.comm:MINOR,freenet.node.NodeDispatcher:MINOR,freenet.node.simulator:MINOR,freenet.node.PeerManager:MINOR,freenet.node.RequestSender:MINOR");
    // NodeStarter.globalTestInit(name, false, LogLevel.ERROR,
    // "freenet.node.FNP:MINOR,freenet.node.Packet:MINOR,freenet.io.comm:MINOR,freenet.node.PeerNode:MINOR,freenet.node.DarknetPeerNode:MINOR");
    NodeStarter.globalTestInit(new File(name), false, Level.ERROR, "", true, null);
    System.out.println("Busy network test (inserts/retrieves in quantity/stress test)");
    System.out.println();
    DummyRandomSource random = new DummyRandomSource();
    // DiffieHellman.init(random);
    Node[] nodes = new Node[NUMBER_OF_NODES];
    LOG.info("Creating nodes...");
    PriorityAwareExecutor executor = new PooledExecutor();
    for (int i = 0; i < NUMBER_OF_NODES; i++) {
      NodeStarter.TestNodeParameters params = new NodeStarter.TestNodeParameters();
      params.setPort(DARKNET_PORT_BASE + i);
      params.setOpennetPort(0);
      params.setBaseDirectory(wd);
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
      LOG.info("Created node " + i);
    }

    // Now link them up
    makeKleinbergNetwork(
        nodes, START_WITH_IDEAL_LOCATIONS, DEGREE, FORCE_NEIGHBOUR_CONNECTIONS, random);

    LOG.info("Added random links");

    for (int i = 0; i < NUMBER_OF_NODES; i++) {
      nodes[i].start(false);
      System.err.println("Started node " + i + "/" + nodes.length);
    }

    waitForAllConnected(nodes);

    waitForPingAverage(0.95, nodes, random, MAX_PINGS, 1000);

    System.out.println();
    System.out.println("Ping average > 95%, lets do some inserts/requests");
    System.out.println();

    HighLevelSimpleClient[] clients = new HighLevelSimpleClient[nodes.length];
    for (int i = 0; i < clients.length; i++) {
      clients[i] =
          nodes[i]
              .getClientCore()
              .makeClient(RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS, false, false);
    }

    // Insert 100 keys into random nodes

    ClientCHK[] keys = new ClientCHK[INSERT_KEYS];

    String baseString = System.currentTimeMillis() + " ";
    for (int i = 0; i < INSERT_KEYS; i++) {
      System.err.println("Inserting " + i + " of " + INSERT_KEYS);
      int node1 = random.nextInt(NUMBER_OF_NODES);
      Node randomNode = nodes[node1];
      String dataString = baseString + i;
      byte[] data = dataString.getBytes(StandardCharsets.UTF_8);
      ClientCHKBlock b;
      b =
          ClientCHKBlock.encode(
              data, false, false, (short) -1, 0, COMPRESSOR_TYPE.DEFAULT_COMPRESSORDESCRIPTOR);
      CHKBlock block = b.getBlock();
      ClientCHK chk = b.getClientKey();
      byte[] encData = block.getData();
      byte[] encHeaders = block.getHeaders();
      ClientCHKBlock newBlock = new ClientCHKBlock(encData, encHeaders, chk, true);
      keys[i] = chk;
      LOG.debug("Decoded: " + new String(newBlock.memoryDecode(), StandardCharsets.UTF_8));
      LOG.info("CHK: " + chk.getURI());
      LOG.debug("Headers: " + HexUtil.bytesToHex(block.getHeaders()));
      // Insert it.
      try {
        randomNode
            .getClientCore()
            .realPut(block, false, FORK_ON_CACHEABLE, false, false, REAL_TIME_FLAG);
        LOG.error("Inserted to " + node1);
        LOG.debug(
            "Data: " + Fields.hashCode(encData) + ", Headers: " + Fields.hashCode(encHeaders));
      } catch (LowLevelPutException putEx) {
        LOG.error("Insert failed: " + putEx);
        System.err.println("Insert failed: " + putEx);
        System.exit(EXIT_INSERT_FAILED);
      }
    }

    // Now queue requests for each key on every node.
    for (int i = 0; i < INSERT_KEYS; i++) {
      ClientCHK key = keys[i];
      System.err.println("Queueing requests for " + i + " of " + INSERT_KEYS);
      for (int j = 0; j < nodes.length; j++) {
        clients[j].prefetch(key.getURI(), DAYS.toMillis(1), 32768, null);
      }
      long totalRunningRequests = 0;
      for (int j = 0; j < nodes.length; j++) {
        totalRunningRequests += nodes[j].getClientCore().countQueuedRequests();
      }
      System.err.println("Running requests: " + totalRunningRequests);
    }

    // Now wait until finished. How???

    while (true) {
      long totalRunningRequests = 0;
      for (int i = 0; i < nodes.length; i++) {
        totalRunningRequests += nodes[i].getClientCore().countQueuedRequests();
      }
      System.err.println("Running requests: " + totalRunningRequests);
      if (totalRunningRequests == 0) break;
      Thread.sleep(1000);
    }
    System.exit(0);
  }
}
