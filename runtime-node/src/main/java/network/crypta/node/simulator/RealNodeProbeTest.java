package network.crypta.node.simulator;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.text.NumberFormat;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.SubConfig;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.node.Node;
import network.crypta.node.NodeInitException;
import network.crypta.node.probe.Error;
import network.crypta.node.probe.Listener;
import network.crypta.node.probe.Probe;
import network.crypta.node.probe.Type;
import network.crypta.runtime.bootstrap.NodeStarter.TestNodeParameters;
import network.crypta.runtime.bootstrap.NodeStarter;
import network.crypta.support.PooledExecutor;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

/**
 * Interactive harness that builds a real-node mesh and sends probes from selected peers.
 *
 * <p>This class spins up a fixed-size test network, waits for routing to settle, and then provides
 * a console-driven menu for executing probe types from a chosen node. It is intended for manual
 * diagnostics and exploratory checks where you want realistic routing behavior but also need to
 * control probe selection and HTL values. The setup uses deterministic random seeds to keep the
 * topology and probe routing comparable across runs, while still exercising real routing logic
 * rather than simulator stubs.
 *
 * <p>The lifecycle is linear: create nodes, link them, start them, optionally run a small insert
 * test, and then enter the probe menu loop until the user exits. The process ends via {@link
 * System#exit(int)} because background nodes continue running otherwise. All interaction occurs on
 * the main thread; node activity is handled by each node's internal executors. This class is not
 * thread-safe and is meant to be run as a standalone tool.
 *
 * <ul>
 *   <li>Builds a deterministic mesh using {@link RealNodeRoutingTest} helpers.
 *   <li>Provides a menu for {@link Probe} types such as bandwidth, uptime, and link lengths.
 *   <li>Allows toggling probe options on the active node via configuration updates.
 * </ul>
 *
 * @see RealNodeRoutingTest
 * @see Probe
 * @see Type
 */
public class RealNodeProbeTest extends RealNodeRoutingTest {
  private static final Logger LOG = LoggerFactory.getLogger(RealNodeProbeTest.class);

  /**
   * Creates the probe harness with default settings.
   *
   * <p>Construction performs no setup work; all runtime initialization happens in {@link #main()}
   * when the harness is executed as a standalone tool.
   */
  public RealNodeProbeTest() {
    // Intentionally empty; this harness is executed via the static main entry point.
  }

  static final int NUMBER_OF_NODES = 100;
  static final int DEGREE = 10;
  static final short MAX_HTL = (short) 5;
  static final boolean START_WITH_IDEAL_LOCATIONS = true;
  static final boolean FORCE_NEIGHBOUR_CONNECTIONS = true;
  static final boolean ENABLE_SWAPPING = false;
  static final boolean ENABLE_SWAP_QUEUEING = false;
  static final boolean ENABLE_FOAF = true;
  static final int MAX_PINGS = 2000;
  static final int OUTPUT_BANDWIDTH_LIMIT = 0; // Can be useful to set this for some tests.
  private static final boolean DO_INSERT_TEST = true;

  /**
   * The first port assigned to probe-test darknet nodes, starting after the routing-test range.
   *
   * <p>The value is derived from {@link RealNodeRoutingTest#DARKNET_PORT_END} to avoid overlaps
   * between the two harnesses. It is constant for a process run and is used to map node indexes to
   * deterministic port assignments for repeatable testing.
   */
  public static final int DARKNET_PORT_BASE = RealNodeRoutingTest.DARKNET_PORT_END;

  /**
   * Exclusive upper bound for ports reserved by this probe harness.
   *
   * <p>The range covers {@link #NUMBER_OF_NODES} ports beginning at {@link #DARKNET_PORT_BASE}. It
   * is used for reporting and capacity planning rather than for dynamic allocation; changing {@link
   * #NUMBER_OF_NODES} changes this bound accordingly.
   */
  public static final int DARKNET_PORT_END = DARKNET_PORT_BASE + NUMBER_OF_NODES;

  /**
   * Runs the probe harness from the command line and starts the interactive menu.
   *
   * <p>The method creates a fresh working directory, initializes deterministic randomness,
   * constructs and links nodes, and optionally runs a small insert/request warm-up. It then enters
   * a console menu that lets you choose the probe type, source node, and HTL, and keeps running
   * until input is closed or a non-menu option is entered. Because nodes remain active on
   * background threads, the program terminates via {@link System#exit(int)} when the menu loop
   * ends. This entry point is intended for manual, developer-driven experimentation.
   *
   * @throws NodeInitException if any node fails during initialization or startup
   * @throws InterruptedException if waiting for connectivity or insert completion is interrupted
   */
  public static void main() throws NodeInitException, InterruptedException {
    logIntro();
    String dir = "realNodeProbeTest";
    File baseDirectory = prepareBaseDirectory(dir);
    if (baseDirectory == null) {
      return;
    }
    DummyRandomSource random = new DummyRandomSource(3142);
    NodeStarter.globalTestInit(baseDirectory, false, Level.ERROR, "", true, random);
    Node[] nodes = createNodes(baseDirectory, random);
    linkNodes(nodes, random);
    startNodes(nodes);
    logInsertTestHeader();
    if (DO_INSERT_TEST) {
      runInsertTest(nodes, random);
    }
    Listener print = createListener();
    runProbeMenu(nodes, random, print);
  }

  private static void logIntro() {
    LOG.info("Probe test using real nodes:");
  }

  private static File prepareBaseDirectory(String dir) {
    File baseDirectory = new File(dir);
    if (!FileUtil.removeAll(baseDirectory)) {
      LOG.error("Mass delete failed, test may not be accurate.");
      System.exit(EXIT_CANNOT_DELETE_OLD_DATA);
    }
    if (!baseDirectory.mkdir()) {
      LOG.error("Unable to create test directory \"{}\".", dir);
      return null;
    }
    return baseDirectory;
  }

  private static Node[] createNodes(File baseDirectory, DummyRandomSource random)
      throws NodeInitException {
    Node[] nodes = new Node[NUMBER_OF_NODES];
    LOG.info("Creating nodes...");
    PriorityAwareExecutor executor = new PooledExecutor();
    for (int i = 0; i < NUMBER_OF_NODES; i++) {
      LOG.info("Creating node {}", i);
      nodes[i] = createNode(baseDirectory, random, executor, i);
      LOG.info("Created node {}", i);
    }
    LOG.info("Created {} nodes", NUMBER_OF_NODES);
    return nodes;
  }

  private static Node createNode(
      File baseDirectory, DummyRandomSource random, PriorityAwareExecutor executor, int index)
      throws NodeInitException {
    int port = DARKNET_PORT_BASE + index;
    boolean enableFcp = index == 0;
    TestNodeParameters params =
        TestNodeParameterFactory.create(
            baseDirectory, random, executor, p -> configureNodeParameters(p, port, enableFcp));
    return NodeStarter.createTestNode(params);
  }

  private static void configureNodeParameters(
      TestNodeParameters params, int port, boolean enableFcp) {
    params.setPort(port);
    params.setOpennetPort(0);
    params.setDisableProbabilisticHTLs(true);
    params.setMaxHTL(MAX_HTL);
    params.setDropProb(0);
    params.setThreadLimit(500 * NUMBER_OF_NODES);
    params.setStoreSize(256L * 1024);
    params.setRamStore(true);
    params.setEnableSwapping(ENABLE_SWAPPING);
    params.setEnableARKs(false);
    params.setEnableULPRs(false);
    params.setEnablePerNodeFailureTables(false);
    params.setEnableSwapQueueing(ENABLE_SWAP_QUEUEING);
    params.setEnablePacketCoalescing(true);
    params.setOutputBandwidthLimit(OUTPUT_BANDWIDTH_LIMIT);
    params.setEnableFOAF(ENABLE_FOAF);
    params.setConnectToSeednodes(false);
    params.setLongPingTimes(true);
    params.setUseSlashdotCache(false);
    params.setEnableFCP(enableFcp);
  }

  private static void linkNodes(Node[] nodes, DummyRandomSource random) {
    makeKleinbergNetwork(
        nodes, START_WITH_IDEAL_LOCATIONS, DEGREE, FORCE_NEIGHBOUR_CONNECTIONS, random);
    LOG.info("Added random links");
  }

  private static void startNodes(Node[] nodes) throws NodeInitException {
    for (int i = 0; i < NUMBER_OF_NODES; i++) {
      LOG.info("Starting node {}", i);
      nodes[i].start(false);
    }
  }

  private static void logInsertTestHeader() {
    LOG.info("Ping average > 95%, lets do some inserts/requests");
  }

  private static void runInsertTest(Node[] nodes, DummyRandomSource random)
      throws InterruptedException {
    waitForPingAverage(0.5, nodes, new DummyRandomSource(3143), MAX_PINGS, 1000);
    RealNodeRequestInsertTest tester = new RealNodeRequestInsertTest(nodes, random, 10);
    waitForAllConnected(nodes);
    boolean completed = false;
    while (!completed) {
      try {
        waitForAllConnected(nodes);
        int status = tester.insertRequestTest();
        if (status != -1) {
          LOG.info("Insert test completed with status {}", status);
          completed = true;
        }
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw e;
      } catch (Exception e) {
        LOG.error("Caught", e);
      }
    }
  }

  private static Listener createListener() {
    NumberFormat nf = NumberFormat.getInstance();
    return new Listener() {
      @Override
      public void onError(Error error, Byte code, boolean local) {
        StringBuilder message = new StringBuilder("Probe error: ").append(error.name());
        if (local) {
          message.append(" (local)");
        }
        if (code != null) {
          message.append(" (").append(code).append(')');
        }
        LOG.warn(message.toString());
      }

      @Override
      public void onRefused() {
        LOG.info("Probe refused.");
      }

      @Override
      public void onOutputBandwidth(float outputBandwidth) {
        LOG.info("Probe got bandwidth limit {} KiB per second.", nf.format(outputBandwidth));
      }

      @Override
      public void onBuild(int build) {
        LOG.info("Probe got build {}.", build);
      }

      @Override
      public void onIdentifier(long identifier, byte uptimePercentage) {
        LOG.info(
            "Probe got identifier {} with uptime percentage {}.", identifier, uptimePercentage);
      }

      @Override
      public void onLinkLengths(float[] linkLengths) {
        StringBuilder message = new StringBuilder("Probe got link lengths: { ");
        for (float length : linkLengths) {
          message.append(length).append(' ');
        }
        message.append("}.");
        LOG.info(message.toString());
      }

      @Override
      public void onLocation(float location) {
        LOG.info("Probe got location {}.", location);
      }

      @Override
      public void onStoreSize(float storeSize) {
        LOG.info("Probe got store size {} GiB.", nf.format(storeSize));
      }

      @Override
      public void onUptime(float uptimePercentage) {
        LOG.info("Probe got uptime {}%.", nf.format(uptimePercentage));
      }

      @Override
      public void onRejectStats(byte[] stats) {
        LOG.info("Probe got reject stats:");
        LOG.info("CHK request: {}", stats[0]);
        LOG.info("SSK request: {}", stats[1]);
        LOG.info("CHK insert: {}", stats[2]);
        LOG.info("SSK insert: {}", stats[3]);
      }

      @Override
      public void onOverallBulkOutputCapacity(
          byte bandwidthClassForCapacityUsage, float outputBulkCapacityUsed) {
        LOG.info(
            "Probe got output capacity {}% (bandwidth class {})",
            nf.format(outputBulkCapacityUsed), bandwidthClassForCapacityUsage);
      }
    };
  }

  private static void runProbeMenu(Node[] nodes, DummyRandomSource random, Listener print) {
    Type[] types = {
      Type.BANDWIDTH,
      Type.BUILD,
      Type.IDENTIFIER,
      Type.LINK_LENGTHS,
      Type.LOCATION,
      Type.STORE_SIZE,
      Type.UPTIME_48H,
      Type.UPTIME_7D,
      Type.REJECT_STATS,
      Type.OVERALL_BULK_OUTPUT_CAPACITY_USAGE
    };

    ProbeMenuState state = new ProbeMenuState();
    BufferedReader reader = createReader();
    boolean running = true;
    while (running) {
      logMenu(state.index, state.htl);
      running = handleMenuInput(reader, state, nodes, random, print, types);
    }
    // Return isn't enough to exit: the nodes are still in the background.
    System.exit(0);
  }

  private static BufferedReader createReader() {
    return new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
  }

  private static void logMenu(int index, byte htl) {
    LOG.info("Sending probes from node {} with HTL {}.", index, htl);
    LOG.info("0) BANDWIDTH");
    LOG.info("1) BUILD");
    LOG.info("2) IDENTIFIER");
    LOG.info("3) LINK_LENGTHS");
    LOG.info("4) LOCATION");
    LOG.info("5) STORE_SIZE");
    LOG.info("6) UPTIME 48-hour");
    LOG.info("7) UPTIME 7-day");
    LOG.info("8) REJECT_STATS");
    LOG.info("9) OVERALL_BULK_OUTPUT_CAPACITY_USAGE");
    LOG.info("10) Pick another node");
    LOG.info("11) Pick another HTL");
    LOG.info("12) Pick current node's refusals");
    LOG.info("Anything else to exit.");
    LOG.info("Select:");
  }

  private static boolean handleMenuInput(
      BufferedReader reader,
      ProbeMenuState state,
      Node[] nodes,
      DummyRandomSource random,
      Listener print,
      Type[] types) {
    String line = readLine(reader);
    if (line == null) {
      LOG.info("Input closed, exiting.");
      return false;
    }
    int selection;
    try {
      selection = Integer.parseInt(line);
    } catch (NumberFormatException e) {
      LOG.error("Invalid selection, exiting.", e);
      return false;
    }
    if (selection < 0 || selection > types.length + 2) {
      LOG.info("Exiting.");
      return false;
    }
    try {
      applySelection(selection, reader, state, nodes, random, print, types);
    } catch (IOException e) {
      LOG.error("Failed to read input, exiting.", e);
      return false;
    } catch (InvalidConfigValueException e) {
      LOG.error("Invalid configuration value, exiting.", e);
      return false;
    } catch (NodeNeedRestartException e) {
      LOG.error("Node requires restart after configuration change, exiting.", e);
      return false;
    }
    return true;
  }

  private static String readLine(BufferedReader reader) {
    try {
      return reader.readLine();
    } catch (IOException e) {
      LOG.error("Failed to read input, exiting.", e);
      return null;
    }
  }

  private static void applySelection(
      int selection,
      BufferedReader reader,
      ProbeMenuState state,
      Node[] nodes,
      DummyRandomSource random,
      Listener print,
      Type[] types)
      throws IOException, InvalidConfigValueException, NodeNeedRestartException {
    if (selection == types.length) {
      state.index = readNodeIndex(reader);
      return;
    }
    if (selection == types.length + 1) {
      state.htl = readHtl(reader);
      return;
    }
    if (selection == types.length + 2) {
      updateProbeOptions(nodes[state.index], reader);
      return;
    }
    nodes[state.index].network().startProbe(state.htl, random.nextLong(), types[selection], print);
  }

  private static int readNodeIndex(BufferedReader reader) throws IOException {
    LOG.info("Enter new node index ([0-{}]):", NUMBER_OF_NODES - 1);
    return Integer.parseInt(reader.readLine());
  }

  private static byte readHtl(BufferedReader reader) throws IOException {
    LOG.info("Enter new HTL:");
    return Byte.parseByte(reader.readLine());
  }

  private static void updateProbeOptions(Node node, BufferedReader reader)
      throws IOException, InvalidConfigValueException, NodeNeedRestartException {
    SubConfig nodeConfig = node.getConfig().get("node");
    String[] options = {
      "probeBandwidth",
      "probeBuild",
      "probeIdentifier",
      "probeLinkLengths",
      "probeLinkLengths",
      "probeUptime"
    };
    for (String option : options) {
      LOG.info("{}:", option);
      nodeConfig.set(option, Boolean.parseBoolean(reader.readLine()));
    }
  }

  private static final class ProbeMenuState {
    private int index = 0;
    private byte htl = Probe.MAX_HTL;
  }
}
