package network.crypta.node.simulator;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.InsertBlock;
import network.crypta.client.InsertException;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.NodeInitException;
import network.crypta.node.Version;
import network.crypta.runtime.bootstrap.NodeStarter.TestNodeParameters;
import network.crypta.runtime.bootstrap.NodeStarter;
import network.crypta.support.Logging;
import network.crypta.support.PooledExecutor;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

/**
 * Runs a long-horizon push/repull simulation between two test nodes.
 *
 * <p>This driver exercises the simulator by inserting a single key per day and then re-fetching
 * that key at exponentially increasing look-back intervals. It is intended for long-running,
 * low-volume validation of data persistence and retrieval behavior rather than throughput. The
 * typical call pattern is to run {@link #main(String[])} with a unique identifier, allow the first
 * node to seed and insert, park it, then start a second node to perform the repull sequence. The
 * test writes a single CSV line with timing measurements and exits the JVM with a status code that
 * reflects success or failure.
 *
 * <p>Notable invariants include using {@link #SEEDNODES_FILENAME} for bootstrap, a fixed test size
 * of {@link #TEST_SIZE} bytes, and deterministic port assignments for the two nodes. The driver
 * itself is single-threaded and not designed for concurrent reuse, although each node runs its own
 * internal threads while active. Trade-offs include long wall-clock runtime and the requirement to
 * rerun on subsequent days to accumulate historical samples.
 *
 * <ul>
 *   <li>Creates per-run storage directories and validates seednodes input.
 *   <li>Starts the primary node, inserts data, and records insert timing.
 *   <li>Starts the secondary node, performs repull fetches, and records timing.
 * </ul>
 *
 * @see LongTermTest
 * @see LongTermPushPullTest
 */
public class LongTermPushRepullTest extends LongTermTest {
  private static final int TEST_SIZE = 64 * 1024;

  private static final String SEEDNODES_FILENAME = "seednodes.fref";

  private static final int DARKNET_PORT1 = 5010;
  private static final int OPENNET_PORT1 = 5011;
  private static final int DARKNET_PORT2 = 5012;
  private static final int OPENNET_PORT2 = 5013;

  private static final int MAX_N = 8;

  private static final Logger LOG = LoggerFactory.getLogger(LongTermPushRepullTest.class);

  /**
   * Creates a test driver instance.
   *
   * <p>This class is normally used through its static {@link #main(String[])} entry point. The
   * explicit constructor exists only to satisfy doclint requirements and does not perform any
   * initialization beyond the implicit default constructor behavior. Creating an instance has no
   * side effects, opens no files, and allocates no test resources; it simply allows tooling to
   * attach constructor-level documentation in a consistent way.
   */
  public LongTermPushRepullTest() {
    // Intentionally empty: this test is driven via static entry points only.
  }

  /**
   * Runs the long-term push/repull test as a standalone JVM entry point.
   *
   * <p>The method validates that exactly one argument is provided, treats it as a unique identifier
   * for KSK URIs and the output CSV filename, and then executes the full test sequence. On failure,
   * it logs a diagnostic message, attempts to park any initialized nodes, writes whatever CSV data
   * is available, and exits with a non-zero status code. The method is not idempotent across days
   * because the generated URIs include the current date, so each run represents a single day's
   * sample.
   *
   * @param args command-line arguments; expects exactly one unique identifier string
   */
  public static void main(String[] args) {
    Logging.setLevel(LongTermPushRepullTest.class.getName(), Level.INFO);
    if (args.length != 1) {
      LOG.error("Usage: java freenet.node.simulator.LongTermPushPullTest <unique identifier>");
      System.exit(1);
    }
    String uid = args[0];

    List<String> csvLine = new ArrayList<>(3 + 2 * MAX_N);
    recordHeader(csvLine);

    int exitCode = 0;
    TestNodes nodes = new TestNodes();
    try {
      exitCode = runTest(uid, csvLine, nodes);
    } catch (Exception e) {
      if (e instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
      LOG.error("Long-term push/repull test failed", e);
      exitCode = EXIT_THREW_SOMETHING;
    } finally {
      parkNodes(nodes);

      File file = new File(uid + ".csv");
      writeToStatusLog(file, csvLine);

      System.exit(exitCode);
    }
  }

  private static void recordHeader(List<String> csvLine) {
    String todayText = dateFormat.format(today.getTime());
    LOG.warn("DATE:{}", todayText);
    csvLine.add(todayText);

    int buildNumber = Version.currentBuildNumber();
    LOG.warn("Version:{}", buildNumber);
    csvLine.add(String.valueOf(buildNumber));
  }

  /**
   * Runs the full push/repull sequence and appends timing data into the CSV line.
   *
   * @param uid unique identifier used for URIs and the output CSV filename
   * @param csvLine list collecting CSV field values for this run
   * @param nodes container for the two test nodes
   * @return exit code that reflects success or failure conditions
   * @throws IOException if I/O operations fail during setup or data generation
   * @throws NodeInitException if node initialization fails
   * @throws InterruptedException if the thread is interrupted while waiting for peers
   */
  private static int runTest(String uid, List<String> csvLine, TestNodes nodes)
      throws IOException, NodeInitException, InterruptedException {
    File dir = new File("longterm-push-pull-test-" + uid);
    FileUtil.removeAll(dir);
    RandomSource random = NodeStarter.globalTestInit(dir, false, Level.ERROR, "", false, null);
    File seednodes = ensureSeednodes();

    prepareSeednodes(dir, seednodes, DARKNET_PORT1);
    nodes.node = createNode(random, dir, DARKNET_PORT1, OPENNET_PORT1, true, 4L * 1024 * 1024);
    Logging.setRootLevel(Level.ERROR);

    nodes.node.start(true);
    if (failedToReachPeers(nodes.node, csvLine)) {
      return EXIT_FAILED_TARGET;
    }
    pushBlock(nodes.node, uid, csvLine);

    nodes.node.park();

    prepareSeednodes(dir, seednodes, DARKNET_PORT2);
    nodes.node2 = createNode(random, dir, DARKNET_PORT2, OPENNET_PORT2, false, 5L * 1024 * 1024);
    nodes.node2.start(true);
    if (failedToReachPeers(nodes.node2, csvLine)) {
      return EXIT_FAILED_TARGET;
    }
    pullBlocks(nodes.node2, uid, csvLine);

    return 0;
  }

  /**
   * Resolves the seednodes file and terminates the JVM if it cannot be used.
   *
   * @return the readable, non-empty seednodes file
   */
  private static File ensureSeednodes() {
    File seednodes = new File(SEEDNODES_FILENAME);
    if (!seednodes.exists() || seednodes.length() == 0 || !seednodes.canRead()) {
      LOG.error(
          "Unable to read {}, it doesn't exist, is unreadable, or is empty", SEEDNODES_FILENAME);
      System.exit(EXIT_NO_SEEDNODES);
    }
    return seednodes;
  }

  /**
   * Copies the seednodes file into the per-node directory layout.
   *
   * @param dir base test directory
   * @param seednodes seednodes file to copy
   * @param darknetPort node port used to choose the subdirectory
   * @throws IOException if the seednodes file cannot be read or written
   */
  private static void prepareSeednodes(File dir, File seednodes, int darknetPort)
      throws IOException {
    File innerDir = new File(dir, Integer.toString(darknetPort));
    if (!innerDir.mkdir() && !innerDir.isDirectory()) {
      throw new IOException("Failed to create seednodes directory: " + innerDir.getAbsolutePath());
    }
    try (FileInputStream fis = new FileInputStream(seednodes)) {
      FileUtil.writeTo(fis, new File(innerDir, SEEDNODES_FILENAME));
    }
  }

  /**
   * Builds and instantiates a test node using the common simulator configuration.
   *
   * @param random random source to seed the node
   * @param dir base directory for node storage
   * @param darknetPort darknet port to bind
   * @param opennetPort opennet port to bind
   * @param enableFoaf whether FOAF connections are enabled
   * @param storeSize size of the data store in bytes
   * @return a started {@link Node} instance configured for this test
   * @throws NodeInitException if the node cannot be initialized
   */
  private static Node createNode(
      RandomSource random,
      File dir,
      int darknetPort,
      int opennetPort,
      boolean enableFoaf,
      long storeSize)
      throws NodeInitException {
    TestNodeParameters params =
        TestNodeParameterFactory.create(
            dir,
            random,
            new PooledExecutor(),
            p -> {
              p.setPort(darknetPort);
              p.setOpennetPort(opennetPort);
              p.setMaxHTL(Node.DEFAULT_MAX_HTL);
              p.setThreadLimit(1000);
              p.setStoreSize(storeSize);
              p.setRamStore(true);
              p.setEnableSwapping(true);
              p.setEnableARKs(true);
              p.setEnableULPRs(true);
              p.setEnablePerNodeFailureTables(true);
              p.setEnableSwapQueueing(true);
              p.setEnablePacketCoalescing(true);
              p.setOutputBandwidthLimit(12 * 1024);
              p.setEnableFOAF(enableFoaf);
              p.setConnectToSeednodes(true);
            });
    return NodeStarter.createTestNode(params);
  }

  /**
   * Waits for a node to reach its target peer count and records the elapsed time.
   *
   * @param node node to monitor
   * @param csvLine list collecting CSV field values for this run
   * @return true if the node reaches the target, false on timeout
   * @throws InterruptedException if the thread is interrupted while waiting
   */
  private static boolean failedToReachPeers(Node node, List<String> csvLine)
      throws InterruptedException {
    long t1 = System.currentTimeMillis();
    boolean success = TestUtil.waitForNodes(node);
    if (success) {
      long t2 = System.currentTimeMillis();
      LOG.info("SEED-TIME:{}", t2 - t1);
      csvLine.add(String.valueOf(t2 - t1));
    }
    return !success;
  }

  /**
   * Inserts a single block for today's date and records the timing result.
   *
   * @param node node that performs the insert
   * @param uid unique identifier used for the KSK URI
   * @param csvLine list collecting CSV field values for this run
   * @throws IOException if temporary data generation fails
   */
  private static void pushBlock(Node node, String uid, List<String> csvLine) throws IOException {
    RandomAccessBucket data = randomData(node);
    try {
      HighLevelSimpleClient client =
          node.services().clientCore().makeClient((short) 0, false, false);
      FreenetURI uri = new FreenetURI("KSK@" + uid + "-" + dateFormat.format(today.getTime()));
      LOG.info("PUSHING {}", uri);

      try {
        InsertBlock block = new InsertBlock(data, new ClientMetadata(), uri);
        long t1 = System.currentTimeMillis();
        client.insert(block, false, null);
        long t2 = System.currentTimeMillis();

        LOG.info("PUSH-TIME-:{}", t2 - t1);
        csvLine.add(String.valueOf(t2 - t1));
      } catch (InsertException e) {
        LOG.error("Insert failed for {}", uri, e);
        csvLine.add("N/A");
      }
    } finally {
      data.free();
    }
  }

  /**
   * Fetches the block for today and for each earlier interval, recording timings.
   *
   * @param node node used to perform fetches
   * @param uid unique identifier used for the KSK URI
   * @param csvLine list collecting CSV field values for this run
   */
  private static void pullBlocks(Node node, String uid, List<String> csvLine) throws IOException {
    for (int i = 0; i <= MAX_N; i++) {
      HighLevelSimpleClient client =
          node.services().clientCore().makeClient((short) 0, false, false);
      Calendar targetDate = today.copyCalendar();
      targetDate.add(Calendar.DAY_OF_MONTH, -((1 << i) - 1));

      FreenetURI uri = new FreenetURI("KSK@" + uid + "-" + dateFormat.format(targetDate.getTime()));
      LOG.info("PULLING {}", uri);

      try {
        long t1 = System.currentTimeMillis();
        client.fetch(uri);
        long t2 = System.currentTimeMillis();

        LOG.info("PULL-TIME-{}:{}", i, t2 - t1);
        csvLine.add(String.valueOf(t2 - t1));
      } catch (FetchException e) {
        if (e.getMode() != FetchExceptionMode.ALL_DATA_NOT_FOUND
            && e.getMode() != FetchExceptionMode.DATA_NOT_FOUND) {
          LOG.warn("Fetch failed for {} with mode {}", uri, e.getMode(), e);
        }
        csvLine.add(FetchException.getShortMessage(e.getMode()));
      }
    }
  }

  /**
   * Attempts to park any initialized nodes, logging failures.
   *
   * @param nodes container with the test nodes
   */
  private static void parkNodes(TestNodes nodes) {
    parkNode(nodes.node, "primary");
    parkNode(nodes.node2, "secondary");
  }

  /**
   * Safely parks a node, restoring the interrupted flag if needed.
   *
   * @param node node to park
   * @param name logical name for log messages
   */
  private static void parkNode(Node node, String name) {
    if (node == null) {
      return;
    }
    try {
      node.park();
    } catch (Exception e) {
      LOG.warn("Failed to park {} node", name, e);
    }
  }

  /**
   * Creates a random bucket of test data of {@link #TEST_SIZE} bytes.
   *
   * @param node node used to allocate temporary storage and RNG
   * @return bucket filled with random data
   * @throws IOException if writing to the bucket fails
   */
  private static RandomAccessBucket randomData(Node node) throws IOException {
    RandomAccessBucket data =
        node.services().clientCore().getTempBucketFactory().makeBucket(TEST_SIZE);
    try (OutputStream os = data.getOutputStream()) {
      byte[] buf = new byte[4096];
      long written = 0;
      while (written < TEST_SIZE) {
        node.bootstrap().fastWeakRandom().nextBytes(buf);
        int toWrite = (int) Math.min(TEST_SIZE - written, buf.length);
        os.write(buf, 0, toWrite);
        written += toWrite;
      }
    }
    return data;
  }

  /** Container for the test nodes so they can be parked in a single cleanup path. */
  private static final class TestNodes {
    private Node node;
    private Node node2;
  }
}
