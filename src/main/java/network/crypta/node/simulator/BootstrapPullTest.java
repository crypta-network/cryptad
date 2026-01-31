package network.crypta.node.simulator;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import network.crypta.client.FetchException;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.NodeInitException;
import network.crypta.node.NodeStarter;
import network.crypta.node.NodeStarter.TestNodeParameters;
import network.crypta.support.PooledExecutor;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.TimeUtil;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.LineReadingInputStream;
import network.crypta.support.math.MersenneTwister;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

/**
 * Inserts a random data block into an existing node via FCP, then bootstraps a fresh node and
 * fetches the inserted key from that node.
 *
 * <p>This class is a small end-to-end simulator for validating that a node can bootstrap from
 * seednodes, join the network, and successfully retrieve content that was inserted elsewhere. It
 * performs two distinct roles in one process: it first acts as an FCP client that inserts a CHK
 * into the locally running “insertor” node (expected to be listening on the standard FCP port),
 * then it starts a second node instance in a temporary directory and uses that node’s client API to
 * fetch the same key.
 *
 * <p>The test is intentionally opinionated and self-contained: it creates its own random payload
 * (size controlled by {@link #setTestSize(int)}), copies {@value #SEEDNODES_FILE_NAME} into the new
 * node’s directory, waits for connectivity, and exits with a stable non-zero code when a specific
 * phase fails. It is designed as a manual or scripted smoke test rather than a JUnit test and is
 * not intended to be thread-safe or reusable across multiple runs within the same JVM.
 *
 * <ul>
 *   <li><b>Responsibilities:</b> generate data, insert via FCP, start a second node, fetch via
 *       {@link HighLevelSimpleClient}.
 *   <li><b>Notable behaviors:</b> uses {@code System.exit(int)} to signal outcomes and cleans the
 *       working directory on startup.
 * </ul>
 *
 * @author Matthew Toseland &lt;toad@amphibian.dyndns.org&gt; (0xE43DA450)
 */
public class BootstrapPullTest {

  private static final Logger logger = LoggerFactory.getLogger(BootstrapPullTest.class);

  private static final String SEEDNODES_FILE_NAME = "seednodes.fref";

  private static int testSize = 1024 * 1024;

  /**
   * Exit code used when the seednodes file is missing, empty, or unreadable.
   *
   * <p>This is treated as a configuration or environment error: without seednodes the newly started
   * node cannot bootstrap into the network, so the test exits early rather than attempting to
   * recover.
   */
  public static final int EXIT_NO_SEEDNODES = 257;

  /**
   * Exit code used when the bootstrapped node fails to reach a usable connected state.
   *
   * <p>The program waits for the node to connect (see {@code TestUtil.waitForNodes(...)}). When
   * that wait times out, the node is parked and the process terminates with this code so callers
   * can distinguish connectivity failures from insertion or fetch failures.
   */
  public static final int EXIT_FAILED_TARGET = 258;

  /**
   * Exit code used when inserting the test payload into the established node fails.
   *
   * <p>This indicates that the insertor node did not report a successful CHK insert via FCP, either
   * because the put failed or because a protocol-level error was encountered.
   */
  public static final int EXIT_INSERT_FAILED = 259;

  /**
   * Exit code used when the bootstrapped node fails to fetch the inserted key.
   *
   * <p>This indicates that the second node started successfully but could not retrieve the CHK via
   * its client API, which is a stronger signal than a bootstrap failure because the node is already
   * up and running.
   */
  public static final int EXIT_FETCH_FAILED = 260;

  /**
   * Exit code used when the insertor node does not speak the expected FCP protocol.
   *
   * <p>This is used for early protocol handshake failures, such as missing {@code NodeHello}, as
   * well as for explicit {@code ProtocolError} responses while performing the put.
   */
  public static final int EXIT_INSERTER_PROBLEM = 261;

  /**
   * Exit code used when the program throws unexpectedly during the run.
   *
   * <p>This is a catch-all for exceptions other than the targeted error cases that have their own
   * exit codes. The test attempts to park the second node (if it exists) before terminating.
   */
  public static final int EXIT_THREW_SOMETHING = 262;

  /**
   * Darknet port used for the bootstrapped test node started by {@link #main(String[])}.
   *
   * <p>This value is passed into the {@link NodeStarter.TestNodeParameters} and also forms part of
   * the on-disk directory layout for the second node under {@code bootstrap-pull-test/}.
   */
  public static final int DARKNET_PORT = 5000;

  /**
   * Opennet port used for the bootstrapped test node started by {@link #main(String[])}.
   *
   * <p>This value is configured alongside {@link #DARKNET_PORT} and is chosen to be stable so the
   * simulator behaves predictably across runs when used in automation.
   */
  public static final int OPENNET_PORT = 5001;

  /**
   * Creates a new simulator instance.
   *
   * <p>Instances are not required for typical usage because {@link #main(String[])} is the primary
   * entry point. This constructor exists to document the default, implicit no-arg constructor to
   * satisfy doclint when building API documentation.
   */
  public BootstrapPullTest() {
    // Intentionally empty: this type is typically used via the static main entry point.
  }

  /**
   * Returns the size of the random payload inserted and fetched by this simulator, in bytes.
   *
   * <p>The size influences both the temporary file that is generated and the {@code DataLength}
   * advertised during the FCP {@code ClientPut}. Callers may override this value before invoking
   * {@link #main(String[])} to exercise different payload sizes. The value is stored in a static
   * field and is shared process-wide.
   *
   * @return the configured test payload size in bytes for the current JVM process
   */
  public static int getTestSize() {
    return testSize;
  }

  /**
   * Sets the size of the random payload inserted and fetched by this simulator, in bytes.
   *
   * <p>The value is used as an upper bound when generating the temporary payload file and as the
   * exact byte count to stream over the FCP socket during insertion. This setter is not
   * synchronized and is intended to be called during single-threaded setup before {@link
   * #main(String[])} begins.
   *
   * @param newTestSize the payload size in bytes; must be non-negative and fit in memory limits
   *     implied by the surrounding environment
   */
  public static void setTestSize(int newTestSize) {
    testSize = newTestSize;
  }

  private static void ensureDirectoryExists(File directory) {
    if (directory.isDirectory()) {
      return;
    }
    if (directory.exists()) {
      logger.warn("Expected directory but found non-directory path: {}", directory);
      return;
    }
    if (!directory.mkdirs()) {
      logger.warn("Failed to create directory: {}", directory);
    }
  }

  /**
   * Runs the bootstrap-and-fetch simulator as a standalone program.
   *
   * <p>The run performs a fixed sequence: it wipes the working directory, initializes randomness,
   * ensures seednodes are available, generates a random data file, inserts that file into an
   * already-running local node via FCP, then starts a second node instance and fetches the inserted
   * key through that node’s {@link HighLevelSimpleClient}. The process exits with a stable code for
   * the most common failure modes so it can be used in scripts.
   *
   * @param args optional command-line arguments; if present, {@code args[0]} is forwarded as an IP
   *     address override for the bootstrapped node’s configuration
   * @throws IOException if the simulator fails to read/write seednodes or test data from disk
   * @throws NodeInitException if the bootstrapped node cannot be initialized from the provided
   *     parameters
   * @throws InterruptedException if the current thread is interrupted while waiting for bootstrap
   *     or while performing blocking operations
   */
  public static void main(String[] args)
      throws IOException, NodeInitException, InterruptedException {
    Node secondNode = null;
    try {
      String ipOverride = null;
      if (args.length > 0) ipOverride = args[0];
      final String ipOverrideFinal = ipOverride;
      File dir = new File("bootstrap-pull-test");
      FileUtil.removeAll(dir);
      RandomSource random = NodeStarter.globalTestInit(dir, false, Level.ERROR, "", false, null);
      byte[] seed = new byte[64];
      random.nextBytes(seed);
      MersenneTwister fastRandom = MersenneTwister.createUnsynchronized(seed);
      File seednodes = new File(SEEDNODES_FILE_NAME);
      if (!seednodes.exists() || seednodes.length() == 0 || !seednodes.canRead()) {
        logger.error(
            "Unable to read {}, it doesn't exist, is empty, or is not readable",
            SEEDNODES_FILE_NAME);
        System.exit(EXIT_NO_SEEDNODES);
      }
      File secondInnerDir = new File(dir, Integer.toString(DARKNET_PORT));
      ensureDirectoryExists(secondInnerDir);
      try (FileInputStream fis = new FileInputStream(seednodes)) {
        FileUtil.writeTo(fis, new File(secondInnerDir, SEEDNODES_FILE_NAME));
      }

      // Create the test data
      logger.info("Creating test data.");
      File dataFile = File.createTempFile("testdata", ".tmp", dir);
      byte[] buf = new byte[4096];
      int testSize = getTestSize();
      try (OutputStream os = new FileOutputStream(dataFile)) {
        long written = 0;
        while (written < testSize) {
          fastRandom.nextBytes(buf);
          int toWrite = (int) Math.min(testSize - written, buf.length);
          os.write(buf, 0, toWrite);
          written += toWrite;
        }
      }

      // Insert it to the established node.
      logger.info("Inserting test data to an established node.");
      FreenetURI uri = insertData(dataFile);

      // Bootstrap a second node.
      ensureDirectoryExists(secondInnerDir);
      try (FileInputStream fis = new FileInputStream(seednodes)) {
        FileUtil.writeTo(fis, new File(secondInnerDir, SEEDNODES_FILE_NAME));
      }
      PooledExecutor executor = new PooledExecutor();
      TestNodeParameters params =
          TestNodeParameterFactory.create(
              dir,
              random,
              executor,
              p -> {
                p.setPort(DARKNET_PORT);
                p.setOpennetPort(OPENNET_PORT);
                p.setMaxHTL(Node.DEFAULT_MAX_HTL);
                p.setThreadLimit(1000);
                p.setStoreSize(5L * 1024 * 1024);
                p.setRamStore(true);
                p.setEnableSwapping(true);
                p.setEnableARKs(true);
                p.setEnableULPRs(true);
                p.setEnablePerNodeFailureTables(true);
                p.setEnableSwapQueueing(true);
                p.setEnablePacketCoalescing(true);
                p.setOutputBandwidthLimit(12 * 1024);
                p.setConnectToSeednodes(true);
                p.setIpAddressOverride(ipOverrideFinal);
              });
      secondNode = NodeStarter.createTestNode(params);
      secondNode.start(true);

      if (!TestUtil.waitForNodes(secondNode)) {
        secondNode.park();
        System.exit(EXIT_FAILED_TARGET);
      }

      // Fetch the data
      long startFetchTime = System.currentTimeMillis();
      HighLevelSimpleClient client =
          secondNode.services().clientCore().makeClient((short) 0, false, false);
      fetchOrExit(client, uri);
      long endFetchTime = System.currentTimeMillis();
      long fetchDurationMs = endFetchTime - startFetchTime;
      if (logger.isInfoEnabled()) {
        logger.info(
            "RESULT: Fetch took {}ms ({}) of {} .",
            fetchDurationMs,
            TimeUtil.formatTime(fetchDurationMs),
            uri);
      }
      secondNode.park();
      System.exit(0);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      logAndExit(secondNode, e);
    } catch (Exception e) {
      logAndExit(secondNode, e);
    }
  }

  private static void fetchOrExit(HighLevelSimpleClient client, FreenetURI uri) {
    try {
      client.fetch(uri);
    } catch (FetchException e) {
      logger.error("FETCH FAILED", e);
      System.exit(EXIT_FETCH_FAILED);
    }
  }

  private static void logAndExit(Node secondNode, Throwable t) {
    logger.error("CAUGHT", t);
    parkQuietly(secondNode);
    System.exit(EXIT_THREW_SOMETHING);
  }

  private static void parkQuietly(Node node) {
    if (node == null) {
      return;
    }
    try {
      node.park();
    } catch (Exception e) {
      logger.warn("Failed to park node during shutdown", e);
    }
  }

  private static FreenetURI insertData(File dataFile) throws IOException {
    long startInsertTime = System.currentTimeMillis();
    InetAddress localhost = InetAddress.getLoopbackAddress();
    try (Socket sock = new Socket(localhost, 9481);
        OutputStream sockOS = sock.getOutputStream();
        InputStream sockIS = sock.getInputStream();
        OutputStreamWriter osw = new OutputStreamWriter(sockOS, StandardCharsets.UTF_8);
        InputStream is = new FileInputStream(dataFile)) {
      logger.info("Connected to node.");
      LineReadingInputStream lis = new LineReadingInputStream(sockIS);
      osw.write(
          "ClientHello\nExpectedVersion=0.7\nName=BootstrapPullTest-"
              + System.currentTimeMillis()
              + "\nEnd\n");
      osw.flush();
      String name = lis.readLine(65536, 128, true);
      new SimpleFieldSet(lis, 65536, 128, true, false, true);
      if (!name.equals("NodeHello")) {
        logger.error("No NodeHello from insertor node!");
        System.exit(EXIT_INSERTER_PROBLEM);
      }
      logger.info("Connected to {}", sock);
      osw.write(
          "ClientPut\n"
              + "Identifier=test-insert\n"
              + "URI=CHK@\n"
              + "Verbosity=1023\n"
              + "UploadFrom=direct\n"
              + "MaxRetries=-1\n"
              + "DataLength="
              + getTestSize()
              + "\nData\n");
      osw.flush();
      FileUtil.copy(is, sockOS, getTestSize());
      logger.info("Sent data");
      while (true) {
        name = lis.readLine(65536, 128, true);
        SimpleFieldSet fs = new SimpleFieldSet(lis, 65536, 128, true, false, true);
        if (logger.isInfoEnabled()) {
          logger.info("Got FCP message:\n{}", name);
          logger.info("{}", fs.toOrderedString());
        }
        switch (name) {
          case "ProtocolError" -> {
            logger.error("Protocol error when inserting data.");
            System.exit(EXIT_INSERTER_PROBLEM);
          }
          case "PutFailed" -> {
            logger.error("Insert failed");
            System.exit(EXIT_INSERT_FAILED);
          }
          case "PutSuccessful" -> {
            long endInsertTime = System.currentTimeMillis();
            FreenetURI uri = new FreenetURI(fs.get("URI"));
            long insertDurationMs = endInsertTime - startInsertTime;
            if (logger.isInfoEnabled()) {
              logger.info(
                  "RESULT: Insert took {}ms ({}) to {} .",
                  insertDurationMs,
                  TimeUtil.formatTime(insertDurationMs),
                  uri);
            }
            return uri;
          }
          default -> logger.debug("Ignoring unexpected FCP message: {}", name);
        }
      }
    }
  }
}
