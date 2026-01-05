package network.crypta.node.simulator;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import network.crypta.client.*;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.NodeInitException;
import network.crypta.node.NodeStarter;
import network.crypta.node.NodeStarter.TestNodeParameters;
import network.crypta.support.Logging;
import network.crypta.support.PooledExecutor;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.TimeUtil;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.FileUtil;
import org.slf4j.event.Level;

/**
 * Standalone bootstrap push/pull smoke test for the simulator.
 *
 * <p>This class is a small, self-contained executable (it has a {@link #main(String[])} entry
 * point) that exercises a common bootstrap workflow: start a first node, insert a small random
 * payload, then start a second node from the same seednodes and verify that the payload can be
 * fetched.
 *
 * <p>The run is intentionally stateful and file-system backed. It creates a working directory named
 * {@code bootstrap-push-pull-test} in the current directory, deletes any previous contents, and
 * then creates per-node subdirectories keyed by port. The {@code seednodes.fref} file is required
 * and is copied into each node directory before startup. Progress and timing are written to {@code
 * stderr}, while internal node logging is reduced once the first node is started.
 *
 * <p><b>Notable behaviors</b>
 *
 * <ul>
 *   <li>Uses {@link System#exit(int)} with stable, tool-specific exit codes for common failure
 *       modes.
 *   <li>Runs as a single JVM process; node internals may spawn worker threads as part of normal
 *       operation.
 *   <li>Not intended as a library API; it is a diagnostic harness for manual runs and automation.
 * </ul>
 *
 * @see NodeStarter#createTestNode(TestNodeParameters)
 * @see TestUtil#waitForNodes(Node)
 */
public class BootstrapPushPullTest {
  private static final String CAUGHT_PREFIX = "CAUGHT: ";
  private static final String SEEDNODES_FILE_NAME = "seednodes.fref";
  private static final PrintStream STDERR =
      new PrintStream(new FileOutputStream(FileDescriptor.err), true, StandardCharsets.UTF_8);

  private static final int TEST_SIZE = 1024 * 1024;

  /**
   * Exit code used when the seednodes file is missing, empty, or unreadable for the current working
   * directory. This indicates that the bootstrap prerequisites were not met before startup.
   *
   * <p>Note that some operating systems truncate exit codes to 8 bits; callers should not assume
   * the full integer value is preserved when invoked via a shell.
   */
  public static final int EXIT_NO_SEEDNODES = 257;

  /**
   * Exit code used when a node fails to reach the expected "ready" state during startup. In this
   * harness that typically means {@link TestUtil#waitForNodes(Node)} returned {@code false} within
   * its timeout.
   *
   * <p>The run stops after attempting to park any started nodes, leaving the working directory on
   * disk for inspection.
   */
  public static final int EXIT_FAILED_TARGET = 258;

  /**
   * Exit code used when inserting the generated test data fails. The underlying {@link
   * network.crypta.client.HighLevelSimpleClient} {@code insert(...)} call throws {@link
   * InsertException}, which is printed to {@code stderr} along with a full stack trace.
   *
   * <p>This code is specific to this harness and is not part of any wire protocol.
   */
  public static final int EXIT_INSERT_FAILED = 259;

  /**
   * Exit code used when fetching the previously inserted URI fails. The failure is reported via
   * {@link FetchException} and the stack trace is printed to {@code stderr} to support diagnosis of
   * routing, key, or bootstrap issues.
   *
   * <p>On success, the fetched content is validated implicitly by the absence of {@link
   * FetchException}; the payload bytes are not rechecked here.
   */
  public static final int EXIT_FETCH_FAILED = 260;

  /**
   * Exit code used when the harness throws an unexpected exception (including interruption) outside
   * of the explicit insert/fetch error paths. The thrown exception and any causes/suppressed
   * exceptions are printed to {@code stderr}.
   *
   * <p>The harness attempts to park any started nodes before exiting to reduce the chance of
   * leaving background threads running.
   */
  public static final int EXIT_THREW_SOMETHING = 261;

  private static final int DARKNET_PORT1 = 5002;
  private static final int OPENNET_PORT1 = 5003;
  private static final int DARKNET_PORT2 = 5004;
  private static final int OPENNET_PORT2 = 5005;

  /**
   * Creates a new instance of the bootstrap push/pull harness.
   *
   * <p>This type is typically used via its {@link #main(String[])} entry point. Instances do not
   * carry configuration or mutable state beyond what is created within a single invocation, and the
   * helper methods are static. The constructor is therefore lightweight and side-effect free, but
   * it is kept public so the class remains usable in reflective or embedding scenarios.
   */
  public BootstrapPushPullTest() {
    // Intentionally empty: this harness is designed to be invoked via static entry points, but a
    // public constructor keeps reflective tooling and doc generation straightforward.
  }

  /**
   * Runs the bootstrap push/pull scenario and terminates the JVM with a stable exit code.
   *
   * <p>This method deletes and recreates a working directory, validates that {@code seednodes.fref}
   * is readable, starts two test nodes (one after the other), inserts a {@link #TEST_SIZE}-byte
   * random payload via the first node, and finally fetches that payload from the second node. All
   * progress and failures are reported to {@code stderr}. The method calls {@link System#exit(int)}
   * on both success and failure, so it does not return normally.
   *
   * <pre>{@code
   * // Example: run with an optional IP address override.
   * BootstrapPushPullTest.main(new String[] {"127.0.0.1"});
   * }</pre>
   *
   * @param args optional arguments; when present, {@code args[0]} is treated as an IP address
   *     override string passed into node configuration, otherwise no override is used
   * @throws IOException if working directories or seednodes cannot be created or copied before node
   *     startup
   * @throws NodeInitException if a node fails to initialize with the requested test parameters
   * @throws InterruptedException if the current thread is interrupted while waiting for node
   *     readiness; the interrupt status is preserved before exiting
   */
  public static void main(String[] args)
      throws IOException, NodeInitException, InterruptedException {
    Node node = null;
    Node secondNode = null;
    try {
      String ipOverride = args.length > 0 ? args[0] : null;
      File dir = new File("bootstrap-push-pull-test");
      FileUtil.removeAll(dir);
      RandomSource random = NodeStarter.globalTestInit(dir, false, Level.INFO, "", false, null);
      File seednodes = new File(SEEDNODES_FILE_NAME);
      if (!seednodes.exists() || seednodes.length() == 0 || !seednodes.canRead()) {
        STDERR.println("Unable to read " + SEEDNODES_FILE_NAME + ", it doesn't exist, or is empty");
        System.exit(EXIT_NO_SEEDNODES);
      }
      createWorkDirAndSeednodes(dir, DARKNET_PORT1, seednodes);
      PriorityAwareExecutor executor = new PooledExecutor();
      TestNodeParameters firstParams =
          createTestNodeParameters(dir, random, executor, DARKNET_PORT1, OPENNET_PORT1, ipOverride);
      node = NodeStarter.createTestNode(firstParams);
      Logging.setRootLevel(Level.ERROR); // kill logging
      node.start(true);
      if (!TestUtil.waitForNodes(node)) {
        node.park();
        System.exit(EXIT_FAILED_TARGET);
      }
      STDERR.println("Creating test data: " + TEST_SIZE + " bytes.");
      RandomAccessBucket data = createTestData(node);
      STDERR.println("Inserting test data.");
      long startInsertTime = System.currentTimeMillis();
      FreenetURI uri = insertTestData(node, data);
      long endInsertTime = System.currentTimeMillis();
      STDERR.println(
          "RESULT: Insert took "
              + (endInsertTime - startInsertTime)
              + "ms ("
              + TimeUtil.formatTime(endInsertTime - startInsertTime)
              + ") to "
              + uri
              + " .");
      node.park();

      // Bootstrap a second node.
      createWorkDirAndSeednodes(dir, DARKNET_PORT2, seednodes);
      executor = new PooledExecutor();
      TestNodeParameters secondParams =
          createTestNodeParameters(dir, random, executor, DARKNET_PORT2, OPENNET_PORT2, ipOverride);
      secondNode = NodeStarter.createTestNode(secondParams);
      secondNode.start(true);
      if (!TestUtil.waitForNodes(secondNode)) {
        secondNode.park();
        System.exit(EXIT_FAILED_TARGET);
      }

      // Fetch the data
      long startFetchTime = System.currentTimeMillis();
      fetchTestData(secondNode, uri);
      long endFetchTime = System.currentTimeMillis();
      STDERR.println(
          "RESULT: Fetch took "
              + (endFetchTime - startFetchTime)
              + "ms ("
              + TimeUtil.formatTime(endFetchTime - startFetchTime)
              + ") of "
              + uri
              + " .");
      secondNode.park();
      System.exit(0);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      exitWithCaught(node, secondNode, e);
    } catch (Exception e) {
      exitWithCaught(node, secondNode, e);
    }
  }

  private static void createWorkDirAndSeednodes(File baseDir, int port, File seednodes)
      throws IOException {
    File innerDir = new File(baseDir, Integer.toString(port));
    if (!innerDir.isDirectory() && !innerDir.mkdirs()) {
      throw new IOException("Failed to create node work dir: " + innerDir.getAbsolutePath());
    }
    try (FileInputStream fis = new FileInputStream(seednodes)) {
      FileUtil.writeTo(fis, new File(innerDir, SEEDNODES_FILE_NAME));
    }
  }

  private static TestNodeParameters createTestNodeParameters(
      File baseDir,
      RandomSource random,
      PriorityAwareExecutor executor,
      int darknetPort,
      int opennetPort,
      String ipOverride) {
    return TestNodeParameterFactory.create(
        baseDir,
        random,
        executor,
        p -> {
          p.setPort(darknetPort);
          p.setOpennetPort(opennetPort);
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
          p.setIpAddressOverride(ipOverride);
        });
  }

  private static RandomAccessBucket createTestData(Node node) throws IOException {
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

  private static FreenetURI insertTestData(Node node, RandomAccessBucket data) {
    HighLevelSimpleClient client = node.services().clientCore().makeClient((short) 0, false, false);
    InsertBlock block = new InsertBlock(data, new ClientMetadata(), FreenetURI.EMPTY_CHK_URI);
    try {
      return client.insert(block, false, null);
    } catch (InsertException e) {
      STDERR.println("INSERT FAILED: " + e);
      writeThrowable(e);
      System.exit(EXIT_INSERT_FAILED);
      return FreenetURI.EMPTY_CHK_URI;
    }
  }

  private static void fetchTestData(Node node, FreenetURI uri) {
    HighLevelSimpleClient client = node.services().clientCore().makeClient((short) 0, false, false);
    try {
      client.fetch(uri);
    } catch (FetchException e) {
      STDERR.println("FETCH FAILED: " + e);
      writeThrowable(e);
      System.exit(EXIT_FETCH_FAILED);
    }
  }

  private static void exitWithCaught(Node node, Node secondNode, Exception e) {
    STDERR.println(CAUGHT_PREFIX + e);
    writeThrowable(e);
    tryPark(node);
    tryPark(secondNode);
    System.exit(EXIT_THREW_SOMETHING);
  }

  private static void tryPark(Node node) {
    if (node == null) {
      return;
    }
    try {
      node.park();
    } catch (Exception e) {
      STDERR.println("Failed to park node: " + e);
      writeThrowable(e);
    }
  }

  private static void writeThrowable(Throwable t) {
    writeThrowable(t, "");
  }

  private static void writeThrowable(Throwable t, String prefix) {
    if (t == null) {
      return;
    }
    STDERR.println(prefix + t);
    for (StackTraceElement frame : t.getStackTrace()) {
      STDERR.println(prefix + "\tat " + frame);
    }
    for (Throwable suppressed : t.getSuppressed()) {
      writeThrowable(suppressed, prefix + "\tSuppressed: ");
    }
    Throwable cause = t.getCause();
    if (cause != null && cause != t) {
      writeThrowable(cause, prefix + "Caused by: ");
    }
  }
}
