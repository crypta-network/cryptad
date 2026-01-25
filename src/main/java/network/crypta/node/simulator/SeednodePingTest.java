package network.crypta.node.simulator;

import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.crypt.RandomSource;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.node.Announcer;
import network.crypta.node.FSParseException;
import network.crypta.node.Node;
import network.crypta.node.NodeFile;
import network.crypta.node.NodeInitException;
import network.crypta.node.NodeStarter;
import network.crypta.node.NodeStarter.TestNodeParameters;
import network.crypta.node.OpennetDisabledException;
import network.crypta.node.PeerTooOldException;
import network.crypta.node.SeedServerPeerNode;
import network.crypta.node.SeedServerTestPeerNode;
import network.crypta.node.SeedServerTestPeerNode.FATE;
import network.crypta.support.Logging;
import network.crypta.support.PooledExecutor;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.TimeUtil;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

/**
 * Standalone simulator that connects to seednodes, pings them, and records their status over time.
 *
 * <p>This harness boots a single test node in a throwaway directory, loads a seed reference list,
 * connects to each seednode, and then performs a short, fixed-duration ping loop. Each ping cycle
 * logs the observed fate of every seednode and emits aggregate totals so scripts can scrape the
 * results. After the loop completes, it appends a status line per seednode to a per-identity log
 * file so that longer runs can build a historical availability picture.
 *
 * <p>The class is intended to be run as a standalone tool via {@link #main(String[])} rather than
 * instantiated directly. It uses a single-threaded scheduler for the ping loop while the node
 * itself manages its own background threads; the harness assumes single-process execution and is
 * not designed for concurrent invocation from multiple callers.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Preparing a test node and ensuring seednodes are available.
 *   <li>Connecting to seednodes and driving a timed ping loop.
 *   <li>Recording per-seednode status lines and summary statistics.
 * </ul>
 *
 * @see RealNodeTest
 * @see SeedServerTestPeerNode
 */
public class SeednodePingTest extends RealNodeTest {
  private static final Logger LOG = LoggerFactory.getLogger(SeednodePingTest.class);
  private static final String STATUS_DIR_PROPERTY = "crypta.seednode.status.dir";

  static File statusDir = defaultStatusDir();
  static final long COUNT_SUCCESSES_PERIOD = DAYS.toMillis(7);

  static final int DARKNET_PORT = RealNodeULPRTest.DARKNET_PORT_END;
  static final int OPENNET_PORT = DARKNET_PORT + 1;

  /**
   * Creates a new instance of the seednode ping harness.
   *
   * <p>This class is primarily used through its static {@link #main(String[])} entry point, and
   * callers do not generally need to instantiate it. The constructor performs no initialization
   * beyond standard object creation and exists solely to provide explicit API documentation for the
   * implicit default constructor.
   */
  public SeednodePingTest() {
    // No-op: this harness is invoked via static entry points only.
  }

  /**
   * Runs the seednode ping simulation using the provided command-line arguments.
   *
   * <p>The method resolves the output directory, creates a temporary test node, ensures seednodes
   * are available, and then connects and pings them for a short, bounded interval. The process logs
   * per-seednode status and final summaries, exiting with a non-zero status on interruptions or
   * unexpected failures. This call is not idempotent because it appends to status logs and
   * initializes a fresh node directory each time.
   *
   * <pre>{@code
   * SeednodePingTest.main(new String[] {"/var/www/freenet/tests/seednodes/status"});
   * }</pre>
   *
   * @param args optional arguments; single non-blank value overrides status directory
   * @throws RuntimeException if initialization or seednode loading fails unexpectedly
   * @throws Error if the JVM cannot complete startup or shutdown
   * @see #runSeednodePingTest(String[])
   * @see #resolveStatusDir(String[])
   * @see #loadSeednodes(Node)
   */
  public static void main(String[] args) {
    int exitCode = runSeednodePingTest(args);
    System.exit(exitCode);
  }

  private static int runSeednodePingTest(String[] args) {
    Node node = null;
    try {
      statusDir = resolveStatusDir(args);
      File baseDir = new File("seednode-pingtest");
      RandomSource random =
          NodeStarter.globalTestInit(baseDir, false, Level.ERROR, "", false, null);
      node = createNode(baseDir, random);
      List<SimpleFieldSet> seedNodesAsSfs = loadSeednodes(node);
      List<SeedServerTestPeerNode> seedNodes = connectSeednodes(node, seedNodesAsSfs);
      startNode(node, seedNodes, seedNodesAsSfs.size());
      runPingLoop(node, seedNodes);
      reportFinalTotals(seedNodes);
      writeFinalStatus(seedNodes, System.currentTimeMillis());
      return 0;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      LOG.error("Seednode ping test interrupted", e);
      return 1;
    } catch (Exception e) {
      LOG.error("CAUGHT: {}", e, e);
      return 1;
    } finally {
      parkNode(node);
    }
  }

  private static Node createNode(File baseDir, RandomSource random) throws NodeInitException {
    PriorityAwareExecutor executor = new PooledExecutor();
    TestNodeParameters params = new TestNodeParameters();
    params.setBaseDirectory(baseDir);
    params.setPort(DARKNET_PORT);
    params.setOpennetPort(OPENNET_PORT);
    params.setMaxHTL(Node.DEFAULT_MAX_HTL);
    params.setRandom(random);
    params.setExecutor(executor);
    params.setThreadLimit(1000);
    params.setStoreSize(5L * 1024 * 1024);
    params.setRamStore(true);
    params.setOutputBandwidthLimit(0);
    return NodeStarter.createTestNode(params);
  }

  /**
   * Loads seednode references, ensuring the node directory contains a readable seednodes file.
   *
   * @param node node whose directory layout determines the seednodes file location
   * @return non-empty list of seednode references
   * @throws IOException when no seednodes are available or required files cannot be created
   */
  private static List<SimpleFieldSet> loadSeednodes(Node node) throws IOException {
    File seednodesFile = NodeFile.SEEDNODES.getFile(node);
    if (!seednodesFile.exists() || seednodesFile.length() == 0 || !seednodesFile.canRead()) {
      File seednodes = new File(NodeFile.SEEDNODES.getFilename());
      if (!seednodes.exists() || seednodes.length() == 0 || !seednodes.canRead()) {
        LOG.error("Unable to read seednodes.fref, it doesn't exist, or is empty");
        throw new IOException("Missing seednodes.fref in node or working directory.");
      }
      File parent = seednodesFile.getParentFile();
      if (parent != null && !parent.mkdirs() && !parent.isDirectory()) {
        throw new IOException("Failed to create directory: " + parent.getAbsolutePath());
      }
      try (FileInputStream fis = new FileInputStream(seednodes)) {
        FileUtil.writeTo(fis, seednodesFile);
      }
    }
    List<SimpleFieldSet> seednodes = Announcer.readSeednodes(seednodesFile);
    if (seednodes.isEmpty()) {
      LOG.error("No seednodes loaded from {}", seednodesFile.getAbsolutePath());
      throw new IOException("Seednodes list is empty: " + seednodesFile.getAbsolutePath());
    }
    return seednodes;
  }

  private static List<SeedServerTestPeerNode> connectSeednodes(
      Node node, List<SimpleFieldSet> seedNodesAsSfs)
      throws PeerParseException,
          FSParseException,
          OpennetDisabledException,
          PeerTooOldException,
          ReferenceSignatureVerificationException {
    List<SeedServerTestPeerNode> seedNodes = new ArrayList<>();
    for (SimpleFieldSet sfs : seedNodesAsSfs) {
      SeedServerTestPeerNode seednode = node.network().createNewSeedServerTestPeerNode(sfs);
      if (connectSeednode(node, seednode)) {
        seedNodes.add(seednode);
      }
    }
    return seedNodes;
  }

  private static boolean connectSeednode(Node node, SeedServerTestPeerNode seednode) {
    try {
      node.network().connectToSeednode(seednode);
      return true;
    } catch (Exception fse) {
      LOG.error("ERROR adding {} {}", seednode, fse.getMessage());
      return false;
    }
  }

  private static void startNode(Node node, List<SeedServerTestPeerNode> seedNodes, int totalSeeds)
      throws InterruptedException, NodeInitException {
    node.start(true);
    Logging.setRootLevel(Level.ERROR);
    Thread.sleep(SECONDS.toMillis(2));
    if (seedNodes.size() != totalSeeds) {
      LOG.error("ERROR ADDING SOME OF THE SEEDNODES!!");
    }
    LOG.error("Let some time for the {} nodes to connect...", seedNodes.size());
    Thread.sleep(SECONDS.toMillis(8));
  }

  private static void runPingLoop(Node node, List<SeedServerTestPeerNode> seedNodes)
      throws InterruptedException {
    AtomicInteger pingId = new AtomicInteger();
    long deadlineNanos = System.nanoTime() + MINUTES.toNanos(2);
    CountDownLatch finished = new CountDownLatch(1);
    AtomicReference<ScheduledFuture<?>> taskRef = new AtomicReference<>();
    Runnable task =
        () -> {
          if (System.nanoTime() >= deadlineNanos) {
            ScheduledFuture<?> scheduled = taskRef.get();
            if (scheduled != null) {
              scheduled.cancel(false);
            }
            finished.countDown();
            return;
          }
          PingLoopResult pingLoopResult = pingConnectedSeednodes(node, pingId.get());
          pingId.set(pingLoopResult.nextPingId());
          logSeednodeFates(seedNodes);
          logTotals(node, pingLoopResult.countConnectedSeednodes());
        };
    try (ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor()) {
      taskRef.set(scheduler.scheduleAtFixedRate(task, 0, 5, SECONDS));
      boolean completed =
          finished.await(MINUTES.toMillis(2) + SECONDS.toMillis(5), TimeUnit.MILLISECONDS);
      if (!completed) {
        LOG.error("Seednode ping loop timed out before reaching the deadline.");
      }
    } finally {
      ScheduledFuture<?> scheduled = taskRef.get();
      if (scheduled != null) {
        scheduled.cancel(true);
      }
    }
  }

  private static PingLoopResult pingConnectedSeednodes(Node node, int pingIdStart) {
    int pingId = pingIdStart;
    int countConnectedSeednodes = 0;
    for (SeedServerPeerNode seednode :
        node.network().peers().seedPeers().getConnectedSeedServerPeersVector(null)) {
      if (pingSeednode(seednode, pingId)) {
        countConnectedSeednodes++;
        pingId++;
      }
    }
    return new PingLoopResult(pingId, countConnectedSeednodes);
  }

  private static boolean pingSeednode(SeedServerPeerNode seednode, int pingId) {
    try {
      double pingTime = seednode.averagePingTime();
      int uptime = seednode.getUptime();
      long timeDelta = seednode.getClockDelta();
      if (seednode.isRealConnection()) {
        return false;
      }
      boolean ping = seednode.transport().ping(pingId);
      if (ping && LOG.isErrorEnabled()) {
        LOG.error(
            "Seednode ping result identity={} uptime={} ping={} pingTime={} reportedUptime={}"
                + " timeDelta={}",
            seednode.getIdentityString(),
            uptime,
            true,
            pingTime,
            seednode.getUptime(),
            TimeUtil.formatTime(timeDelta));
      }
      if (seednode.isRoutable()) {
        LOG.error("{} is routable!", seednode);
      }
      return true;
    } catch (NotConnectedException _) {
      LOG.error(
          "{} is not connected {}", seednode.getIdentityString(), seednode.getHandshakeCount());
      return false;
    }
  }

  private static void logSeednodeFates(List<SeedServerTestPeerNode> seedNodes) {
    Map<FATE, Integer> totals = new EnumMap<>(SeedServerTestPeerNode.FATE.class);
    for (SeedServerTestPeerNode seednode : seedNodes) {
      FATE fate = seednode.getFate();
      totals.put(fate, totals.getOrDefault(fate, 0) + 1);
      LOG.error(
          "Seednode fate snapshot identity={} fate={} status={}",
          seednode.getIdentityString(),
          fate,
          seednode.getPeerNodeStatusString());
    }
    LOG.error("Seednode fate totals:");
    for (Entry<FATE, Integer> fateEntry : totals.entrySet()) {
      LOG.error("Seednode fate total fate={} count={}", fateEntry.getKey(), fateEntry.getValue());
    }
  }

  private static void logTotals(Node node, int countConnectedSeednodes) {
    LOG.error(
        "################## ({}) {}/{}",
        node.network().peers().countConnectedPeers(),
        countConnectedSeednodes,
        node.network().peers().countSeednodes());
  }

  private static void reportFinalTotals(List<SeedServerTestPeerNode> seedNodes) {
    Map<FATE, Integer> totals = new EnumMap<>(SeedServerTestPeerNode.FATE.class);
    for (SeedServerTestPeerNode seednode : seedNodes) {
      FATE fate = seednode.getFate();
      totals.put(fate, totals.getOrDefault(fate, 0) + 1);
      LOG.error(
          "Seednode final fate identity={} fate={} status={}",
          seednode.getIdentityString(),
          fate,
          seednode.getPeerNodeStatusString());
    }
    LOG.error("Seednode final totals:");
    for (Entry<FATE, Integer> fateEntry : totals.entrySet()) {
      LOG.error("Seednode final total fate={} count={}", fateEntry.getKey(), fateEntry.getValue());
    }
    LOG.error("Seednode scan completed.");
  }

  private static void writeFinalStatus(List<SeedServerTestPeerNode> seedNodes, long writeTime)
      throws IOException {
    LOG.error("Seednode final status lines:");
    for (SeedServerTestPeerNode peer : seedNodes) {
      String status = writeTime + " : " + peer.getIdentityString() + " : " + peer.getFate();
      LOG.error("Seednode final status line: {}", status);
      File logFile = new File(statusDir, peer.getIdentityString());
      appendStatus(logFile, status);
      SeednodeHistory history = readHistory(logFile, writeTime);
      logHistory(peer, history, writeTime);
    }
  }

  private static void appendStatus(File logFile, String status) throws IOException {
    try (OutputStreamWriter osw =
        new OutputStreamWriter(new FileOutputStream(logFile, true), StandardCharsets.UTF_8)) {
      osw.write(status);
      osw.write(System.lineSeparator());
    }
  }

  private static SeednodeHistory readHistory(File logFile, long writeTime) throws IOException {
    int successes = 0;
    int failures = 0;
    long lastSuccess = 0;
    long firstSample = 0;
    long countSince = writeTime - COUNT_SUCCESSES_PERIOD;
    try (BufferedReader br =
        new BufferedReader(
            new InputStreamReader(new FileInputStream(logFile), StandardCharsets.UTF_8))) {
      String line;
      while ((line = br.readLine()) != null) {
        String[] results = line.split(" : ");
        if (results.length != 3) {
          LOG.error(
              "Unable to parse line in {} : wrong number of fields : {} : {}",
              logFile,
              results.length,
              line);
          continue;
        }
        long time = Long.parseLong(results[0]);
        FATE fate = FATE.valueOf(results[2]);
        if (firstSample == 0) {
          firstSample = time;
        }
        if (fate == FATE.CONNECTED_SUCCESS) {
          if (time >= countSince) {
            successes++;
          }
          lastSuccess = time;
        } else if (time >= countSince) {
          failures++;
        }
      }
    }
    return new SeednodeHistory(firstSample, lastSuccess, successes, failures);
  }

  private static void logHistory(
      SeedServerTestPeerNode peer, SeednodeHistory history, long writeTime) {
    if (history.firstSample() < writeTime - COUNT_SUCCESSES_PERIOD && history.successes() == 0) {
      LOG.error(
          "RESULT:{} NOT CONNECTED IN LAST WEEK! LAST CONNECTED: {}",
          peer.getIdentityString(),
          history.lastSuccess() > 0
              ? TimeUtil.formatTime(writeTime - history.lastSuccess())
              : "NEVER");
    }
    LOG.error(
        "{} : last success {} failures in last week: {} successes in last week: {}",
        peer.getIdentityString(),
        history.lastSuccess() > 0
            ? TimeUtil.formatTime(writeTime - history.lastSuccess())
            : "NEVER",
        history.failures(),
        history.successes());
  }

  private static void parkNode(Node node) {
    if (node == null) {
      return;
    }
    try {
      node.park();
    } catch (Exception e) {
      LOG.error("Failed to park node", e);
    }
  }

  private static File resolveStatusDir(String[] args) {
    if (args != null && args.length == 1 && !args[0].isBlank()) {
      return new File(args[0]);
    }
    String override = System.getProperty(STATUS_DIR_PROPERTY);
    if (override != null && !override.isBlank()) {
      return new File(override);
    }
    return defaultStatusDir();
  }

  private static File defaultStatusDir() {
    return Path.of(File.separator, "var", "www", "freenet", "tests", "seednodes", "status")
        .toFile();
  }

  private record SeednodeHistory(long firstSample, long lastSuccess, int successes, int failures) {}

  private record PingLoopResult(int nextPingId, int countConnectedSeednodes) {}
}
