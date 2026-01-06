package network.crypta.node.simulator;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.InsertBlock;
import network.crypta.client.InsertException;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.NodeInitException;
import network.crypta.node.NodeStarter;
import network.crypta.node.NodeStarter.TestNodeParameters;
import network.crypta.node.Version;
import network.crypta.support.Logging;
import network.crypta.support.PooledExecutor;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

/**
 * Runs a long-term push/pull check for CHK insertion and retrieval timing.
 *
 * <p>This test harness creates two local nodes, inserts a small set of randomly generated CHK
 * blocks, and records both insert and fetch timings to a CSV log keyed by a unique identifier. It
 * is intended for multi-day benchmarking where a daily run can accumulate historical entries and
 * later retrieve them at exponentially spaced offsets. The runner manages its own work directory,
 * requires a readable {@code seednodes.fref}, and always terminates the JVM with an explicit exit
 * code after writing status output.
 *
 * <p>Notable behaviors include the exponential backoff of target dates, best-effort logging when
 * data is missing, and cleanup of temporary node directories. The implementation is single-threaded
 * in orchestration but exercises network and storage subsystems. It is not designed to be
 * re-entrant or long-lived within a hosting process.
 *
 * <ul>
 *   <li>Creates two test nodes with different ports and store sizes.
 *   <li>Writes a per-run CSV log with timing and URI data.
 *   <li>Pulls historical CHKs only when a matching log entry exists.
 * </ul>
 *
 * @see LongTermTest
 * @see TestUtil
 */
public class LongTermPushPullCHKTest extends LongTermTest {
  private static final Logger LOG = LoggerFactory.getLogger(LongTermPushPullCHKTest.class);

  private static final int TEST_SIZE = 64 * 1024;

  private static final int EXIT_NO_SEEDNODES = 257;
  private static final int EXIT_FAILED_TARGET = 258;
  private static final int EXIT_THREW_SOMETHING = 261;

  private static final int DARKNET_PORT1 = 5010;
  private static final int OPENNET_PORT1 = 5011;
  private static final int DARKNET_PORT2 = 5012;
  private static final int OPENNET_PORT2 = 5013;

  private static final int MAX_N = 8;
  private static final String SEEDNODES_FILENAME = "seednodes.fref";
  private static final int OUTPUT_BANDWIDTH_LIMIT = 12 * 1024;

  /**
   * Creates a new test runner instance with no additional state.
   *
   * <p>The class is typically used in a static manner via {@link #main(String[])}, but an explicit
   * constructor is provided to satisfy Javadoc completeness when instantiation is required by tools
   * or reflective test harnesses. The constructor performs no initialization beyond the implicit
   * default behavior and introduces no external side effects. It is therefore safe and idempotent
   * to call.
   */
  public LongTermPushPullCHKTest() {
    // No-op: constructor exists only to satisfy doclint for the implicit default constructor.
  }

  /**
   * Runs the long-term push/pull test using a single unique identifier argument.
   *
   * <p>The method validates that a single argument is supplied, wipes any existing working
   * directory for that identifier, and initializes the test runtime and seed node data. It then
   * starts a primary node to insert test blocks, parks that node, and starts a secondary node to
   * fetch current and historical CHKs derived from prior CSV logs. The method always writes a CSV
   * status line and invokes {@link System#exit(int)} with a stable code, even when interruptions or
   * unexpected exceptions occur.
   *
   * <pre>{@code
   * // Example: run with a unique identifier for the CSV log.
   * LongTermPushPullCHKTest.main(new String[] {"nightly-2025-12-21"});
   * }</pre>
   *
   * @param args expects exactly one entry, the unique identifier for log and directory names
   */
  public static void main(String[] args) {
    Logging.setLevel(LongTermPushPullCHKTest.class.getName(), Level.INFO);
    String uid = requireUid(args);
    List<String> csvLine = initCsvLine();

    int exitCode = 0;
    Node node = null;
    Node node2 = null;
    try {
      final File dir = new File("longterm-push-pull-test-" + uid);
      FileUtil.removeAll(dir);
      RandomSource random = NodeStarter.globalTestInit(dir, false, Level.ERROR, "", false, null);
      File seednodes = requireSeednodes();
      copySeednodes(seednodes, new File(dir, Integer.toString(DARKNET_PORT1)));

      // Create one node
      TestNodeParameters nodeParams =
          buildNodeParameters(
              DARKNET_PORT1,
              OPENNET_PORT1,
              dir,
              random,
              new PooledExecutor(),
              4 * 1024 * 1024,
              true);
      node = startNode(nodeParams);
      Logging.setRootLevel(org.slf4j.event.Level.ERROR);
      Logging.setLevel(LongTermPushPullCHKTest.class.getName(), Level.INFO);

      if (recordSeedTimeFailed(node, csvLine)) {
        exitCode = EXIT_FAILED_TARGET;
        return;
      }

      FreenetURI todaysInsert = pushBlocks(node, csvLine);
      node.park();

      // Node 2
      copySeednodes(seednodes, new File(dir, Integer.toString(DARKNET_PORT2)));
      TestNodeParameters node2Params =
          buildNodeParameters(
              DARKNET_PORT2,
              OPENNET_PORT2,
              dir,
              random,
              new PooledExecutor(),
              5 * 1024 * 1024,
              false);
      node2 = startNode(node2Params);

      if (recordSeedTimeFailed(node2, csvLine)) {
        exitCode = EXIT_FAILED_TARGET;
        return;
      }

      pullBlocks(node2, uid, todaysInsert, csvLine);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      LOG.warn("Long-term CHK push/pull test interrupted.", e);
      exitCode = EXIT_THREW_SOMETHING;
    } catch (Exception e) {
      LOG.error("Long-term CHK push/pull test failed unexpectedly.", e);
      exitCode = EXIT_THREW_SOMETHING;
    } finally {
      try {
        if (node != null) node.park();
      } catch (Exception e) {
        LOG.debug("Failed to park primary node.", e);
      }
      try {
        if (node2 != null) node2.park();
      } catch (Exception e) {
        LOG.debug("Failed to park secondary node.", e);
      }

      File file = new File(uid + ".csv");
      writeToStatusLog(file, csvLine);
      System.exit(exitCode);
    }
  }

  private static String requireUid(String[] args) {
    if (args.length != 1) {
      LOG.error("Usage: java freenet.node.simulator.LongTermPushPullTest <unique identifier>");
      System.exit(1);
    }
    return args[0];
  }

  private static List<String> initCsvLine() {
    List<String> csvLine = new ArrayList<>(3 + 2 * MAX_N);
    String date = dateFormat.format(today.getTime());
    LOG.info("DATE:{}", date);
    csvLine.add(date);
    long buildNumber = Version.currentBuildNumber();
    LOG.info("Version:{}", buildNumber);
    csvLine.add(String.valueOf(buildNumber));
    return csvLine;
  }

  private static File requireSeednodes() {
    File seednodes = new File(SEEDNODES_FILENAME);
    if (!seednodes.exists() || seednodes.length() == 0 || !seednodes.canRead()) {
      LOG.error("Unable to read {}, it doesn't exist, or is empty", SEEDNODES_FILENAME);
      System.exit(EXIT_NO_SEEDNODES);
    }
    return seednodes;
  }

  private static void copySeednodes(File seednodes, File innerDir) throws IOException {
    if (!innerDir.exists() && !innerDir.mkdirs()) {
      LOG.warn("Failed to create directory {}", innerDir);
    }
    try (FileInputStream fis = new FileInputStream(seednodes)) {
      FileUtil.writeTo(fis, new File(innerDir, SEEDNODES_FILENAME));
    }
  }

  private static Node startNode(TestNodeParameters params) throws NodeInitException {
    Node node = NodeStarter.createTestNode(params);
    node.start(true);
    return node;
  }

  private static boolean recordSeedTimeFailed(Node node, List<String> csvLine)
      throws InterruptedException {
    long start = System.currentTimeMillis();
    if (!TestUtil.waitForNodes(node)) {
      return true;
    }
    long end = System.currentTimeMillis();
    long seedTime = end - start;
    LOG.info("SEED-TIME:{}", seedTime);
    csvLine.add(String.valueOf(seedTime));
    return false;
  }

  private static FreenetURI pushBlocks(Node node, List<String> csvLine) throws IOException {
    FreenetURI todaysInsert = null;
    for (int i = 0; i <= MAX_N; i++) {
      RandomAccessBucket data = randomData(node);
      try {
        HighLevelSimpleClient client =
            node.services().clientCore().makeClient((short) 0, false, false);
        LOG.info("PUSHING {}", i);

        try {
          InsertBlock block = new InsertBlock(data, new ClientMetadata(), FreenetURI.EMPTY_CHK_URI);
          long t1 = System.currentTimeMillis();
          FreenetURI uri = client.insert(block, false, null);
          if (i == 0) {
            todaysInsert = uri;
          }
          long t2 = System.currentTimeMillis();

          LOG.info("PUSH-TIME-{}:{} for {}", i, (t2 - t1), uri);
          csvLine.add(String.valueOf(t2 - t1));
          csvLine.add(uri.toASCIIString());
        } catch (InsertException e) {
          LOG.warn("Insert failed for index {}", i, e);
          csvLine.add("N/A");
          csvLine.add("N/A");
        }
      } finally {
        data.free();
      }
    }
    return todaysInsert;
  }

  private static void pullBlocks(
      Node node, String uid, FreenetURI todaysInsert, List<String> csvLine) throws IOException {
    for (int i = 0; i <= MAX_N; i++) {
      HighLevelSimpleClient client =
          node.services().clientCore().makeClient((short) 0, false, false);
      Calendar targetDate = today.copyCalendar();
      targetDate.add(Calendar.DAY_OF_MONTH, -((1 << i) - 1));

      FreenetURI uri = i == 0 ? todaysInsert : getHistoricURI(uid, i, targetDate);
      if (uri == null) {
        LOG.info("SKIPPING PULL FOR {}", i);
        continue;
      }

      LOG.info("PULLING {}", uri);

      try {
        long t1 = System.currentTimeMillis();
        client.fetch(uri);
        long t2 = System.currentTimeMillis();

        LOG.info("PULL-TIME-{}:{}", i, (t2 - t1));
        csvLine.add(String.valueOf(t2 - t1));
      } catch (FetchException e) {
        if (e.getMode() != FetchExceptionMode.ALL_DATA_NOT_FOUND
            && e.getMode() != FetchExceptionMode.DATA_NOT_FOUND) {
          LOG.warn("Fetch failed for {}", uri, e);
        }
        csvLine.add(FetchException.getShortMessage(e.getMode()));
      }
    }
  }

  private static FreenetURI getHistoricURI(String uid, int i, Calendar targetDate)
      throws IOException {
    // Quick and dirty, since we only have 1...8 it's not worth caching it.
    File file = new File(uid + ".csv");
    try (FileInputStream fis = new FileInputStream(file);
        InputStreamReader isr = new InputStreamReader(fis, ENCODING);
        BufferedReader br = new BufferedReader(isr)) {
      String line;
      String dateString = dateFormat.format(targetDate.getTime());
      while ((line = br.readLine()) != null) {
        String[] split = line.split("!");
        int fieldnum = 3 + i * 2;
        if (split.length == 0 || !dateString.equals(split[0]) || line.length() >= fieldnum) {
          continue;
        }
        return new FreenetURI(split[fieldnum]);
      }
      return null;
    }
  }

  private static TestNodeParameters buildNodeParameters(
      int darknetPort,
      int opennetPort,
      File baseDirectory,
      RandomSource random,
      PriorityAwareExecutor executor,
      int storeSize,
      boolean enableFoaf) {
    TestNodeParameters params = new TestNodeParameters();
    params.setBaseDirectory(baseDirectory);
    params.setPort(darknetPort);
    params.setOpennetPort(opennetPort);
    params.setMaxHTL(Node.DEFAULT_MAX_HTL);
    params.setRandom(random);
    params.setExecutor(executor);
    params.setThreadLimit(1000);
    params.setStoreSize(storeSize);
    params.setRamStore(true);
    params.setEnableSwapping(true);
    params.setEnableARKs(true);
    params.setEnableULPRs(true);
    params.setEnablePerNodeFailureTables(true);
    params.setEnableSwapQueueing(true);
    params.setEnablePacketCoalescing(true);
    params.setOutputBandwidthLimit(OUTPUT_BANDWIDTH_LIMIT);
    params.setEnableFOAF(enableFoaf);
    params.setConnectToSeednodes(true);
    return params;
  }

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
}
