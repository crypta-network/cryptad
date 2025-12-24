package network.crypta.node.simulator;

import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TimeZone;
import java.util.TreeMap;
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
import network.crypta.node.Version;
import network.crypta.support.Logging;
import network.crypta.support.PooledExecutor;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

/**
 * Executes a long-horizon push/pull benchmark for deterministic KSK keys.
 *
 * <p>This simulator builds a single, dated key namespace, inserts a batch of keys, parks the first
 * node, then starts a second node to fetch the same keys after a fixed day offset. Each key uses a
 * unique identifier, a formatted date, and an index so results are reproducible across runs. Output
 * is written as a CSV line per run, capturing the seed time, per-key push timings, and per-key pull
 * timings so that long-term retention and latency trends can be analyzed offline.
 *
 * <p>The test is designed to be executed as a standalone process and is not intended to be
 * thread-safe. It mutates process-wide state (logging level, working directory) and writes to files
 * in the current working directory.
 *
 * <p>CSV format (single line per run):
 *
 * <pre>{@code
 * DATE, VERSION, SEED-TIME-1, PUSH-TIME-#0, ... , PUSH-TIME-#N, SEED-TIME-2, PULL-TIME-#0, ... , PULL-TIME-#N
 * }</pre>
 *
 * <p>Key responsibilities:
 *
 * <ul>
 *   <li>Generate deterministic KSK URIs using the run identifier and date.
 *   <li>Seed, start, and park test nodes in a controlled order.
 *   <li>Record timing and failure modes to a CSV status log.
 * </ul>
 *
 * @author sdiz
 * @see LongTermTest
 * @see TestUtil
 */
public class LongTermPushPullTest extends LongTermTest {
  private static final int TEST_SIZE = 64 * 1024;

  private static final String SEEDNODES_FILENAME = "seednodes.fref";

  private static final int EXIT_NO_SEEDNODES = 257;
  private static final int EXIT_FAILED_TARGET = 258;
  private static final int EXIT_THREW_SOMETHING = 261;

  private static final int DARKNET_PORT1 = 5010;
  private static final int OPENNET_PORT1 = 5011;
  private static final int DARKNET_PORT2 = 5012;
  private static final int OPENNET_PORT2 = 5013;

  private static final int MAX_N = 8;

  private static final Logger LOG = LoggerFactory.getLogger(LongTermPushPullTest.class);

  /**
   * Creates a test driver instance.
   *
   * <p>This class is normally used through its static {@link #main(String[])} entry point. The
   * explicit constructor exists only to satisfy doclint requirements and does not perform any
   * initialization beyond the implicit default constructor behavior. Creating an instance has no
   * side effects, opens no files, and allocates no test resources; it simply allows tooling to
   * attach constructor-level documentation in a consistent way.
   */
  public LongTermPushPullTest() {
    // Intentionally empty: this test is driven via static entry points only.
  }

  /**
   * Runs the long-term push/pull test or dumps previously recorded statistics.
   *
   * <p>The first argument is a unique identifier used to construct KSK URIs and the CSV filename.
   * If a second argument is supplied and matches one of the supported dump tokens, the process
   * reads the existing CSV file and prints aggregate statistics instead of running inserts/fetches.
   * This method configures logging, writes the CSV line on completion, and exits the JVM with a
   * status code that reflects the outcome.
   *
   * <pre>{@code
   * // Example: run a new test with identifier "demo".
   * LongTermPushPullTest.main(new String[] {"demo"});
   * }</pre>
   *
   * @param args command-line arguments; expects a run identifier and optional dump mode flag
   */
  public static void main(String[] args) {
    Logging.setLevel(LongTermPushPullTest.class.getName(), Level.INFO);
    if (args.length < 1 || args.length > 2) {
      LOG.error("Usage: java freenet.node.simulator.LongTermPushPullTest <unique identifier>");
      System.exit(1);
    }
    String uid = args[0];

    if (isDumpMode(args)) {
      handleDump(uid);
      return;
    }

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
      LOG.error("Long-term push/pull test failed", e);
      exitCode = EXIT_THREW_SOMETHING;
    } finally {
      parkNodes(nodes);

      File file = new File(uid + ".csv");
      writeToStatusLog(file, csvLine);
      System.exit(exitCode);
    }
  }

  private static void dumpStats(String uid) throws IOException, ParseException {
    File file = new File(uid + ".csv");
    TreeMap<GregorianCalendar, DumpElement> map = new TreeMap<>();
    readDumpElements(file, map);
    for (int i = 0; i <= MAX_N; i++) {
      int delta = ((1 << i) - 1);
      summarizeDelta(map, delta, i);
    }
  }

  private static boolean isDumpMode(String[] args) {
    if (args.length != 2) {
      return false;
    }
    String mode = args[1];
    return mode.equalsIgnoreCase("--dump")
        || mode.equalsIgnoreCase("-dump")
        || mode.equalsIgnoreCase("dump");
  }

  private static void handleDump(String uid) {
    try {
      dumpStats(uid);
    } catch (IOException e) {
      LOG.error("IO ERROR: {}", e, e);
      LOG.error("Failed to read dump file for {}", uid, e);
      System.exit(1);
    } catch (ParseException e) {
      LOG.error("PARSE ERROR: {}", e, e);
      LOG.error("Failed to parse dump file for {}", uid, e);
      System.exit(2);
    }
    System.exit(0);
  }

  private static void recordHeader(List<String> csvLine) {
    String todayText = dateFormat.format(today.getTime());
    LOG.warn("DATE:{}", todayText);
    csvLine.add(todayText);

    int buildNumber = Version.currentBuildNumber();
    LOG.warn("Version:{}", buildNumber);
    csvLine.add(String.valueOf(buildNumber));
  }

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
    if (waitForNodes(nodes.node, csvLine)) {
      pushBlocks(uid, nodes.node, csvLine);
    } else {
      return EXIT_FAILED_TARGET;
    }

    nodes.node.park();

    prepareSeednodes(dir, seednodes, DARKNET_PORT2);
    nodes.node2 = createNode(random, dir, DARKNET_PORT2, OPENNET_PORT2, false, 5L * 1024 * 1024);
    nodes.node2.start(true);

    if (waitForNodes(nodes.node2, csvLine)) {
      pullBlocks(uid, nodes.node2, csvLine);
    } else {
      return EXIT_FAILED_TARGET;
    }
    return 0;
  }

  private static File ensureSeednodes() {
    File seednodes = new File(SEEDNODES_FILENAME);
    if (!seednodes.exists() || seednodes.length() == 0 || !seednodes.canRead()) {
      LOG.error("Unable to read seednodes.fref, it doesn't exist, or is empty");
      System.exit(EXIT_NO_SEEDNODES);
    }
    return seednodes;
  }

  private static void prepareSeednodes(File baseDir, File seednodes, int darknetPort)
      throws IOException {
    File innerDir = new File(baseDir, Integer.toString(darknetPort));
    if (!innerDir.mkdir() && !innerDir.isDirectory()) {
      throw new IOException("Unable to create seednodes directory: " + innerDir.getAbsolutePath());
    }
    try (FileInputStream fis = new FileInputStream(seednodes)) {
      FileUtil.writeTo(fis, new File(innerDir, SEEDNODES_FILENAME));
    }
  }

  private static Node createNode(
      RandomSource random,
      File baseDir,
      int darknetPort,
      int opennetPort,
      boolean enableFoaf,
      long storeSize)
      throws NodeInitException {
    NodeStarter.TestNodeParameters params = new NodeStarter.TestNodeParameters();
    params.setPort(darknetPort);
    params.setOpennetPort(opennetPort);
    params.setBaseDirectory(baseDir);
    params.setDisableProbabilisticHTLs(false);
    params.setMaxHTL(Node.DEFAULT_MAX_HTL);
    params.setRandom(random);
    params.setExecutor(new PooledExecutor());
    params.setThreadLimit(1000);
    params.setStoreSize(storeSize);
    params.setRamStore(true);
    params.setEnableSwapping(true);
    params.setEnableARKs(true);
    params.setEnableULPRs(true);
    params.setEnablePerNodeFailureTables(true);
    params.setEnableSwapQueueing(true);
    params.setEnablePacketCoalescing(true);
    params.setOutputBandwidthLimit(12 * 1024);
    params.setEnableFOAF(enableFoaf);
    params.setConnectToSeednodes(true);
    return NodeStarter.createTestNode(params);
  }

  private static boolean waitForNodes(Node node, List<String> csvLine) throws InterruptedException {
    long start = System.currentTimeMillis();
    if (!TestUtil.waitForNodes(node)) {
      return false;
    }
    long end = System.currentTimeMillis();
    LOG.warn("SEED-TIME:{}", (end - start));
    csvLine.add(String.valueOf(end - start));
    return true;
  }

  private static void pushBlocks(String uid, Node node, List<String> csvLine) throws IOException {
    for (int i = 0; i <= MAX_N; i++) {
      RandomAccessBucket data = randomData(node);
      HighLevelSimpleClient client = node.getClientCore().makeClient((short) 0, false, false);
      FreenetURI uri = pushUri(uid, i);
      LOG.warn("PUSHING {}", uri);
      client.addEventHook(
          (ce, context) -> {
            if (LOG.isWarnEnabled()) {
              LOG.warn(ce.getDescription());
            }
          });

      try {
        InsertBlock block = new InsertBlock(data, new ClientMetadata(), uri);
        long start = System.currentTimeMillis();
        client.insert(block, false, null);
        long end = System.currentTimeMillis();

        LOG.warn("PUSH-TIME-{}:{}", i, (end - start));
        csvLine.add(String.valueOf(end - start));
      } catch (InsertException e) {
        LOG.warn("Insert failed for {}", uri, e);
        csvLine.add("N/A");
      } finally {
        data.free();
      }
    }
  }

  private static FreenetURI pushUri(String uid, int index) throws MalformedURLException {
    return new FreenetURI("KSK@" + uid + "-" + dateFormat.format(today.getTime()) + "-" + index);
  }

  private static void pullBlocks(String uid, Node node, List<String> csvLine) throws IOException {
    for (int i = 0; i <= MAX_N; i++) {
      HighLevelSimpleClient client = node.getClientCore().makeClient((short) 0, false, false);
      Calendar targetDate = today.copyCalendar();
      targetDate.add(Calendar.DAY_OF_MONTH, -((1 << i) - 1));

      FreenetURI uri = pullUri(uid, targetDate, i);
      LOG.warn("PULLING {}", uri);

      try {
        long start = System.currentTimeMillis();
        client.fetch(uri);
        long end = System.currentTimeMillis();

        LOG.warn("PULL-TIME-{}:{}", i, (end - start));
        csvLine.add(String.valueOf(end - start));
      } catch (FetchException e) {
        if (e.getMode() != FetchExceptionMode.ALL_DATA_NOT_FOUND
            && e.getMode() != FetchExceptionMode.DATA_NOT_FOUND) {
          LOG.warn("Fetch failed for {}", uri, e);
        }
        csvLine.add(FetchException.getShortMessage(e.getMode()));
      }
    }
  }

  private static FreenetURI pullUri(String uid, Calendar targetDate, int index)
      throws MalformedURLException {
    return new FreenetURI(
        "KSK@" + uid + "-" + dateFormat.format(targetDate.getTime()) + "-" + index);
  }

  private static void parkNodes(TestNodes nodes) {
    try {
      if (nodes.node != null) {
        nodes.node.park();
      }
    } catch (Exception e) {
      LOG.debug("Failed to park first node", e);
    }
    try {
      if (nodes.node2 != null) {
        nodes.node2.park();
      }
    } catch (Exception e) {
      LOG.debug("Failed to park second node", e);
    }
  }

  private static void readDumpElements(File file, TreeMap<GregorianCalendar, DumpElement> map)
      throws IOException, ParseException {
    Calendar prevDate = null;
    try (FileInputStream fis = new FileInputStream(file);
        BufferedReader br = new BufferedReader(new InputStreamReader(fis, ENCODING))) {
      String line;
      while ((line = br.readLine()) != null) {
        ParsedDumpLine parsed = parseDumpLine(line, prevDate);
        prevDate = parsed.calendar;
        map.put(parsed.calendar, parsed.element);
      }
    }
  }

  private static ParsedDumpLine parseDumpLine(String line, Calendar prevDate)
      throws ParseException {
    String[] split = line.split(",");
    Date date = dateFormat.parse(split[0]);
    GregorianCalendar calendar = new GregorianCalendar(TimeZone.getTimeZone("GMT"));
    calendar.setTime(date);
    if (LOG.isWarnEnabled()) {
      LOG.warn("Date: {}", dateFormat.format(calendar.getTime()));
    }
    if (prevDate != null) {
      long now = calendar.getTimeInMillis();
      long prev = prevDate.getTimeInMillis();
      long dist = DAYS.convert(now - prev, MILLISECONDS);
      if (dist != 1) {
        LOG.warn("{} days since last report", dist);
      }
    }

    DumpElement element = buildDumpElement(split, calendar);
    normalizeCalendar(calendar);
    return new ParsedDumpLine(calendar, element);
  }

  private static DumpElement buildDumpElement(String[] split, GregorianCalendar calendar) {
    int version = Integer.parseInt(split[1]);
    if (split.length == 2) {
      return new DumpElement(calendar, version);
    }
    int[] pushTimes = new int[MAX_N + 1];
    String[] pushFailures = new String[MAX_N + 1];
    readTimes(split, 3, pushTimes, pushFailures);
    if (split.length <= 3 + MAX_N + 1) {
      return new DumpElement(calendar, version, pushTimes, pushFailures);
    }
    int[] pullTimes = new int[MAX_N + 1];
    String[] pullFailures = new String[MAX_N + 1];
    readTimes(split, 3 + MAX_N + 2, pullTimes, pullFailures);
    return new DumpElement(calendar, version, pushTimes, pushFailures, pullTimes, pullFailures);
  }

  private static void readTimes(String[] split, int startIndex, int[] times, String[] failures) {
    for (int i = 0; i <= MAX_N; i++) {
      String s = split[startIndex + i];
      try {
        times[i] = Integer.parseInt(s);
      } catch (NumberFormatException _) {
        failures[i] = s;
      }
    }
  }

  private static void normalizeCalendar(GregorianCalendar calendar) {
    calendar.set(Calendar.MILLISECOND, 0);
    calendar.set(Calendar.SECOND, 0);
    calendar.set(Calendar.MINUTE, 0);
    calendar.set(Calendar.HOUR_OF_DAY, 0);
  }

  private static void summarizeDelta(
      TreeMap<GregorianCalendar, DumpElement> map, int delta, int index) {
    LOG.warn("Checking delta: {} days", delta);
    DeltaStats stats = new DeltaStats();
    for (Entry<GregorianCalendar, DumpElement> entry : map.entrySet()) {
      DumpElement element = entry.getValue();
      if (element.pullTimes == null) {
        continue;
      }
      stats.processEntry(map, entry.getKey(), element, delta, index);
    }
    stats.printSummary(delta);
  }

  static class DumpElement {
    /**
     * Creates a dump element for a run that only captured seed time and version.
     *
     * <p>The resulting element contains no push or pull timing arrays. It is used when the CSV line
     * contains only the date and build version, typically due to early failure or incomplete data.
     * The stored {@code seedTime} remains set to its sentinel value, and the missing arrays signal
     * that no per-key timings were recorded for this run.
     *
     * @param date run date normalized to midnight in GMT, non-null
     * @param version build number parsed from the CSV line for the run
     */
    public DumpElement(GregorianCalendar date, int version) {
      this.date = date;
      this.version = version;
      this.seedTime = -1;
      this.pushTimes = null;
      this.pushFailures = null;
      this.pullTimes = null;
      this.pullFailures = null;
    }

    /**
     * Creates a dump element that contains push timing data but no pull timings.
     *
     * <p>The push arrays store integer millisecond durations or zero for failures; failure strings
     * provide the raw CSV tokens when timing could not be parsed. Pull arrays are left {@code null}
     * to indicate they are unavailable for this run, which commonly happens when the fetch phase
     * did not complete or the CSV line ended after the push data.
     *
     * @param date run date normalized to midnight in GMT, non-null
     * @param version build number parsed from the CSV line for the run
     * @param pushTimes per-index push durations in milliseconds, zero for failure entries
     * @param pushFailures per-index failure token when a push time was not numeric
     */
    public DumpElement(
        GregorianCalendar date, int version, int[] pushTimes, String[] pushFailures) {
      this.date = date;
      this.version = version;
      this.seedTime = -1;
      this.pushTimes = pushTimes;
      this.pushFailures = pushFailures;
      this.pullTimes = null;
      this.pullFailures = null;
    }

    /**
     * Creates a dump element that includes both push and pull timing data.
     *
     * <p>The push and pull arrays store integer millisecond durations or zero for failures; the
     * failure arrays capture the raw CSV tokens when timing could not be parsed. All arrays are
     * stored by reference and are expected to be aligned by index. This form represents the most
     * complete data set for a run, enabling analysis of end-to-end retention and fetch latency.
     *
     * @param date run date normalized to midnight in GMT, non-null
     * @param version build number parsed from the CSV line for the run
     * @param pushTimes per-index push durations in milliseconds, zero for failure entries
     * @param pushFailures per-index failure token when a push time was not numeric
     * @param pullTimes per-index pull durations in milliseconds, zero for failure entries
     * @param pullFailures per-index failure token when a pull time was not numeric
     */
    public DumpElement(
        GregorianCalendar date,
        int version,
        int[] pushTimes,
        String[] pushFailures,
        int[] pullTimes,
        String[] pullFailures) {
      this.date = date;
      this.version = version;
      this.seedTime = -1;
      this.pushTimes = pushTimes;
      this.pushFailures = pushFailures;
      this.pullTimes = pullTimes;
      this.pullFailures = pullFailures;
    }

    final GregorianCalendar date;
    final int version;
    final long seedTime;
    final int[] pushTimes; // 0 = failure, look up in pushFailures
    final String[] pushFailures;
    final int[] pullTimes;
    final String[] pullFailures;
  }

  private static RandomAccessBucket randomData(Node node) throws IOException {
    RandomAccessBucket data = node.getClientCore().getTempBucketFactory().makeBucket(TEST_SIZE);
    try (OutputStream os = data.getOutputStream()) {
      byte[] buf = new byte[4096];
      long written = 0;
      while (written < TEST_SIZE) {
        node.getFastWeakRandom().nextBytes(buf);
        int toWrite = (int) Math.min(TEST_SIZE - written, buf.length);
        os.write(buf, 0, toWrite);
        written += toWrite;
      }
    }
    return data;
  }

  private static final class TestNodes {
    private Node node;
    private Node node2;
  }

  private record ParsedDumpLine(GregorianCalendar calendar, DumpElement element) {}

  private static final class DeltaStats {
    private int failures;
    private int successes;
    private long successTime;
    private int noMatch;
    private int insertFailure;
    private final Map<String, Integer> failureModes = new HashMap<>();

    private void processEntry(
        TreeMap<GregorianCalendar, DumpElement> map,
        GregorianCalendar date,
        DumpElement element,
        int delta,
        int index) {
      if (element.pullTimes == null || element.pullFailures == null) {
        return;
      }
      GregorianCalendar targetDate = (GregorianCalendar) date.clone();
      targetDate.add(Calendar.DAY_OF_MONTH, -delta);
      LOG.warn("Checking {} for {} delta {}", targetDate.getTime(), element.date.getTime(), delta);
      DumpElement inserted = map.get(targetDate);
      if (inserted == null) {
        LOG.warn("No match");
        noMatch++;
        return;
      }
      if (inserted.pushTimes == null || inserted.pushTimes[index] == 0) {
        LOG.warn("Insert failure");
        if (element.pullTimes[index] != 0) {
          LOG.warn("Fetched it anyway??!?!?: time {}", element.pullTimes[index]);
        }
        insertFailure++;
      }
      if (element.pullTimes[index] == 0) {
        recordFailure(element.pullFailures[index]);
        failures++;
      } else {
        successes++;
        successTime += element.pullTimes[index];
      }
    }

    private void recordFailure(String failureMode) {
      failureModes.merge(failureMode, 1, Integer::sum);
    }

    private void printSummary(int delta) {
      LOG.warn("Successes: {}", successes);
      if (successes != 0) {
        LOG.warn("Average success time {}", (successTime / successes));
      }
      LOG.warn("Failures: {}", failures);
      for (Map.Entry<String, Integer> entry : failureModes.entrySet()) {
        LOG.warn("{} : {}", entry.getKey(), entry.getValue());
      }
      LOG.warn("No match: {}", noMatch);
      LOG.warn("Insert failure: {}", insertFailure);
      double psuccess = (successes * 1.0 / (1.0 * (successes + failures)));
      LOG.warn(
          "Success rate for {} days: {} ({} samples)", delta, psuccess, (successes + failures));
      if (delta != 0) {
        double halfLifeEstimate = -1 * Math.log(2) / (Math.log(psuccess) / delta);
        LOG.warn("Half-life estimate: {} days", halfLifeEstimate);
      }
      LOG.warn("");
    }
  }
}
