package network.crypta.node.simulator;

import static java.util.concurrent.TimeUnit.HOURS;

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
import java.util.List;
import java.util.TimeZone;
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
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

/**
 * Runs a long-term mixed hash key (MHK) durability simulation and summarizes fetch success rates.
 *
 * <p>The test inserts one single-block CHK three times and three additional MHK-related CHKs once
 * each, records insertion timing, and later replays fetches to measure how often each strategy
 * succeeds. Results are appended to a per-run CSV file named after the supplied identifier, and
 * parsing logic can locate the target date window to compute success metrics for a specific run.
 * This class is a standalone command-line harness intended for manual simulation runs rather than a
 * reusable library component.
 *
 * <p>Notable behaviors include deterministic file naming, early exit on inconsistent insert URIs,
 * and logging-oriented progress reporting. The implementation is single-threaded, mutates local
 * files under the working directory, and does not attempt to coordinate concurrent invocations.
 *
 * <ul>
 *   <li>Creates a temporary test node and inserts sample data.
 *   <li>Writes a CSV row with insert and fetch timing outcomes.
 *   <li>Parses prior rows to evaluate success rates for a target day.
 * </ul>
 *
 * @author Matthew Toseland &lt;toad@amphibian.dyndns.org&gt; (0xE43DA450)
 * @see LongTermTest
 */
public class LongTermMHKTest extends LongTermTest {

  private static final Logger LOGGER = LoggerFactory.getLogger(LongTermMHKTest.class);

  private static final int TEST_SIZE = 64 * 1024;

  private static final int EXIT_DIFFERENT_URI = 262;

  private static final int DARKNET_PORT1 = 5010;
  private static final int OPENNET_PORT1 = 5011;

  /** Delta - the number of days we wait before fetching. */
  private static final int DELTA = 7;

  /**
   * Creates a new simulation harness instance.
   *
   * <p>The class is primarily used through its static {@link #main(String[])} entry point, but a
   * public constructor keeps the type compatible with reflective tooling and doclint requirements.
   * The instance carries no mutable state, so constructing it has no side effects and does not
   * allocate external resources.
   */
  public LongTermMHKTest() {
    // Intentionally empty: this class is used via static entry points only.
  }

  /**
   * Launches the MHK simulation, records inserts, and optionally replays fetches for the target
   * day.
   *
   * <p>The first argument supplies a unique identifier used to name the CSV output. An optional
   * {@code --dump} flag skips inserts and only parses the existing CSV to compute statistics. The
   * method writes status lines to disk, logs progress, and terminates the process with an exit code
   * that reflects the outcome. It is safe to call only from a standalone JVM process, because it
   * performs {@link System#exit(int)} on completion.
   *
   * <pre>{@code
   * LongTermMHKTest.main(new String[] {"run-2025-12-20"});
   * }</pre>
   *
   * @param args command-line arguments: a unique identifier and optional {@code --dump} flag.
   */
  @SuppressWarnings("java:S1181")
  public static void main(String[] args) {
    Args parsedArgs = parseArgs(args);
    String uid = parsedArgs.uid;
    boolean dumpOnly = parsedArgs.dumpOnly;

    List<String> csvLine = new ArrayList<>();
    recordRunStart(csvLine);

    int exitCode = 0;
    Node node = null;
    HighLevelSimpleClient client = null;
    File file = new File("mhk-test-" + uid + ".csv");

    try {
      if (!dumpOnly) {
        InsertResult insertResult = insertData(uid, csvLine);
        node = insertResult.node;
        client = insertResult.client;
        exitCode = insertResult.exitCode;
        if (insertResult.shouldStop) {
          return;
        }
      }

      ParseResult parseResult = parseFile(file);
      if (!dumpOnly && parseResult.match) {
        fetchData(client, parseResult.singleURI, parseResult.mhkURIs, csvLine);
      }
    } catch (Throwable t) {
      if (t instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
      LOGGER.error("Test failed unexpectedly", t);
      exitCode = EXIT_THREW_SOMETHING;
    } finally {
      parkNode(node);
      parkNode(null);

      if (!dumpOnly) {
        writeToStatusLog(file, csvLine);
      }
      System.exit(exitCode);
    }
  }

  private static Args parseArgs(String[] args) {
    if (args.length < 1 || args.length > 2) {
      LOGGER.error("Usage: java freenet.node.simulator.LongTermPushPullTest <unique identifier>");
      System.exit(1);
    }
    String uid = args[0];
    boolean dumpOnly = args.length == 2 && "--dump".equalsIgnoreCase(args[1]);
    return new Args(uid, dumpOnly);
  }

  private static void recordRunStart(List<String> csvLine) {
    String formattedDate = dateFormat.format(today.getTime());
    LOGGER.info("DATE:{}", formattedDate);
    csvLine.add(formattedDate);

    int buildNumber = Version.currentBuildNumber();
    LOGGER.info("Version:{}", buildNumber);
    csvLine.add(String.valueOf(buildNumber));
  }

  private static InsertResult insertData(String uid, List<String> csvLine)
      throws IOException, NodeInitException, InterruptedException {
    TestSetup setup = prepareTestDirectory(uid);
    Node node = createNode(setup.dir, setup.random);
    long seedTime = startAndWaitForNode(node);
    if (seedTime < 0) {
      return new InsertResult(node, null, EXIT_FAILED_TARGET, true);
    }
    LOGGER.info("SEED-TIME:{}", seedTime);
    csvLine.add(String.valueOf(seedTime));

    try (RandomAccessBucket single = randomData(node);
        RandomAccessBucket mhk0 = randomData(node);
        RandomAccessBucket mhk1 = randomData(node);
        RandomAccessBucket mhk2 = randomData(node)) {
      RandomAccessBucket[] mhks = new RandomAccessBucket[] {mhk0, mhk1, mhk2};
      HighLevelSimpleClient client = node.getClientCore().makeClient((short) 0, false, false);

      int successes = insertSingleBlocks(client, single, csvLine);
      logInsertOutcome("single block", successes);

      successes = insertMhkBlocks(client, mhks, csvLine, successes);
      logInsertOutcome("MHK", successes);

      return new InsertResult(node, client, 0, false);
    }
  }

  private static ParseResult parseFile(File file) throws IOException, ParseException {
    boolean match = false;
    FreenetURI singleURI = null;
    FreenetURI[] mhkURIs = null;
    ParseCounters counters = new ParseCounters();

    try (FileInputStream fis = new FileInputStream(file);
        BufferedReader br = new BufferedReader(new InputStreamReader(fis, ENCODING))) {
      String line;
      while ((line = br.readLine()) != null) {
        LineOutcome outcome = parseLine(line, counters);
        if (!outcome.shouldContinue && outcome.match) {
          match = true;
          singleURI = outcome.singleURI;
          mhkURIs = outcome.mhkURIs;
          break;
        }
      }
    }

    logParseSummary(counters);

    return new ParseResult(match, singleURI, mhkURIs);
  }

  private static LineOutcome parseLine(String line, ParseCounters counters) throws ParseException {
    FreenetURI singleURI;
    FreenetURI[] mhkURIs;

    String[] split = line.split("!");
    Date date = dateFormat.parse(split[0]);
    GregorianCalendar calendar = new GregorianCalendar(TimeZone.getTimeZone("GMT"));
    calendar.setTime(date);
    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("Date: {}", dateFormat.format(calendar.getTime()));
    }

    GregorianCalendar target = today.copyCalendar();
    target.set(Calendar.HOUR_OF_DAY, 0);
    target.set(Calendar.MINUTE, 0);
    target.set(Calendar.MILLISECOND, 0);
    target.set(Calendar.SECOND, 0);
    target.add(Calendar.DAY_OF_MONTH, -DELTA);
    calendar.set(Calendar.HOUR_OF_DAY, 0);
    calendar.set(Calendar.MINUTE, 0);
    calendar.set(Calendar.MILLISECOND, 0);
    calendar.set(Calendar.SECOND, 0);
    calendar.getTime();
    target.getTime();

    try {
      ParseLineResult parsed = parseInsertSection(split, counters);
      if (parsed.shortLine) {
        return LineOutcome.continueLine();
      }
      singleURI = parsed.singleURI;
      mhkURIs = parsed.mhkURIs;
    } catch (NumberFormatException e) {
      LOGGER.error("Failed to parse row: {}", e.toString());
      counters.linesNoNumber++;
      return LineOutcome.continueLine();
    } catch (MalformedURLException e) {
      LOGGER.error("Failed to parse row: {}", e.toString());
      counters.linesNoURL++;
      return LineOutcome.continueLine();
    }

    if (Math.abs(target.getTimeInMillis() - calendar.getTimeInMillis()) < HOURS.toMillis(12)) {
      if (LOGGER.isInfoEnabled()) {
        LOGGER.info(
            "Found row for target date {} : {}",
            dateFormat.format(target.getTime()),
            dateFormat.format(calendar.getTime()));
        LOGGER.info("Version: {}", split[1]);
      }
      return LineOutcome.match(singleURI, mhkURIs);
    }

    boolean hasFetchSection = split.length > 3 + 6 + 6;
    if (hasFetchSection) {
      parseFetchSection(split, counters, date);
    } else {
      counters.linesNoFetch++;
    }

    return LineOutcome.noMatch();
  }

  private static TestSetup prepareTestDirectory(String uid) throws IOException {
    File dir = new File("longterm-mhk-test-" + uid);
    FileUtil.removeAll(dir);
    RandomSource random = NodeStarter.globalTestInit(dir, false, Level.ERROR, "", false, null);
    File seednodes = new File("seednodes.fref");
    if (!seednodes.exists() || seednodes.length() == 0 || !seednodes.canRead()) {
      LOGGER.error("Unable to read seednodes.fref, it doesn't exist, or is empty");
      System.exit(EXIT_NO_SEEDNODES);
    }

    File innerDir = new File(dir, Integer.toString(DARKNET_PORT1));
    if (!innerDir.mkdir() && !innerDir.isDirectory()) {
      LOGGER.error("Failed to create directory {}", innerDir.getAbsolutePath());
    }
    try (FileInputStream seedInputStream = new FileInputStream(seednodes)) {
      FileUtil.writeTo(seedInputStream, new File(innerDir, "seednodes.fref"));
    }

    return new TestSetup(dir, random);
  }

  private static Node createNode(File dir, RandomSource random) throws NodeInitException {
    TestNodeParameters params =
        TestNodeParameterFactory.create(
            dir,
            random,
            new PooledExecutor(),
            p -> {
              p.setPort(DARKNET_PORT1);
              p.setOpennetPort(OPENNET_PORT1);
              p.setMaxHTL(Node.DEFAULT_MAX_HTL);
              p.setThreadLimit(1000);
              p.setStoreSize(4L * 1024 * 1024);
              p.setRamStore(true);
              p.setEnableSwapping(true);
              p.setEnableARKs(true);
              p.setEnableULPRs(true);
              p.setEnablePerNodeFailureTables(true);
              p.setEnableSwapQueueing(true);
              p.setEnablePacketCoalescing(true);
              p.setOutputBandwidthLimit(12 * 1024);
              p.setEnableFOAF(true);
              p.setConnectToSeednodes(true);
            });
    Node node = NodeStarter.createTestNode(params);
    Logging.setRootLevel(Level.ERROR);
    return node;
  }

  private static long startAndWaitForNode(Node node)
      throws NodeInitException, InterruptedException {
    node.start(true);
    long t1 = System.currentTimeMillis();
    if (!TestUtil.waitForNodes(node)) {
      return -1;
    }
    long t2 = System.currentTimeMillis();
    return t2 - t1;
  }

  private static int insertSingleBlocks(
      HighLevelSimpleClient client, RandomAccessBucket single, List<String> csvLine) {
    LOGGER.error("Inserting single block 3 times");
    InsertBlock block = new InsertBlock(single, new ClientMetadata(), FreenetURI.EMPTY_CHK_URI);
    FreenetURI uri = null;
    int successes = 0;
    for (int i = 0; i < 3; i++) {
      LOGGER.error("Inserting single block, try #{}", i);
      try {
        long t1 = System.currentTimeMillis();
        FreenetURI thisURI = client.insert(block, false, null);
        if (uri != null && !thisURI.equals(uri)) {
          LOGGER.error("URI {} is {} but previous is {}", i, thisURI, uri);
          System.exit(EXIT_DIFFERENT_URI);
        }
        uri = thisURI;
        long t2 = System.currentTimeMillis();

        LOGGER.info("PUSH-TIME-{}:{} for {} for single block", i, t2 - t1, uri);
        csvLine.add(String.valueOf(t2 - t1));
        csvLine.add(uri.toASCIIString());
        successes++;
      } catch (InsertException e) {
        LOGGER.error("Insert failed for single block insert {}", i, e);
        csvLine.add(InsertException.getShortMessage(e.getMode()));
        csvLine.add("N/A");
        LOGGER.info("INSERT FAILED: {} for insert {} for single block", e, i);
      }
    }
    return successes;
  }

  private static int insertMhkBlocks(
      HighLevelSimpleClient client,
      RandomAccessBucket[] mhks,
      List<String> csvLine,
      int successes) {
    for (int i = 0; i < 3; i++) {
      LOGGER.error("Inserting MHK #{}", i);
      InsertBlock block = new InsertBlock(mhks[i], new ClientMetadata(), FreenetURI.EMPTY_CHK_URI);
      try {
        long t1 = System.currentTimeMillis();
        FreenetURI uri = client.insert(block, false, null);
        long t2 = System.currentTimeMillis();

        LOGGER.info("PUSH-TIME-{}:{} for {} for MHK #{}", i, t2 - t1, uri, i);
        csvLine.add(String.valueOf(t2 - t1));
        csvLine.add(uri.toASCIIString());
        successes++;
      } catch (InsertException e) {
        LOGGER.error("Insert failed for MHK #{}", i, e);
        csvLine.add(InsertException.getShortMessage(e.getMode()));
        csvLine.add("N/A");
        LOGGER.info("INSERT FAILED: {} for MHK #{}", e, i);
      }
    }
    return successes;
  }

  private static void logInsertOutcome(String label, int successes) {
    if (successes == 3) {
      LOGGER.error("All inserts succeeded for {}: {}", label, successes);
    } else if (successes != 0) {
      LOGGER.error("Some inserts succeeded for {}: {}", label, successes);
    } else {
      LOGGER.error("NO INSERTS SUCCEEDED FOR {}: {}", label, successes);
    }
  }

  private static ParseLineResult parseInsertSection(String[] split, ParseCounters counters)
      throws MalformedURLException {
    if (split.length < 3) {
      counters.linesTooShort++;
      return ParseLineResult.shortLine();
    }
    int seedTime = Integer.parseInt(split[2]);
    LOGGER.info("Seed time: {}", seedTime);

    if (split.length < 4) {
      counters.linesTooShort++;
      return ParseLineResult.shortLine();
    }

    int token = 3;
    FreenetURI singleURI = null;
    FreenetURI[] mhkURIs = new FreenetURI[3];

    for (int i = 0; i < 3; i++) {
      int insertTime = Integer.parseInt(split[token]);
      LOGGER.info("Single key insert {} : {}", i, insertTime);
      token++;
      FreenetURI thisURI = new FreenetURI(split[token]);
      if (singleURI == null) {
        singleURI = thisURI;
      } else if (!singleURI.equals(thisURI)) {
        LOGGER.error(
            "URI is not the same for all 3 inserts: was {} but {} is {}", singleURI, i, thisURI);
        counters.linesBroken++;
        return ParseLineResult.shortLine();
      }
      token++;
    }
    LOGGER.info("Single key URI: {}", singleURI);

    for (int i = 0; i < 3; i++) {
      int insertTime = Integer.parseInt(split[token]);
      token++;
      mhkURIs[i] = new FreenetURI(split[token]);
      token++;
      LOGGER.info("MHK #{} URI: {} insert time {}", i, mhkURIs[i], insertTime);
    }

    return new ParseLineResult(singleURI, mhkURIs, false);
  }

  private static void parseFetchSection(String[] split, ParseCounters counters, Date date) {
    int token = 3 + 6 + 6;
    boolean singleKeySuccess = parseSingleKeyFetches(split, token, date);
    token += 3;

    boolean mhkSuccess = parseMhkFetches(split, token, counters, date);
    counters.total++;
    if (singleKeySuccess) {
      counters.singleKeysSucceeded++;
    }
    if (mhkSuccess) {
      counters.mhkSucceeded++;
    }
  }

  private static boolean parseSingleKeyFetches(String[] split, int token, Date date) {
    boolean singleKeySuccess = false;
    for (int i = 0; i < 3; i++) {
      if (!singleKeySuccess) {
        try {
          int fetchTime = Integer.parseInt(split[token]);
          singleKeySuccess = true;
          LOGGER.info("Fetched single key on try {} on {} in {}ms", i, date, fetchTime);
        } catch (NumberFormatException _) {
          LOGGER.info("Failed fetch single key on {} try {} : {}", date, i, split[token]);
        }
      }
      token++;
    }
    return singleKeySuccess;
  }

  private static boolean parseMhkFetches(
      String[] split, int token, ParseCounters counters, Date date) {
    boolean mhkSuccess = false;
    for (int i = 0; i < 3; i++) {
      counters.totalSingleKeyFetches++;
      try {
        int fetchTime = Integer.parseInt(split[token]);
        mhkSuccess = true;
        counters.totalSingleKeySuccesses++;
        LOGGER.info("Fetched MHK #{} on {} in {}ms", i, date, fetchTime);
      } catch (NumberFormatException _) {
        LOGGER.info("Failed fetch MHK #{} on {} : {}", i, date, split[token]);
      }
      token++;
    }
    return mhkSuccess;
  }

  private static void logParseSummary(ParseCounters counters) {
    LOGGER.info(
        "Lines where insert failed or no fetch: too short: {} broken: {} no number: {} no url: {}"
            + " no fetch {}",
        counters.linesTooShort,
        counters.linesBroken,
        counters.linesNoNumber,
        counters.linesNoURL,
        counters.linesNoFetch);
    LOGGER.info("Total attempts where insert succeeded and fetch executed: {}", counters.total);
    LOGGER.info("Single keys succeeded: {}", counters.singleKeysSucceeded);
    LOGGER.info("MHKs succeeded: {}", counters.mhkSucceeded);
    LOGGER.info("Single key individual fetches: {}", counters.totalSingleKeyFetches);
    LOGGER.info("Single key individual fetches succeeded: {}", counters.totalSingleKeySuccesses);
    LOGGER.info(
        "Success rate for individual keys (from MHK inserts): {}",
        ((double) counters.totalSingleKeySuccesses) / ((double) counters.totalSingleKeyFetches));
    LOGGER.info(
        "Success rate for the single key triple inserted: {}",
        ((double) counters.singleKeysSucceeded) / ((double) counters.total));
    LOGGER.info(
        "Success rate for the MHK (success = any of the 3 different keys worked): {}",
        ((double) counters.mhkSucceeded) / ((double) counters.total));
  }

  private static void fetchData(
      HighLevelSimpleClient client,
      FreenetURI singleURI,
      FreenetURI[] mhkURIs,
      List<String> csvLine) {
    fetchSingleUri(client, singleURI, csvLine);
    fetchMhkUris(client, mhkURIs, csvLine);
  }

  private static void fetchSingleUri(
      HighLevelSimpleClient client, FreenetURI singleURI, List<String> csvLine) {
    boolean fetched = false;
    for (int i = 0; i < 3; i++) {
      if (fetched) {
        csvLine.add("");
        continue;
      }
      try {
        long t1 = System.currentTimeMillis();
        client.fetch(singleURI);
        long t2 = System.currentTimeMillis();

        LOGGER.info("PULL-TIME FOR SINGLE URI:{}", t2 - t1);
        csvLine.add(String.valueOf(t2 - t1));
        fetched = true;
      } catch (FetchException e) {
        if (e.getMode() != FetchExceptionMode.ALL_DATA_NOT_FOUND
            && e.getMode() != FetchExceptionMode.DATA_NOT_FOUND) {
          LOGGER.error("Unexpected fetch error for single URI", e);
        }
        csvLine.add(FetchException.getShortMessage(e.getMode()));
        LOGGER.error("FAILED PULL FOR SINGLE URI: {}", e.toString());
      }
    }
  }

  private static void fetchMhkUris(
      HighLevelSimpleClient client, FreenetURI[] mhkURIs, List<String> csvLine) {
    for (int i = 0; i < mhkURIs.length; i++) {
      try {
        long t1 = System.currentTimeMillis();
        client.fetch(mhkURIs[i]);
        long t2 = System.currentTimeMillis();

        LOGGER.info("PULL-TIME FOR MHK #{}:{}", i, t2 - t1);
        csvLine.add(String.valueOf(t2 - t1));
      } catch (FetchException e) {
        if (e.getMode() != FetchExceptionMode.ALL_DATA_NOT_FOUND
            && e.getMode() != FetchExceptionMode.DATA_NOT_FOUND) {
          LOGGER.error("Unexpected fetch error for MHK #{}", i, e);
        }
        csvLine.add(FetchException.getShortMessage(e.getMode()));
        LOGGER.error("FAILED PULL FOR MHK #{}: {}", i, e.toString());
      }
    }
  }

  private static void parkNode(Node node) {
    if (node == null) {
      return;
    }
    try {
      node.park();
    } catch (Exception e) {
      LOGGER.debug("Failed to park node", e);
    }
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

  private static final class Args {
    private final String uid;
    private final boolean dumpOnly;

    private Args(String uid, boolean dumpOnly) {
      this.uid = uid;
      this.dumpOnly = dumpOnly;
    }
  }

  private static final class InsertResult {
    private final Node node;
    private final HighLevelSimpleClient client;
    private final int exitCode;
    private final boolean shouldStop;

    private InsertResult(
        Node node, HighLevelSimpleClient client, int exitCode, boolean shouldStop) {
      this.node = node;
      this.client = client;
      this.exitCode = exitCode;
      this.shouldStop = shouldStop;
    }
  }

  private static final class ParseResult {
    private final boolean match;
    private final FreenetURI singleURI;
    private final FreenetURI[] mhkURIs;

    private ParseResult(boolean match, FreenetURI singleURI, FreenetURI[] mhkURIs) {
      this.match = match;
      this.singleURI = singleURI;
      this.mhkURIs = mhkURIs;
    }
  }

  private static final class LineOutcome {
    private final boolean shouldContinue;
    private final boolean match;
    private final FreenetURI singleURI;
    private final FreenetURI[] mhkURIs;

    private LineOutcome(
        boolean shouldContinue, boolean match, FreenetURI singleURI, FreenetURI[] mhkURIs) {
      this.shouldContinue = shouldContinue;
      this.match = match;
      this.singleURI = singleURI;
      this.mhkURIs = mhkURIs;
    }

    private static LineOutcome continueLine() {
      return new LineOutcome(true, false, null, null);
    }

    private static LineOutcome noMatch() {
      return new LineOutcome(false, false, null, null);
    }

    private static LineOutcome match(FreenetURI singleURI, FreenetURI[] mhkURIs) {
      return new LineOutcome(false, true, singleURI, mhkURIs);
    }
  }

  private static final class ParseCounters {
    private int linesTooShort;
    private int linesBroken;
    private int linesNoNumber;
    private int linesNoURL;
    private int linesNoFetch;
    private int total;
    private int singleKeysSucceeded;
    private int mhkSucceeded;
    private int totalSingleKeyFetches;
    private int totalSingleKeySuccesses;
  }

  private static final class TestSetup {
    private final File dir;
    private final RandomSource random;

    private TestSetup(File dir, RandomSource random) {
      this.dir = dir;
      this.random = random;
    }
  }

  private static final class ParseLineResult {
    private final FreenetURI singleURI;
    private final FreenetURI[] mhkURIs;
    private final boolean shortLine;

    private ParseLineResult(FreenetURI singleURI, FreenetURI[] mhkURIs, boolean shortLine) {
      this.singleURI = singleURI;
      this.mhkURIs = mhkURIs;
      this.shortLine = shortLine;
    }

    private static ParseLineResult shortLine() {
      return new ParseLineResult(null, null, true);
    }
  }
}
