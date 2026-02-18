package network.crypta.node.simulator;

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
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchWaiter;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.InsertBlock;
import network.crypta.client.InsertException;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.NodeInitException;
import network.crypta.node.NodeStarter;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestClientBuilder;
import network.crypta.node.Version;
import network.crypta.support.Logging;
import network.crypta.support.PooledExecutor;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

import static java.util.concurrent.TimeUnit.HOURS;

/**
 * Long-term simulator driver that inserts many single blocks and later re-fetches them at fixed day
 * offsets.
 *
 * <p>This class is a standalone, repeatable harness intended for long-running latency and
 * availability experiments against a local test node. One execution creates a temporary node
 * directory, inserts {@link #INSERTED_BLOCKS} randomly generated single-block CHKs, and records the
 * observed insert times and resulting URIs. Subsequent executions with the same identifier read
 * prior result rows from a status file and opportunistically fetch those historical URIs when the
 * current run falls near a target day offset.
 *
 * <p>The target offsets are computed as {@code (2^n - 1)} days for {@code n = 0..MAX_N}, with a
 * 12-hour tolerance to avoid false negatives due to clock skew or scheduling. Fetch retries are
 * explicitly disabled to measure first-attempt behavior, and aggregate totals are logged across all
 * matched deltas.
 *
 * <ul>
 *   <li><b>Lifecycle:</b> Run via {@link #main(String[])}; intermediate state is persisted in the
 *       status file, not in memory.
 *   <li><b>Concurrency:</b> Inserts run on daemon threads; {@link InsertBatch} provides a simple
 *       join mechanism for this harness.
 *   <li><b>Thread-safety:</b> This type is not designed as a reusable API; it is a single-process
 *       tool that relies on synchronized blocks for its internal counters.
 * </ul>
 *
 * @author Matthew Toseland {@literal <toad@amphibian.dyndns.org>} (0xE43DA450)
 */
public class LongTermManySingleBlocksTest extends LongTermTest {

  private static final Logger LOGGER = LoggerFactory.getLogger(LongTermManySingleBlocksTest.class);

  /**
   * Creates a new instance of the harness.
   *
   * <p>This driver is typically invoked via {@link #main(String[])}, and callers generally do not
   * need to instantiate it directly. The explicit constructor exists so doc generation tools can
   * attach documentation to the otherwise implicit default constructor.
   */
  public LongTermManySingleBlocksTest() {
    // Intentionally empty: this harness is normally invoked via main(...) and has no instance
    // state.
  }

  /**
   * Coordinates a batch of asynchronous inserts and provides access to their outcomes.
   *
   * <p>This helper encapsulates the minimal synchronization needed by this long-term harness: it
   * tracks a count of currently running insert threads, exposes a blocking wait method, and returns
   * per-insert results as parallel arrays (URIs, durations, and exceptions). The batch preserves
   * the order in which inserts are started, so array indices correspond to the same insert across
   * the different accessors.
   *
   * <p>Thread-safety is intentionally narrow: methods are synchronized where required to publish
   * completion and result fields, and the typical call pattern is to enqueue work via {@link
   * #startInsert(InsertBlock)}, then call {@link #waitUntilFinished()} once, and only then read
   * results.
   */
  public static class InsertBatch {

    private final HighLevelSimpleClient client;
    private int runningInserts;
    private final ArrayList<BatchInsert> inserts = new ArrayList<>();

    /**
     * Creates a new insert batch that will execute inserts using the provided client.
     *
     * <p>The supplied client is used by every insert thread started by this batch. Callers are
     * expected to keep the client valid for the lifetime of the batch and to avoid mutating client
     * configuration concurrently in ways that would affect timing measurements.
     *
     * @param client client used to perform inserts; must be non-null and ready to use
     */
    public InsertBatch(HighLevelSimpleClient client) {
      this.client = client;
    }

    /**
     * Starts an asynchronous insert operation for a single block.
     *
     * <p>This method schedules the insert on a new daemon thread and returns immediately. Results
     * become visible after {@link #waitUntilFinished()} completes; before then, callers may observe
     * partially populated arrays and should treat them as unstable. Each started insert contributes
     * one entry to the arrays returned by {@link #getURIs()}, {@link #getTimes()}, and {@link
     * #getErrors()}.
     *
     * @param block block to insert; must be non-null and contain the data payload
     */
    public void startInsert(InsertBlock block) {
      BatchInsert bi = new BatchInsert(block);
      synchronized (this) {
        inserts.add(bi);
        runningInserts++;
        LOGGER.info("Insert scheduled; running inserts {}", runningInserts);
      }
      bi.start();
    }

    class BatchInsert implements Runnable {

      private final InsertBlock block;
      private long insertTime;
      private InsertException failed;
      private FreenetURI uri;

      public BatchInsert(InsertBlock block) {
        this.block = block;
      }

      public void start() {
        Thread t = new Thread(this);
        t.setDaemon(true);
        t.start();
      }

      @Override
      public void run() {
        long t1 = 0;
        long t2 = 0;
        FreenetURI thisURI = null;
        InsertException failure = null;
        try {
          t1 = System.currentTimeMillis();
          thisURI = client.insert(block, false, null);
          t2 = System.currentTimeMillis();
        } catch (InsertException e) {
          failure = e;
        } finally {
          synchronized (InsertBatch.this) {
            runningInserts--;
            LOGGER.info("Insert finished; running inserts {}", runningInserts);
            if (thisURI != null) {
              uri = thisURI;
              insertTime = t2 - t1;
            } else {
              failed = failure;
            }

            InsertBatch.this.notifyAll();
          }
        }
      }
    }

    /**
     * Blocks the current thread until all started inserts have completed.
     *
     * <p>This method waits until the internal running-insert counter reaches zero. If the waiting
     * thread is interrupted, it restores the interrupt flag and returns early; callers should treat
     * the batch as incomplete in that case and handle partial results appropriately.
     */
    public synchronized void waitUntilFinished() {
      while (true) {
        if (runningInserts == 0) return;
        try {
          wait();
        } catch (InterruptedException _) {
          Thread.currentThread().interrupt();
          return;
        }
      }
    }

    /**
     * Returns the inserted URIs in the order inserts were started.
     *
     * <p>Each position corresponds to a {@link #startInsert(InsertBlock)} call. Entries are {@code
     * null} when the corresponding insert failed or has not yet finished. For stable results, call
     * {@link #waitUntilFinished()} before accessing this array.
     *
     * @return snapshot array of resulting URIs; may contain {@code null} for failures
     */
    public synchronized FreenetURI[] getURIs() {
      FreenetURI[] uris = new FreenetURI[inserts.size()];
      for (int i = 0; i < uris.length; i++) uris[i] = inserts.get(i).uri;
      return uris;
    }

    /**
     * Returns per-insert durations, in milliseconds, in the order inserts were started.
     *
     * <p>Entries correspond one-to-one with {@link #getURIs()} indices. Failed inserts typically
     * report {@code 0} because no successful start/end timestamps were recorded. For stable
     * results, call {@link #waitUntilFinished()} before accessing this array.
     *
     * @return snapshot array of insert durations in milliseconds; values may be {@code 0} on
     *     failure
     */
    public synchronized long[] getTimes() {
      long[] times = new long[inserts.size()];
      for (int i = 0; i < times.length; i++) times[i] = inserts.get(i).insertTime;
      return times;
    }

    /**
     * Returns any insert failures observed for the batch, in the order inserts were started.
     *
     * <p>Array indices match {@link #getURIs()} and {@link #getTimes()}. Each entry is {@code null}
     * when the corresponding insert succeeded; otherwise it contains the {@link InsertException}
     * that was thrown by the client. Callers should typically invoke {@link #waitUntilFinished()}
     * first so that all failures have been recorded. This accessor is synchronized to provide
     * visibility of failures recorded by worker threads.
     *
     * @return snapshot array of insert exceptions; {@code null} indicates success
     */
    public synchronized InsertException[] getErrors() {
      InsertException[] errors = new InsertException[inserts.size()];
      for (int i = 0; i < errors.length; i++) errors[i] = inserts.get(i).failed;
      return errors;
    }
  }

  private static final int TEST_SIZE = 32 * 1024;

  private static final int DARKNET_PORT1 = 9010;
  private static final int OPENNET_PORT1 = 9011;

  private static final int MAX_N = 8;

  private static final int INSERTED_BLOCKS = 32;

  /**
   * Runs the long-term "many single blocks" experiment and writes/reads status rows on disk.
   *
   * <p>This entry point expects a stable identifier that becomes part of the output filenames. On a
   * fresh run it creates a dedicated working directory, starts a local test node, inserts {@link
   * #INSERTED_BLOCKS} single-block CHKs, and writes a row capturing timing and URI data. On later
   * runs with the same identifier, it reads the existing status file and, when the current run's
   * date is close to a target offset, performs a single fetch attempt for each previously inserted
   * URI with retries disabled.
   *
   * <p>This method exits the JVM with a status code that is also recorded in logs. It is designed
   * for execution as a standalone process rather than as a library call.
   *
   * @param args command-line arguments; the first element is a unique identifier used in filenames
   */
  public static void main(String[] args) {
    if (args.length < 1 || args.length > 2) {
      LOGGER.error("Usage: java freenet.node.simulator.LongTermPushPullTest <unique identifier>");
      System.exit(1);
    }
    String uid = args[0];

    List<String> csvLine = new ArrayList<>();
    String formattedDate = dateFormat.format(today.getTime());
    LOGGER.info("Run date: {}", formattedDate);
    csvLine.add(formattedDate);

    int buildNumber = Version.currentBuildNumber();
    LOGGER.info("Build version: {}", buildNumber);
    csvLine.add(String.valueOf(buildNumber));

    int exitCode = 0;
    Node node = null;

    File statusFile = new File("many-single-blocks-test-" + uid + ".csv");

    try {
      File dir = new File("longterm-mhk-test-" + uid);
      FileUtil.removeAll(dir);
      RandomSource random = NodeStarter.globalTestInit(dir, false, Level.ERROR, "", false, null);
      copySeednodesIntoDir(dir);

      node = createAndStartNode(dir, random);
      long seedTimeMillis = waitForSeedingMillis(node);
      if (seedTimeMillis < 0) {
        exitCode = EXIT_FAILED_TARGET;
        return;
      }
      LOGGER.info("Seed time millis: {}", seedTimeMillis);
      csvLine.add(String.valueOf(seedTimeMillis));

      HighLevelSimpleClient client =
          node.services().clientCore().makeClient((short) 0, false, false);
      insertBlocksAndRecord(node, client, csvLine);

      FetchContext fctx = configureFetchContext(client);
      RequestClient requestContext = new RequestClientBuilder().build();
      FetchTotals totals = new FetchTotals(MAX_N + 1);
      FetchRequestContext fetchRequestContext =
          new FetchRequestContext(client, fctx, requestContext);
      FetchRunContext runContext = new FetchRunContext(csvLine, fetchRequestContext);
      processExistingStatusFile(statusFile, runContext, totals);
      logTotals(totals);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      LOGGER.error("Long-term many single blocks run interrupted", e);
      exitCode = EXIT_THREW_SOMETHING;
    } catch (Exception e) {
      LOGGER.error("Long-term many single blocks run failed", e);
      exitCode = EXIT_THREW_SOMETHING;
    } finally {
      parkQuietly(node);
      parkQuietly(null);
      writeToStatusLog(statusFile, csvLine);

      LOGGER.info("Exiting with status {}", exitCode);
      System.exit(exitCode);
    }
  }

  private static void copySeednodesIntoDir(File dir) throws IOException {
    File seednodes = new File("seednodes.fref");
    ensureSeednodesReadable(seednodes);

    File innerDir = new File(dir, Integer.toString(DARKNET_PORT1));
    if (!innerDir.mkdir() && !innerDir.isDirectory()) {
      throw new IOException("Unable to create seednodes directory: " + innerDir.getAbsolutePath());
    }

    try (FileInputStream seedInputStream = new FileInputStream(seednodes)) {
      FileUtil.writeTo(seedInputStream, new File(innerDir, "seednodes.fref"));
    }
  }

  private static void ensureSeednodesReadable(File seednodes) {
    if (!seednodes.exists() || seednodes.length() == 0 || !seednodes.canRead()) {
      LOGGER.error("Unable to read seednodes.fref, it doesn't exist, or is empty");
      System.exit(EXIT_NO_SEEDNODES);
    }
  }

  private static Node createAndStartNode(File dir, RandomSource random) throws NodeInitException {
    NodeStarter.TestNodeParameters params = new NodeStarter.TestNodeParameters();
    params.setPort(DARKNET_PORT1);
    params.setOpennetPort(OPENNET_PORT1);
    params.setBaseDirectory(dir);
    params.setDisableProbabilisticHTLs(false);
    params.setMaxHTL(Node.DEFAULT_MAX_HTL);
    params.setRandom(random);
    params.setExecutor(new PooledExecutor());
    params.setThreadLimit(1000);
    params.setStoreSize(4L * 1024 * 1024);
    params.setRamStore(true);
    params.setEnableSwapping(true);
    params.setEnableARKs(true);
    params.setEnableULPRs(true);
    params.setEnablePerNodeFailureTables(true);
    params.setEnableSwapQueueing(true);
    params.setEnablePacketCoalescing(true);
    params.setOutputBandwidthLimit(12 * 1024);
    params.setEnableFOAF(true);
    params.setConnectToSeednodes(true);

    Node node = NodeStarter.createTestNode(params);
    Logging.setRootLevel(Level.ERROR);
    Logging.setLevel(LongTermManySingleBlocksTest.class.getName(), Level.INFO);
    node.start(true);
    return node;
  }

  private static long waitForSeedingMillis(Node node) throws InterruptedException {
    long start = System.currentTimeMillis();
    if (!TestUtil.waitForNodes(node)) {
      return -1;
    }
    return System.currentTimeMillis() - start;
  }

  private static void insertBlocksAndRecord(
      Node node, HighLevelSimpleClient client, List<String> csvLine) throws IOException {
    long startInsertsTime = System.currentTimeMillis();
    InsertBatch batch = new InsertBatch(client);

    for (int i = 0; i < INSERTED_BLOCKS; i++) {
      LOGGER.info("Insert request for block {}", i);
      RandomAccessBucket single = randomData(node);
      InsertBlock block = new InsertBlock(single, new ClientMetadata(), FreenetURI.EMPTY_CHK_URI);
      batch.startInsert(block);
    }

    batch.waitUntilFinished();
    FreenetURI[] uris = batch.getURIs();
    long[] times = batch.getTimes();
    InsertException[] errors = batch.getErrors();

    int successes = 0;
    for (int i = 0; i < INSERTED_BLOCKS; i++) {
      if (uris[i] != null) {
        csvLine.add(String.valueOf(times[i]));
        csvLine.add(uris[i].toASCIIString());
        LOGGER.info("Insert succeeded for block {} : {} in {}", i, uris[i], times[i]);
        successes++;
      } else {
        csvLine.add(InsertException.getShortMessage(errors[i].getMode()));
        csvLine.add("N/A");
        LOGGER.warn("Insert failed for block {}", i, errors[i]);
      }
    }

    long endInsertsTime = System.currentTimeMillis();
    LOGGER.info(
        "Succeeded inserts: {} of {} in {}ms",
        successes,
        INSERTED_BLOCKS,
        endInsertsTime - startInsertsTime);
  }

  private static FetchContext configureFetchContext(HighLevelSimpleClient client) {
    FetchContext fctx = client.getFetchContext();
    fctx.setMaxNonSplitfileRetries(0);
    fctx.setMaxSplitfileBlockRetries(0);
    return fctx;
  }

  private static void processExistingStatusFile(
      File statusFile, FetchRunContext runContext, FetchTotals totals)
      throws IOException, ParseException {
    GregorianCalendar[] targets = computeTargets();
    try (FileInputStream fis = new FileInputStream(statusFile);
        BufferedReader br = new BufferedReader(new InputStreamReader(fis, ENCODING))) {
      String line;
      while ((line = br.readLine()) != null) {
        processExistingStatusLine(line, runContext, targets, totals);
      }
    }
  }

  private static void processExistingStatusLine(
      String line, FetchRunContext runContext, GregorianCalendar[] targets, FetchTotals totals)
      throws ParseException {
    String[] split = line.split("!");
    if (split.length < 4) {
      return;
    }

    Date date = dateFormat.parse(split[0]);
    GregorianCalendar calendar = new GregorianCalendar(TimeZone.getTimeZone("GMT"));
    calendar.setTime(date);
    calendar.set(Calendar.HOUR_OF_DAY, 0);
    calendar.set(Calendar.MINUTE, 0);
    calendar.set(Calendar.MILLISECOND, 0);
    calendar.set(Calendar.SECOND, 0);
    calendar.getTime();

    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("Status row date: {}", dateFormat.format(calendar.getTime()));
    }
    Integer seedTime = parseIntOrNull(split[2]);
    if (seedTime != null) {
      LOGGER.info("Status row seed time: {}", seedTime);
    }

    int token = 3;
    if (split.length < token + INSERTED_BLOCKS * 2) {
      return;
    }

    ParsedInsertedBlocks inserted = parseInsertedBlocks(split, token);
    for (int i = 0; i < INSERTED_BLOCKS; i++) {
      LOGGER.info(
          "Recorded insert {} : {} in {}", i, inserted.insertedUris[i], inserted.insertTimes[i]);
    }

    int tokenAfterInserts = token + INSERTED_BLOCKS * 2;
    maybeFetchTargets(split[1], calendar, inserted.insertedUris, runContext, targets);
    processDeltaSection(split, tokenAfterInserts, calendar, date, totals);
  }

  private static ParsedInsertedBlocks parseInsertedBlocks(String[] split, int tokenStart) {
    FreenetURI[] insertedURIs = new FreenetURI[INSERTED_BLOCKS];
    int[] insertTimes = new int[INSERTED_BLOCKS];
    int token = tokenStart;
    for (int i = 0; i < INSERTED_BLOCKS; i++) {
      insertTimes[i] = parseIntOrMinusOne(split[token]);
      token++;
      insertedURIs[i] = parseUriOrNull(split[token]);
      token++;
    }
    return new ParsedInsertedBlocks(insertedURIs, insertTimes);
  }

  private static void maybeFetchTargets(
      String versionToken,
      GregorianCalendar calendar,
      FreenetURI[] insertedURIs,
      FetchRunContext runContext,
      GregorianCalendar[] targets) {
    for (int i = 0; i < targets.length; i++) {
      if (!isNearTargetDate(targets[i], calendar)) {
        continue;
      }
      LOGGER.info("Matched target date row from {} days ago", (1 << i) - 1);
      LOGGER.info("Row version token: {}", versionToken);
      runContext.csvLine().add(Integer.toString(i));
      fetchInsertedBlocks(i, insertedURIs, runContext);
    }
  }

  private static boolean isNearTargetDate(GregorianCalendar target, GregorianCalendar candidate) {
    return Math.abs(target.getTimeInMillis() - candidate.getTimeInMillis()) < HOURS.toMillis(12);
  }

  private static void fetchInsertedBlocks(
      int deltaIndex, FreenetURI[] insertedURIs, FetchRunContext runContext) {
    List<String> csvLine = runContext.csvLine();
    FetchRequestContext fetchRequestContext = runContext.fetchRequestContext();
    int pulled = 0;
    int inserted = 0;
    for (int j = 0; j < INSERTED_BLOCKS; j++) {
      FreenetURI uri = insertedURIs[j];
      if (uri == null) {
        csvLine.add("INSERT FAILED");
        continue;
      }

      inserted++;
      FetchResult result = fetchOneBlock(uri, j, fetchRequestContext);
      csvLine.add(result.csvToken());
      if (result.succeeded()) {
        pulled++;
      }
    }

    LOGGER.info(
        "Fetch results: pulled {} of {} blocks from {} days ago",
        pulled,
        inserted,
        (1 << deltaIndex) - 1);
  }

  private static FetchResult fetchOneBlock(
      FreenetURI uri, int blockIndex, FetchRequestContext fetchRequestContext) {
    long start = System.currentTimeMillis();
    try {
      FetchWaiter fw = new FetchWaiter(fetchRequestContext.requestClient());
      fetchRequestContext.client().fetch(uri, fw, fetchRequestContext.fetchContext());
      fw.waitForCompletion();
      long fetchTime = System.currentTimeMillis() - start;
      LOGGER.info("Fetch duration for block {}: {}", blockIndex, fetchTime);
      return FetchResult.success(String.valueOf(fetchTime));
    } catch (FetchException e) {
      logFetchException(blockIndex, e);
      return FetchResult.failure(FetchException.getShortMessage(e.getMode()));
    }
  }

  private static void logFetchException(int blockIndex, FetchException e) {
    FetchExceptionMode mode = e.getMode();
    if (mode != FetchExceptionMode.ALL_DATA_NOT_FOUND
        && mode != FetchExceptionMode.DATA_NOT_FOUND) {
      LOGGER.warn("Fetch failed for block {}", blockIndex, e);
    } else {
      LOGGER.warn("Fetch failed for block {}", blockIndex);
    }
  }

  private static void processDeltaSection(
      String[] split, int tokenStart, GregorianCalendar calendar, Date date, FetchTotals totals) {
    int token = tokenStart;
    while (split.length > token + INSERTED_BLOCKS) {
      Integer delta = parseIntOrNull(split[token]);
      if (delta == null) {
        LOGGER.warn("Delta token parse failed at index {} = \"{}\"", token, split[token]);
        LOGGER.warn("Delta token expected but missing");
        if (LOGGER.isWarnEnabled()) {
          LOGGER.warn(
              "Skipping remainder of status row for date {}",
              dateFormat.format(calendar.getTime()));
        }
        return;
      }
      LOGGER.info("Processing delta window: {} days", (1 << delta) - 1);
      token++;

      DeltaTotals deltaTotals = parseDeltaTotals(split, token, date);
      token = deltaTotals.nextToken();
      totals.recordDelta(
          delta,
          deltaTotals.totalFetches(),
          deltaTotals.totalSuccesses(),
          deltaTotals.totalFetchTime());

      double averageMillis =
          deltaTotals.totalSuccesses() == 0
              ? Double.NaN
              : ((double) deltaTotals.totalFetchTime()) / ((double) deltaTotals.totalSuccesses());
      if (LOGGER.isInfoEnabled()) {
        LOGGER.info(
            "Delta summary: {} of {} succeeded, avg {}ms for delta {} on {}",
            deltaTotals.totalSuccesses(),
            deltaTotals.totalFetches(),
            averageMillis,
            delta,
            dateFormat.format(date));
      }
    }
  }

  private static DeltaTotals parseDeltaTotals(String[] split, int tokenStart, Date date) {
    int token = tokenStart;
    int totalFetchTime = 0;
    int totalSuccesses = 0;
    int totalFetches = 0;
    for (int i = 0; i < INSERTED_BLOCKS; i++) {
      if (split[token].isEmpty()) {
        continue;
      }
      totalFetches++;

      Integer fetchTime = parseIntOrNull(split[token]);
      if (fetchTime != null) {
        LOGGER.info("Fetch succeeded for block #{} on {} in {}ms", i, date, fetchTime);
        totalSuccesses++;
        totalFetchTime += fetchTime;
      } else {
        LOGGER.info("Fetch failed for block #{} on {} : {}", i, date, split[token]);
      }
      token++;
    }
    return new DeltaTotals(token, totalFetchTime, totalSuccesses, totalFetches);
  }

  private static GregorianCalendar[] computeTargets() {
    GregorianCalendar target = today.copyCalendar();
    target.set(Calendar.HOUR_OF_DAY, 0);
    target.set(Calendar.MINUTE, 0);
    target.set(Calendar.MILLISECOND, 0);
    target.set(Calendar.SECOND, 0);
    GregorianCalendar[] targets = new GregorianCalendar[MAX_N + 1];
    for (int i = 0; i < targets.length; i++) {
      targets[i] = ((GregorianCalendar) target.clone());
      targets[i].add(Calendar.DAY_OF_MONTH, -((1 << i) - 1));
      targets[i].getTime();
    }
    return targets;
  }

  private static void logTotals(FetchTotals totals) {
    for (int i = 0; i < totals.totalFetchesByDelta.length; i++) {
      int fetches = totals.totalFetchesByDelta[i];
      int successes = totals.totalSuccessfulFetchesByDelta[i];
      long totalTime = totals.totalFetchTimeByDelta[i];
      double successRate = fetches == 0 ? Double.NaN : (successes * 100.0) / fetches;
      double averageMillis = successes == 0 ? Double.NaN : (totalTime * 1.0) / successes;
      LOGGER.info(
          "Delta totals for {} days: fetches {} successes {} = {}% avg {}ms",
          i, fetches, successes, successRate, averageMillis);
    }
  }

  private static void parkQuietly(Node node) {
    if (node == null) {
      return;
    }
    try {
      node.park();
    } catch (Exception e) {
      LOGGER.debug("Failed to park node during shutdown", e);
    }
  }

  private static int parseIntOrMinusOne(String s) {
    Integer value = parseIntOrNull(s);
    return value == null ? -1 : value;
  }

  private static Integer parseIntOrNull(String s) {
    try {
      return Integer.valueOf(s);
    } catch (NumberFormatException _) {
      return null;
    }
  }

  private static FreenetURI parseUriOrNull(String token) {
    try {
      return new FreenetURI(token);
    } catch (MalformedURLException _) {
      return null;
    }
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class ParsedInsertedBlocks {
    private final FreenetURI[] insertedUris;
    private final int[] insertTimes;

    private ParsedInsertedBlocks(FreenetURI[] insertedUris, int[] insertTimes) {
      this.insertedUris = insertedUris;
      this.insertTimes = insertTimes;
    }
  }

  private record DeltaTotals(
      int nextToken, int totalFetchTime, int totalSuccesses, int totalFetches) {}

  private static final class FetchTotals {
    private final int[] totalFetchesByDelta;
    private final int[] totalSuccessfulFetchesByDelta;
    private final long[] totalFetchTimeByDelta;

    private FetchTotals(int size) {
      this.totalFetchesByDelta = new int[size];
      this.totalSuccessfulFetchesByDelta = new int[size];
      this.totalFetchTimeByDelta = new long[size];
    }

    private void recordDelta(int delta, int totalFetches, int totalSuccesses, int totalFetchTime) {
      if (delta < 0 || delta >= totalFetchesByDelta.length) {
        return;
      }
      totalFetchesByDelta[delta] += totalFetches;
      totalSuccessfulFetchesByDelta[delta] += totalSuccesses;
      totalFetchTimeByDelta[delta] += totalFetchTime;
    }
  }

  private record FetchResult(boolean succeeded, String csvToken) {
    private static FetchResult success(String csvToken) {
      return new FetchResult(true, csvToken);
    }

    private static FetchResult failure(String csvToken) {
      return new FetchResult(false, csvToken);
    }
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
