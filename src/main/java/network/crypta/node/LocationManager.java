package network.crypta.node;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.time.temporal.ChronoUnit;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.InsertBlock;
import network.crypta.client.InsertException;
import network.crypta.crypt.RandomSource;
import network.crypta.crypt.SHA256;
import network.crypta.crypt.Util;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientKSK;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.FreenetURI;
import network.crypta.support.Base64;
import network.crypta.support.Fields;
import network.crypta.support.ShortBuffer;
import network.crypta.support.TimeSortedHashtable;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.math.BootstrappingDecayingRunningAverage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.HOURS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * Manages this node's logical location and the swap protocol.
 *
 * <p>Responsibilities: - Maintains the node's current normalized location used for routing. -
 * Initiates and processes location swap attempts (incoming and outgoing). - Coordinates locking and
 * a small FIFO for concurrent swap requests to avoid deadlocks. - Samples peer locations to
 * estimate network size. - Schedules a periodic "pitch‑black" mitigation probe (KSK/CHK
 * round‑trip).
 *
 * <p>Threading and state: - The instance serializes swap handling via an internal lock; some
 * methods are synchronized when mutating {@code loc} and session metrics. - Uses the node's
 * executor for background tasks and the USM for network I/O. - Implements {@link
 * network.crypta.io.comm.ByteCounter} to attribute swap traffic in stats.
 *
 * <p>Locations: - A location is a normalized {@code double} as defined by {@link Location}. -
 * Callers must only set values accepted by {@link Location#isValid(double)}.
 *
 * @author amphibian
 */
public class LocationManager implements ByteCounter {
  private static final Logger LOG = LoggerFactory.getLogger(LocationManager.class);
  private static final String UNMATCHED_SWAP_REPLY_WRONG_SOURCE_MSG =
      "Unmatched SwapReply {} from wrong source: from {} should be {} to {}";
  private static final String UNMATCHED_SWAP_REJECTED_WRONG_SOURCE_MSG =
      "Unmatched SwapRejected {} from wrong source: from {} should be {} to {}";
  private static final String UNMATCHED_SWAP_COMMIT_WRONG_SOURCE_MSG =
      "Unmatched SwapCommit {} from wrong source: from {} should be {} to {}";
  private static final String UNMATCHED_SWAP_COMPLETE_WRONG_SOURCE_MSG =
      "Unmatched SwapComplete {} from wrong source: from {} should be {} to {}";

  /**
   * Filename prefix for daily pitch‑black mitigation markers written in {@code userDir()}.
   *
   * <p>Files named {@code mitigate-pitch-black-attack-<ISO_DATE>-<random>} record that a KSK/CHK
   * pair was inserted for that date so the next day's probe can verify availability.
   */
  public static final String FOIL_PITCH_BLACK_ATTACK_PREFIX = "mitigate-pitch-black-attack-";

  // Renamed to lowerCamelCase; encapsulated via accessors for tests/simulators to adjust.
  private static volatile long pitchBlackMitigationFrequencyOneDay = DAYS.toMillis(1);
  private static volatile long pitchBlackMitigationStartupDelay = HOURS.toMillis(2);

  /**
   * Returns the nominal frequency for the pitch‑black mitigation task.
   *
   * @return period in milliseconds (default one day)
   */
  @SuppressWarnings("unused")
  public static long getPitchBlackMitigationFrequencyOneDay() {
    return pitchBlackMitigationFrequencyOneDay;
  }

  /**
   * Sets the nominal frequency for the pitch‑black mitigation task.
   *
   * <p>Primarily intended for tests and simulations.
   *
   * @param millis period in milliseconds
   */
  public static void setPitchBlackMitigationFrequencyOneDay(long millis) {
    pitchBlackMitigationFrequencyOneDay = millis;
  }

  /**
   * Returns the randomized startup delay upper bound for mitigation scheduling.
   *
   * @return delay in milliseconds
   */
  public static long getPitchBlackMitigationStartupDelay() {
    return pitchBlackMitigationStartupDelay;
  }

  /**
   * Sets the randomized startup delay upper bound for mitigation scheduling.
   *
   * <p>Primarily intended for tests and simulations.
   *
   * @param millis delay in milliseconds
   */
  public static void setPitchBlackMitigationStartupDelay(long millis) {
    pitchBlackMitigationStartupDelay = millis;
  }

  private class MyCallback extends SendMessageOnErrorCallback {

    RecentlyForwardedItem item;

    MyCallback(Message message, PeerNode pn, RecentlyForwardedItem item) {
      super(message, pn, LocationManager.this);
      this.item = item;
    }

    @Override
    public void disconnected() {
      super.disconnected();
      removeRecentlyForwardedItem(item);
    }

    @Override
    public void acknowledged() {
      item.successfullyForwarded = true;
    }
  }

  static final long TIMEOUT = SECONDS.toMillis(60);
  static final int SWAP_MAX_HTL = 10;

  /**
   * Number of swap evaluations, either incoming or outgoing, between resetting our location. There
   * is a 2 in SWAP_RESET chance that a reset will occur on one or other end of a swap request.
   *
   * <p>ALCHEMY: This depends on a number of factors, not least the size of the network. It is hard
   * to get a good value from simulations. But it can take time to recover after a random reset, so
   * we have increased it from 4000 to 16,000 on 8 April 2008. At the time location churn was
   * significant, and some of it was likely caused by this. OTOH if we get major keyspace
   * fragmentation, we must reduce it to 8000 or 4000.
   */
  static final int SWAP_RESET = 16000;

  // NOTE: vary automatically
  static final long SEND_SWAP_INTERVAL = SECONDS.toMillis(8);

  /** The average time between sending a swap request, and completion. */
  final BootstrappingDecayingRunningAverage averageSwapTime;

  /** Minimum swap delay */
  static final long MIN_SWAP_TIME = Node.MIN_INTERVAL_BETWEEN_INCOMING_SWAP_REQUESTS;

  /** Maximum swap delay */
  static final long MAX_SWAP_TIME = MINUTES.toMillis(1);

  private static void incrementSwaps() {
    swaps.incrementAndGet();
  }

  private static void incrementNoSwaps() {
    noSwaps.incrementAndGet();
  }

  private static void incrementStartedSwaps() {
    startedSwaps.incrementAndGet();
  }

  private static void incrementSwapsRejectedAlreadyLocked() {
    swapsRejectedAlreadyLocked.incrementAndGet();
  }

  private static void incrementSwapsRejectedNowhereToGo() {
    swapsRejectedNowhereToGo.incrementAndGet();
  }

  private static void incrementSwapsRejectedRecognizedID() {
    swapsRejectedRecognizedID.incrementAndGet();
  }

  private static void incrementSwapsRejectedRateLimit() {
    swapsRejectedRateLimit.incrementAndGet();
  }

  /** Don't start swapping until our peers have had a reasonable chance to reconnect. */
  private static final long STARTUP_DELAY = MINUTES.toMillis(1);

  final RandomSource r;
  final SwapRequestSender sender;
  final Node node;
  long timeLastSuccessfullySwapped;
  private static Clock systemClockUTC = Clock.system(ZoneOffset.UTC);

  public LocationManager(RandomSource r, Node node) {
    loc = r.nextDouble();
    sender = new SwapRequestSender();
    this.r = r;
    this.node = node;
    recentlyForwardedIDs = Collections.synchronizedMap(new HashMap<>());
    // NOTE: persist to disk!
    averageSwapTime =
        new BootstrappingDecayingRunningAverage(SEND_SWAP_INTERVAL, 0, Integer.MAX_VALUE, 20, null);
    timeLocSet = System.currentTimeMillis();

    // Debug gating derives from LOG.isDebugEnabled() where needed
  }

  private double loc;
  private volatile long timeLocSet;
  private double locChangeSession = 0.0;

  int numberOfRemotePeerLocationsSeenInSwaps = 0;

  /**
   * Returns this node's current routing location.
   *
   * @return normalized location as defined by {@link Location}
   */
  public synchronized double getLocation() {
    return loc;
  }

  /**
   * Updates this node's routing location.
   *
   * <p>Accepts only values for which {@link Location#isValid(double)} returns {@code true}. In
   * success, updates the internal timestamp used by duplicate‑location detection.
   *
   * @param l new location (must be valid per {@link Location})
   */
  public synchronized void setLocation(double l) {
    if (!Location.isValid(l)) {
      LOG.error("Reject invalid location {}", l);
      return;
    }
    this.loc = l;
    timeLocSet = System.currentTimeMillis();
  }

  /**
   * Accumulates session movement by adding the delta between the current and a new location.
   *
   * @param newLoc prospective location used only to compute the delta
   */
  public synchronized void updateLocationChangeSession(double newLoc) {
    double oldLoc = loc;
    double diff = Location.change(oldLoc, newLoc);
    if (LOG.isDebugEnabled())
      LOG.debug(
          "updateLocationChangeSession: oldLoc: {} -> newLoc: {} moved: {}", oldLoc, newLoc, diff);
    this.locChangeSession += diff;
  }

  /**
   * Starts background tasks: swap initiator, cleanup, and mitigation scheduler.
   *
   * <p>Enqueues the swap sender after a short startup delay, a periodic cleanup of queued/old
   * chains, and the daily pitch‑black mitigation probe. No threads are started when swapping is
   * disabled by configuration.
   */
  public void start() {
    if (node.isEnableSwapping()) {
      node.network().ticker().queueTimedJob(sender, STARTUP_DELAY);
    }
    // Periodic cleanup of swap chains and queued items.
    node.network().ticker().queueTimedJob(cleanupTask, SECONDS.toMillis(10));
    // Periodic pitch‑black mitigation probe.
    int startup =
        (int) Math.min(Integer.MAX_VALUE, LocationManager.getPitchBlackMitigationStartupDelay());
    int initialDelay = startup > 0 ? node.bootstrap().fastWeakRandom().nextInt(startup) : 0;
    node.network().ticker().queueTimedJob(pitchBlackMitigationTask, initialDelay);
  }

  // Schedules recurring cleanup of old swap chains and outdated queued items.
  private final Runnable cleanupTask =
      new Runnable() {
        @Override
        public void run() {
          try {
            clearOldSwapChains();
            removeTooOldQueuedItems();
          } finally {
            node.network().ticker().queueTimedJob(this, SECONDS.toMillis(10));
          }
        }
      };

  // Schedules and performs the periodic pitch-black mitigation work.
  private final Runnable pitchBlackMitigationTask =
      new Runnable() {
        @Override
        public void run() {
          runAndReschedule();
        }

        private void runAndReschedule() {
          LocalDateTime now = LocalDateTime.now(systemClockUTC);
          long millisUntilNextRequestTomorrow =
              getNextPitchBlackMitigationDelayMillisecondsTomorrow(now);
          node.network().ticker().queueTimedJob(this, millisUntilNextRequestTomorrow);
          if (swappingDisabled()) {
            return;
          }
          String isoDateStringToday = DateTimeFormatter.ISO_DATE.format(now);
          String isoDateStringYesterday = DateTimeFormatter.ISO_DATE.format(now.minusDays(1));

          HighLevelSimpleClient highLevelSimpleClient =
              node.services()
                  .clientCore()
                  .makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, true, false);

          maybeInsertTodayPitchBlackCheck(highLevelSimpleClient, isoDateStringToday);
          handlePitchBlackStatusFiles(
              highLevelSimpleClient, isoDateStringToday, isoDateStringYesterday);
        }

        private void maybeInsertTodayPitchBlackCheck(
            HighLevelSimpleClient highLevelSimpleClient, String isoDateStringToday) {
          File[] previousInsertFromToday =
              node.userDir()
                  .dir()
                  .listFiles(
                      (ignored, name) -> name.startsWith(getPitchBlackPrefix(isoDateStringToday)));
          if (previousInsertFromToday != null && previousInsertFromToday.length == 0) {
            byte[] randomContentForKSK = new byte[20];
            node.bootstrap().secureRandom().nextBytes(randomContentForKSK);
            String randomPart = Base64.encode(randomContentForKSK);
            String nameForInsert = getPitchBlackPrefix(isoDateStringToday + "-" + randomPart);
            tryToInsertPitchBlackCheck(highLevelSimpleClient, nameForInsert);
          }
        }

        private void handlePitchBlackStatusFiles(
            HighLevelSimpleClient highLevelSimpleClient,
            String isoDateStringToday,
            String isoDateStringYesterday) {
          File[] foilPitchBlackStatusFiles =
              node.userDir()
                  .dir()
                  .listFiles((ignored, name) -> name.startsWith(getPitchBlackPrefix("")));
          if (foilPitchBlackStatusFiles == null) {
            return;
          }

          File[] successfulInsertFromYesterday =
              Arrays.stream(foilPitchBlackStatusFiles)
                  .filter(file -> file.getName().contains(isoDateStringYesterday))
                  .toArray(File[]::new);
          for (File f : successfulInsertFromYesterday) {
            tryToRequestPitchBlackCheckFromYesterday(
                highLevelSimpleClient, successfulInsertFromYesterday[0]);
            // cleanup file, regardless of success
            try {
              Files.delete(f.toPath());
            } catch (IOException _) {
              f.deleteOnExit();
            }
          }

          // delete files from more than one day ago
          File[] leftoverFiles =
              Arrays.stream(foilPitchBlackStatusFiles)
                  .filter(file -> !file.getName().contains(isoDateStringToday))
                  .toArray(File[]::new);
          for (File f : leftoverFiles) {
            try {
              Files.delete(f.toPath());
            } catch (IOException _) {
              f.deleteOnExit();
            }
          }
        }

        private long getNextPitchBlackMitigationDelayMillisecondsTomorrow(LocalDateTime now) {
          return Math.max(HOURS.toMillis(12), getMillisUntilRandomTimeTomorrow(now));
        }

        private long getMillisUntilRandomTimeTomorrow(LocalDateTime now) {
          LocalDateTime tomorrowTime =
              now.plusDays(1)
                  .withHour(node.bootstrap().fastWeakRandom().nextInt(23))
                  .withMinute(node.bootstrap().fastWeakRandom().nextInt(59))
                  .withSecond(node.bootstrap().fastWeakRandom().nextInt(59));
          return now.until(tomorrowTime, ChronoUnit.MILLIS);
        }

        private void tryToRequestPitchBlackCheckFromYesterday(
            HighLevelSimpleClient highLevelSimpleClient, File insertInfoFromYesterday) {
          ClientKSK insertFromYesterday = ClientKSK.create(insertInfoFromYesterday.getName());
          Optional<byte[]> expectedContentOpt = readBytesFromYesterdayFile(insertInfoFromYesterday);
          if (expectedContentOpt.isEmpty()) {
            return;
          }
          byte[] expectedContent = expectedContentOpt.get();
          // check the SSK
          FetchResult sskFetchResult = null;
          try {
            sskFetchResult = highLevelSimpleClient.fetch(insertFromYesterday.getURI());
            if (!Arrays.equals(expectedContent, sskFetchResult.asByteArray())) {
              // if we received false data, this is definitely an attack: move there to provide a
              // good
              // node in the location
              switchLocationToDefendAgainstPitchBlackAttack(insertFromYesterday);
            }
          } catch (FetchException e) {
            if (isRequestExceptionBecauseUriIsNotAvailable(e)
                && node.bootstrap().fastWeakRandom().nextBoolean()) {
              // switch to the attacked location with only 50% probability,
              // because it could be caused by the defensive swap of another node
              // which made its current content inaccessible.
              switchLocationToDefendAgainstPitchBlackAttack(insertFromYesterday);
            }
            return;
          } catch (IOException _) {
            LOG.warn("Cannot convert fetched data to byte array (fetch={})", sskFetchResult);
            return;
          }
          // check the CHK
          ArrayBucket randomBucketToInsert = new ArrayBucket(expectedContent);
          InsertBlock chkInsertBlock =
              new InsertBlock(randomBucketToInsert, null, FreenetURI.EMPTY_CHK_URI);
          FreenetURI calculatedChkUri;
          try {
            calculatedChkUri = highLevelSimpleClient.insert(chkInsertBlock, true, null);
          } catch (InsertException _) {
            LOG.error("Could not create CHK for expected content.");
            return;
          }
          try {
            highLevelSimpleClient.fetch(calculatedChkUri);
          } catch (FetchException e) {
            if (isRequestExceptionBecauseUriIsNotAvailable(e)
                && node.bootstrap().fastWeakRandom().nextBoolean()) {
              // switch to the attacked location with only 50% probability,
              // because it could be caused by the defensive swap of another node
              // which made its current content inaccessible.
              try {
                switchLocationToDefendAgainstPitchBlackAttack(new ClientCHK(calculatedChkUri));
              } catch (MalformedURLException _) {
                LOG.error("Cannot create ClientCHK from calculated CHK URI: {}", calculatedChkUri);
              }
            }
          }
        }

        private void tryToInsertPitchBlackCheck(
            HighLevelSimpleClient highLevelSimpleClient, String nameForInsert) {
          // create some random data of up to 1021 bytes to insert to the KSK
          byte[] contentLengthSource = new byte[2];
          node.bootstrap().fastWeakRandom().nextBytes(contentLengthSource);
          // bytes are -127 to 128,
          // so this gives us 253 to 1021 bytes of size
          int contentLength =
              (5 * 127) + (3 * contentLengthSource[0]) + contentLengthSource[1] / 64; // -1 to 2
          byte[] randomContentToInsert = new byte[contentLength];
          node.bootstrap().fastWeakRandom().nextBytes(randomContentToInsert);
          ArrayBucket randomBucketToInsert = new ArrayBucket(randomContentToInsert);
          // create the KSK
          ClientKSK insertForToday = ClientKSK.create(nameForInsert);
          InsertBlock kskInsertBlock =
              new InsertBlock(randomBucketToInsert, null, insertForToday.getInsertURI());
          // create the CHK
          InsertBlock chkInsertBlock =
              new InsertBlock(randomBucketToInsert, null, FreenetURI.EMPTY_CHK_URI);
          try {
            highLevelSimpleClient.insert(kskInsertBlock, false, null);
            highLevelSimpleClient.insert(chkInsertBlock, false, null);
            // create a file to check on the next run tomorrow
            File succeededInsertFile = node.userDir().file(nameForInsert);
            writeSuccessfulInsertFile(randomContentToInsert, nameForInsert, succeededInsertFile);
          } catch (InsertException _) {
            LOG.error(
                "Could not insert pitch-black detection data to today's KSK: {}, retry tomorrow",
                insertForToday.getURI());
          }
        }

        private Optional<byte[]> readBytesFromYesterdayFile(File insertInfoFromYesterday) {
          try {
            return Optional.of(Files.readAllBytes(insertInfoFromYesterday.toPath()));
          } catch (FileNotFoundException _) {
            LOG.warn(
                "Missing insert-info file from yesterday: {}", insertInfoFromYesterday.getName());
            return Optional.empty();
          } catch (IOException _) {
            LOG.warn(
                "I/O error reading insert-info file from yesterday: {}",
                insertInfoFromYesterday.getName());
            return Optional.empty();
          }
        }

        private void switchLocationToDefendAgainstPitchBlackAttack(ClientKey insertFromYesterday) {
          double probedLocationFromYesterday =
              insertFromYesterday.getNodeKey().toNormalizedDouble();
          // decide between SSK and pubkey at random, because they always break together.
          if (insertFromYesterday instanceof ClientSSK sK
              && node.bootstrap().fastWeakRandom().nextBoolean()) {
            probedLocationFromYesterday =
                Util.keyDigestAsNormalizedDouble(sK.getPubKey().getRoutingKey());
          }
          LOG.atWarn()
              .addArgument(() -> insertFromYesterday.getURI().toString())
              .addArgument(probedLocationFromYesterday)
              .log("Cannot fetch yesterday's insert {}; assume attack and switch to location {}");
          setLocation(probedLocationFromYesterday);
        }

        private void writeSuccessfulInsertFile(
            byte[] randomContentToInsert, String nameForInsert, File succeededInsertFile) {
          try (FileOutputStream fileOutputStream = new FileOutputStream(succeededInsertFile)) {
            fileOutputStream.write(randomContentToInsert);
          } catch (IOException _) {
            LOG.error("Cannot write successful-insert content to file: {}", nameForInsert);
          }
        }

        private boolean isRequestExceptionBecauseUriIsNotAvailable(FetchException fetchException) {
          return FetchException.FetchExceptionMode.DATA_NOT_FOUND.equals(fetchException.getMode());
        }
      };

  // moved helper methods into the anonymous runnable above

  /**
   * Returns the filename prefix used for pitch‑black mitigation markers.
   *
   * @param middleSubstring suffix component to append after the constant prefix
   * @return the combined filename prefix
   */
  public String getPitchBlackPrefix(String middleSubstring) {
    return FOIL_PITCH_BLACK_ATTACK_PREFIX + middleSubstring;
  }

  /**
   * Periodically initiates swap requests when swapping is enabled and not locked.
   *
   * <p>The runnable waits a randomized interval based on the observed average swap latency before
   * each attempt and exits promptly when interrupted.
   */
  public class SwapRequestSender implements Runnable {

    @Override
    public void run() {
      Thread.currentThread().setName("SwapRequestSender");
      while (true) {
        if (node.isStopping()) return;
        try {
          // If interrupted during the wait, exit to avoid a busy loop and swap flooding.
          if (!waitWithRandomizedInterval()) {
            if (LOG.isDebugEnabled()) LOG.debug("SwapRequestSender interrupted; stop");
            return;
          }
          // NOTE: Consider shutting down the initiator when swapping is disabled and
          // re-enabling it when swapping comes back up.
          if (!swappingDisabled() && performPreSendChecks()) {
            // Send a swap request
            startSwapRequest();
          }
        } catch (Exception t) {
          LOG.error("SwapRequestSender loop failed: {}", t, t);
        }
      }
    }

    /**
     * Waits for a randomized interval based on {@link #getSendSwapInterval()}.
     *
     * <p>Returns {@code false} if the thread was interrupted while sleeping so the caller can
     * terminate the sender loop promptly without spinning. Returning instead of re‑throwing keeps
     * call sites simple and avoids executing post‑wait logic after an interrupt.
     *
     * @return {@code true} when the wait completed normally; {@code false} when interrupted.
     */
    private boolean waitWithRandomizedInterval() {
      long startTime = System.currentTimeMillis();
      double nextRandom = r.nextDouble();
      while (true) {
        long sleepTime = getSendSwapInterval();
        sleepTime = (long) (sleepTime * nextRandom);
        sleepTime = Math.min(sleepTime, Integer.MAX_VALUE);
        long endTime = startTime + sleepTime;
        long now = System.currentTimeMillis();
        long diff = endTime - now;
        try {
          if (diff > 0) { // noinspection BusyWait
            Thread.sleep(Math.min(diff, SECONDS.toMillis(10)));
          }
        } catch (InterruptedException _) {
          // Treat interrupt as a shutdown signal for the sender thread.
          Thread.currentThread().interrupt();
          return false;
        }
        if (System.currentTimeMillis() >= endTime) break;
      }
      return true;
    }

    private boolean performPreSendChecks() {
      // Don't send one if we are locked
      if (!lock()) {
        return false;
      }
      try {
        if (System.currentTimeMillis() - timeLastSuccessfullySwapped > SECONDS.toMillis(30)
            && shouldRandomizeLocationDueToDuplicatePeer()) {
          setLocation(node.bootstrap().random().nextDouble());
          announceLocChange(true, true, true);
          node.writeNodeFile();
        }
      } finally {
        unlock();
      }
      return true;
    }

    private boolean shouldRandomizeLocationDueToDuplicatePeer() {
      double myLoc = getLocation();
      for (PeerNode pn : node.network().peers().connectedPeers()) {
        if (!pn.isRoutable()) {
          continue;
        }
        long[] snap = pn.getLocationSnapshot();
        double ploc = Double.longBitsToDouble(snap[0]);
        if (Location.equals(ploc, myLoc)) {
          // Don't reset location unless we're SURE there is a problem.
          // If the node has had its location equal to ours for at least 2 minutes,
          // and ours has been likewise...
          long now = System.currentTimeMillis();
          if (now - snap[1] > MINUTES.toMillis(2) && now - timeLocSet > MINUTES.toMillis(2)) {
            // As this is an ERROR, it results from either a bug or malicious action.
            // If it happens very frequently, it indicates either an attack or a serious bug.
            LOG.error("Randomizing location: my loc={} but loc={} for {}", myLoc, ploc, pn);
            return true;
          } else {
            LOG.info(
                "Node {} has identical location to us, waiting until this has persisted for 2"
                    + " minutes...",
                pn);
          }
        }
      }
      return false;
    }

    /** Create and dispatch an outgoing swap request on the node's executor. */
    private void startSwapRequest() {
      node.network()
          .executor()
          .execute(
              new OutgoingSwapRequestHandler(),
              "Outgoing swap request handler for port " + node.network().darknetPortNumber());
    }
  }

  /**
   * Returns whether swapping is disabled for this node.
   *
   * <p>Call without holding locks. Current policy disables swapping when opennet is enabled to
   * reduce location churn.
   *
   * @return {@code true} when swapping is disabled
   */
  public boolean swappingDisabled() {
    // Swapping on opennet nodes, even hybrid nodes, causes significant and unnecessary location
    // churn. Simulations show significantly improved performance if all opennet enabled nodes don't
    // participate in swapping.
    // NOTE: Investigate the possibility of enabling swapping on hybrid nodes with mostly darknet
    // peers (more simulation needed).
    // NOTE: Hybrid nodes with all darknet peers who haven't upgraded to HIGH.
    // Probably we should have a useralert for this to get the user to do the right thing ... but
    // we could auto-detect it and start swapping. However, we should not start swapping just
    // because we temporarily have no opennet peers on startup.
    return node.network().isOpennetEnabled();
  }

  /** Returns the randomized base interval for sending swap requests in milliseconds. */
  public long getSendSwapInterval() {
    long interval = (long) averageSwapTime.currentValue();
    if (interval < MIN_SWAP_TIME) interval = MIN_SWAP_TIME;
    if (interval > MAX_SWAP_TIME) interval = MAX_SWAP_TIME;
    return interval;
  }

  /** Processes a swap request we did not initiate. */
  public class IncomingSwapRequestHandler implements Runnable {

    Message origMessage;
    PeerNode pn;
    long uid;
    RecentlyForwardedItem item;

    IncomingSwapRequestHandler(Message msg, PeerNode pn, RecentlyForwardedItem item) {
      this.origMessage = msg;
      this.pn = pn;
      this.item = item;
      uid = origMessage.getLong(DMT.UID);
    }

    @Override
    public void run() {
      MessageDigest md = SHA256.getMessageDigest();

      try {
        // Caller already locks us
        // Because if we can't get lock, they need to send a reject

        // Firstly, is their message valid?
        Optional<byte[]> hisHashOpt = extractHisHashOrNull(origMessage, md, uid);
        if (hisHashOpt.isEmpty()) return;
        byte[] hisHash = hisHashOpt.get();

        // Looks okay, let's get on with it
        // Only one ID because we are only receiving
        addForwardedItem(uid, uid, pn, null);

        // Create my side
        long random = r.nextLong();
        double myLoc = getLocation();
        double[] friendLocs = node.network().peers().getPeerLocationDoubles(false);
        long[] myValueLong = new long[1 + 1 + friendLocs.length];
        myValueLong[0] = random;
        myValueLong[1] = Double.doubleToLongBits(myLoc);
        for (int i = 0; i < friendLocs.length; i++)
          myValueLong[i + 2] = Double.doubleToLongBits(friendLocs[i]);
        byte[] myValue = Fields.longsToBytes(myValueLong);

        byte[] myHash = md.digest(myValue);

        Message commit = waitForCommitFromPeer(pn, uid, myHash);
        if (commit == null) return;

        CommitPayload payload = decodeAndValidateCommit(commit, hisHash, md, uid);
        if (payload == null) return;

        // Send our SwapComplete and decide whether to swap
        boolean shouldSwap =
            sendConfirmAndDecideSwap(uid, myValue, myLoc, friendLocs, payload, random);
        spyOnLocations(commit, true, shouldSwap, myLoc);

        if (shouldSwap) {
          timeLastSuccessfullySwapped = System.currentTimeMillis();
          // Swap
          updateLocationChangeSession(payload.hisLoc);
          setLocation(payload.hisLoc);
          if (LOG.isDebugEnabled())
            LOG.debug("Incoming swap succeeds: {} <-> {} uid={}", myLoc, payload.hisLoc, uid);
          incrementSwaps();
          announceLocChange(true, false, false);
          node.writeNodeFile();
        } else {
          if (LOG.isDebugEnabled())
            LOG.debug("Incoming swap skipped: {} <-> {} uid={}", myLoc, payload.hisLoc, uid);
          incrementNoSwaps();
        }

        // Randomize our location every 2*SWAP_RESET swap attempts, whichever way it went.
        if (node.bootstrap().random().nextInt(SWAP_RESET) == 0) {
          setLocation(node.bootstrap().random().nextDouble());
          announceLocChange(true, true, false);
          node.writeNodeFile();
        }
      } catch (Exception t) {
        LOG.error("Incoming swap handler failed: {}", t, t);
      } finally {
        unlock();
        removeRecentlyForwardedItem(item);
      }
    }

    private Optional<byte[]> extractHisHashOrNull(Message orig, MessageDigest md, long uid) {
      byte[] hisHash = ((ShortBuffer) orig.getObject(DMT.HASH)).getData();
      if (hisHash.length != md.getDigestLength()) {
        LOG.error("SwapRequest invalid hash length {} on {}", hisHash.length, uid);
        // NOTE: We could consider sending an explicit reject in this case.
        return Optional.empty();
      }
      return Optional.of(hisHash);
    }

    private Message waitForCommitFromPeer(PeerNode pn, long uid, byte[] myHash) {
      Message m = DMT.createFNPSwapReply(uid, myHash);

      MessageFilter filter =
          MessageFilter.create()
              .setType(DMT.FNPSwapCommit)
              .setField(DMT.UID, uid)
              .setTimeout(TIMEOUT)
              .setSource(pn);

      try {
        node.network().usm().send(pn, m, LocationManager.this);
      } catch (NotConnectedException _) {
        if (LOG.isDebugEnabled()) LOG.debug("Disconnected before sending SwapReply to {}", pn);
        return null;
      }

      try {
        return node.network().usm().waitFor(filter, LocationManager.this);
      } catch (DisconnectedException _) {
        if (LOG.isDebugEnabled())
          LOG.debug("Disconnected while waiting for SwapCommit from {}", pn);
        return null;
      }
    }

    private CommitPayload decodeAndValidateCommit(
        Message commit, byte[] hisHash, MessageDigest md, long uid) {
      byte[] hisBuf = ((ShortBuffer) commit.getObject(DMT.DATA)).getData();

      if ((hisBuf.length % 8 != 0) || (hisBuf.length < 16)) {
        LOG.error("SwapCommit invalid content length on {}", uid);
        return null;
      }

      byte[] rehash = md.digest(hisBuf);
      if (!Arrays.equals(rehash, hisHash)) {
        LOG.error("SwapCommit hash mismatch on {}", uid);
        return null;
      }

      long[] hisBufLong = Fields.bytesToLongs(hisBuf);
      if (hisBufLong.length < 2) {
        LOG.error("SwapCommit invalid buffer length (no random, no location) on {}", uid);
        return null;
      }

      long hisRandom = hisBufLong[0];
      double hisLoc = Double.longBitsToDouble(hisBufLong[1]);
      if (!Location.isValid(hisLoc)) {
        LOG.error("SwapCommit invalid location {} on {}", hisLoc, uid);
        return null;
      }
      registerKnownLocation(hisLoc);

      double[] hisFriendLocs = new double[hisBufLong.length - 2];
      for (int i = 0; i < hisFriendLocs.length; i++) {
        hisFriendLocs[i] = Double.longBitsToDouble(hisBufLong[i + 2]);
        if (!Location.isValid(hisFriendLocs[i])) {
          LOG.error("SwapCommit invalid friend location {} on {}", hisFriendLocs[i], uid);
          return null;
        }
        registerLocationLink(hisLoc, hisFriendLocs[i]);
        registerKnownLocation(hisFriendLocs[i]);
      }
      numberOfRemotePeerLocationsSeenInSwaps += hisFriendLocs.length;
      return new CommitPayload(hisRandom, hisLoc, hisFriendLocs);
    }

    private boolean sendConfirmAndDecideSwap(
        long uid,
        byte[] myValue,
        double myLoc,
        double[] friendLocs,
        CommitPayload payload,
        long random) {
      Message confirm = DMT.createFNPSwapComplete(uid, myValue);
      try {
        node.network().usm().send(pn, confirm, LocationManager.this);
      } catch (NotConnectedException _) {
        if (LOG.isDebugEnabled()) LOG.debug("Disconnected before sending SwapCommit to {}", pn);
        return false;
      }
      return shouldSwap(
          myLoc, friendLocs, payload.hisLoc, payload.hisFriendLocs, random ^ payload.hisRandom);
    }
  }

  /** Initiates an outgoing swap request and drives the reply/commit/complete sequence. */
  public class OutgoingSwapRequestHandler implements Runnable {

    RecentlyForwardedItem item;

    @Override
    public void run() {
      long uid = r.nextLong();
      if (!lock()) return;

      try {
        incrementStartedSwaps();
        long random = r.nextLong();
        double myLoc = getLocation();
        double[] friendLocs = node.network().peers().getPeerLocationDoubles(false);
        byte[] myValue = buildMyValue(random, myLoc, friendLocs);

        byte[] myHash = SHA256.digest(myValue);

        // Build request data; the actual request message is constructed and sent by
        // sendRequestAndWaitForReply.

        PeerNode pn = node.network().peers().getRandomPeer();
        if (pn == null) {
          // Nowhere to send
          return;
        }
        // Only 1 ID because we are sending; we won't receive
        item = addForwardedItem(uid, uid, null, pn);

        if (LOG.isDebugEnabled()) LOG.debug("Send SwapRequest {} to {}", uid, pn);

        Message reply = sendRequestAndWaitForReply(pn, uid, myHash);
        if (reply == null) return;

        if (isRejectedAfterRequest(reply, uid)) return;

        // We have an FNPSwapReply.
        // FNPSwapReply is exactly the same format as FNPSwapRequest
        byte[] hisHash = ((ShortBuffer) reply.getObject(DMT.HASH)).getData();

        reply = sendCommitAndWaitForComplete(pn, uid, myValue);
        if (reply == null) return;

        if (isRejectedAfterComplete(reply)) return;

        CommitPayload payload = decodeAndValidateSwapComplete(reply, hisHash, uid);
        if (payload == null) return;

        boolean shouldSwap =
            shouldSwap(
                myLoc,
                friendLocs,
                payload.hisLoc,
                payload.hisFriendLocs,
                random ^ payload.hisRandom);

        spyOnLocations(reply, true, shouldSwap, myLoc);

        applySwapDecision(shouldSwap, payload, myLoc, uid);

        // Randomize our location every 2*SWAP_RESET swap attempts, whichever way it went.
        if (node.bootstrap().random().nextInt(SWAP_RESET) == 0) {
          setLocation(node.bootstrap().random().nextDouble());
          announceLocChange(true, true, false);
          node.writeNodeFile();
        }

      } catch (Exception t) {
        LOG.error("Outgoing swap handler failed: {}", t, t);
      } finally {
        unlock();
        if (item != null) removeRecentlyForwardedItem(item);
      }
    }

    private byte[] buildMyValue(long random, double myLoc, double[] friendLocs) {
      long[] myValueLong = new long[1 + 1 + friendLocs.length];
      myValueLong[0] = random;
      myValueLong[1] = Double.doubleToLongBits(myLoc);
      for (int i = 0; i < friendLocs.length; i++) {
        myValueLong[i + 2] = Double.doubleToLongBits(friendLocs[i]);
      }
      return Fields.longsToBytes(myValueLong);
    }

    private Message sendRequestAndWaitForReply(PeerNode pn, long uid, byte[] myHash) {
      Message m = DMT.createFNPSwapRequest(uid, myHash, SWAP_MAX_HTL);

      MessageFilter filter1 =
          MessageFilter.create()
              .setType(DMT.FNPSwapRejected)
              .setField(DMT.UID, uid)
              .setSource(pn)
              .setTimeout(TIMEOUT);
      MessageFilter filter2 =
          MessageFilter.create()
              .setType(DMT.FNPSwapReply)
              .setField(DMT.UID, uid)
              .setSource(pn)
              .setTimeout(TIMEOUT);
      MessageFilter filter = filter1.or(filter2);

      try {
        node.network().usm().send(pn, m, LocationManager.this);
      } catch (NotConnectedException _) {
        if (LOG.isDebugEnabled())
          LOG.debug("Disconnected while sending SwapRequest/SwapReply to {}", pn);
        return null;
      }
      if (LOG.isDebugEnabled()) LOG.debug("Waiting for SwapReply/SwapRejected on {}", uid);
      try {
        Message reply = node.network().usm().waitFor(filter, LocationManager.this);
        if (reply == null
            && pn.isRoutable()
            && (System.currentTimeMillis() - pn.timeLastConnectionCompleted() > TIMEOUT * 2)) {
          LOG.error("Timeout waiting for SwapRejected/SwapReply on {}", uid);
        }
        return reply;
      } catch (DisconnectedException _) {
        if (LOG.isDebugEnabled())
          LOG.debug("Disconnected while waiting for SwapReply/SwapRejected for {}", uid);
        return null;
      }
    }

    private Message sendCommitAndWaitForComplete(PeerNode pn, long uid, byte[] myValue) {
      Message confirm = DMT.createFNPSwapCommit(uid, myValue);

      MessageFilter filter1 =
          MessageFilter.create()
              .setType(DMT.FNPSwapRejected)
              .setField(DMT.UID, uid)
              .setTimeout(TIMEOUT)
              .setSource(pn);
      MessageFilter filter3 =
          MessageFilter.create()
              .setField(DMT.UID, uid)
              .setType(DMT.FNPSwapComplete)
              .setTimeout(TIMEOUT)
              .setSource(pn);
      MessageFilter filter = filter1.or(filter3);

      try {
        node.network().usm().send(pn, confirm, LocationManager.this);
      } catch (NotConnectedException _) {
        if (LOG.isDebugEnabled()) LOG.debug("Disconnected while sending SwapCommit to {}", pn);
        return null;
      }
      if (LOG.isDebugEnabled()) LOG.debug("Waiting for SwapComplete: uid={}", uid);
      try {
        Message reply = node.network().usm().waitFor(filter, LocationManager.this);
        if (reply == null
            && pn.isRoutable()
            && (System.currentTimeMillis() - pn.timeLastConnectionCompleted() > TIMEOUT * 2)) {
          LOG.error("Timeout waiting for SwapComplete on {}", uid);
        }
        return reply;
      } catch (DisconnectedException _) {
        if (LOG.isDebugEnabled())
          LOG.debug("Disconnected while waiting for SwapComplete on {}", uid);
        return null;
      }
    }

    private CommitPayload decodeAndValidateSwapComplete(Message reply, byte[] hisHash, long uid) {
      byte[] hisBuf = ((ShortBuffer) reply.getObject(DMT.DATA)).getData();
      if ((hisBuf.length % 8 != 0) || (hisBuf.length < 16)) {
        LOG.error("SwapComplete invalid content length on {}", uid);
        return null;
      }
      byte[] rehash = SHA256.digest(hisBuf);
      if (!Arrays.equals(rehash, hisHash)) {
        LOG.error("SwapComplete hash mismatch on {}", uid);
        return null;
      }
      long[] hisBufLong = Fields.bytesToLongs(hisBuf);
      if (hisBufLong.length < 2) {
        LOG.error("SwapComplete invalid buffer length (no random, no location) on {}", uid);
        return null;
      }
      long hisRandom = hisBufLong[0];
      double hisLoc = Double.longBitsToDouble(hisBufLong[1]);
      if (!Location.isValid(hisLoc)) {
        LOG.error("SwapComplete invalid location {} on {}", hisLoc, uid);
        return null;
      }
      registerKnownLocation(hisLoc);
      double[] hisFriendLocs = new double[hisBufLong.length - 2];
      for (int i = 0; i < hisFriendLocs.length; i++) {
        hisFriendLocs[i] = Double.longBitsToDouble(hisBufLong[i + 2]);
        if (!Location.isValid(hisFriendLocs[i])) {
          LOG.error("SwapComplete invalid friend location {} on {}", hisFriendLocs[i], uid);
          return null;
        }
        registerLocationLink(hisLoc, hisFriendLocs[i]);
        registerKnownLocation(hisFriendLocs[i]);
      }
      numberOfRemotePeerLocationsSeenInSwaps += hisFriendLocs.length;
      return new CommitPayload(hisRandom, hisLoc, hisFriendLocs);
    }

    private boolean isRejectedAfterRequest(Message reply, long uid) {
      if (Objects.equals(reply.getSpec(), DMT.FNPSwapRejected)) {
        if (LOG.isDebugEnabled()) LOG.debug("Swap rejected for {}", uid);
        return true;
      }
      return false;
    }

    private boolean isRejectedAfterComplete(Message reply) {
      if (Objects.equals(reply.getSpec(), DMT.FNPSwapRejected)) {
        LOG.error(
            "SwapRejected received while waiting for SwapComplete; occasional disconnects are"
                + " expected, frequent occurrences indicate a bug or attack");
        return true;
      }
      return false;
    }

    private void applySwapDecision(
        boolean shouldSwap, CommitPayload payload, double myLoc, long uid) {
      if (shouldSwap) {
        timeLastSuccessfullySwapped = System.currentTimeMillis();
        updateLocationChangeSession(payload.hisLoc);
        setLocation(payload.hisLoc);
        if (LOG.isDebugEnabled())
          LOG.debug("Outgoing swap succeeds: {} <-> {} uid={}", myLoc, payload.hisLoc, uid);
        incrementSwaps();
        announceLocChange(true, false, false);
        node.writeNodeFile();
      } else {
        if (LOG.isDebugEnabled())
          LOG.debug("Outgoing swap skipped: {} <-> {} uid={}", myLoc, payload.hisLoc, uid);
        incrementNoSwaps();
      }
    }
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static class CommitPayload {
    final long hisRandom;
    final double hisLoc;
    final double[] hisFriendLocs;

    CommitPayload(long hisRandom, double hisLoc, double[] hisFriendLocs) {
      this.hisRandom = hisRandom;
      this.hisLoc = hisLoc;
      this.hisFriendLocs = hisFriendLocs;
    }
  }

  /** Announces our location change to all connected peers. */
  protected void announceLocChange() {
    announceLocChange(false, false, false);
  }

  private void announceLocChange(boolean log, boolean randomReset, boolean fromDupLocation) {
    Message msg =
        DMT.createFNPLocChangeNotificationNew(
            getLocation(), node.network().peers().getPeerLocationDoubles(true));
    node.network().peers().messenger().localBroadcast(msg, false, true, this);
    if (log) recordLocChange(randomReset, fromDupLocation);
  }

  private void recordLocChange(final boolean randomReset, final boolean fromDupLocation) {
    node.network()
        .executor()
        .execute(
            () -> {
              File locationLog = node.nodeDir().file("location.log.txt");
              if (locationLog.exists() && locationLog.length() > 1024 * 1024 * 10) {
                try {
                  Files.delete(locationLog.toPath());
                } catch (IOException _) {
                  locationLog.deleteOnExit();
                }
              }
              try (FileOutputStream os = new FileOutputStream(locationLog, true);
                  BufferedWriter bw =
                      new BufferedWriter(new OutputStreamWriter(os, StandardCharsets.ISO_8859_1))) {
                DateTimeFormatter formatter =
                    DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM)
                        .withLocale(Locale.getDefault())
                        .withZone(ZoneOffset.UTC);
                String suffix = "";
                if (randomReset) {
                  suffix =
                      " (random reset" + (fromDupLocation ? " from duplicated location" : "") + ")";
                }
                bw.write(
                    formatter.format(Instant.now(systemClockUTC))
                        + " : "
                        + getLocation()
                        + suffix
                        + '\n');
              } catch (IOException e) {
                LOG.error("Unable to write changed location to {} : {}", locationLog, e, e);
              }
            },
            "Record new location");
  }

  private boolean locked;

  private static final AtomicInteger swaps = new AtomicInteger();
  private static final AtomicInteger noSwaps = new AtomicInteger();
  private static final AtomicInteger startedSwaps = new AtomicInteger();
  private static final AtomicInteger swapsRejectedAlreadyLocked = new AtomicInteger();
  private static final AtomicInteger swapsRejectedNowhereToGo = new AtomicInteger();
  private static final AtomicInteger swapsRejectedRateLimit = new AtomicInteger();
  private static final AtomicInteger swapsRejectedRecognizedID = new AtomicInteger();

  /** Returns the number of successful swaps since start. */
  public static int getSwaps() {
    return swaps.get();
  }

  /** Returns the number of swap attempts that did not result in a swap. */
  public static int getNoSwaps() {
    return noSwaps.get();
  }

  /** Returns the number of outgoing swap attempts started. */
  public static int getStartedSwaps() {
    return startedSwaps.get();
  }

  /** Returns the number of rejections due to lock contention or queue limits. */
  public static int getSwapsRejectedAlreadyLocked() {
    return swapsRejectedAlreadyLocked.get();
  }

  /** Returns the number of rejections due to no available peer to forward to. */
  public static int getSwapsRejectedNowhereToGo() {
    return swapsRejectedNowhereToGo.get();
  }

  /** Returns the number of rejections due to peer-advised rate limiting. */
  public static int getSwapsRejectedRateLimit() {
    return swapsRejectedRateLimit.get();
  }

  /** Returns the number of rejections due to duplicate or recognized IDs. */
  public static int getSwapsRejectedRecognizedID() {
    return swapsRejectedRecognizedID.get();
  }

  long lockedTime;

  /**
   * Attempts to lock the manager to process a swap.
   *
   * @return {@code true} when the lock was acquired; {@code false} if already locked
   */
  @SuppressWarnings("BooleanMethodIsAlwaysInverted")
  synchronized boolean lock() {
    if (locked) {
      if (LOG.isDebugEnabled()) LOG.debug("Already locked");
      return false;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Locking on port {}", node.network().darknetPortNumber());
    locked = true;
    lockedTime = System.currentTimeMillis();
    return true;
  }

  /** Unlocks the manager and starts the next queued swap if any. */
  void unlock() {
    Message nextMessage;
    synchronized (this) {
      if (!locked) throw new IllegalStateException("Unlocking when not locked!");
      long lockTime = System.currentTimeMillis() - lockedTime;
      if (LOG.isDebugEnabled()) {
        LOG.debug("Unlocking on port {}", node.network().darknetPortNumber());
        LOG.debug("lockTime: {}", lockTime);
      }
      averageSwapTime.report(lockTime);

      if (incomingMessageQueue.isEmpty()) {
        locked = false;
        return;
      }

      // Otherwise, stay locked and start the next one from the queue.

      nextMessage = incomingMessageQueue.removeFirst();
      lockedTime = System.currentTimeMillis();
    }

    long oldID = nextMessage.getLong(DMT.UID);
    long newID = oldID + 1;
    PeerNode pn = (PeerNode) nextMessage.getSource();

    innerHandleSwapRequest(oldID, newID, pn, nextMessage);
  }

  /**
   * Decides whether to swap locations based on the Freenet 0.7 criterion.
   *
   * <p>Let A be the product of distances from each node to its neighbors before the swap, and B be
   * the product after hypothetically swapping the two nodes. If {@code A > B}, swap. Otherwise,
   * swap with probability {@code A / B} using {@code rand} as the shared randomness.
   *
   * @param myLoc this node's location
   * @param friendLocs this node's neighbor locations
   * @param hisLoc the counterparty's location
   * @param hisFriendLocs the counterparty's neighbor locations
   * @param rand shared random value used to derive a probability
   * @return {@code true} to swap; {@code false} otherwise
   */
  private boolean shouldSwap(
      double myLoc, double[] friendLocs, double hisLoc, double[] hisFriendLocs, long rand) {

    // A = product of distances from each node to all their neighbors
    if (Math.abs(hisLoc - myLoc) <= Double.MIN_VALUE * 2) return false; // Probably self

    debugDumpSwapCandidates(myLoc, friendLocs, hisLoc, hisFriendLocs);

    double prodA =
        productDistanceExcludingSelf(friendLocs, myLoc)
            * productDistanceExcludingSelf(hisFriendLocs, hisLoc);

    // B = the same, with our two values swapped
    double prodB =
        productDistanceExcludingSelf(friendLocs, hisLoc)
            * productDistanceExcludingSelf(hisFriendLocs, myLoc);

    if (prodA > prodB) return true;

    double p = prodA / prodB;

    // Take the last 63 bits, then turn into a double
    double randProb = ((double) (rand & Long.MAX_VALUE)) / ((double) Long.MAX_VALUE);

    return randProb < p;
  }

  private void debugDumpSwapCandidates(
      double myLoc, double[] friendLocs, double hisLoc, double[] hisFriendLocs) {
    if (!LOG.isDebugEnabled()) return;
    StringBuilder sb = new StringBuilder();
    sb.append("my: ")
        .append(myLoc)
        .append(", his: ")
        .append(hisLoc)
        .append(", myFriends: ")
        .append(friendLocs.length)
        .append(", hisFriends: ")
        .append(hisFriendLocs.length)
        .append(" mine:\n");
    for (double friendLoc : friendLocs) {
      sb.append(friendLoc).append(' ');
    }
    sb.append("\nhis:\n");
    for (double hisFriendLoc : hisFriendLocs) {
      sb.append(hisFriendLoc).append(' ');
    }
    LOG.debug(sb.toString());
  }

  private double productDistanceExcludingSelf(double[] locs, double anchor) {
    double product = 1.0;
    for (double otherLoc : locs) {
      if (Math.abs(otherLoc - anchor) <= Double.MIN_VALUE * 2) continue;
      product *= Location.distance(otherLoc, anchor);
    }
    return product;
  }

  final Map<Long, RecentlyForwardedItem> recentlyForwardedIDs;

  static class RecentlyForwardedItem {
    final long incomingID; // unnecessary?
    final long outgoingID;
    final long addedTime;
    long lastMessageTime; // can delete it when no messages for 2*TIMEOUT
    final PeerNode requestSender;
    PeerNode routedTo;
    // Set when a request is accepted. Unset when we send one.
    boolean successfullyForwarded;

    RecentlyForwardedItem(long id, long outgoingID, PeerNode from, PeerNode to) {
      this.incomingID = id;
      this.outgoingID = outgoingID;
      requestSender = from;
      routedTo = to;
      addedTime = System.currentTimeMillis();
      lastMessageTime = addedTime;
    }
  }

  /** Queue of swap requests to handle after this one. */
  private final Deque<Message> incomingMessageQueue = new ArrayDeque<>();

  static final int MAX_INCOMING_QUEUE_LENGTH = 10;

  /** Prevent timeouts and deadlocks due to A waiting for B waiting for A */
  static final long MAX_TIME_ON_INCOMING_QUEUE = SECONDS.toMillis(30);

  void removeTooOldQueuedItems() {
    while (true) {
      Message first;
      synchronized (this) {
        if (incomingMessageQueue.isEmpty()) return;
        first = incomingMessageQueue.getFirst();
        if (first.age() < MAX_TIME_ON_INCOMING_QUEUE) return;
        incomingMessageQueue.removeFirst();
        if (LOG.isDebugEnabled())
          LOG.debug("Cancel queued item {} (too long on queue; possible circular wait)", first);
        incrementSwapsRejectedAlreadyLocked();
      }
      long oldID = first.getLong(DMT.UID);
      PeerNode pn = (PeerNode) first.getSource();

      // Reject
      Message reject = DMT.createFNPSwapRejected(oldID);
      try {
        pn.transport().sendAsync(reject, null, this);
      } catch (NotConnectedException _) {
        if (LOG.isDebugEnabled())
          LOG.debug("Disconnected while rejecting timed-out queued SwapRequest to {}", pn);
      }
    }
  }

  /**
   * Handles an incoming FNPSwapRequest.
   *
   * <p>Validates the request, decrements HTL, and either forwards, queues, or processes it locally
   * subject to locking and rate limits.
   *
   * @param m swap request message
   * @param pn sending peer
   */
  public void handleSwapRequest(Message m, PeerNode pn) {
    final long oldID = m.getLong(DMT.UID);
    final long newID = oldID + 1;
    /*
     * UID is used to record the state i.e., UID x, came in from node a, forwarded to node b. We
     * increment it on each hop, because in order for the node selection to be as random as possible
     * we *must allow loops*! I.e., the same swap chain may pass over the same node twice or more.
     * However, if we get a request with either the incoming or the outgoing UID, we can safely kill
     * it as it's clearly the result of a bug.
     */
    if (rejectIfDuplicateRequest(oldID, pn)) return;
    if (rejectIfRateLimited(pn, oldID)) return;
    if (LOG.isDebugEnabled()) LOG.debug("SwapRequest from {} uid={}", pn, oldID);
    int htl = sanitizeAndDecrementHtl(m.getInt(DMT.HTL), oldID, pn);
    if (rejectIfSwappingDisabledOrLowHtl(htl, oldID, pn)) return;
    // Either forward it or handle it
    if (htl <= 0) {
      if (LOG.isDebugEnabled()) LOG.debug("Accept request {}", oldID);
      lockOrQueue(m, oldID, newID, pn);
      return;
    }
    m.set(DMT.HTL, htl);
    m.set(DMT.UID, newID);
    if (LOG.isDebugEnabled()) LOG.debug("Forward request {}", oldID);
    forwardSwapRequest(m, oldID, newID, pn);
  }

  /**
   * If we can get the lock, then execute the swap by calling innerHandleSwapRequest(). If we can
   * queue the message, queue it. Otherwise, reject it.
   */
  void lockOrQueue(Message msg, long oldID, long newID, PeerNode pn) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Locking on port {} for uid {} from {}", node.network().darknetPortNumber(), oldID, pn);
    LockDecision decision = decideAndMaybeQueue(msg);
    if (decision.reject) {
      if (LOG.isDebugEnabled()) LOG.debug("Reject message {}", msg);
      Message rejected = DMT.createFNPSwapRejected(oldID);
      try {
        pn.transport().sendAsync(rejected, null, this);
      } catch (NotConnectedException _) {
        if (LOG.isDebugEnabled())
          LOG.debug("Disconnected while rejecting SwapRequest (lock/queue limit) to {}", pn);
      }
    } else if (decision.runNow) {
      if (LOG.isDebugEnabled()) LOG.debug("Run message {}", msg);
      boolean completed = false;
      try {
        innerHandleSwapRequest(oldID, newID, pn, msg);
        completed = true;
      } finally {
        if (!completed) unlock();
      }
    }
  }

  private LockDecision decideAndMaybeQueue(Message msg) {
    boolean runNow = false;
    boolean reject = false;
    synchronized (this) {
      if (!locked) {
        locked = true;
        runNow = true;
        lockedTime = System.currentTimeMillis();
      } else {
        if (!node.isEnableSwapQueueing()
            || incomingMessageQueue.size() > MAX_INCOMING_QUEUE_LENGTH) {
          reject = true;
          incrementSwapsRejectedAlreadyLocked();
          if (LOG.isDebugEnabled())
            LOG.debug(
                "Incoming queue length {} exceeds limit; reject {}",
                incomingMessageQueue.size(),
                msg);
        } else {
          incomingMessageQueue.addLast(msg);
          if (LOG.isDebugEnabled())
            LOG.debug("Queued {}; queue length {}", msg, incomingMessageQueue.size());
        }
      }
    }
    return new LockDecision(runNow, reject);
  }

  private record LockDecision(boolean runNow, boolean reject) {}

  private void forwardSwapRequest(Message m, long oldID, long newID, PeerNode pn) {
    while (true) {
      PeerNode randomPeer = node.network().peers().getRandomPeer(pn);
      if (randomPeer == null) {
        rejectLateBecauseNoPeer(oldID, pn);
        return;
      }
      if (LOG.isDebugEnabled()) LOG.debug("Forward {} to {}", oldID, randomPeer);
      RecentlyForwardedItem forwarded = addForwardedItem(oldID, newID, pn, randomPeer);
      forwarded.successfullyForwarded = false;
      if (attemptForward(m, oldID, pn, randomPeer, forwarded)) return;
      // else try a different node
    }
  }

  private void rejectLateBecauseNoPeer(long oldID, PeerNode pn) {
    if (LOG.isDebugEnabled()) LOG.debug("Late reject {}", oldID);
    Message reject = DMT.createFNPSwapRejected(oldID);
    try {
      pn.transport().sendAsync(reject, null, this);
    } catch (NotConnectedException _) {
      LOG.info("Disconnected while sending late reject to {}", pn);
    }
    incrementSwapsRejectedNowhereToGo();
  }

  private boolean attemptForward(
      Message m, long oldID, PeerNode pn, PeerNode randomPeer, RecentlyForwardedItem forwarded) {
    try {
      randomPeer
          .transport()
          .sendAsync(
              m.cloneAndDropSubMessages(),
              new MyCallback(DMT.createFNPSwapRejected(oldID), pn, forwarded),
              LocationManager.this);
      return true;
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled()) LOG.debug("Peer not connected");
      return false;
    }
  }

  private void innerHandleSwapRequest(long oldID, long newID, PeerNode pn, Message m) {
    RecentlyForwardedItem item = addForwardedItem(oldID, newID, pn, null);
    // Locked, do it
    IncomingSwapRequestHandler isrh = new IncomingSwapRequestHandler(m, pn, item);
    if (LOG.isDebugEnabled()) LOG.debug("Handle request {} from {}", oldID, pn);
    node.network()
        .executor()
        .execute(
            isrh, "Incoming swap request handler for port " + node.network().darknetPortNumber());
  }

  private boolean rejectIfDuplicateRequest(long oldID, PeerNode pn) {
    RecentlyForwardedItem item = recentlyForwardedIDs.get(oldID);
    if (item == null) return false;
    if (LOG.isDebugEnabled()) LOG.debug("Reject duplicate request ID");
    Message reject = DMT.createFNPSwapRejected(oldID);
    try {
      pn.transport().sendAsync(reject, null, this);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled()) LOG.debug("Disconnected while rejecting SwapRequest to {}", pn);
    }
    incrementSwapsRejectedRecognizedID();
    return true;
  }

  private boolean rejectIfRateLimited(PeerNode pn, long oldID) {
    if (!pn.shouldRejectSwapRequest()) return false;
    if (LOG.isDebugEnabled()) LOG.debug("Peer advises rejection due to rate limit");
    Message reject = DMT.createFNPSwapRejected(oldID);
    try {
      pn.transport().sendAsync(reject, null, this);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled()) LOG.debug("Disconnected while rejecting SwapRequest from {}", pn);
    }
    incrementSwapsRejectedRateLimit();
    return true;
  }

  private int sanitizeAndDecrementHtl(int htl, long oldID, PeerNode pn) {
    int out = htl;
    if (out > SWAP_MAX_HTL) {
      LOG.error("Invalid swap HTL={} from {} uid={}", out, pn, oldID);
      out = SWAP_MAX_HTL;
    }
    return out - 1;
  }

  private boolean rejectIfSwappingDisabledOrLowHtl(int htl, long oldID, PeerNode pn) {
    if (node.isEnableSwapping() && !(htl <= 0 && swappingDisabled())) {
      return false;
    }
    Message reject = DMT.createFNPSwapRejected(oldID);
    try {
      pn.transport().sendAsync(reject, null, this);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled())
        LOG.debug("Disconnected while rejecting SwapRequest (disabled/low HTL) to {}", pn);
    }
    return true;
  }

  private RecentlyForwardedItem addForwardedItem(
      long uid, long oid, PeerNode pn, PeerNode randomPeer) {
    RecentlyForwardedItem item = new RecentlyForwardedItem(uid, oid, pn, randomPeer);
    synchronized (recentlyForwardedIDs) {
      recentlyForwardedIDs.put(uid, item);
      recentlyForwardedIDs.put(oid, item);
    }
    return item;
  }

  /**
   * Handles an unmatched FNPSwapReply by forwarding along the saved chain.
   *
   * @param m swap reply message
   * @param source sending peer
   * @return {@code true} if recognized and forwarded; {@code false} otherwise
   */
  public boolean handleSwapReply(Message m, PeerNode source) {
    final long uid = m.getLong(DMT.UID);
    RecentlyForwardedItem item = recentlyForwardedIDs.get(uid);
    if (item == null) {
      LOG.error("Unrecognized SwapReply id={} ", uid);
      return false;
    }
    if (item.requestSender == null) {
      if (LOG.isDebugEnabled())
        LOG.debug("SwapReply from {} on chain originated locally {}", source, uid);
      return false;
    }
    if (item.routedTo == null) {
      LOG.error("SwapReply on {} but routedTo is null", uid);
      return false;
    }
    if (!Objects.equals(source, item.routedTo)) {
      LOG.error(
          UNMATCHED_SWAP_REPLY_WRONG_SOURCE_MSG, uid, source, item.routedTo, item.requestSender);
      return true;
    }
    item.lastMessageTime = System.currentTimeMillis();
    // Returning to source - use incomingID
    byte[] hisHash = ((ShortBuffer) m.getObject(DMT.HASH)).getData();
    Message fwd = DMT.createFNPSwapReply(item.incomingID, hisHash);
    if (LOG.isDebugEnabled())
      LOG.debug("Forwarding SwapReply {} from {} to {}", uid, source, item.requestSender);
    try {
      item.requestSender.transport().sendAsync(fwd, null, this);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled())
        LOG.debug("Lost connection forwarding SwapReply {} to {}", uid, item.requestSender);
    }
    return true;
  }

  /**
   * Handles an unmatched FNPSwapRejected by forwarding along the saved chain.
   *
   * @param m rejection message
   * @param source sending peer
   * @return {@code true} if recognized and forwarded; {@code false} otherwise
   */
  public boolean handleSwapRejected(Message m, PeerNode source) {
    final long uid = m.getLong(DMT.UID);
    RecentlyForwardedItem item = recentlyForwardedIDs.get(uid);
    if (item == null) return false;
    if (item.requestSender == null) {
      if (LOG.isDebugEnabled())
        LOG.debug("FNPSwapRejected without requestSender; cannot claim; uid={}", uid);
      return false;
    }
    if (item.routedTo == null) {
      LOG.error("SwapRejected on {} but routedTo is null", uid);
      return false;
    }
    if (!Objects.equals(source, item.routedTo)) {
      LOG.error(
          UNMATCHED_SWAP_REJECTED_WRONG_SOURCE_MSG, uid, source, item.routedTo, item.requestSender);
      return true;
    }
    removeRecentlyForwardedItem(item);
    item.lastMessageTime = System.currentTimeMillis();
    if (LOG.isDebugEnabled())
      LOG.debug("Forwarding SwapRejected {} from {} to {}", uid, source, item.requestSender);
    m = m.cloneAndDropSubMessages();
    // Returning to source - use incomingID
    m.set(DMT.UID, item.incomingID);
    try {
      item.requestSender.transport().sendAsync(m, null, this);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled())
        LOG.debug("Lost connection forwarding SwapRejected {} to {}", uid, item.requestSender);
    }
    return true;
  }

  /**
   * Handles an unmatched FNPSwapCommit by forwarding along the saved chain.
   *
   * @param m commit message
   * @param source sending peer
   * @return {@code true} if recognized and forwarded; {@code false} otherwise
   */
  public boolean handleSwapCommit(Message m, PeerNode source) {
    final long uid = m.getLong(DMT.UID);
    RecentlyForwardedItem item = recentlyForwardedIDs.get(uid);
    if (item == null) return false;
    if (item.routedTo == null) return false;
    if (!Objects.equals(source, item.requestSender)) {
      LOG.error(
          UNMATCHED_SWAP_COMMIT_WRONG_SOURCE_MSG, uid, source, item.requestSender, item.routedTo);
      return true;
    }
    item.lastMessageTime = System.currentTimeMillis();
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Forwarding SwapCommit {},{} from {} to {}", uid, item.outgoingID, source, item.routedTo);
    m = m.cloneAndDropSubMessages();
    // Sending onwards - use outgoing ID
    m.set(DMT.UID, item.outgoingID);
    try {
      item.routedTo
          .transport()
          .sendAsync(
              m,
              new SendMessageOnErrorCallback(
                  DMT.createFNPSwapRejected(item.incomingID), item.requestSender, this),
              this);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled())
        LOG.debug("Lost connection forwarding SwapCommit {} to {}", uid, item.routedTo);
    }
    spyOnLocations(m);
    return true;
  }

  /**
   * Handles an unmatched FNPSwapComplete by forwarding along the saved chain.
   *
   * @param m completion message
   * @param source sending peer
   * @return {@code true} if recognized and forwarded; {@code false} otherwise
   */
  public boolean handleSwapComplete(Message m, PeerNode source) {
    final long uid = m.getLong(DMT.UID);
    if (LOG.isDebugEnabled()) LOG.debug("handleSwapComplete({})", uid);
    RecentlyForwardedItem item = recentlyForwardedIDs.get(uid);
    if (item == null) {
      if (LOG.isDebugEnabled()) LOG.debug("Item not found for uid={} msg={}", uid, m);
      return false;
    }
    if (item.requestSender == null) {
      if (LOG.isDebugEnabled()) LOG.debug("Not matched uid={} msg={}", uid, m);
      return false;
    }
    if (item.routedTo == null) {
      LOG.error("SwapComplete on {} but routedTo is null", uid);
      return false;
    }
    if (!Objects.equals(source, item.routedTo)) {
      LOG.error(
          UNMATCHED_SWAP_COMPLETE_WRONG_SOURCE_MSG, uid, source, item.routedTo, item.requestSender);
      return true;
    }
    if (LOG.isDebugEnabled())
      LOG.debug("Forwarding SwapComplete {} from {} to {}", uid, source, item.requestSender);
    m = m.cloneAndDropSubMessages();
    // Returning to source - use incomingID
    m.set(DMT.UID, item.incomingID);
    try {
      item.requestSender.transport().sendAsync(m, null, this);
    } catch (NotConnectedException _) {
      LOG.info("Disconnected while forwarding SwapComplete {} to {}", uid, item.requestSender);
    }
    item.lastMessageTime = System.currentTimeMillis();
    removeRecentlyForwardedItem(item);
    spyOnLocations(m);
    return true;
  }

  private void spyOnLocations(Message m) {
    spyOnLocations(m, false, false, -1.0);
  }

  /**
   * Spy on locations in somebody else's swap request. Greatly increases the speed at which we can
   * gather location data to estimate the network's size.
   *
   * @param swappingWithMe True if this node is participating in the swap, false if it is merely
   *     spying on somebody else's swap.
   */
  private void spyOnLocations(
      Message m, boolean ignoreIfOld, boolean swappingWithMe, double myLoc) {

    long[] uids = null;

    Message uidsMessage = m.getSubMessage(DMT.FNPSwapNodeUIDs);
    if (uidsMessage != null) {
      uids = Fields.bytesToLongs(((ShortBuffer) uidsMessage.getObject(DMT.NODE_UIDS)).getData());
    }

    byte[] data = ((ShortBuffer) m.getObject(DMT.DATA)).getData();

    if (data.length < 16 || data.length % 8 != 0) {
      LOG.error("SwapCommit data length invalid: {}", data.length);
      return;
    }

    double[] locations = Fields.bytesToDoubles(data, 8, data.length - 8);

    double hisLoc = locations[0];
    if (!Location.isValid(hisLoc)) {
      LOG.error("SwapCommit invalid location: {}", hisLoc);
      return;
    }

    if (uids != null) {
      registerKnownLocation(hisLoc, uids[0]);
      if (swappingWithMe) registerKnownLocation(myLoc, uids[0]);
    } else if (!ignoreIfOld) registerKnownLocation(hisLoc);

    for (int i = 1; i < locations.length; i++) {
      double friendLocation = locations[i];
      if (uids != null) {
        registerKnownLocation(friendLocation, uids[i - 1]);
        registerLink(uids[0], uids[i - 1]);
      } else if (!ignoreIfOld) {
        registerKnownLocation(friendLocation);
        registerLocationLink(hisLoc, friendLocation);
      }
    }
  }

  public void clearOldSwapChains() {
    long now = System.currentTimeMillis();
    synchronized (recentlyForwardedIDs) {
      RecentlyForwardedItem[] items = new RecentlyForwardedItem[recentlyForwardedIDs.size()];
      if (items.length < 1) return;
      items = recentlyForwardedIDs.values().toArray(items);
      for (RecentlyForwardedItem item : items) {
        if (now - item.lastMessageTime > (TIMEOUT * 2)) {
          removeRecentlyForwardedItem(item);
        }
      }
    }
  }

  /** Called when a peer disconnects or restarts to clear pending swap chains. */
  public void lostOrRestartedNode(PeerNode pn) {
    List<RecentlyForwardedItem> v = new ArrayList<>();
    synchronized (recentlyForwardedIDs) {
      Set<Map.Entry<Long, RecentlyForwardedItem>> entrySet = recentlyForwardedIDs.entrySet();
      for (Map.Entry<Long, RecentlyForwardedItem> entry : entrySet) {
        Long l = entry.getKey();
        RecentlyForwardedItem item = entry.getValue();

        if (item == null) {
          LOG.error("recentlyForwardedIDs missing value for key {}", l);
        } else if (Objects.equals(item.routedTo, pn) && item.successfullyForwarded) {
          v.add(item);
        }
      }

      // remove them
      for (RecentlyForwardedItem item : v) removeRecentlyForwardedItem(item);
    }
    int dumped = v.size();
    if (dumped != 0 && LOG.isDebugEnabled())
      LOG.debug("lostOrRestartedNode dumps {} swap requests for {}", dumped, pn.getPeer());
    for (RecentlyForwardedItem item : v) {
      // Just reject it to avoid locking problems etc.
      Message msg = DMT.createFNPSwapRejected(item.incomingID);
      if (LOG.isDebugEnabled())
        LOG.debug("Reject in lostOrRestartedNode: {} from {}", item.incomingID, item.requestSender);
      try {
        item.requestSender.transport().sendAsync(msg, null, this);
      } catch (NotConnectedException _) {
        LOG.info("Both sender and receiver disconnected for {}", item);
      }
    }
  }

  private void removeRecentlyForwardedItem(RecentlyForwardedItem item) {
    if (LOG.isDebugEnabled()) LOG.debug("Removing: {}", item);
    if (item == null) {
      LOG.warn("removeRecentlyForwardedItem(null)");
      return;
    }
    synchronized (recentlyForwardedIDs) {
      recentlyForwardedIDs.remove(item.incomingID);
      recentlyForwardedIDs.remove(item.outgoingID);
    }
  }

  private static final long MAX_AGE = DAYS.toMillis(7);

  private final TimeSortedHashtable<Double> knownLocs = new TimeSortedHashtable<>();

  void registerLocationLink(double d, double t) {
    if (LOG.isDebugEnabled()) LOG.debug("Known Link: {} {}", d, t);
  }

  void registerKnownLocation(double d, long uid) {
    if (LOG.isDebugEnabled()) LOG.debug("LOCATION: {} UID: {}", d, uid);
    registerKnownLocation(d);
  }

  void registerKnownLocation(double d) {
    if (LOG.isDebugEnabled()) LOG.debug("Known Location: {}", d);
    long now = System.currentTimeMillis();

    synchronized (knownLocs) {
      LOG.debug("Adding location {} knownLocs size {}", d, knownLocs.size());
      knownLocs.push(d, now);
      LOG.debug("Added location {} knownLocs size {}", d, knownLocs.size());
      knownLocs.removeBefore(now - MAX_AGE);
      LOG.debug("Added and pruned location {} knownLocs size {}", d, knownLocs.size());
    }
    if (LOG.isDebugEnabled()) LOG.debug("Estimated network size (session)={}", knownLocs.size());
  }

  void registerLink(long uid1, long uid2) {
    if (LOG.isDebugEnabled()) LOG.debug("UID LINK: {} , {}", uid1, uid2);
  }

  // Return the estimated network size based on locations seen after timestamp or for the whole
  // session if -1.
  public int getNetworkSizeEstimate(long timestamp) {
    return knownLocs.countValuesAfter(timestamp);
  }

  /**
   * Returns known locations seen since {@code timestamp}.
   *
   * <p>Intended for {@code Node.getKnownLocations(long)}. The return value is a two‑element array:
   * the first contains locations, the second their last‑seen timestamps.
   *
   * @param timestamp epoch milliseconds; pass {@code -1} for the current session
   * @return two‑element array: locations and last‑seen timestamps
   */
  public Object[] getKnownLocations(long timestamp) {
    synchronized (knownLocs) {
      return knownLocs.pairsAfter(timestamp, new Double[knownLocs.size()]);
    }
  }

  /** Sets a custom {@link Clock} for deterministic tests. */
  public static void setClockForTesting(Clock clock) {
    systemClockUTC = clock;
  }

  /** Returns the current {@link Clock} used for mitigation scheduling. */
  public static Clock getClockForTesting() {
    return systemClockUTC;
  }

  /**
   * Extracts peer locations, optionally encoding routing backoff state.
   *
   * @param peers peers to read
   * @param indicateBackoff when true, the backoff state is encoded by sign/offset
   * @return array of locations, one per {@code peers[i]}
   */
  public static double[] extractLocs(PeerNode[] peers, boolean indicateBackoff) {
    double[] locs = new double[peers.length];
    for (int i = 0; i < peers.length; i++) {
      locs[i] = peers[i].getLocation();
      if (indicateBackoff) {
        if (peers[i].isRoutingBackedOffEither()) locs[i] += 1;
        else locs[i] = -1 - locs[i];
      }
    }
    return locs;
  }

  /**
   * Extracts swap identifiers from peers in index order.
   *
   * @param peers peers to read
   * @return array of {@code swapIdentifier} values
   */
  public static long[] extractUIDs(PeerNode[] peers) {
    long[] uids = new long[peers.length];
    for (int i = 0; i < peers.length; i++) uids[i] = peers[i].swapIdentifier;
    return uids;
  }

  /** Returns the cumulative location delta observed this session. */
  public synchronized double getLocChangeSession() {
    return locChangeSession;
  }

  /** Returns the current moving average of swap latency in milliseconds. */
  public int getAverageSwapTime() {
    return (int) averageSwapTime.currentValue();
  }

  /**
   * Returns the count of remote peer locations seen during swap exchanges.
   *
   * @return number of remote peer locations observed in swaps
   */
  public int getNumberOfRemotePeerLocationsSeenInSwaps() {
    return numberOfRemotePeerLocationsSeenInSwaps;
  }

  @Override
  public void receivedBytes(int x) {
    node.network().stats().swappingReceivedBytes(x);
  }

  @Override
  public void sentBytes(int x) {
    node.network().stats().swappingSentBytes(x);
  }

  @Override
  public void sentPayload(int x) {
    LOG.warn("Unexpected sentPayload() call in LocationManager");
  }
}
