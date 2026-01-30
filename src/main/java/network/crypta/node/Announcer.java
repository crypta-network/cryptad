package network.crypta.node;

import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.useralerts.AbstractUserEvent;
import network.crypta.node.useralerts.SimpleUserAlert;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.node.useralerts.UserEvent;
import network.crypta.support.ByteArrayWrapper;
import network.crypta.support.HTMLNode;
import network.crypta.support.ListUtils;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.TimeUtil;
import network.crypta.support.transport.ip.IPUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates when and how this node announces itself to the network.
 *
 * <p>The announcer decides whether an announcement is needed based on the current peer count and
 * then announces either to a node in the routing table or to seed nodes ("seednodes"). It manages
 * backoff and deduplication so we do not repeatedly announce to the same identities or IP
 * addresses, and so we avoid flooding the network.
 *
 * <p>Threading: calls may originate from different threads. Internal counters and the {@code
 * announcedTo*} sets are guarded by synchronization on {@code this}. Long-running and
 * network-facing operations are scheduled on the node's ticker/executor and are not performed on
 * the caller's thread.
 *
 * <p>Side effects: reads seed nodes from disk, registers transient user alerts, and schedules
 * background jobs.
 *
 * @author toad
 */
public class Announcer {
  private static final Logger LOG = LoggerFactory.getLogger(Announcer.class);

  // Reused logging fragments to avoid duplicated string literals (Sonar S1192)
  private static final String TRYING_TO_SEND_ANNOUNCEMENTS = " trying to send announcements";
  private static final String ANNOUNCE_DISABLED_TOO_OLD_KEY = "announceDisabledTooOld";
  private static final String ANNOUNCEMENT_TO = "Announcement to ";
  private static final String ANNOUNCEMENT_TO_NODE = "Announcement to node ";
  private static final String L10N_PREFIX = "Announcer.";

  private final Node node;
  private final OpennetManager om;
  private static final int STATUS_LOADING = 0;
  private static final int STATUS_CONNECTING_SEEDNODES = 1;
  private static final int STATUS_NO_SEEDNODES = -1;
  private int runningAnnouncements;

  /** We want to announce to 5 different seednodes. */
  private static final int WANT_ANNOUNCEMENTS = 5;

  private int sentAnnouncements;
  private long startTime;
  private long timeAddedSeeds;
  private static final long MIN_ADDED_SEEDS_INTERVAL = SECONDS.toMillis(60);

  /**
   * After we have sent 3 announcements, wait for 30 seconds before sending 3 more if we still have
   * no connections.
   */
  static final long COOLING_OFF_PERIOD = SECONDS.toMillis(30);

  /** Pubkey hashes of nodes we have announced to */
  private final HashSet<ByteArrayWrapper> announcedToIdentities;

  /**
   * IPs of nodes we have announced to. Maybe this should be first-two-bytes, but I'm not sure how
   * to do that with IPv6.
   */
  private final HashSet<InetAddress> announcedToIPs;

  /** How many nodes to connect to at once? */
  private static final int CONNECT_AT_ONCE = 15;

  /** Do not announce if there are more than this many opennet peers connected */
  private static final int MIN_OPENNET_CONNECTED_PEERS = 10;

  private static final long NOT_ALL_CONNECTED_DELAY = SECONDS.toMillis(60);
  private static final long RETRY_MISSING_SEEDNODES_DELAY = SECONDS.toMillis(30);

  /** Total nodes added by announcement so far */
  private int announcementAddedNodes;

  /** Total nodes that didn't want us so far */
  private int announcementNotWantedNodes;

  Announcer(OpennetManager om) {
    this.om = om;
    this.node = om.getNode();
    announcedToIdentities = new HashSet<>();
    announcedToIPs = new HashSet<>();
    // Debug gating derives from LOG.isDebugEnabled() where needed
  }

  /**
   * Starts the announcer logic.
   *
   * <p>If opennet is enabled and the node has no peers at all (darknet, opennet, or old opennet),
   * this immediately attempts to connect to seed nodes and announce. Otherwise, it waits for {@link
   * #MIN_ADDED_SEEDS_INTERVAL} and reassesses. Work is scheduled on the node's ticker.
   *
   * <p>Preconditions: opennet must be enabled on the node; otherwise the call returns without
   * scheduling anything. The method itself is non-blocking.
   */
  protected void start() {
    if (!node.network().isOpennetEnabled()) return;
    int darkPeers = node.network().peers().roster().getDarknetPeers().length;
    int openPeers = node.network().peers().roster().getOpennetPeers().length;
    int oldOpenPeers = om.countOldOpennetPeers();
    if (darkPeers + openPeers + oldOpenPeers == 0) {
      // Opennet is enabled and there are no peers. Connect to several seed nodes and announce.
      LOG.info("Attempting announcement to seednodes...");
      synchronized (this) {
        registerEvent(STATUS_LOADING);
        started = true;
      }
      connectSomeSeednodes();
    } else {
      LOG.info(
          "Not attempting immediate announcement: dark peers={} open peers={} old open peers={} -"
              + " will wait 1 minute...",
          darkPeers,
          openPeers,
          oldOpenPeers);
      // Wait a minute, then check whether we need to seed.
      node.network()
          .ticker()
          .queueTimedJob(
              () -> {
                synchronized (Announcer.this) {
                  started = true;
                }
                try {
                  maybeSendAnnouncement();
                } catch (Exception e) {
                  LOG.atError()
                      .setCause(e)
                      .addArgument(e::toString)
                      .addArgument(() -> TRYING_TO_SEND_ANNOUNCEMENTS)
                      .log("{}{}");
                }
              },
              MIN_ADDED_SEEDS_INTERVAL);
    }
  }

  private void registerEvent(int eventStatus) {
    node.services().clientCore().getAlerts().register(new AnnouncementUserEvent(eventStatus));
  }

  private void connectSomeSeednodes() {
    if (!node.network().isOpennetEnabled()) return;
    boolean announceNow;
    if (LOG.isDebugEnabled()) LOG.debug("Connecting some seednodes...");
    List<SimpleFieldSet> seeds = Announcer.readSeednodes(NodeFile.SEEDNODES.getFile(node));
    LOG.info("Trying to connect to {} seednodes...", seeds.size());
    long now = System.currentTimeMillis();
    if (prepareSeedsAndRegister(seeds, now)) return;
    // Connect to a subset of seed nodes. Once connected they report back and we can announce.

    int count = connectSomeNodesInner(seeds);
    boolean stillConnecting;
    List<SeedServerPeerNode> tryingSeeds =
        node.network().peers().seedPeers().getSeedServerPeersVector();
    stillConnecting = hasUnannouncedTryingSeeds(tryingSeeds);
    debugCounts(count, stillConnecting);
    announceNow = handleNoMorePeers(count, stillConnecting);
    node.network().dnsRequester().forceRun();
    // If none connect in a minute, try some more.
    scheduleMaybeSendAnnouncement(announceNow ? 0 : MIN_ADDED_SEEDS_INTERVAL);
  }

  /**
   * Prepare seed handling by enforcing the minimum interval and registering the appropriate user
   * event. Returns true when the caller should return early.
   */
  private boolean prepareSeedsAndRegister(List<SimpleFieldSet> seeds, long now) {
    synchronized (this) {
      if (now - timeAddedSeeds < MIN_ADDED_SEEDS_INTERVAL) return true;
      timeAddedSeeds = now;
      if (seeds.isEmpty()) {
        registerEvent(STATUS_NO_SEEDNODES);
        // File may be added later; re-check periodically without requiring a restart.
        node.network()
            .ticker()
            .queueTimedJob(this::maybeSendAnnouncement, Announcer.RETRY_MISSING_SEEDNODES_DELAY);
        return true;
      }
      registerEvent(STATUS_CONNECTING_SEEDNODES);
      return false;
    }
  }

  /** Return true if any trying seed has not yet been announced to. */
  private boolean hasUnannouncedTryingSeeds(List<SeedServerPeerNode> tryingSeeds) {
    synchronized (this) {
      for (SeedServerPeerNode seed : tryingSeeds) {
        if (!announcedToIdentities.contains(new ByteArrayWrapper(seed.peerECDSAPubKeyHash))) {
          return true;
        }
      }
      return false;
    }
  }

  /** Log current counts when debug is enabled. */
  private void debugCounts(int count, boolean stillConnecting) {
    if (!LOG.isDebugEnabled()) return;
    synchronized (this) {
      LOG.debug(
          "count = {} announced = {} running = {} still connecting {}",
          count,
          announcedToIdentities.size(),
          runningAnnouncements,
          stillConnecting);
    }
  }

  /**
   * Handle the case where there are no more peers to connect and no announcements running. Returns
   * true when we should announce immediately.
   */
  private boolean handleNoMorePeers(int count, boolean stillConnecting) {
    int runningNow;
    synchronized (this) {
      runningNow = runningAnnouncements;
    }
    if (count != 0 || runningNow != 0) return false;
    if (stillConnecting) {
      scheduleClearAnnouncedAndRetry();
      return false;
    }
    synchronized (this) {
      clearAnnouncedSets();
    }
    return true;
  }

  private void scheduleClearAnnouncedAndRetry() {
    if (LOG.isDebugEnabled()) LOG.debug("Will clear announced-to in 1 minute...");
    node.network()
        .ticker()
        .queueTimedJob(
            () -> {
              if (LOG.isDebugEnabled()) LOG.debug("Clearing old announced-to list");
              synchronized (Announcer.this) {
                if (runningAnnouncements != 0) return;
                clearAnnouncedSets();
              }
              maybeSendAnnouncement();
            },
            NOT_ALL_CONNECTED_DELAY);
  }

  private synchronized void clearAnnouncedSets() {
    announcedToIdentities.clear();
    announcedToIPs.clear();
  }

  /** Schedule maybeSendAnnouncement with a try/catch logging wrapper. */
  private void scheduleMaybeSendAnnouncement(long delayMs) {
    node.network()
        .ticker()
        .queueTimedJob(
            () -> {
              try {
                maybeSendAnnouncement();
              } catch (Exception e) {
                LOG.atError()
                    .setCause(e)
                    .addArgument(e::toString)
                    .addArgument(() -> TRYING_TO_SEND_ANNOUNCEMENTS)
                    .log("{}{}");
              }
            },
            delayMs);
  }

  // Synchronize to protect announcedToIdentities and prevent running in parallel.
  private synchronized int connectSomeNodesInner(List<SimpleFieldSet> seeds) {
    if (LOG.isDebugEnabled()) LOG.debug("Connecting some seednodes from {}", seeds.size());
    int count = 0;
    while (count < CONNECT_AT_ONCE) {
      if (seeds.isEmpty()) break;
      SimpleFieldSet fs = ListUtils.removeRandomBySwapLastSimple(node.bootstrap().random(), seeds);
      if (processSeedFromFieldSet(fs)) count++;
    }
    if (LOG.isDebugEnabled()) LOG.debug("connectSomeNodesInner() returning {}", count);
    return count;
  }

  private boolean processSeedFromFieldSet(SimpleFieldSet fs) {
    try {
      SeedServerPeerNode seed =
          new SeedServerPeerNode(fs, node, om.getCrypto(), false, node.network().peers());
      if (shouldSkipSeed(seed)) return false;
      if (LOG.isDebugEnabled()) LOG.debug("Trying to connect to seednode {}", seed);
      boolean added = node.network().peers().addPeer(seed);
      if (added) {
        if (LOG.isDebugEnabled()) LOG.debug("Connecting to seednode {}", seed);
      } else {
        if (LOG.isDebugEnabled()) LOG.debug("Not connecting to seednode {}", seed);
      }
      return added;
    } catch (FSParseException
        | PeerTooOldException
        | ReferenceSignatureVerificationException
        | PeerParseException e) {
      LOG.atError()
          .setCause(e)
          .addArgument(e::toString)
          .addArgument(() -> fs)
          .log("Invalid seed in file: {} for\n{}");
    }
    return false;
  }

  private boolean shouldSkipSeed(SeedServerPeerNode seed) {
    if (node.network().wantAnonAuth(true)
        && Arrays.equals(node.network().opennetPubKeyHash(), seed.peerECDSAPubKeyHash)) {
      if (LOG.isDebugEnabled()) LOG.atDebug().log(seed::userToString);
      return true;
    }
    if (announcedToIdentities.contains(new ByteArrayWrapper(seed.peerECDSAPubKeyHash))) {
      if (LOG.isDebugEnabled())
        LOG.atDebug().addArgument(seed::userToString).log("Not adding: already announced-to: {}");
      return true;
    }
    return false;
  }

  /**
   * Reads {@link SimpleFieldSet} noderef blocks from a seed nodes file.
   *
   * <p>The parser continues after recoverable I/O errors and logs them; successfully parsed entries
   * that follow are still returned. Resources are closed on exit.
   *
   * @param file path to the seed nodes file (for example, {@code NodeFile.SEEDNODES.getFile(node)})
   * @return a list of parsed {@link SimpleFieldSet} objects; empty if the file is missing or could
   *     not be read
   */
  public static List<SimpleFieldSet> readSeednodes(File file) {
    List<SimpleFieldSet> list = new ArrayList<>();
    try (FileInputStream fis = new FileInputStream(file);
        BufferedInputStream bis = new BufferedInputStream(fis);
        InputStreamReader isr = new InputStreamReader(bis, StandardCharsets.UTF_8);
        BufferedReader br = new BufferedReader(isr)) {
      while (true) {
        ReadStatus status = readNextSeed(br, file, list);
        if (status == ReadStatus.EOF) return list;
        // On IO_ERROR, continue the loop to try parsing the next block.
      }
    } catch (IOException e) {
      LOG.error("Unexpected error while reading seednodes from {}", file, e);
      return list;
    }
  }

  private enum ReadStatus {
    OK,
    EOF,
    IO_ERROR
  }

  private static ReadStatus readNextSeed(BufferedReader br, File file, List<SimpleFieldSet> out)
      throws IOException {
    try {
      SimpleFieldSet fs = new SimpleFieldSet(br, false, false, true, false);
      if (!fs.isEmpty()) out.add(fs);
      return ReadStatus.OK;
    } catch (EOFException _) {
      return ReadStatus.EOF;
    } catch (IOException e) {
      LOG.error("Error while reading seednodes from {}", file, e);
      // Continue reading to keep later noderefs. Advance one line to avoid an endless loop.
      // If advancing fails, propagate the IOException; if EOF is reached, signal EOF.
      String skipped = br.readLine();
      if (skipped == null) {
        return ReadStatus.EOF;
      }
      return ReadStatus.IO_ERROR;
    }
  }

  /**
   * Stops the announcer.
   *
   * <p>Currently a no-op placeholder kept for lifecycle symmetry with {@link #start()}. Future
   * implementations may cancel scheduled tasks.
   */
  protected void stop() {
    // Intentionally left blank
  }

  private long timeGotEnoughPeers = -1;
  private final Object timeGotEnoughPeersLock = new Object();
  private boolean killedAnnouncementTooOld;

  /**
   * Returns the minimum number of connected peers required before announcements are considered
   * unnecessary.
   *
   * <p>The threshold is {@code min(MIN_OPENNET_CONNECTED_PEERS, target/2)}, where {@code target} is
   * the desired number of connected peers (including darknet) reported by the opennet manager.
   *
   * @return a non-negative peer count threshold
   */
  public int getAnnouncementThreshold() {
    // First, do we actually need to announce?
    return Math.min(
        MIN_OPENNET_CONNECTED_PEERS, om.getNumberOfConnectedPeersToAimIncludingDarknet() / 2);
  }

  private final SimpleUserAlert announcementDisabledAlert =
      new SimpleUserAlert(
          false,
          l10n("announceDisabledTooOldTitle"),
          l10n(ANNOUNCE_DISABLED_TOO_OLD_KEY),
          l10n("announceDisabledTooOldShort"),
          UserAlert.CRITICAL_ERROR) {

        @Override
        public HTMLNode getHTMLText() {
          HTMLNode div = new HTMLNode("div");
          div.addChild("#", l10n(ANNOUNCE_DISABLED_TOO_OLD_KEY));
          if (!node.services().nodeUpdater().isEnabled()) {
            div.addChild("#", " ");
            NodeL10n.getBase()
                .addL10nSubstitution(
                    div,
                    "Announcer.announceDisabledTooOldUpdateDisabled",
                    new String[] {"config"},
                    new HTMLNode[] {HTMLNode.link("/config/node.updater")});
          }
          // No point with !armed() or blown() because they have their own messages.
          return div;
        }

        @Override
        public String getText() {
          StringBuilder sb = new StringBuilder();
          sb.append(l10n(ANNOUNCE_DISABLED_TOO_OLD_KEY));
          sb.append(" ");
          if (!node.services().nodeUpdater().isEnabled()) {
            sb.append(
                l10n(
                    "announceDisabledTooOldUpdateDisabled",
                    new String[] {"config", "/config"},
                    new String[] {"", ""}));
          }
          return sb.toString();
        }

        @Override
        public boolean isValid() {
          if (node.services().nodeUpdater().isEnabled()) return false;
          // If it is enabled but not armed there will be a message from the updater.
          synchronized (Announcer.this) {
            return killedAnnouncementTooOld;
          }
        }
      };

  /**
   * Returns whether the node currently has enough peers so no announcement is needed.
   *
   * @return true if announcements can be skipped
   */
  boolean enoughPeers() {
    if (om.stopping()) return true;
    // Do we want to send an announcement to the node?
    int opennetCount = node.network().peers().countConnectedPeers();
    int target = getAnnouncementThreshold();
    if (opennetCount >= target) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "We have enough opennet peers: {} > {} since {} ms",
            opennetCount,
            target,
            System.currentTimeMillis() - timeGotEnoughPeers);
      synchronized (timeGotEnoughPeersLock) {
        if (timeGotEnoughPeers <= 0) timeGotEnoughPeers = System.currentTimeMillis();
      }
      return true;
    }
    if (checkAndMaybeKillForTooOld()) {
      disconnectAllAsync();
      return true;
    }
    clearKilledAndUnregisterAlert();
    if (shouldPauseForUomAndTooNew()) return true;

    synchronized (timeGotEnoughPeersLock) {
      timeGotEnoughPeers = -1;
    }
    return false;
  }

  private boolean checkAndMaybeKillForTooOld() {
    if (!node.services().nodeUpdater().isEnabled()
        || (node.services().nodeUpdater().canUpdateNow()
            && !node.services().nodeUpdater().isArmed())) {
      synchronized (this) {
        if (killedAnnouncementTooOld) return true;
      }
      if (node.network().peers().getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_TOO_NEW, false)
          > 10) {
        synchronized (this) {
          if (killedAnnouncementTooOld) return true;
          killedAnnouncementTooOld = true;
        }
        LOG.error(
            "Shutting down announcement as we are older than the current mandatory build and"
                + " auto-update is disabled or waiting for user input.");
        if (node.services().clientCore() != null)
          node.services().clientCore().getAlerts().register(announcementDisabledAlert);
        return true;
      }
    }
    return false;
  }

  private void disconnectAllAsync() {
    node.network()
        .executor()
        .execute(
            () -> {
              for (OpennetPeerNode pn : node.network().peers().roster().getOpennetPeers()) {
                node.network().peers().messenger().disconnectAndRemove(pn, true, true, true);
              }
              for (SeedServerPeerNode pn :
                  node.network().peers().seedPeers().getSeedServerPeersVector()) {
                node.network().peers().messenger().disconnectAndRemove(pn, true, true, true);
              }
            });
  }

  private void clearKilledAndUnregisterAlert() {
    synchronized (this) {
      killedAnnouncementTooOld = false;
    }
    if (node.services().clientCore() != null)
      node.services().clientCore().getAlerts().unregister(announcementDisabledAlert);
  }

  private boolean shouldPauseForUomAndTooNew() {
    return node.services().nodeUpdater().isEnabled()
        && node.services().nodeUpdater().isArmed()
        && node.services().nodeUpdater().getUpdateOverMandatory().fetchingFromTwo()
        && node.network().peers().getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_TOO_NEW, false)
            > 5;
  }

  /**
   * Get the earliest time at which we had enough opennet peers. This is reset when we drop below
   * the threshold.
   */
  long timeGotEnoughPeers() {
    synchronized (timeGotEnoughPeersLock) {
      return timeGotEnoughPeers;
    }
  }

  /**
   * 1 minute after we have enough peers, remove all seednodes left (presumably disconnected ones)
   */
  private static final long FINAL_DELAY = SECONDS.toMillis(60);

  /**
   * But if we don't have enough peers at that point, wait another minute and if the situation has
   * not improved, reannounce.
   */
  static final long RETRY_DELAY = SECONDS.toMillis(60);

  private boolean started = false;

  private void runChecker() {
    int running;
    synchronized (Announcer.this) {
      running = runningAnnouncements;
    }
    if (enoughPeers()) {
      for (SeedServerPeerNode pn :
          node.network().peers().seedPeers().getConnectedSeedServerPeersVector(null)) {
        node.network().peers().messenger().disconnectAndRemove(pn, true, true, false);
      }
      // Re-check every minute. Adverse conditions (e.g., CPU starvation) might require reseeding.
      node.network()
          .ticker()
          .queueTimedJob(
              this::maybeSendAnnouncement,
              "Check whether we need to announce",
              RETRY_DELAY,
              false,
              true);
    } else {
      node.network()
          .ticker()
          .queueTimedJob(
              this::maybeSendAnnouncement,
              "Check whether we need to announce",
              RETRY_DELAY,
              false,
              true);
      if (running != 0) maybeSendAnnouncement();
    }
  }

  /**
   * Asynchronously requests an immediate re-evaluation and announcement, if needed.
   *
   * <p>If {@link #enoughPeers()} is true, nothing is scheduled. Otherwise, this enqueues a job on
   * the node's ticker to call {@link #maybeSendAnnouncement()}.
   */
  public void maybeSendAnnouncementOffThread() {
    if (enoughPeers()) return;
    node.network().ticker().queueTimedJob(this::maybeSendAnnouncement, 0);
  }

  /**
   * Entry point for the announcement decision flow.
   *
   * <p>Performs inexpensive pre-checks and, if announcements are needed, prefers announcing to
   * already connected seed nodes first. If not enough announcements are running and the last batch
   * of seeds was added too long ago, it schedules connecting to more seed nodes. Cooling-off and
   * sent-announcement limits are enforced to avoid excessive traffic.
   */
  protected void maybeSendAnnouncement() {
    if (preChecksAndScheduleIfNotNeeded()) return;
    long now = System.currentTimeMillis();
    synchronized (this) {
      if (checksUnderLock()) return;
      announceToAvailableSeeds();
      if (runningAnnouncements >= WANT_ANNOUNCEMENTS) {
        if (LOG.isDebugEnabled()) LOG.debug("Running {} announcements", runningAnnouncements);
        return;
      }
      if (delayIfRecentlyAddedSeeds(now)) return;
    }
    connectSomeSeednodes();
  }

  private boolean preChecksAndScheduleIfNotNeeded() {
    synchronized (this) {
      if (!started) return true;
    }
    if (LOG.isDebugEnabled()) LOG.debug("maybeSendAnnouncement()");
    if (!node.network().isOpennetEnabled()) return true;
    if (enoughPeers()) {
      node.network()
          .ticker()
          .queueTimedJob(this::runChecker, "Announcement checker", FINAL_DELAY, false, true);
      return true;
    }
    return false;
  }

  private boolean checksUnderLock() {
    // Double check after taking the lock.
    if (enoughPeers()) {
      node.network()
          .ticker()
          .queueTimedJob(this::runChecker, "Announcement checker", FINAL_DELAY, false, true);
      return true;
    }
    if (runningAnnouncements > WANT_ANNOUNCEMENTS) {
      if (LOG.isDebugEnabled()) LOG.debug("Running announcements already");
      return true;
    }
    if (System.currentTimeMillis() < startTime) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "In cooling-off period for next {}",
            TimeUtil.formatTime(startTime - System.currentTimeMillis()));
      return true;
    }
    if (sentAnnouncements >= WANT_ANNOUNCEMENTS) {
      if (LOG.isDebugEnabled()) LOG.debug("Sent enough announcements");
      return true;
    }
    return false;
  }

  private void announceToAvailableSeeds() {
    List<SeedServerPeerNode> seeds =
        node.network().peers().seedPeers().getConnectedSeedServerPeersVector(announcedToIdentities);
    while (sentAnnouncements < WANT_ANNOUNCEMENTS && !seeds.isEmpty()) {
      final SeedServerPeerNode seed =
          ListUtils.removeRandomBySwapLastSimple(node.bootstrap().random(), seeds);
      if (seed == null) {
        LOG.debug("Null seed encountered while selecting; skipping.");
        continue; // Single allowed continue: keep nesting shallow and reduce complexity.
      }
      InetAddress[] addrs =
          java.util.Objects.requireNonNullElseGet(
              seed.getInetAddresses(), () -> new InetAddress[0]);
      boolean skip = !newAnnouncedIPs(addrs);
      if (skip) {
        LOG.debug("Not announcing to {} because already used those IPs", seed);
      } else {
        addAnnouncedIPs(addrs);
        recordAnnouncementIfSent(seed);
      }
    }
  }

  private void recordAnnouncementIfSent(final SeedServerPeerNode seed) {
    if (sendAnnouncement(seed)) {
      sentAnnouncements++;
      runningAnnouncements++;
      announcedToIdentities.add(new ByteArrayWrapper(seed.peerECDSAPubKeyHash));
    }
  }

  private boolean delayIfRecentlyAddedSeeds(long now) {
    if (now - timeAddedSeeds < MIN_ADDED_SEEDS_INTERVAL) {
      LOG.debug("Waiting for MIN_ADDED_SEEDS_INTERVAL");
      scheduleMaybeSendAnnouncement((timeAddedSeeds + MIN_ADDED_SEEDS_INTERVAL) - now);
      return true;
    }
    return false;
  }

  private synchronized void addAnnouncedIPs(InetAddress[] addrs) {
    Collections.addAll(announcedToIPs, addrs);
  }

  /**
   * Determines whether the provided addresses contain a new non-local IP that has not yet been
   * announced to.
   *
   * <p>Returns {@code true} if at least one non-local address is new, or if the node has no
   * non-local addresses at all. Returns {@code false} when all non-local addresses were already
   * used for announcements.
   *
   * @param addrs node IP addresses to evaluate
   * @return {@code true} if announcement via these addresses should proceed
   */
  private synchronized boolean newAnnouncedIPs(InetAddress[] addrs) {
    boolean hasNonLocalAddresses = false;
    for (InetAddress addr : addrs) {
      if (!IPUtil.isValidAddress(addr, false)) continue;
      hasNonLocalAddresses = true;
      if (!announcedToIPs.contains(addr)) return true;
    }
    return !hasNonLocalAddresses;
  }

  /**
   * Schedules an announcement to a connected seed node.
   *
   * <p>The work is executed asynchronously on the node's executor. Progress is reported via the
   * {@link AnnouncementCallback}. When opennet is disabled, the method returns {@code false} and no
   * work is scheduled.
   *
   * @param seed the seed to which the announcement should be sent; expected to be connected
   * @return {@code true} if the announcement run was scheduled; {@code false} if opennet is
   *     disabled
   */
  protected boolean sendAnnouncement(final SeedServerPeerNode seed) {
    if (!node.network().isOpennetEnabled()) {
      if (LOG.isDebugEnabled()) LOG.debug("Not announcing to {} because opennet is disabled", seed);
      return false;
    }
    LOG.atInfo().addArgument(seed::userToString).log("Announcement to {} starting...");
    if (LOG.isDebugEnabled())
      LOG.atDebug().addArgument(seed::userToString).log(ANNOUNCEMENT_TO + "{} starting...");
    AnnounceSender sender =
        new AnnounceSender(
            node.network().location(),
            om,
            node,
            new AnnouncementCallback() {
              private int totalAdded;
              private int totalNotWanted;
              private boolean acceptedSomewhere;

              @Override
              public synchronized void acceptedSomewhere() {
                acceptedSomewhere = true;
              }

              @Override
              public void addedNode(PeerNode pn) {
                synchronized (Announcer.this) {
                  announcementAddedNodes++;
                  totalAdded++;
                }
                LOG.atInfo()
                    .addArgument(seed::userToString)
                    .addArgument(pn::userToString)
                    .addArgument(() -> announcementAddedNodes)
                    .addArgument(() -> totalAdded)
                    .log(
                        ANNOUNCEMENT_TO
                            + "{} added node {} for a total of {} ({} from this announcement)");
                LOG.atInfo()
                    .addArgument(seed::userToString)
                    .addArgument(pn::userToString)
                    .log("Announcement to {} added node {}.");
              }

              @Override
              public void bogusNoderef(String reason) {
                LOG.atInfo()
                    .setCause(new Exception("debug"))
                    .addArgument(seed::userToString)
                    .addArgument(() -> reason)
                    .log(ANNOUNCEMENT_TO + "{} got bogus noderef: {}");
              }

              @Override
              public void completed() {
                boolean announceNow = false;
                synchronized (Announcer.this) {
                  runningAnnouncements--;
                  LOG.atInfo()
                      .addArgument(seed::userToString)
                      .addArgument(() -> runningAnnouncements)
                      .log(ANNOUNCEMENT_TO + "{} completed, now running {} announcements");
                  if (runningAnnouncements == 0 && announcementAddedNodes > 0) {
                    // No point waiting if no nodes have been added!
                    startTime = System.currentTimeMillis() + COOLING_OFF_PERIOD;
                    sentAnnouncements = 0;
                    // Wait for COOLING_OFF_PERIOD before trying again
                    node.network()
                        .ticker()
                        .queueTimedJob(() -> maybeSendAnnouncement(), COOLING_OFF_PERIOD);
                  } else if (runningAnnouncements == 0) {
                    sentAnnouncements = 0;
                    announceNow = true;
                  }
                }
                // If disconnect takes longer than COOLING_OFF_PERIOD we might not reannounce to
                // this seed immediately. Regardless, we cannot reannounce until the announced-to
                // set is cleared, which is typically later than that period.
                node.network().peers().messenger().disconnectAndRemove(seed, true, false, false);
                int shallow = node.maxHTL() - (totalAdded + totalNotWanted);
                if (acceptedSomewhere)
                  LOG.atInfo()
                      .addArgument(seed::userToString)
                      .addArgument(() -> totalAdded)
                      .addArgument(() -> totalNotWanted)
                      .addArgument(() -> shallow)
                      .log("Announcement to {} completed ({} added, {} not wanted, {} shallow)");
                else
                  LOG.atInfo()
                      .addArgument(seed::userToString)
                      .addArgument(seed::getBuildNumber)
                      .log("Announcement to {} not accepted (version {}).");
                if (announceNow) maybeSendAnnouncement();
              }

              @Override
              public void nodeFailed(PeerNode pn, String reason) {
                LOG.atInfo()
                    .addArgument(pn::userToString)
                    .addArgument(() -> reason)
                    .log(ANNOUNCEMENT_TO_NODE + "{} failed: {}");
              }

              @Override
              public void noMoreNodes() {
                LOG.atInfo()
                    .addArgument(seed::userToString)
                    .log(ANNOUNCEMENT_TO + "{} ran out of nodes (route not found)");
              }

              @Override
              public void nodeNotWanted() {
                synchronized (Announcer.this) {
                  announcementNotWantedNodes++;
                  totalNotWanted++;
                }
                LOG.atInfo()
                    .addArgument(seed::userToString)
                    .addArgument(() -> announcementNotWantedNodes)
                    .addArgument(() -> totalNotWanted)
                    .log(
                        ANNOUNCEMENT_TO
                            + "{} returned node not wanted for a total of {} ({} from this"
                            + " announcement)");
              }

              @Override
              public void nodeNotAdded() {
                LOG.atInfo()
                    .addArgument(seed::userToString)
                    .log(
                        ANNOUNCEMENT_TO
                            + "{} : node not wanted (maybe already have it, opennet just turned"
                            + " off, etc)");
              }

              @Override
              public void relayedNoderef() {
                LOG.atError()
                    .addArgument(seed::userToString)
                    .log(ANNOUNCEMENT_TO + "{} : RELAYED ?!?!?!");
              }
            },
            seed);
    node.network().executor().execute(sender, "Announcer to " + seed);
    return true;
  }

  class AnnouncementUserEvent extends AbstractUserEvent {

    private final int status;

    public AnnouncementUserEvent(int status) {
      this.status = status;
    }

    @Override
    public String dismissButtonText() {
      return NodeL10n.getBase().getString("UserAlert.hide");
    }

    @Override
    public HTMLNode getHTMLText() {
      return new HTMLNode("#", getText());
    }

    @Override
    public short getPriorityClass() {
      return UserAlert.ERROR;
    }

    @Override
    public String getText() {
      StringBuilder sb = new StringBuilder();
      sb.append(l10n("announceAlertIntro"));
      if (status == STATUS_NO_SEEDNODES) {
        return l10n("announceAlertNoSeednodes");
      }
      if (status == STATUS_LOADING) {
        return l10n("announceLoading");
      }
      if (node.services().clientCore().isAdvancedModeEnabled()) {
        // Detail
        sb.append(' ');
        int addedNodes;
        int refusedNodes;
        int recentSentAnnouncements;
        int runningAnnouncementsLocal;
        int connectedSeednodes = 0;
        int disconnectedSeednodes = 0;
        long coolingOffSeconds = Math.max(0, startTime - System.currentTimeMillis()) / 1000;
        synchronized (this) {
          addedNodes = announcementAddedNodes;
          refusedNodes = announcementNotWantedNodes;
          recentSentAnnouncements = sentAnnouncements;
          runningAnnouncementsLocal = Announcer.this.runningAnnouncements;
        }
        List<SeedServerPeerNode> nodes =
            node.network().peers().seedPeers().getSeedServerPeersVector();
        for (SeedServerPeerNode seed : nodes) {
          if (seed.isConnected()) connectedSeednodes++;
          else disconnectedSeednodes++;
        }
        sb.append(
            l10nAnnounceDetails(
                new String[] {
                  "addedNodes",
                  "refusedNodes",
                  "recentSentAnnouncements",
                  "runningAnnouncements",
                  "connectedSeednodes",
                  "disconnectedSeednodes"
                },
                new String[] {
                  Integer.toString(addedNodes),
                  Integer.toString(refusedNodes),
                  Integer.toString(recentSentAnnouncements),
                  Integer.toString(runningAnnouncementsLocal),
                  Integer.toString(connectedSeednodes),
                  Integer.toString(disconnectedSeednodes)
                }));
        if (coolingOffSeconds > 0) {
          sb.append(' ');
          sb.append(l10nCoolingOffTime(Long.toString(coolingOffSeconds)));
        }
      }
      return sb.toString();
    }

    @Override
    public String getTitle() {
      return l10n("announceAlertTitle");
    }

    @Override
    public boolean isValid() {
      return !enoughPeers() && node.network().isOpennetEnabled();
    }

    @Override
    public void isValid(boolean validity) {
      // Ignore
    }

    @Override
    public void onDismiss() {
      // Ignore
    }

    @Override
    public boolean shouldUnregisterOnDismiss() {
      return true;
    }

    @Override
    public boolean userCanDismiss() {
      return true;
    }

    @Override
    public String anchor() {
      return "announcer:" + hashCode();
    }

    @Override
    public String getShortText() {
      return l10n("announceAlertShort");
    }

    @Override
    public UserEvent.Type getEventType() {
      return UserEvent.Type.ANNOUNCER;
    }

    // Private helper specialized for the only usage here.
    private String l10nCoolingOffTime(String seconds) {
      return NodeL10n.getBase().getString(L10N_PREFIX + "coolingOff", "time", seconds);
    }

    // Delegate overloads to outer class for convenience within the inner class
    private String l10n(String key) {
      return Announcer.this.l10n(key);
    }

    private String l10nAnnounceDetails(String[] patterns, String[] values) {
      return Announcer.this.l10n("announceDetails", patterns, values);
    }
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString(L10N_PREFIX + key);
  }

  /**
   * Localizes a key within the announcer bundle and applies simple substitutions.
   *
   * @param key key without the {@code Announcer.} prefix
   * @param patterns placeholder names to replace
   * @param values replacement values corresponding to {@code patterns}
   * @return localized string with substitutions applied
   */
  protected String l10n(String key, String[] patterns, String[] values) {
    return NodeL10n.getBase().getString(L10N_PREFIX + key, patterns, values);
  }

  // Note: the inner class contains a narrowly scoped helper for its specific key to avoid a
  // private outer helper used solely by an inner class (Sonar S3398).

  /**
   * Triggers a near-immediate re-evaluation and announcement attempt.
   *
   * <p>Equivalent to calling {@link #maybeSendAnnouncementOffThread()}.
   */
  public void reannounce() {
    LOG.info("Re-announcing...");
    maybeSendAnnouncementOffThread();
  }

  /**
   * Indicates whether announcements are currently suppressed because the node is older than the
   * mandatory build and the updater is disabled or awaiting user action.
   *
   * <p>Intended for UI and status surfaces.
   *
   * @return {@code true} if announcement has been killed due to an out-of-date build
   */
  public boolean isWaitingForUpdater() {
    synchronized (this) {
      return killedAnnouncementTooOld;
    }
  }
}
