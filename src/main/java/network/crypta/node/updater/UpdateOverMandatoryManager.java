package network.crypta.node.updater;

import static java.util.concurrent.TimeUnit.HOURS;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.WeakHashMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchResult;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertException;
import network.crypta.client.async.BaseClientPutter;
import network.crypta.client.async.BinaryBlob;
import network.crypta.client.async.BinaryBlobFormatException;
import network.crypta.client.async.BinaryBlobWriter;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetCallback;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.ClientPutCallback;
import network.crypta.client.async.ClientPutter;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.SimpleBlockSet;
import network.crypta.crypt.SHA256;
import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.xfer.BulkReceiver;
import network.crypta.io.xfer.BulkTransmitter;
import network.crypta.io.xfer.PartiallyReceivedBulk;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.PeerNode;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestStarter;
import network.crypta.node.Version;
import network.crypta.node.useralerts.AbstractUserAlert;
import network.crypta.node.useralerts.AbstractUserAlert.DismissOptions;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.support.HTMLNode;
import network.crypta.support.HexUtil;
import network.crypta.support.ShortBuffer;
import network.crypta.support.SizeUtil;
import network.crypta.support.TimeUtil;
import network.crypta.support.WeakHashSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.api.RandomAccessBuffer;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.ByteArrayRandomAccessBuffer;
import network.crypta.support.io.FileBucket;
import network.crypta.support.io.FileRandomAccessBuffer;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates Update‑Over‑Mandatory (UoM) interactions between this node and its peers.
 *
 * <p>UoM is a fallback update path used when peers are too far apart in protocol/build versions to
 * route requests normally. It piggybacks small control messages and bulk binary transfers so a node
 * can receive critical information such as revocation certificates and, when enabled, a new core
 * jar. The {@link network.crypta.node.NodeDispatcher} forwards UoM messages to this class, which
 * decides whether and how to respond (accept, delay, or ignore) based on local policy and current
 * update state managed by {@link NodeUpdateManager}.
 *
 * <p>Behavior differs depending on the update mode. In the current package‑based updater flow
 * (where {@link NodeUpdateManager#supportsJarUOM()} returns {@code false}), UoM is only used for
 * revocation handling; main‑jar exchange is disabled and any received main‑jar offers are ignored
 * after being logged for diagnostics. In legacy jar‑based mode, this manager may fetch a new jar
 * directly from peers after a configurable grace period.
 *
 * <p>Concurrency and state: this class is designed to be called from network/async threads; it uses
 * internal synchronization around its shared sets and maps to maintain consistency. At most {@link
 * #MAX_NODES_SENDING_JAR} concurrent main‑jar transfers are allowed to reduce waste. A grace window
 * ({@link #GRACE_TIME}) gives the normal updater time to succeed before UoM takes over. All state
 * changes are defensive: inconsistent or malicious inputs are ignored and logged.
 *
 * <ul>
 *   <li>Responsibilities: handle announces, serve/request revocation certificates, and gate main
 *       jar offers.
 *   <li>Notable behaviors: rate limits concurrent transfers, avoids duplicate work, and clears
 *       transient state on disconnect.
 * </ul>
 *
 * @author toad
 * @see NodeUpdateManager
 * @see network.crypta.node.NodeDispatcher
 */
public class UpdateOverMandatoryManager implements RequestClient {
  private static final Logger LOG = LoggerFactory.getLogger(UpdateOverMandatoryManager.class);

  private static final String SOMEONE_DELETED_PREFIX = "Somebody deleted ";
  private static final String FROM_NODE_LITERAL = " from node ";
  private static final String PEER_ASKED_BLOB_PREFIX =
      "Peer {} asked us for the blob file for the ";

  final NodeUpdateManager updateManager;

  /** Set of PeerNode's which say (or said before they disconnected) the key has been revoked */
  private final HashSet<PeerNode> nodesSayKeyRevoked;

  /**
   * Set of PeerNode's which say the key has been revoked but failed to transfer the revocation key.
   */
  private final HashSet<PeerNode> nodesSayKeyRevokedFailedTransfer;

  /**
   * Set of PeerNode's which say the key has been revoked and are transferring the revocation
   * certificate.
   */
  private final HashSet<PeerNode> nodesSayKeyRevokedTransferring;

  /** PeerNode's which have offered the main jar which we are not fetching it from right now */
  private final HashSet<PeerNode> nodesOfferedMainJar;

  /** PeerNode's which have offered the ext jar which we are not fetching it from right now */
  private final HashSet<PeerNode> nodesAskedSendMainJar;

  /** PeerNode's sending us the main jar */
  private final HashSet<PeerNode> nodesSendingMainJar;

  /** PeerNode's that we've successfully fetched a jar from */
  private final HashSet<PeerNode> nodesSentMainJar;

  /** All PeerNode's that offered the main jar, regardless of what happened after that. */
  private final HashSet<PeerNode> allNodesOfferedMainJar;

  // 2 for reliability, no more as gets very slow/wasteful
  static final int MAX_NODES_SENDING_JAR = 2;

  /** Maximum time between asking for the main jar and starting to transfer */
  static final long REQUEST_MAIN_JAR_TIMEOUT = SECONDS.toMillis(60);

  /**
   * Grace period before switching to UoM for main‑jar updates.
   *
   * <p>When a peer offers a newer main jar, the normal updater is given this much time before UoM
   * initiates a peer‑to‑peer fetch. The value is expressed in milliseconds and currently equals
   * three hours. Implementations should treat this as read‑only configuration; callers must not
   * modify it.
   */
  public static final long GRACE_TIME = HOURS.toMillis(3);

  private static final String BUILD_NUM_PREFIX = " (build #";
  private static final String NODE_PREFIX = "Node ";
  private static final String PEER_PREFIX = "Peer ";
  private static final String FOR_LITERAL = " for ";
  private static final String FROM_LITERAL = " from ";
  private static final String FBLOB_TMP_SUFFIX = ".fblob.tmp";
  private static final String FAILED_DELETE_TMP = "Failed to delete temp file: {}";
  private UserAlert alert;
  private static final Pattern mainBuildNumberPattern =
      Pattern.compile("^main(?:-jar)?-(\\d+)\\.fblob$");
  private static final Pattern mainTempBuildNumberPattern =
      Pattern.compile("^main(?:-jar)?-(\\d+-)?(\\d+)\\.fblob\\.tmp*$");
  private static final Pattern revocationTempBuildNumberPattern =
      Pattern.compile("^revocation(?:-jar)?-(\\d+-)?(\\d+)\\.fblob\\.tmp*$");

  // Main jar insert policy via UOM is handled elsewhere; no random insert here.

  private boolean fetchingUOM;

  private final HashMap<ShortBuffer, File> dependencies;

  private final WeakHashMap<PeerNode, Integer> peersFetchingDependencies;

  private final HashMap<ShortBuffer, UOMDependencyFetcher> dependencyFetchers;

  /**
   * Creates a new manager bound to the given updater.
   *
   * <p>The instance observes and updates UoM‑related state through the provided {@link
   * NodeUpdateManager}. The manager is ready for use immediately after construction and maintains
   * its own internal synchronization.
   *
   * @param manager The {@link NodeUpdateManager} coordinating updates and holding shared state;
   *     must be non‑null and remain valid for the lifetime of this instance.
   */
  public UpdateOverMandatoryManager(NodeUpdateManager manager) {
    this.updateManager = manager;
    nodesSayKeyRevoked = new HashSet<>();
    nodesSayKeyRevokedFailedTransfer = new HashSet<>();
    nodesSayKeyRevokedTransferring = new HashSet<>();
    nodesOfferedMainJar = new HashSet<>();
    nodesSentMainJar = new HashSet<>();
    nodesAskedSendMainJar = new HashSet<>();
    nodesSendingMainJar = new HashSet<>();
    allNodesOfferedMainJar = new HashSet<>();
    dependencies = new HashMap<>();
    peersFetchingDependencies = new WeakHashMap<>();
    dependencyFetchers = new HashMap<>();
  }

  /**
   * Handles a UOM announcement from a peer and schedules any required actions.
   *
   * <p>The message may advertise a revocation certificate, a main‑jar offer (when jar UoM is
   * enabled), or both. Revocation announcements are processed first and may short‑circuit further
   * handling. For main‑jar offers, this method validates the advertised version and file length and
   * either fetches immediately (when outdated or past the grace time) or remembers the offer for a
   * later takeover.
   *
   * @param m UOM announce message to handle. Expected to contain keys such as {@code MAIN_JAR_KEY},
   *     {@code MAIN_JAR_VERSION}, and revocation fields; the map must be well‑formed for correct
   *     processing.
   * @param source The peer that sent the announcement. Must be a currently known {@link PeerNode};
   *     its connection status influences later scheduling.
   * @return Always {@code true}. Returning a value allows symmetry with other handlers and aids
   *     integration with dispatch loops that expect boolean results.
   */
  public boolean handleAnnounce(Message m, final PeerNode source) {

    String mainJarKey = m.getString(DMT.MAIN_JAR_KEY);
    String revocationKey = m.getString(DMT.REVOCATION_KEY);
    boolean haveRevocationKey = m.getBoolean(DMT.HAVE_REVOCATION_KEY);
    int mainJarVersion = m.getInt(DMT.MAIN_JAR_VERSION);
    long revocationKeyLastTried = m.getLong(DMT.REVOCATION_KEY_TIME_LAST_TRIED);
    int revocationKeyDNFs = m.getInt(DMT.REVOCATION_KEY_DNF_COUNT);
    long revocationKeyFileLength = m.getLong(DMT.REVOCATION_KEY_FILE_LENGTH);
    long mainJarFileLength = m.getLong(DMT.MAIN_JAR_FILE_LENGTH);
    int pingTime = m.getInt(DMT.PING_TIME);
    int delayTime = m.getInt(DMT.BWLIMIT_DELAY_TIME);

    // Log it

    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Update Over Mandatory offer from node {} : {}:",
          source.getPeer(),
          source.userToString());
      LOG.debug(
          "Main jar key: {} version={} length={}", mainJarKey, mainJarVersion, mainJarFileLength);
      LOG.debug(
          "Revocation key: {} found={} length={} last had 3 DNFs {} ms ago, {} DNFs so far",
          revocationKey,
          haveRevocationKey,
          revocationKeyFileLength,
          revocationKeyLastTried,
          revocationKeyDNFs);
      LOG.debug("Load stats: {}ms ping, {}ms bwlimit delay time", pingTime, delayTime);
    }

    boolean stopProcessing = false;

    // First off, if a node says it has the revocation key, and its key is the same as ours,
    // we should 1) suspend any auto-updates and tell the user, 2) try to download it, and
    // 3) if the download fails, move the notification; if the download succeeds, process it

    if (haveRevocationKey) {
      stopProcessing = handleRevocationAnnounce(revocationKey, source);
    }

    if (!stopProcessing) {
      tellFetchers(source);

      // Don't proceed with main-jar logic if blown or disabled
      if (!updateManager.isBlown() && updateManager.isEnabled()) {
        long now = System.currentTimeMillis();
        // In package-based updater mode there is no main-jar UOM; only revocation is handled.
        if (updateManager.supportsJarUOM()) {
          handleMainJarOffer(now, mainJarFileLength, mainJarVersion, source, mainJarKey);
        }
      }
    }

    return true;
  }

  private void tellFetchers(PeerNode source) {
    HashSet<UOMDependencyFetcher> fetchList;
    synchronized (dependencyFetchers) {
      fetchList = new HashSet<>(dependencyFetchers.values());
    }
    for (UOMDependencyFetcher f : fetchList) {
      if (source.isDarknet()) f.peerMaybeFreeSlots(source);
      f.start();
    }
  }

  /**
   * Handle a revocation announcement from a peer. Returns true if no further processing should be
   * performed for this message (equivalent to the previous early-return behavior).
   */
  private boolean handleRevocationAnnounce(String revocationKey, final PeerNode source) {
    if (updateManager.isBlown()) {
      // We already know
      return true;
    }
    try {
      FreenetURI revocationURI = new FreenetURI(revocationKey);
      if (revocationURI.equals(updateManager.getRevocationURI())) {

        // Have to do this first to avoid race condition
        boolean alreadyTransferringOrWaiting;
        synchronized (this) {
          alreadyTransferringOrWaiting =
              nodesSayKeyRevokedTransferring.contains(source)
                  || nodesSayKeyRevoked.contains(source);
          if (!alreadyTransferringOrWaiting) {
            nodesSayKeyRevoked.add(source);
          }
        }
        if (alreadyTransferringOrWaiting) {
          return true;
        }

        // Disable the update
        updateManager.peerClaimsKeyBlown();

        // Tell the user
        alertUser();

        if (LOG.isWarnEnabled()) {
          LOG.warn(
              "Your peer {}{}{}) says that the auto-update key is blown!",
              source.userToString(),
              BUILD_NUM_PREFIX,
              source.getSimpleVersion());
        }
        LOG.info("Attempting to fetch revocation certificate...");

        tryFetchRevocation(source);
      } else {
        // Should probably also be an useralert?
        LOG.info(
            """
            Node {} sent us a UOM claiming that the auto-update key was blown, but it used a different key to us:
            our key={}
            his key={}
            """,
            source,
            updateManager.getRevocationURI(),
            revocationURI);
      }
    } catch (MalformedURLException e) {
      // Should maybe be an useralert?
      LOG.error(
          "Node {} sent us a UOMAnnouncement claiming that the auto-update key was blown, but it"
              + " had an invalid revocation URI: {}",
          source,
          revocationKey,
          e);
    } catch (NotConnectedException e) {
      LOG.warn(
          "{}{} says that the auto-update key was blown, but has now gone offline! Something bad"
              + " may be happening!",
          NODE_PREFIX,
          source);
      LOG.error(
          "Node {} says that the auto-update key was blown, but has now gone offline! Something bad"
              + " may be happening!",
          source);
      synchronized (UpdateOverMandatoryManager.this) {
        nodesSayKeyRevoked.remove(source);
        // Might be valid, but no way to tell except if other peers tell us.
        // And there's a good chance it isn't.
      }
      maybeNotRevoked();
    }
    return false;
  }

  private void tryFetchRevocation(final PeerNode source) throws NotConnectedException {
    // Try to transfer it.

    Message msg = DMT.createUOMRequestRevocation(updateManager.getNode().getRandom().nextLong());
    source.sendAsync(
        msg,
        new AsyncMessageCallback() {

          @Override
          public void acknowledged() {
            // Ok
          }

          @Override
          public void disconnected() {
            // :(
            LOG.warn(
                "Failed to send request for revocation key to {}{}{}) because it disconnected!",
                source.userToString(),
                BUILD_NUM_PREFIX,
                source.getSimpleVersion());
            source.failedRevocationTransfer();
            synchronized (UpdateOverMandatoryManager.this) {
              nodesSayKeyRevokedFailedTransfer.add(source);
            }
          }

          @Override
          public void fatalError() {
            // Not good!
            LOG.error(
                "Failed to send request for revocation key to {} because of a fatal error.",
                source.userToString());
          }

          @Override
          public void sent() {
            // Cool
          }
        },
        updateManager.getByteCounter());

    updateManager
        .getNode()
        .getTicker()
        .queueTimedJob(
            () -> {
              if (updateManager.isBlown()) return;
              synchronized (UpdateOverMandatoryManager.this) {
                if (nodesSayKeyRevokedFailedTransfer.contains(source)) return;
                if (nodesSayKeyRevokedTransferring.contains(source)) return;
                nodesSayKeyRevoked.remove(source);
              }
              LOG.warn(
                  "{}{}{}{}) said that the auto-update key had been blown, but did not transfer the"
                      + " revocation certificate. The most likely explanation is that the key has"
                      + " not been blown (the node is buggy or malicious), so we are ignoring"
                      + " this.",
                  PEER_PREFIX,
                  source,
                  BUILD_NUM_PREFIX,
                  source.getSimpleVersion());
              maybeNotRevoked();
            },
            SECONDS.toMillis(60));

    // The reply message will start the transfer. It includes the revocation URI
    // so we can tell if anything wierd is happening.

  }

  private void handleMainJarOffer(
      long now, long mainJarFileLength, int mainJarVersion, PeerNode source, String jarKey) {

    long started = updateManager.getStartedFetchingNextMainJarTimestamp();
    long whenToTakeOverTheNormalUpdater =
        (started > 0) ? started + GRACE_TIME : System.currentTimeMillis() + GRACE_TIME;
    boolean isOutdated = updateManager.getNode().isOudated();
    // if the new build is self-mandatory or if the "normal" updater has been trying to update for
    // more than one hour
    if (LOG.isInfoEnabled()) {
      String takeoverDelay = TimeUtil.formatTime(whenToTakeOverTheNormalUpdater - now);
      LOG.info(
          "We received a valid UOMAnnouncement (main) : (isOutdated={} version={}"
              + " whenToTakeOverTheNormalUpdater={}) file length {} updateManager version {}",
          isOutdated,
          mainJarVersion,
          takeoverDelay,
          mainJarFileLength,
          updateManager.newMainJarVersion());
    }

    boolean offerIsValid =
        mainJarVersion > Version.currentBuildNumber()
            && mainJarFileLength > 0
            && mainJarVersion > updateManager.newMainJarVersion();

    if (offerIsValid) {
      source.setMainJarOfferedVersion(mainJarVersion);
      if (LOG.isDebugEnabled()) LOG.debug("Offer is valid");
      onValidMainJarOffer(
          now, started, isOutdated, mainJarVersion, source, jarKey, whenToTakeOverTheNormalUpdater);
    } else {
      // We may want the dependencies.
      // These may be similar even if his url is different, so add unconditionally.
      synchronized (this) {
        allNodesOfferedMainJar.add(source);
      }
    }
    startSomeDependencyFetchers();
  }

  private void onValidMainJarOffer(
      long now,
      long started,
      boolean isOutdated,
      int mainJarVersion,
      PeerNode source,
      String jarKey,
      long whenToTakeOverTheNormalUpdater) {
    if (isOutdated || whenToTakeOverTheNormalUpdater < now) {
      fetchMainJarNow(now, started, isOutdated, mainJarVersion, source, jarKey);
    } else {
      scheduleMainJarTakeover(whenToTakeOverTheNormalUpdater, now, source);
    }
  }

  private void fetchMainJarNow(
      long now,
      long started,
      boolean isOutdated,
      int mainJarVersion,
      PeerNode source,
      String jarKey) {
    // Take up the offer, subject to limits on number of simultaneous downloads.
    // If we have fetches running already, then sendUOMRequestMainJar() will add the offer to
    // nodesOfferedMainJar, so that if all our fetches fail, we can fetch from this node.
    if (!isOutdated) {
      String howLong = TimeUtil.formatTime(now - started);
      LOG.error(
          "The update process seems to have been stuck for {}; let's switch to UoM! SHOULD NOT"
              + " HAPPEN! (1)",
          howLong);
    } else if (LOG.isDebugEnabled()) {
      LOG.debug("Fetching via UOM as our build is deprecated");
    }
    try {
      FreenetURI mainJarURI = new FreenetURI(jarKey).setSuggestedEdition(mainJarVersion);
      if (mainJarURI.equals(updateManager.getURI().setSuggestedEdition(mainJarVersion))) {
        sendUOMRequest(source, true);
      } else {
        // Transitional version differences may be expected; logging retained for diagnostics.
        if (LOG.isWarnEnabled()) {
          LOG.warn(
              "{}{} offered us a new main jar (version {}) but key differs. our key: {} his key:{}",
              NODE_PREFIX,
              source.userToString(),
              mainJarVersion,
              updateManager.getURI(),
              mainJarURI);
        }
      }
    } catch (MalformedURLException e) {
      // Should maybe be an useralert?
      LOG.error(
          "Node {} sent us a UOMAnnouncement claiming to have a new ext jar, but it had an invalid"
              + " URI: {}",
          source,
          jarKey,
          e);
    }
    synchronized (this) {
      allNodesOfferedMainJar.add(source);
    }
  }

  private void scheduleMainJarTakeover(
      long whenToTakeOverTheNormalUpdater, long now, final PeerNode source) {
    // Don't take up the offer. Add to nodesOfferedMainJar, so that we know where to fetch it
    // from when we need it.
    synchronized (this) {
      nodesOfferedMainJar.add(source);
      allNodesOfferedMainJar.add(source);
    }
    updateManager
        .getNode()
        .getTicker()
        .queueTimedJob(
            () -> {
              if (updateManager.isBlown()) return;
              if (!updateManager.isEnabled()) return;
              if (updateManager.hasNewMainJar()) return;
              if (!updateManager.getNode().isOudated()) {
                LOG.error(
                    "The update process seems to have been stuck for too long; let's switch to UoM!"
                        + " SHOULD NOT HAPPEN! (2) (ext)");
              }
              maybeRequestMainJar();
            },
            whenToTakeOverTheNormalUpdater - now);
  }

  private void sendUOMRequest(final PeerNode source, boolean addOnFail) {
    final String name = "Main";
    String lname = "main";
    if (LOG.isDebugEnabled()) LOG.debug("sendUOMRequest {} ({},{})", name, source, addOnFail);
    if (!source.isConnected() || source.isSeed()) {
      if (LOG.isDebugEnabled())
        LOG.debug("Not sending UOM {} request to {} (disconnected or seednode)", lname, source);
      return;
    }
    final HashSet<PeerNode> sendingJar = nodesSendingMainJar;
    final HashSet<PeerNode> askedSendJar = nodesAskedSendMainJar;

    UomRequestDecision decision =
        decideUomRequest(source, addOnFail, lname, sendingJar, askedSendJar);
    if (!decision.proceed) return;
    if (decision.startedFetching) this.updateManager.onStartFetchingUOM();

    Message msg = DMT.createUOMRequestMainJar(updateManager.getNode().getRandom().nextLong());
    doSendUomRequestAsync(source, lname, sendingJar, askedSendJar, msg);
  }

  private void doSendUomRequestAsync(
      final PeerNode source,
      String lname,
      final HashSet<PeerNode> sendingJar,
      final HashSet<PeerNode> askedSendJar,
      Message msg) {
    try {
      if (LOG.isInfoEnabled()) {
        LOG.info("Fetching {} jar from {}", lname, source.userToString());
      }
      source.sendAsync(
          msg,
          new AsyncMessageCallback() {

            @Override
            public void acknowledged() {
              // Cool! Wait for the actual transfer.
            }

            @Override
            public void disconnected() {
              if (LOG.isInfoEnabled()) {
                LOG.info(
                    "Disconnected from {} after sending UOMRequestMainJar", source.userToString());
              }
              synchronized (UpdateOverMandatoryManager.this) {
                sendingJar.remove(source);
              }
              maybeRequestMainJar();
            }

            @Override
            public void fatalError() {
              LOG.info(
                  "Fatal error from {} after sending UOMRequestMainJar", source.userToString());
              synchronized (UpdateOverMandatoryManager.this) {
                askedSendJar.remove(source);
              }
              maybeRequestMainJar();
            }

            @Override
            public void sent() {
              // Timeout...
              updateManager
                  .getNode()
                  .getTicker()
                  .queueTimedJob(
                      () -> {
                        synchronized (UpdateOverMandatoryManager.this) {
                          // free up a slot
                          if (!askedSendJar.remove(source)) return;
                        }
                        maybeRequestMainJar();
                      },
                      REQUEST_MAIN_JAR_TIMEOUT);
            }
          },
          updateManager.getByteCounter());
    } catch (NotConnectedException e) {
      synchronized (this) {
        askedSendJar.remove(source);
      }
      maybeRequestMainJar();
    }
  }

  private record UomRequestDecision(boolean proceed, boolean startedFetching) {}

  private UomRequestDecision decideUomRequest(
      final PeerNode source,
      boolean addOnFail,
      String lname,
      final HashSet<PeerNode> sendingJar,
      final HashSet<PeerNode> askedSendJar) {
    boolean startedFetching;
    synchronized (this) {
      int offeredVersion = source.getMainJarOfferedVersion();
      int updateVersion = updateManager.newMainJarVersion();
      if (isOfferedVersionInvalid(source, lname, offeredVersion, updateVersion))
        return new UomRequestDecision(false, false);

      int curVersion = updateManager.getMainVersion();
      if (isCurrentVersionUpToDate(source, lname, curVersion, offeredVersion))
        return new UomRequestDecision(false, false);

      if (askedSendJar.contains(source)) {
        if (LOG.isDebugEnabled())
          LOG.debug("Recently asked node {} ({}) so not re-asking yet.", source, lname);
        return new UomRequestDecision(false, false);
      }

      if (isAtCapacityAndQueueOffer(addOnFail, sendingJar, askedSendJar, source, lname))
        return new UomRequestDecision(false, false);

      if (alreadyFetchingFromSource(sendingJar, source, lname))
        return new UomRequestDecision(false, false);

      sendingJar.add(source);
      startedFetching = !fetchingUOM;
      fetchingUOM = true;
    }
    return new UomRequestDecision(true, startedFetching);
  }

  private boolean isOfferedVersionInvalid(
      PeerNode source, String lname, int offeredVersion, int updateVersion) {
    if (offeredVersion < updateVersion) {
      if (offeredVersion <= 0)
        LOG.error(
            "Not sending UOM {} request to {} because it hasn't offered anything!", lname, source);
      else if (LOG.isDebugEnabled())
        LOG.debug(
            "Not sending UOM {} request to {} because we already have its offered version {}",
            lname,
            source,
            offeredVersion);
      return true;
    }
    return false;
  }

  private boolean isCurrentVersionUpToDate(
      PeerNode source, String lname, int curVersion, int offeredVersion) {
    if (curVersion >= offeredVersion) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Not fetching from {} because current {} jar version {} is more recent than {}",
            source,
            lname,
            curVersion,
            offeredVersion);
      return true;
    }
    return false;
  }

  private boolean isAtCapacityAndQueueOffer(
      boolean addOnFail,
      HashSet<PeerNode> sendingJar,
      HashSet<PeerNode> askedSendJar,
      PeerNode source,
      String lname) {
    if (addOnFail && askedSendJar.size() + sendingJar.size() >= MAX_NODES_SENDING_JAR) {
      if (nodesOfferedMainJar.add(source) && LOG.isInfoEnabled()) {
        LOG.info(
            "Offered {} jar by {} (already fetching from {}), will use this offer if our current"
                + " fetches fail.",
            lname,
            source.userToString(),
            sendingJar.size());
      }
      return true;
    }
    return false;
  }

  private boolean alreadyFetchingFromSource(
      HashSet<PeerNode> sendingJar, PeerNode source, String lname) {
    if (sendingJar.contains(source)) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Not fetching {} jar from {} because already fetching from that node",
            lname,
            source.userToString());
      return true;
    }
    return false;
  }

  /**
   * Attempts to request the main jar from queued offers when capacity allows.
   *
   * <p>Respects {@link #MAX_NODES_SENDING_JAR}. If no capacity is available or no offers remain,
   * the method returns immediately. This method is idempotent with respect to already contacted
   * peers.
   */
  protected void maybeRequestMainJar() {
    PeerNode[] offers;
    synchronized (this) {
      if (nodesAskedSendMainJar.size() + nodesSendingMainJar.size() >= MAX_NODES_SENDING_JAR)
        return;
      if (nodesOfferedMainJar.isEmpty()) return;
      offers = nodesOfferedMainJar.toArray(new PeerNode[0]);
    }
    for (PeerNode offer : offers) {
      boolean shouldSkip;
      synchronized (this) {
        if (nodesAskedSendMainJar.size() + nodesSendingMainJar.size() >= MAX_NODES_SENDING_JAR)
          return;
        shouldSkip = nodesSendingMainJar.contains(offer) || nodesAskedSendMainJar.contains(offer);
      }
      if (!offer.isConnected() || shouldSkip) continue;
      sendUOMRequest(offer, false);
    }
  }

  private void alertUser() {
    synchronized (this) {
      if (alert != null) return;
      alert = new PeersSayKeyBlownAlert();
    }
    updateManager.getNode().getClientCore().getAlerts().register(alert);
  }

  private class PeersSayKeyBlownAlert extends AbstractUserAlert {

    public PeersSayKeyBlownAlert() {
      super(false, null, null, UserAlert.WARNING, true, new DismissOptions(null, false));
    }

    @Override
    public HTMLNode getHTMLText() {
      HTMLNode div = new HTMLNode("div");

      div.addChild("p").addChild("#", l10n("intro"));

      PeerNode[][] nodes = getNodesSayBlown();
      PeerNode[] nodesSayBlownConnected = nodes[0];
      PeerNode[] nodesSayBlownDisconnected = nodes[1];
      PeerNode[] nodesSayBlownFailedTransfer = nodes[2];

      if (nodesSayBlownConnected.length > 0) div.addChild("p").addChild("#", l10n("fetching"));
      else div.addChild("p").addChild("#", l10n("failedFetch"));

      if (nodesSayBlownConnected.length > 0) {
        div.addChild("p").addChild("#", l10n("connectedSayBlownLabel"));
        HTMLNode list = div.addChild("ul");
        for (PeerNode pn : nodesSayBlownConnected) {
          list.addChild("li", pn.userToString() + " (" + pn.getPeer() + ")");
        }
      }

      if (nodesSayBlownDisconnected.length > 0) {
        div.addChild("p").addChild("#", l10n("disconnectedSayBlownLabel"));
        HTMLNode list = div.addChild("ul");
        for (PeerNode pn : nodesSayBlownDisconnected) {
          list.addChild("li", pn.userToString() + " (" + pn.getPeer() + ")");
        }
      }

      if (nodesSayBlownFailedTransfer.length > 0) {
        div.addChild("p").addChild("#", l10n("failedTransferSayBlownLabel"));
        HTMLNode list = div.addChild("ul");
        for (PeerNode pn : nodesSayBlownFailedTransfer) {
          list.addChild("li", pn.userToString() + " (" + pn.getPeer() + ")");
        }
      }

      return div;
    }

    private String l10n(String key) {
      return NodeL10n.getBase().getString("PeersSayKeyBlownAlert." + key);
    }

    private String l10nTitleWithCount(String value) {
      return NodeL10n.getBase().getString("PeersSayKeyBlownAlert.titleWithCount", "count", value);
    }

    @Override
    public String getText() {
      StringBuilder sb = new StringBuilder();
      sb.append(l10n("intro")).append("\n\n");
      PeerNode[][] nodes = getNodesSayBlown();
      PeerNode[] nodesSayBlownConnected = nodes[0];
      PeerNode[] nodesSayBlownDisconnected = nodes[1];
      PeerNode[] nodesSayBlownFailedTransfer = nodes[2];

      if (nodesSayBlownConnected.length > 0) sb.append(l10n("fetching")).append("\n\n");
      else sb.append(l10n("failedFetch")).append("\n\n");

      if (nodesSayBlownConnected.length > 0) {
        sb.append(l10n("connectedSayBlownLabel")).append("\n\n");
        for (PeerNode pn : nodesSayBlownConnected) {
          sb.append(pn.userToString()).append(" (").append(pn.getPeer()).append(")").append("\n");
        }
        sb.append("\n");
      }

      if (nodesSayBlownDisconnected.length > 0) {
        sb.append(l10n("disconnectedSayBlownLabel"));

        for (PeerNode pn : nodesSayBlownDisconnected) {
          sb.append(pn.userToString()).append(" (").append(pn.getPeer()).append(")").append("\n");
        }
        sb.append("\n");
      }

      if (nodesSayBlownFailedTransfer.length > 0) {
        sb.append(l10n("failedTransferSayBlownLabel"));

        for (PeerNode pn : nodesSayBlownFailedTransfer) {
          sb.append(pn.userToString()).append(" (").append(pn.getPeer()).append(")").append('\n');
        }
        sb.append("\n");
      }

      return sb.toString();
    }

    @Override
    public String getTitle() {
      return l10nTitleWithCount(Integer.toString(nodesSayKeyRevoked.size()));
    }

    @Override
    public void isValid(boolean validity) {
      // Do nothing
    }

    @Override
    public boolean isValid() {
      if (updateManager.isBlown()) return false;
      return mightBeRevoked();
    }

    @Override
    public String getShortText() {
      return l10n("short");
    }
  }

  /**
   * Returns peers that reported the auto‑update key as revoked, grouped by status.
   *
   * <p>The returned array has three elements: index {@code 0} lists connected peers that reported
   * revocation; index {@code 1} lists peers that reported revocation but are currently
   * disconnected; index {@code 2} lists peers for which revocation transfer attempts failed.
   * Callers must treat the returned arrays as read‑only snapshots.
   *
   * @return A three‑element array of peer arrays: connected, disconnected, and failed‑transfer
   *     reporters, in that order. Arrays may be empty but are never {@code null}.
   */
  public PeerNode[][] getNodesSayBlown() {
    List<PeerNode> nodesConnectedSayRevoked = new ArrayList<>();
    List<PeerNode> nodesDisconnectedSayRevoked = new ArrayList<>();
    List<PeerNode> nodesFailedSayRevoked = new ArrayList<>();
    synchronized (this) {
      PeerNode[] nodesSayRevoked = nodesSayKeyRevoked.toArray(new PeerNode[0]);
      for (PeerNode pn : nodesSayRevoked) {
        if (nodesSayKeyRevokedFailedTransfer.contains(pn)) nodesFailedSayRevoked.add(pn);
        else nodesConnectedSayRevoked.add(pn);
      }
    }
    for (java.util.Iterator<PeerNode> it = nodesConnectedSayRevoked.iterator(); it.hasNext(); ) {
      PeerNode pn = it.next();
      if (!pn.isConnected()) {
        nodesDisconnectedSayRevoked.add(pn);
        it.remove();
      }
    }
    return new PeerNode[][] {
      nodesConnectedSayRevoked.toArray(new PeerNode[0]),
      nodesDisconnectedSayRevoked.toArray(new PeerNode[0]),
      nodesFailedSayRevoked.toArray(new PeerNode[0]),
    };
  }

  /**
   * Handles a peer request to send the revocation certificate binary blob.
   *
   * <p>If the certificate is available locally, a bulk transfer is scheduled back to the requester
   * using the message’s {@code UID}. Otherwise, the request is ignored after logging; the peer may
   * retry later. This method does not block on I/O.
   *
   * @param m Request message containing a unique {@code UID} and necessary metadata for the bulk
   *     transfer; the message must be well‑formed.
   * @param source The requesting peer. Its connection state determines whether the transfer can be
   *     initiated.
   * @return Always {@code true} to indicate the message was consumed by this handler.
   */
  public boolean handleRequestRevocation(Message m, final PeerNode source) {
    // Do we have the data?

    final RandomAccessBuffer data = updateManager.getRevocationChecker().getBlobBuffer();

    if (data != null) {
      final long uid = m.getLong(DMT.UID);
      sendRevocationBlobToPeer(uid, data, source);
    } else {
      LOG.info(
          "Peer {} asked us for the blob file for the revocation key but we don't have it!",
          source);
      // Probably a race condition on reconnect, hopefully we'll be asked again
    }

    return true;
  }

  private void sendRevocationBlobToPeer(
      final long uid, final RandomAccessBuffer data, final PeerNode source) {
    long length = data.size();
    final PartiallyReceivedBulk prb =
        new PartiallyReceivedBulk(
            updateManager.getNode().getUSM(), length, Node.PACKET_SIZE, data, true);

    BulkTransmitter bt = buildRevocationTransmitter(prb, source, uid, data);
    if (bt == null) return;

    final Runnable r = buildRevocationSenderRunnable(bt, data, source);
    sendRevocationAsync(source, uid, length, r);
  }

  private BulkTransmitter buildRevocationTransmitter(
      PartiallyReceivedBulk prb, PeerNode source, long uid, RandomAccessBuffer data) {
    try {
      return new BulkTransmitter(prb, source, uid, false, updateManager.getByteCounter(), true);
    } catch (DisconnectedException e) {
      LOG.error(
          "Peer {} asked us for the blob file for the revocation key, then disconnected: {}",
          source,
          e,
          e);
      data.close();
      return null;
    }
  }

  private Runnable buildRevocationSenderRunnable(
      final BulkTransmitter btFinal, final RandomAccessBuffer data, final PeerNode source) {
    return (() -> {
      try {
        if (!btFinal.send()) {
          if (LOG.isErrorEnabled()) {
            LOG.error(
                "Failed to send revocation key blob to {} : {}",
                source.userToString(),
                btFinal.getCancelReason());
          }
        } else {
          if (LOG.isInfoEnabled()) {
            LOG.info("Sent revocation key blob to {}", source.userToString());
          }
        }
      } catch (DisconnectedException e) {
        // Not much we can do here either.
        if (LOG.isWarnEnabled()) {
          LOG.warn(
              "Failed to send revocation key blob (disconnected) to {} : {}",
              source.userToString(),
              btFinal.getCancelReason());
        }
      } finally {
        data.close();
      }
    });
  }

  private void sendRevocationAsync(
      final PeerNode source, final long uid, long length, final Runnable r) {
    Message msg =
        DMT.createUOMSendingRevocation(uid, length, updateManager.getRevocationURI().toString());
    try {
      source.sendAsync(
          msg,
          new AsyncMessageCallback() {

            @Override
            public void acknowledged() {
              if (LOG.isDebugEnabled()) LOG.debug("Sending data...");
              updateManager
                  .getNode()
                  .getExecutor()
                  .execute(
                      r,
                      "Revocation key send" + FOR_LITERAL + uid + " to " + source.userToString());
            }

            @Override
            public void disconnected() {
              LOG.error(
                  "Peer {} asked us for the blob file for the revocation key, then disconnected"
                      + " when we tried to send the UOMSendingRevocation",
                  source);
            }

            @Override
            public void fatalError() {
              LOG.error(
                  "Peer {} asked us for the blob file for the revocation key, then got a fatal"
                      + " error when we tried to send the UOMSendingRevocation",
                  source);
            }

            @Override
            public void sent() {
              if (LOG.isDebugEnabled()) LOG.debug("Message sent, data soon");
            }

            @Override
            public String toString() {
              return super.toString() + "(" + uid + ":" + source.getPeer() + ")";
            }
          },
          updateManager.getByteCounter());
    } catch (NotConnectedException e) {
      LOG.error(
          "Peer {} asked us for the blob file for the revocation key, then disconnected when we"
              + " tried to send the UOMSendingRevocation: {}",
          source,
          e,
          e);
    }
  }

  /**
   * Handles a peer announcement that it is sending the revocation certificate to us.
   *
   * <p>Validates the advertised {@code URI} and length, checks acceptance rules and size limits,
   * and, if acceptable, schedules a bulk receive to a temporary file followed by verification and
   * processing. If the offer is rejected or malformed, the transfer is cancelled.
   *
   * @param m Message describing the transfer, including {@code UID}, {@code FILE_LENGTH}, and
   *     {@code REVOCATION_KEY} fields.
   * @param source The peer that will transmit the certificate.
   * @return {@code true} when the message was handled; {@code false} is not used.
   */
  public boolean handleSendingRevocation(Message m, final PeerNode source) {
    final long uid = m.getLong(DMT.UID);
    final long length = m.getLong(DMT.FILE_LENGTH);
    String key = m.getString(DMT.REVOCATION_KEY);

    boolean proceed = true;
    FreenetURI revocationURI = null;
    try {
      revocationURI = new FreenetURI(key);
    } catch (MalformedURLException e) {
      LOG.error("Failed receiving revocation because URI not parsable: {} for {}", e, key);
      synchronized (this) {
        nodesSayKeyRevoked.remove(source);
        nodesSayKeyRevokedTransferring.remove(source);
      }
      cancelSend(source, uid);
      maybeNotRevoked();
      proceed = false;
    }

    if (proceed) {
      proceed = validateRevocationOffer(source, uid, length, revocationURI);
    }
    if (proceed) {
      receiveRevocationCertificate(uid, length, source);
    }
    return true;
  }

  private boolean validateRevocationOffer(
      final PeerNode source, long uid, long length, FreenetURI revocationURI) {
    if (!revocationURI.equals(updateManager.getRevocationURI())) {
      if (LOG.isWarnEnabled()) {
        LOG.warn(
            """
            Node sending us a revocation certificate from the wrong URI:
            Node: {}
            Our   URI: {}
            Their URI: {}
            """,
            source.userToString(),
            updateManager.getRevocationURI(),
            revocationURI);
      }
      synchronized (this) {
        nodesSayKeyRevoked.remove(source);
        nodesSayKeyRevokedTransferring.remove(source);
      }
      cancelSend(source, uid);
      maybeNotRevoked();
      return false;
    }
    if (updateManager.isBlown()) {
      if (LOG.isDebugEnabled())
        LOG.debug("Already blown, so not receiving from {}({})", source, uid);
      cancelSend(source, uid);
      return false;
    }
    if (length > NodeUpdateManager.MAX_REVOCATION_KEY_BLOB_LENGTH) {
      if (LOG.isErrorEnabled()) {
        LOG.error(
            "{}{} offered us a revocation certificate {} long. This is unacceptably long so we have"
                + " refused the transfer. No real revocation cert would be this big.",
            NODE_PREFIX,
            source.userToString(),
            SizeUtil.formatSize(length));
        LOG.error(
            "Node {} offered us a revocation certificate {} long. This is unacceptably long so we"
                + " have refused the transfer. No real revocation cert would be this big.",
            source.userToString(),
            SizeUtil.formatSize(length));
      }
      synchronized (UpdateOverMandatoryManager.this) {
        nodesSayKeyRevoked.remove(source);
        nodesSayKeyRevokedTransferring.remove(source);
      }
      cancelSend(source, uid);
      maybeNotRevoked();
      return false;
    }
    if (length <= 0) {
      LOG.warn(
          "Revocation key is zero bytes from {} - ignoring as this is almost certainly a bug or an"
              + " attack, it is definitely not valid.",
          source);
      synchronized (UpdateOverMandatoryManager.this) {
        nodesSayKeyRevoked.remove(source);
        nodesSayKeyRevokedTransferring.remove(source);
      }
      cancelSend(source, uid);
      maybeNotRevoked();
      return false;
    }
    return true;
  }

  private void receiveRevocationCertificate(long uid, long length, final PeerNode source) {
    LOG.info(
        "Transferring auto-updater revocation certificate length {}{}{}",
        length,
        FROM_LITERAL,
        source);

    final File temp;
    try {
      temp =
          File.createTempFile(
              "revocation-",
              FBLOB_TMP_SUFFIX,
              updateManager.getNode().getClientCore().getPersistentTempDir());
      temp.deleteOnExit();
    } catch (IOException e) {
      LOG.error(
          "Cannot save revocation certificate to disk and therefore cannot fetch it from our"
              + " peer!:",
          e);
      updateManager.blow(
          "Cannot fetch the revocation certificate from our peer because we cannot write it to"
              + " disk: "
              + e,
          true);
      cancelSend(source, uid);
      return;
    }

    FileRandomAccessBuffer raf;
    try {
      raf = new FileRandomAccessBuffer(temp, length, false);
    } catch (FileNotFoundException e) {
      LOG.error(
          "Peer {} asked us for the blob file for the revocation key, we have downloaded it but"
              + " don't have the file even though we did have it when we checked!: {}",
          source,
          e,
          e);
      updateManager.blow(
          "Internal error after fetching the revocation certificate from our peer, maybe out of"
              + " disk space, file disappeared "
              + temp
              + " : "
              + e,
          true);
      return;
    } catch (IOException e) {
      LOG.error(
          "Peer {} asked us for the blob file for the revocation key, we have downloaded it but now"
              + " can't read the file due to a disk I/O error: {}",
          source,
          e,
          e);
      updateManager.blow(
          "Internal error after fetching the revocation certificate from our peer, maybe out of"
              + " disk space or other disk I/O error, file disappeared "
              + temp
              + " : "
              + e,
          true);
      return;
    }

    synchronized (this) {
      nodesSayKeyRevokedTransferring.add(source);
      nodesSayKeyRevoked.remove(source);
    }

    scheduleRevocationReceive(temp, uid, length, source, raf);
  }

  private void scheduleRevocationReceive(
      final File temp,
      final long uid,
      long length,
      final PeerNode source,
      FileRandomAccessBuffer raf) {
    PartiallyReceivedBulk prb =
        new PartiallyReceivedBulk(
            updateManager.getNode().getUSM(), length, Node.PACKET_SIZE, raf, false);
    final BulkReceiver br = new BulkReceiver(prb, source, uid, updateManager.getByteCounter());
    updateManager
        .getNode()
        .getExecutor()
        .execute(
            () -> processRevocationReceive(br, temp, source),
            "Revocation key receive" + FOR_LITERAL + uid + FROM_LITERAL + source.userToString());
  }

  private void processRevocationReceive(BulkReceiver br, File temp, PeerNode source) {
    try {
      if (br.receive()) {
        processRevocationBlob(temp, source);
      } else {
        LOG.error("Failed to transfer revocation certificate from {}", source);
        source.failedRevocationTransfer();
        int count = source.countFailedRevocationTransfers();
        boolean retry = count < 3;
        synchronized (UpdateOverMandatoryManager.this) {
          nodesSayKeyRevokedFailedTransfer.add(source);
          nodesSayKeyRevokedTransferring.remove(source);
          if (retry) {
            if (nodesSayKeyRevoked.contains(source)) retry = false;
            else nodesSayKeyRevoked.add(source);
          }
        }
        maybeNotRevoked();
        if (retry) tryFetchRevocation(source);
      }
    } catch (Exception t) {
      LOG.error("Caught error while transferring revocation certificate from {}", source, t);
      updateManager.blow(
          "Internal error while fetching the revocation certificate from our peer "
              + source
              + " : "
              + t,
          true);
      synchronized (UpdateOverMandatoryManager.this) {
        nodesSayKeyRevokedTransferring.remove(source);
      }
    }
  }

  /**
   * Clears the “peers say key blown” condition if it no longer plausibly holds.
   *
   * <p>Evaluates current reports and in‑flight transfers; if all connected reporters have failed or
   * disconnected beyond allowed retries, informs the updater that peers no longer claim revocation.
   */
  protected void maybeNotRevoked() {
    synchronized (this) {
      if (!updateManager.peersSayBlown()) return;
      if (mightBeRevoked()) return;
      updateManager.notPeerClaimsKeyBlown();
    }
  }

  private boolean mightBeRevoked() {
    PeerNode[] started;
    PeerNode[] transferring;
    synchronized (this) {
      started = nodesSayKeyRevoked.toArray(new PeerNode[0]);
      transferring = nodesSayKeyRevokedTransferring.toArray(new PeerNode[0]);
    }
    // If a peer is not connected, ignore it.
    // If a peer has already tried 3 times to send the revocation cert, ignore it,
    // because it is probably evil.
    for (PeerNode peer : started) {
      if (peer.isConnected() && peer.countFailedRevocationTransfers() <= 3) {
        return true;
      }
    }
    for (PeerNode peer : transferring) {
      if (peer.isConnected() && peer.countFailedRevocationTransfers() <= 3) {
        return true;
      }
    }
    return false;
  }

  void processRevocationBlob(final File temp, PeerNode source) {
    processRevocationBlob(
        new FileBucket(temp, true, false, false, true), source.userToString(), false);
  }

  /**
   * Process a binary blob for a revocation certificate (the revocation key).
   *
   * @param temp The file it was written to.
   */
  void processRevocationBlob(final Bucket temp, final String source, final boolean fromDisk) {

    SimpleBlockSet blocks = new SimpleBlockSet();
    if (!readRevocationBlob(temp, source, fromDisk, blocks)) return;

    // Fetch our revocation key from the datastore plus the binary blob
    FetchContext seedContext =
        updateManager
            .getNode()
            .getClientCore()
            .makeClient((short) 0, true, false)
            .getFetchContext();
    FetchContext tempContext =
        new FetchContext(seedContext, FetchContext.IDENTICAL_MASK, true, blocks);
    tempContext.maxOutputLength = NodeUpdateManager.MAX_REVOCATION_KEY_LENGTH;
    tempContext.maxTempLength = NodeUpdateManager.MAX_REVOCATION_KEY_TEMP_LENGTH;
    tempContext.localRequestOnly = true;

    final ArrayBucket cleanedBlob = new ArrayBucket();
    ClientGetCallback myCallback = buildRevocationCallback(temp, source, fromDisk, cleanedBlob);

    ClientGetter cg =
        new ClientGetter(
            myCallback,
            updateManager.getRevocationURI(),
            tempContext,
            (short) 0,
            null,
            new BinaryBlobWriter(cleanedBlob),
            null);

    try {
      updateManager.getNode().getClientCore().getClientContext().start(cg);
    } catch (FetchException e1) {
      LOG.error("Failed to decode UOM blob", e1);
      myCallback.onFailure(e1, cg);
    } catch (PersistenceDisabledException e) {
      // Impossible
    }
  }

  private boolean readRevocationBlob(
      Bucket temp, String source, boolean fromDisk, SimpleBlockSet blocks) {
    try (DataInputStream dis = new DataInputStream(temp.getInputStream())) {
      BinaryBlob.readBinaryBlob(dis, blocks, true);
      return true;
    } catch (FileNotFoundException e) {
      LOG.error(
          "{}{} ? We lost the revocation certificate from {}!",
          SOMEONE_DELETED_PREFIX,
          temp,
          source);
      if (!fromDisk)
        updateManager.blow(
            SOMEONE_DELETED_PREFIX
                + temp
                + " ? We lost the revocation certificate from "
                + source
                + "!",
            true);
      return false;
    } catch (EOFException e) {
      LOG.error(
          "Peer {} sent us an invalid revocation certificate! (data too short, might be truncated):"
              + " {} (data in {})",
          source,
          e,
          temp);
      return false;
    } catch (BinaryBlobFormatException e) {
      LOG.error(
          "Peer {} sent us an invalid revocation certificate!: {} (data in {})", source, e, temp);
      return false;
    } catch (IOException e) {
      LOG.error("Could not read revocation cert from temp file {} from node {} !", temp, source, e);
      if (!fromDisk)
        updateManager.blow(
            "Could not read revocation cert from temp file "
                + temp
                + FROM_NODE_LITERAL
                + source
                + " ! : "
                + e,
            true);
      return false;
    }
  }

  private ClientGetCallback buildRevocationCallback(
      final Bucket temp,
      final String source,
      final boolean fromDisk,
      final ArrayBucket cleanedBlob) {
    return new ClientGetCallback() {
      @Override
      public void onFailure(FetchException e, ClientGetter state) {
        if (e.mode == FetchExceptionMode.CANCELLED) {
          LOG.error(
              "Cancelled fetch from store/blob of revocation certificate from {} to {} - please"
                  + " report to developers",
              source,
              temp);
        } else if (e.isFatal()) {
          LOG.error(
              "Got revocation certificate from {} (fatal error i.e. someone with the key inserted"
                  + " bad data)",
              source,
              e);
          updateManager.getRevocationChecker().onFailure(e, state, cleanedBlob);
          if (!fromDisk) temp.free();
          insertRevocationBlob(updateManager.getRevocationChecker().getBlobBucket());
        } else {
          String message =
              "Failed to fetch revocation certificate from blob from "
                  + source
                  + " : "
                  + e
                  + (fromDisk
                      ? " : did you change the revocation key?"
                      : " : this is almost certainly bogus i.e. the auto-update is fine but the"
                          + " node is broken.");
          LOG.error(message);
          temp.free();
          cleanedBlob.free();
        }
      }

      @Override
      public void onSuccess(FetchResult result, ClientGetter state) {
        LOG.info("Got revocation certificate from {}", source);
        updateManager.getRevocationChecker().onSuccess(result, state, cleanedBlob);
        if (!fromDisk) temp.free();
        insertRevocationBlob(updateManager.getRevocationChecker().getBlobBucket());
      }

      @Override
      public void onResume(ClientContext context) {
        // Not persistent.
      }

      @Override
      public RequestClient getRequestClient() {
        return UpdateOverMandatoryManager.this;
      }
    };
  }

  private void insertRevocationBlob(final RandomAccessBucket bucket) {
    final String type = "revocation";
    final short priority = RequestStarter.INTERACTIVE_PRIORITY_CLASS;
    ClientPutCallback callback =
        new ClientPutCallback() {

          @Override
          public void onFailure(InsertException e, BaseClientPutter state) {
            LOG.error("Failed to insert {} binary blob: {}", type, e, e);
          }

          @Override
          public void onFetchable(BaseClientPutter state) {
            // Ignore
          }

          @Override
          public void onGeneratedURI(FreenetURI uri, BaseClientPutter state) {
            // Ignore
          }

          @Override
          public void onSuccess(BaseClientPutter state) {
            // All done. Cool.
            LOG.info("Inserted {} binary blob", type);
          }

          @Override
          public void onGeneratedMetadata(Bucket metadata, BaseClientPutter state) {
            LOG.error(
                "Got onGeneratedMetadata inserting blob from {}", state, new Exception("error"));
            metadata.free();
          }

          @Override
          public void onResume(ClientContext context) {
            // Not persistent.
          }

          @Override
          public RequestClient getRequestClient() {
            return UpdateOverMandatoryManager.this;
          }
        };
    // We are inserting a binary blob so we don't need to worry about CompatibilityMode etc.
    InsertContext ctx =
        updateManager
            .getNode()
            .getClientCore()
            .makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, false, false)
            .getInsertContext(true);
    ClientPutter putter =
        new ClientPutter(
            callback,
            bucket,
            FreenetURI.EMPTY_CHK_URI,
            null,
            ctx,
            priority,
            false,
            null,
            true,
            null,
            -1);
    try {
      updateManager.getNode().getClientCore().getClientContext().start(putter);
    } catch (InsertException e1) {
      LOG.error("Failed to start insert of {} binary blob: {}", type, e1, e1);
    } catch (PersistenceDisabledException e) {
      // Impossible
    }
  }

  private void cancelSend(PeerNode source, long uid) {
    Message msg = DMT.createFNPBulkReceiveAborted(uid);
    try {
      source.sendAsync(msg, null, updateManager.getByteCounter());
    } catch (NotConnectedException e1) {
      // Ignore
    }
  }

  private void removeAskedAndCancel(PeerNode source, long uid) {
    cancelSend(source, uid);
    synchronized (this) {
      this.nodesAskedSendMainJar.remove(source);
    }
  }

  /**
   * Unregisters and clears the current “peers say key blown” alert, if any.
   *
   * <p>This is a best‑effort cleanup used when conditions rendering the alert obsolete are met. It
   * is safe to call even when no alert is registered.
   */
  public void killAlert() {
    updateManager.getNode().getClientCore().getAlerts().unregister(alert);
  }

  /**
   * Handles a peer request to send the current main jar binary blob.
   *
   * <p>Validates policy (e.g., opennet restrictions and minimum peer version), locates the local
   * jar, and initiates a bulk transfer back to the requester. When requirements are not met or the
   * jar is unavailable, the method logs and returns without transferring.
   *
   * @param m Request message with a unique {@code UID} to correlate the bulk transfer.
   * @param source The requesting peer; connection state and version determine eligibility.
   */
  public void handleRequestJar(Message m, final PeerNode source) {
    final String name = "main";

    Message msg;

    if (source.isOpennet() && updateManager.dontAllowUOM()) {
      LOG.info(
          "Peer {} asked us for the blob file for {}; We are a seenode, so we ignore it!",
          source,
          name);
      return;
    }
    // Do we have the data?

    File data;
    int version;
    FreenetURI uri;
    // Legacy support removed - only serve current version
    if (!Version.isBuildAtLeast(
        source.getNodeName(), source.getBuildNumber(), NodeUpdateManager.TRANSITION_VERSION)) {
      // Don't serve updates to very old nodes
      LOG.info(
          "Peer {} is too old (version < {}), not serving update",
          source,
          NodeUpdateManager.TRANSITION_VERSION);
      return;
    }
    data = updateManager.getCurrentVersionBlobFile();
    version = Version.currentBuildNumber();
    uri = updateManager.getURI();

    if (data == null) {
      LOG.info(PEER_ASKED_BLOB_PREFIX + "{} jar but we don't have it!", source, name);
      // Probably a race condition on reconnect, hopefully we'll be asked again
      return;
    }

    final long uid = m.getLong(DMT.UID);

    if (!source.sendingUOMJar(false)) {
      LOG.error("Peer {} asked for UOM main jar twice", source);
      return;
    }

    final long length = data.length();
    msg = DMT.createUOMSendingMainJar(uid, length, uri.toString(), version);

    final Runnable r = buildMainJarSender(source, data, uid, length);

    try {
      source.sendAsync(
          msg,
          new AsyncMessageCallback() {

            @Override
            public void acknowledged() {
              if (LOG.isDebugEnabled()) LOG.debug("Sending data...");
              // Send the data

              updateManager
                  .getNode()
                  .getExecutor()
                  .execute(r, name + " jar send for " + uid + " to " + source.userToString());
            }

            @Override
            public void disconnected() {
              // Argh
              LOG.error(
                  PEER_ASKED_BLOB_PREFIX
                      + "{} jar, then disconnected when we tried to send the UOMSendingMainJar",
                  source,
                  name);
              source.finishedSendingUOMJar(false);
            }

            @Override
            public void fatalError() {
              // Argh
              LOG.error(
                  PEER_ASKED_BLOB_PREFIX
                      + "{} jar, then got a fatal error when we tried to send the"
                      + " UOMSendingMainJar",
                  source,
                  name);
              source.finishedSendingUOMJar(false);
            }

            @Override
            public void sent() {
              if (LOG.isDebugEnabled()) LOG.debug("Message sent, data soon");
            }

            @Override
            public String toString() {
              return super.toString() + "(" + uid + ":" + source.getPeer() + ")";
            }
          },
          updateManager.getByteCounter());
    } catch (NotConnectedException e) {
      LOG.error(
          "Peer {} asked us for the blob file for the {} jar, then disconnected when we tried to"
              + " send the UOMSendingMainJar",
          source,
          name,
          e);
    } catch (RuntimeException e) {
      source.finishedSendingUOMJar(false);
      throw e;
    }
  }

  private Runnable buildMainJarSender(
      final PeerNode source, final File data, final long uid, final long length) {
    return () -> {
      try (FileRandomAccessBuffer rafLocal = new FileRandomAccessBuffer(data, true)) {
        PartiallyReceivedBulk prb =
            new PartiallyReceivedBulk(
                updateManager.getNode().getUSM(), length, Node.PACKET_SIZE, rafLocal, true);
        BulkTransmitter bt =
            new BulkTransmitter(prb, source, uid, false, updateManager.getByteCounter(), true);
        if (!bt.send()) {
          if (LOG.isErrorEnabled()) {
            LOG.error(
                "Failed to send {} jar blob to {} : {}",
                "main",
                source.userToString(),
                bt.getCancelReason());
          }
        } else {
          if (LOG.isInfoEnabled()) {
            LOG.info("Sent {} jar blob to {}", "main", source.userToString());
          }
        }
      } catch (FileNotFoundException e) {
        LOG.error(
            "{}{}don't have the file even though we did have it when we checked!",
            PEER_ASKED_BLOB_PREFIX,
            "main",
            e);
      } catch (IOException e) {
        LOG.error(
            "{}{} jar, we have downloaded it but can't read the file due to a disk I/O error",
            PEER_ASKED_BLOB_PREFIX,
            "main",
            e);
      } catch (DisconnectedException e) {
        LOG.error(
            "Peer {} asked us for the blob file for the {} jar, then disconnected",
            source,
            "main",
            e);
      } finally {
        source.finishedSendingUOMJar(false);
      }
    };
  }

  /**
   * Handles a peer announcement that it is sending the main jar to us.
   *
   * <p>Validates the advertised {@code URI}, version, and length, checks local acceptance rules,
   * and, if acceptable, schedules a bulk receive to a temporary file followed by verification and
   * cleanup. If the offer is rejected, the method cancels the transfer.
   *
   * @param m Message describing the transfer, including {@code UID}, {@code FILE_LENGTH}, {@code
   *     MAIN_JAR_KEY}, and {@code MAIN_JAR_VERSION}.
   * @param source The peer that will transmit the jar.
   * @return {@code true} when the message was handled; {@code false} is not used.
   */
  public boolean handleSendingMain(Message m, final PeerNode source) {
    final long uid = m.getLong(DMT.UID);
    final long length = m.getLong(DMT.FILE_LENGTH);
    final String key = m.getString(DMT.MAIN_JAR_KEY);
    final int version = m.getInt(DMT.MAIN_JAR_VERSION);
    processSendingMain(uid, length, key, version, source);
    return true;
  }

  private void processSendingMain(long uid, long length, String key, int version, PeerNode source) {
    final FreenetURI jarURI;
    try {
      jarURI = new FreenetURI(key).setSuggestedEdition(version);
    } catch (MalformedURLException e) {
      LOG.error(
          "Failed receiving main jar {} because URI not parsable: {} for {}", version, e, key);
      removeAskedAndCancel(source, uid);
      return;
    }

    if (!isUriAccepted(jarURI, version, source, uid)) return;
    if (!canReceiveMainJar(source, uid)) return;
    if (!isMainJarLengthAccepted(length, version, source, uid)) return;

    if (LOG.isInfoEnabled()) {
      LOG.info("Receiving main jar {}{}{}", version, FROM_LITERAL, source.userToString());
    }

    final File temp = prepareTempMainJarFile(uid, source);
    if (temp == null) return;

    FileRandomAccessBuffer raf = prepareMainJarRaf(temp, length, source);
    if (raf == null) return;

    PartiallyReceivedBulk prb =
        new PartiallyReceivedBulk(
            updateManager.getNode().getUSM(), length, Node.PACKET_SIZE, raf, false);

    final BulkReceiver br = new BulkReceiver(prb, source, uid, updateManager.getByteCounter());
    final FreenetURI jarUriForLambda = jarURI;
    updateManager
        .getNode()
        .getExecutor()
        .execute(
            () -> {
              boolean success = false;
              try {
                synchronized (UpdateOverMandatoryManager.class) {
                  nodesAskedSendMainJar.remove(source);
                  nodesSendingMainJar.add(source);
                }
                success = br.receive();
                if (success) processMainJarBlob(temp, source, version, jarUriForLambda);
                else {
                  LOG.error("Failed to transfer main jar {}{}{}", version, FROM_LITERAL, source);
                  try {
                    Files.delete(temp.toPath());
                  } catch (IOException ex) {
                    LOG.warn(FAILED_DELETE_TMP, temp, ex);
                  }
                }
              } finally {
                synchronized (UpdateOverMandatoryManager.class) {
                  nodesSendingMainJar.remove(source);
                  if (success) nodesSentMainJar.add(source);
                }
              }
            },
            "Main jar ("
                + version
                + ") receive"
                + FOR_LITERAL
                + uid
                + FROM_LITERAL
                + source.userToString());
  }

  private boolean isUriAccepted(FreenetURI jarURI, int version, PeerNode source, long uid) {
    if (!jarURI.equals(updateManager.getURI().setSuggestedEdition(version))) {
      if (LOG.isWarnEnabled()) {
        LOG.warn(
            """
            Node sending us a main jar update ({}) from the wrong URI:
            Node: {}
            Our   URI: {}
            Their URI: {}
            """,
            version,
            source.userToString(),
            updateManager.getURI(),
            jarURI);
      }
      removeAskedAndCancel(source, uid);
      return false;
    }
    return true;
  }

  private boolean canReceiveMainJar(PeerNode source, long uid) {
    if (updateManager.isBlown()) {
      LOG.debug("Key blown, so not receiving main jar from {}({})", source, uid);
      removeAskedAndCancel(source, uid);
      return false;
    }
    return true;
  }

  private boolean isMainJarLengthAccepted(long length, int version, PeerNode source, long uid) {
    if (length > NodeUpdateManager.MAX_MAIN_JAR_LENGTH) {
      if (LOG.isErrorEnabled()) {
        LOG.error(
            "{}{} offered us a main jar ({}) {} long. This is unacceptably long so we have refused"
                + " the transfer.",
            NODE_PREFIX,
            source.userToString(),
            version,
            SizeUtil.formatSize(length));
        LOG.error(
            "Node {} offered us a main jar ({}) {} long. This is unacceptably long so we have"
                + " refused the transfer.",
            source.userToString(),
            version,
            SizeUtil.formatSize(length));
      }
      // If the transfer fails, we don't try again.
      removeAskedAndCancel(source, uid);
      return false;
    }
    return true;
  }

  private File prepareTempMainJarFile(long uid, PeerNode source) {
    try {
      File temp =
          File.createTempFile(
              "main-",
              FBLOB_TMP_SUFFIX,
              updateManager.getNode().getClientCore().getPersistentTempDir());
      temp.deleteOnExit();
      return temp;
    } catch (IOException e) {
      LOG.error("Cannot save new main jar to disk and therefore cannot fetch it from our peer!", e);
      removeAskedAndCancel(source, uid);
      return null;
    }
  }

  private FileRandomAccessBuffer prepareMainJarRaf(File temp, long length, PeerNode source) {
    try {
      return new FileRandomAccessBuffer(temp, length, false);
    } catch (IOException e) {
      LOG.error(
          "Peer {} sending us a main jar binary blob, but we {}{} : {}",
          source,
          (e instanceof FileNotFoundException)
              ? "lost the temp file "
              : "cannot read the temp file ",
          temp,
          e,
          e);
      synchronized (this) {
        this.nodesAskedSendMainJar.remove(source);
      }
      return null;
    }
  }

  /**
   * Verifies and processes a received main‑jar binary blob.
   *
   * <p>Reads the blob, reconstructs a temporary fetch context using its blocks, and fetches the jar
   * via the local store using the supplied {@code uri}. On success, the cleaned blob is freed and
   * the temporary file is deleted; failures are logged and the temp file is removed.
   *
   * @param temp Temporary file containing the binary blob as received over UoM; must exist.
   * @param source Peer that sent the blob; used for logs, may be {@code null} for local testing.
   * @param version Suggested edition to fetch; must be positive.
   * @param uri Expected URI of the jar to fetch from the store for validation and assembly.
   */
  protected void processMainJarBlob(
      final File temp, final PeerNode source, final long version, FreenetURI uri) {
    SimpleBlockSet blocks = new SimpleBlockSet();
    final String toString = source == null ? "(local)" : source.userToString();

    if (!readMainJarBlob(temp, version, toString, blocks)) return;

    // Fetch the jar from the datastore plus the binary blob

    FetchContext seedContext =
        updateManager
            .getNode()
            .getClientCore()
            .makeClient((short) 0, true, false)
            .getFetchContext();
    FetchContext tempContext =
        new FetchContext(seedContext, FetchContext.IDENTICAL_MASK, true, blocks);
    tempContext.localRequestOnly = true;

    final ArrayBucket cleanedBlob = new ArrayBucket();

    ClientGetCallback myCallback = buildMainJarCallback(temp, version, toString, cleanedBlob);

    ClientGetter cg =
        new ClientGetter(
            myCallback, uri, tempContext, (short) 0, null, new BinaryBlobWriter(cleanedBlob), null);

    try {
      updateManager.getNode().getClientCore().getClientContext().start(cg);
    } catch (FetchException e1) {
      myCallback.onFailure(e1, cg);
    } catch (PersistenceDisabledException e) {
      // Impossible
    }
  }

  private boolean readMainJarBlob(File temp, long version, String toString, SimpleBlockSet blocks) {
    try (DataInputStream dis =
        new DataInputStream(new BufferedInputStream(new FileInputStream(temp)))) {
      BinaryBlob.readBinaryBlob(dis, blocks, true);
      return true;
    } catch (FileNotFoundException e) {
      LOG.error(
          "{}{} ? We lost the main jar ({}) from {}!",
          SOMEONE_DELETED_PREFIX,
          temp,
          version,
          toString);
      return false;
    } catch (IOException e) {
      LOG.error(
          "Could not read main jar ({}) from temp file {} from node {} !", version, temp, toString);
      return false;
    } catch (BinaryBlobFormatException e) {
      LOG.error("Peer {} sent us an invalid main jar ({})!", toString, version, e);
      return false;
    }
  }

  // No file-backed cleaned blob is required for UOM; we buffer in memory.

  private ClientGetCallback buildMainJarCallback(
      final File temp, final long version, final String toString, final Bucket cleanedBlob) {
    return new ClientGetCallback() {

      @Override
      public void onFailure(FetchException e, ClientGetter state) {
        handleMainJarFetchFailure(e, temp, version, toString, cleanedBlob);
      }

      @Override
      public void onSuccess(FetchResult result, ClientGetter state) {
        LOG.info("Got main jar version {}{}{}", version, FROM_LITERAL, toString);
        if (result.size() == 0) {
          LOG.warn("Ignoring main jar because 0 bytes long");
          return;
        }

        if (!updateManager.supportsJarUOM()) {
          LOG.info("Ignoring UOM main jar because jar updates are disabled.");
          try {
            Files.delete(temp.toPath());
          } catch (IOException ex) {
            LOG.warn(FAILED_DELETE_TMP, temp, ex);
          }
          if (cleanedBlob != null) cleanedBlob.free();
          return;
        }
        if (cleanedBlob != null) cleanedBlob.free();
      }

      @Override
      public void onResume(ClientContext context) {
        // Not persistent.
      }

      @Override
      public RequestClient getRequestClient() {
        return UpdateOverMandatoryManager.this;
      }
    };
  }

  private void handleMainJarFetchFailure(
      FetchException e, File temp, long version, String toString, Bucket cleanedBlob) {
    if (e.mode == FetchExceptionMode.CANCELLED) {
      LOG.error("Cancelled fetch from store/blob of main jar ({}) from {}", version, toString);
    } else if (e.newURI != null) {
      try {
        Files.delete(temp.toPath());
      } catch (IOException ex) {
        LOG.warn(FAILED_DELETE_TMP, temp, ex);
      }
      LOG.error("URI changed fetching main jar {} from {}", version, toString);
    } else if (e.isFatal()) {
      try {
        Files.delete(temp.toPath());
      } catch (IOException ex) {
        LOG.warn(FAILED_DELETE_TMP, temp, ex);
      }
      LOG.error(
          "Failed to fetch main jar {} from {} : fatal error (update was probably inserted badly):",
          version,
          toString,
          e);
    } else {
      LOG.error("Failed to fetch main jar {} from blob from {}", version, toString);
    }
    if (cleanedBlob != null) cleanedBlob.free();
  }

  // Removed unused method maybeInsertMainJar: insertion is coordinated via updater flows.

  /**
   * Deletes obsolete persistent temporary files related to UoM transfers.
   *
   * <p>The method scans the persistent temp directory for known UoM patterns (revocation and
   * main‑jar blobs and their temporary variants) and removes files that are clearly safe to delete,
   * including old build‑number‑scoped files below the minimum acceptable build. Errors are logged
   * but otherwise ignored.
   */
  protected void removeOldTempFiles() {
    File oldTempFilesPeerDir = updateManager.getNode().getClientCore().getPersistentTempDir();
    if (!oldTempFilesPeerDir.exists()) return;
    if (!oldTempFilesPeerDir.isDirectory()) {
      LOG.error(
          "Persistent temporary files location is not a directory: {}",
          oldTempFilesPeerDir.getPath());
      return;
    }

    // Best-effort cleanup; failures are only logged.
    File[] oldTempFiles =
        oldTempFilesPeerDir.listFiles(file -> shouldDeleteTempFile(file.getName()));
    if (oldTempFiles == null) {
      LOG.warn("Could not list temporary persistent files in {}", oldTempFilesPeerDir);
      return;
    }

    for (File fileToDelete : oldTempFiles) {
      String fileToDeleteName = fileToDelete.getName();
      try {
        Files.delete(fileToDelete.toPath());
      } catch (NoSuchFileException ex) {
        LOG.info("Temporary persistent file does not exist when deleting: {}", fileToDeleteName);
      } catch (IOException ex) {
        LOG.error(
            "Cannot delete temporary persistent file {} even though it exists: must be TOO"
                + " persistent :)",
            fileToDeleteName);
      }
    }

    // Result not used by caller; nothing to return.
  }

  private boolean shouldDeleteTempFile(String fileName) {
    if (fileName.startsWith("revocation-") && fileName.endsWith(FBLOB_TMP_SUFFIX)) return true;

    Matcher mainBuildNumberMatcher = mainBuildNumberPattern.matcher(fileName);
    Matcher mainTempBuildNumberMatcher = mainTempBuildNumberPattern.matcher(fileName);
    Matcher revocationTempBuildNumberMatcher = revocationTempBuildNumberPattern.matcher(fileName);

    if (mainBuildNumberMatcher.matches()) {
      try {
        String buildNumberStr = mainBuildNumberMatcher.group(1);
        int buildNumber = Integer.parseInt(buildNumberStr);
        int lastGoodMainBuildNumber = Version.MIN_ACCEPTABLE_CRYPTAD_BUILD_NUMBER;
        return buildNumber < lastGoodMainBuildNumber;
      } catch (NumberFormatException e) {
        LOG.error("Wierd file in persistent temp: {}", fileName);
        return false;
      }
    }
    return mainTempBuildNumberMatcher.matches() || revocationTempBuildNumberMatcher.matches();
  }

  /** {@inheritDoc} */
  @Override
  public boolean persistent() {
    return false;
  }

  /**
   * Clears UoM state associated with a disconnected peer.
   *
   * <p>Removes the peer from all tracking sets (offers, active transfers, and revocation reports)
   * and re‑evaluates whether the revocation condition still plausibly holds.
   *
   * @param pn The peer that disconnected.
   */
  public void disconnected(PeerNode pn) {
    synchronized (this) {
      nodesSayKeyRevoked.remove(pn);
      nodesSayKeyRevokedFailedTransfer.remove(pn);
      nodesSayKeyRevokedTransferring.remove(pn);
      nodesOfferedMainJar.remove(pn);
      allNodesOfferedMainJar.remove(pn);
      nodesSentMainJar.remove(pn);
      nodesAskedSendMainJar.remove(pn);
      nodesSendingMainJar.remove(pn);
    }
    maybeNotRevoked();
  }

  /**
   * Reports whether two concurrent main‑jar transfers are in progress.
   *
   * <p>This reflects the internal cap enforced by {@link #MAX_NODES_SENDING_JAR} for reliability
   * and bandwidth conservation.
   *
   * @return {@code true} if at least two peers are currently sending the main jar; otherwise {@code
   *     false}.
   */
  public boolean fetchingFromTwo() {
    synchronized (this) {
      return (this.nodesSendingMainJar.size()) >= 2;
    }
  }

  /** {@inheritDoc} */
  @Override
  public boolean realTimeFlag() {
    return false;
  }

  /**
   * Indicates whether a main‑jar transfer is currently active.
   *
   * @return {@code true} if at least one peer is sending the main jar; {@code false} otherwise.
   */
  public boolean isFetchingMain() {
    synchronized (this) {
      return !nodesSendingMainJar.isEmpty();
    }
  }

  /**
   * Advertises a locally available dependency that can be served to peers by hash.
   *
   * <p>The file is indexed by its {@code SHA‑256} hash and may later be read and transferred on
   * demand. Only register files that currently exist and are readable; absence at transfer time is
   * treated as a transient failure.
   *
   * @param expectedHash The exact SHA‑256 of the file content as a byte array; must not be null.
   * @param filename The on‑disk file to serve when requested; the path is not copied.
   */
  @SuppressWarnings("unused")
  public void addDependency(byte[] expectedHash, File filename) {
    if (LOG.isDebugEnabled())
      LOG.debug("Add dependency: {} for {}", filename, HexUtil.bytesToHex(expectedHash));
    synchronized (dependencies) {
      dependencies.put(new ShortBuffer(expectedHash), filename);
    }
  }

  static final int MAX_TRANSFERS_PER_PEER = 2;

  /**
   * Handles a peer request to fetch a registered dependency by its hash.
   *
   * <p>Validates the request, enforces per‑peer transfer caps, and streams the file using the bulk
   * transfer protocol when available. If the file is unavailable or the request exceeds limits, a
   * cancellation is sent instead.
   *
   * @param m The request message containing {@code EXPECTED_HASH}, {@code FILE_LENGTH}, and {@code
   *     UID} fields.
   * @param source The requesting peer.
   */
  public void handleFetchDependency(Message m, final PeerNode source) {
    File data;
    final ShortBuffer buf = (ShortBuffer) m.getObject(DMT.EXPECTED_HASH);
    long length = m.getLong(DMT.FILE_LENGTH);
    long uid = m.getLong(DMT.UID);
    synchronized (dependencies) {
      data = dependencies.get(buf);
    }
    boolean fail = !incrementDependencies(source);
    FileRandomAccessBuffer raf;
    final BulkTransmitter bt;

    DepOpen dep = openDependency(data, buf, source);
    raf = dep.raf;
    fail = fail || dep.fail;

    PrbDecision prbDecision = buildDependencyPrb(raf, length);
    PartiallyReceivedBulk prb = prbDecision.prb();
    fail = fail || prbDecision.sizeMismatch();

    try {
      bt = new BulkTransmitter(prb, source, uid, false, updateManager.getByteCounter(), true);
    } catch (DisconnectedException e) {
      LOG.error(
          "Peer {} asked us for the dependency with hash {} jar then disconnected",
          source,
          HexUtil.bytesToHex(buf.getData()),
          e);
      if (raf != null) {
        raf.close();
      }
      decrementDependencies(source);
      return;
    }

    if (fail) {
      cancelSend(source, uid);
      decrementDependencies(source);
    } else {
      final FileRandomAccessBuffer r = raf;
      updateManager
          .getNode()
          .getExecutor()
          .execute(
              () -> {
                source.incrementUOMSends();
                try {
                  bt.send();
                } catch (DisconnectedException e) {
                  LOG.info(
                      "Disconnected while sending dependency with hash {} to {}",
                      HexUtil.bytesToHex(buf.getData()),
                      source);
                } finally {
                  source.decrementUOMSends();
                  decrementDependencies(source);
                  if (r != null) {
                    r.close();
                  }
                }
              });
    }
  }

  private record PrbDecision(PartiallyReceivedBulk prb, boolean sizeMismatch) {}

  private PrbDecision buildDependencyPrb(FileRandomAccessBuffer raf, long expectedLength) {
    if (raf != null) {
      long thisLength = raf.size();
      PartiallyReceivedBulk prb =
          new PartiallyReceivedBulk(
              updateManager.getNode().getUSM(), thisLength, Node.PACKET_SIZE, raf, true);
      return new PrbDecision(prb, expectedLength != thisLength);
    }
    PartiallyReceivedBulk prb =
        new PartiallyReceivedBulk(
            updateManager.getNode().getUSM(),
            0,
            Node.PACKET_SIZE,
            new ByteArrayRandomAccessBuffer(new byte[0]),
            true);
    return new PrbDecision(prb, false);
  }

  private void decrementDependencies(PeerNode source) {
    synchronized (peersFetchingDependencies) {
      Integer x = peersFetchingDependencies.get(source);
      if (x == null) {
        LOG.error("Inconsistent dependency counting? Should not be null for {}", source);
      } else if (x == 1) {
        peersFetchingDependencies.remove(source);
      } else if (x <= 0) {
        LOG.error("Inconsistent dependency counting? Counter is {} for {}", x, source);
        peersFetchingDependencies.remove(source);
      } else {
        peersFetchingDependencies.put(source, x - 1);
      }
    }
  }

  private record DepOpen(FileRandomAccessBuffer raf, boolean fail) {}

  private DepOpen openDependency(File data, ShortBuffer buf, PeerNode source) {
    try {
      if (data != null) return new DepOpen(new FileRandomAccessBuffer(data, true), false);
      if (LOG.isErrorEnabled()) {
        LOG.error("Dependency with hash {} not found!", HexUtil.bytesToHex(buf.getData()));
      }
      return new DepOpen(null, true);
    } catch (IOException e) {
      LOG.error(
          "Peer {} asked us for the dependency with hash {} jar, we have downloaded it but {} even"
              + " though we did have it when we checked!: {}",
          source,
          HexUtil.bytesToHex(buf.getData()),
          e instanceof FileNotFoundException ? "don't have the file" : "can't read the file",
          e,
          e);
      return new DepOpen(null, true);
    }
  }

  /**
   * @return False if we cannot accept any more transfers from this node. True to accept the
   *     transfer.
   */
  private boolean incrementDependencies(PeerNode source) {
    synchronized (peersFetchingDependencies) {
      Integer x = peersFetchingDependencies.get(source);
      if (x == null) x = 0;
      x++;
      if (x > MAX_TRANSFERS_PER_PEER) {
        LOG.info("Too many dependency transfers for peer {} - rejecting", source);
        return false;
      } else peersFetchingDependencies.put(source, x);
      return true;
    }
  }

  boolean fetchingUOM() {
    return fetchingUOM;
  }

  /** Callback notified when a dependency fetch completes successfully. */
  public interface UOMDependencyFetcherCallback {
    /**
     * Invoked once when the dependency has been fully received, verified, and moved into place.
     * Implementations should return quickly; long‑running work should be offloaded.
     */
    void onSuccess();
  }

  /**
   * Tries to fetch a dependency by its content hash from any available peer.
   *
   * <p>Registers a fetcher that will contact peers advertising UoM service, receive the file to a
   * temporary location, verify its {@code SHA‑256} against {@code expectedHash}, optionally mark it
   * executable, and atomically move it to {@code saveTo} on success.
   *
   * @param expectedHash Exact SHA‑256 of the file to fetch, as a 32‑byte array; must not be null.
   * @param size Expected size of the file in bytes; used to preallocate and validate the transfer.
   * @param saveTo Destination path to receive into on success; parent directory must be writable.
   * @param executable When {@code true}, attempts to mark the resulting file executable if not
   *     already permitted by the filesystem.
   * @param cb Callback invoked once on successful completion; never {@code null}.
   */
  @SuppressWarnings("unused")
  public void fetchDependency(
      byte[] expectedHash,
      long size,
      File saveTo,
      boolean executable,
      UOMDependencyFetcherCallback cb) {
    final UOMDependencyFetcher f =
        new UOMDependencyFetcher(expectedHash, size, saveTo, executable, cb);
    synchronized (this) {
      dependencyFetchers.put(f.expectedHashBuffer, f);
    }
    this.updateManager.getNode().getExecutor().execute(f::start);
    f.start();
  }

  /** Starts all registered dependency fetchers if they have pending work. */
  protected void startSomeDependencyFetchers() {
    UOMDependencyFetcher[] fetchers;
    synchronized (this) {
      fetchers = dependencyFetchers.values().toArray(new UOMDependencyFetcher[0]);
    }
    for (UOMDependencyFetcher f : fetchers) {
      f.start();
    }
  }

  /**
   * Reconsiders stalled dependency downloads after a successful transfer from a peer.
   *
   * <p>Useful when transient failures clear and capacity may be available again. This nudges all
   * active fetchers to retry using the specified peer.
   *
   * @param fetchFrom Peer from which a download just succeeded; must not be {@code null}.
   */
  protected void peerMaybeFreeAllSlots(PeerNode fetchFrom) {
    UOMDependencyFetcher[] fetchers;
    synchronized (this) {
      fetchers = dependencyFetchers.values().toArray(new UOMDependencyFetcher[0]);
    }
    for (UOMDependencyFetcher f : fetchers) {
      f.peerMaybeFreeSlots(fetchFrom);
    }
  }

  /**
   * Fetches a single dependency by hash via UoM, retrying across peers.
   *
   * <p>Instances track their own progress and avoid duplicate concurrent requests to the same peer.
   * Completion is signalled through a callback.
   */
  class UOMDependencyFetcher {

    final byte[] expectedHash;
    final ShortBuffer expectedHashBuffer;
    final long size;
    final File saveTo;
    final boolean executable;
    private boolean completed;
    private final UOMDependencyFetcherCallback cb;
    private final WeakHashSet<PeerNode> peersFailed;
    private final HashSet<PeerNode> peersFetching;

    private UOMDependencyFetcher(
        byte[] expectedHash,
        long size,
        File saveTo,
        boolean executable,
        UOMDependencyFetcherCallback callback) {
      this.expectedHash = expectedHash;
      expectedHashBuffer = new ShortBuffer(expectedHash);
      this.size = size;
      this.executable = executable;
      this.saveTo = saveTo;
      cb = callback;
      peersFailed = new WeakHashSet<>();
      peersFetching = new HashSet<>();
    }

    /** If a transfer has failed from this peer, retry it. */
    private void peerMaybeFreeSlots(PeerNode fetchFrom) {
      synchronized (this) {
        if (!peersFailed.remove(fetchFrom)) return;
        if (completed) return;
      }
      start();
    }

    private boolean maybeFetch() {
      if (isAtCapacityOrCompleted()) return false;
      PeerNode chosen = findPeerWithFallback();
      if (chosen == null) return false;
      scheduleFetch(chosen);
      return true;
    }

    private boolean isAtCapacityOrCompleted() {
      synchronized (this) {
        if (peersFetching.size() >= MAX_NODES_SENDING_JAR) {
          if (LOG.isDebugEnabled())
            LOG.debug("Already fetching jar from 2 peers {}", peersFetching);
          return true;
        }
        return completed;
      }
    }

    private PeerNode findPeerWithFallback() {
      boolean tryEverything = false;
      while (true) {
        HashSet<PeerNode> uomPeers;
        synchronized (UpdateOverMandatoryManager.this) {
          uomPeers = new HashSet<>(nodesSentMainJar);
        }
        PeerNode chosen = chooseRandomPeer(uomPeers);
        if (chosen != null) return chosen;
        synchronized (UpdateOverMandatoryManager.this) {
          uomPeers = new HashSet<>(nodesSendingMainJar);
        }
        chosen = chooseRandomPeer(uomPeers);
        if (chosen != null) return chosen;
        synchronized (UpdateOverMandatoryManager.this) {
          uomPeers = new HashSet<>(allNodesOfferedMainJar);
        }
        chosen = chooseRandomPeer(uomPeers);
        if (chosen != null) return chosen;
        if (tryEverything) {
          LOG.debug("Could not find a peer to send request to for {}", saveTo);
          return null;
        }
        synchronized (this) {
          if (!peersFailed.isEmpty()) {
            LOG.info(
                "UOM trying peers which have failed downloads for {} because nowhere else to go"
                    + " ...",
                saveTo.getName());
            peersFailed.clear();
            tryEverything = true;
          } else {
            LOG.debug("Could not find a peer to send request to for {}", saveTo);
            return null;
          }
        }
      }
    }

    private void scheduleFetch(final PeerNode fetchFrom) {
      updateManager.getNode().getExecutor().execute(() -> fetchDependencyFromPeer(fetchFrom));
    }

    private void fetchDependencyFromPeer(final PeerNode fetchFrom) {
      boolean failed = false;
      File tmp = null;
      try {
        LOG.info("Fetching {}{}{}", saveTo, FROM_LITERAL, fetchFrom);
        long uid = updateManager.getNode().getFastWeakRandom().nextLong();
        fetchFrom.sendAsync(
            DMT.createUOMFetchDependency(uid, expectedHash, size),
            null,
            updateManager.getByteCounter());
        tmp =
            FileUtil.createTempFile(
                saveTo.getName(), NodeUpdateManager.TEMP_FILE_SUFFIX, saveTo.getParentFile());
        failed = !receiveDependency(fetchFrom, uid, tmp);
        if (!failed) {
          failed = !handleSuccessfulReceive(tmp, fetchFrom);
        } else {
          LOG.warn("Download failed: {}{}{}", saveTo, FROM_LITERAL, fetchFrom);
        }
      } catch (NotConnectedException e) {
        LOG.info("Disconnected while downloading {}{}{}", saveTo, FROM_LITERAL, fetchFrom);
      } catch (IOException e) {
        LOG.error("IOException while downloading {} from {}", saveTo, fetchFrom, e);
      } catch (RuntimeException e) {
        LOG.error("Fetch failed due to internal error (bug or severe local problem?)", e);
      } finally {
        afterFetchFinally(fetchFrom, failed, tmp);
      }
    }

    private boolean receiveDependency(PeerNode fetchFrom, long uid, File tmp) throws IOException {
      try (FileRandomAccessBuffer raf = new FileRandomAccessBuffer(tmp, size, false)) {
        PartiallyReceivedBulk prb =
            new PartiallyReceivedBulk(
                updateManager.getNode().getUSM(), size, Node.PACKET_SIZE, raf, false);
        BulkReceiver br = new BulkReceiver(prb, fetchFrom, uid, updateManager.getByteCounter());
        return br.receive();
      }
    }

    private boolean handleSuccessfulReceive(File tmp, PeerNode fetchFrom) {
      if (validDependencyFile(tmp, expectedHash, size, executable)) {
        if (FileUtil.moveTo(tmp, saveTo)) {
          synchronized (UOMDependencyFetcher.this) {
            if (completed) return true;
            completed = true;
          }
          synchronized (UpdateOverMandatoryManager.this) {
            dependencyFetchers.remove(expectedHashBuffer);
          }
          cb.onSuccess();
        } else {
          synchronized (UOMDependencyFetcher.this) {
            if (completed) return false;
          }
          LOG.error(
              "Update failing: Saved dependency to {} for {} but cannot rename it! Permissions"
                  + " problems?",
              tmp,
              saveTo);
          peerMaybeFreeAllSlots(fetchFrom);
          return false;
        }
        peerMaybeFreeAllSlots(fetchFrom);
        return true;
      } else {
        synchronized (UOMDependencyFetcher.this) {
          if (completed) return false;
        }
        LOG.error(
            "Update failing: Downloaded file {}{}{} but file does not match expected hash.",
            saveTo,
            FROM_LITERAL,
            fetchFrom);
        peerMaybeFreeAllSlots(fetchFrom);
        return false;
      }
    }

    private void afterFetchFinally(PeerNode fetchFrom, boolean failed, File tmp) {
      boolean connected = fetchFrom.isConnected();
      boolean addFailed = failed && connected;
      synchronized (UOMDependencyFetcher.this) {
        if (addFailed) peersFailed.add(fetchFrom);
        peersFetching.remove(fetchFrom);
      }
      if (tmp != null) {
        try {
          // Avoid warnings on the normal success path where tmp was moved/renamed.
          Files.deleteIfExists(tmp.toPath());
        } catch (IOException ex) {
          LOG.warn(FAILED_DELETE_TMP, tmp, ex);
        }
      }
      if (failed) {
        start();
        if (fetchFrom.isConnected() && fetchFrom.isDarknet()) {
          updateManager
              .getNode()
              .getTicker()
              .queueTimedJob(() -> peerMaybeFreeSlots(fetchFrom), TimeUnit.HOURS.toMillis(1));
        }
      }
    }

    private synchronized PeerNode chooseRandomPeer(HashSet<PeerNode> uomPeers) {
      if (completed) return null;
      if (peersFetching.size() >= MAX_NODES_SENDING_JAR) {
        LOG.debug("Already fetching jar from 2 peers {}", peersFetching);
        return null;
      }
      LOG.debug("Trying to choose peer from {}", uomPeers.size());
      ArrayList<PeerNode> notTried = null;
      for (PeerNode pn : uomPeers) {
        boolean alreadyFetching = peersFetching.contains(pn);
        boolean alreadyFailed = peersFailed.contains(pn);
        boolean notConnected = !pn.isConnected();
        if (alreadyFetching || alreadyFailed || notConnected) {
          logPeerSkip(pn, alreadyFetching, alreadyFailed);
        } else {
          if (notTried == null) notTried = new ArrayList<>();
          notTried.add(pn);
        }
      }
      if (notTried == null) {
        if (LOG.isDebugEnabled()) LOG.debug("No peers to ask for {}", saveTo);
        return null;
      }
      PeerNode fetchFrom =
          notTried.get(updateManager.getNode().getFastWeakRandom().nextInt(notTried.size()));
      peersFetching.add(fetchFrom);
      return fetchFrom;
    }

    private void logPeerSkip(PeerNode pn, boolean alreadyFetching, boolean alreadyFailed) {
      if (alreadyFetching) LOG.debug("Already fetching from {}", pn);
      else if (alreadyFailed) LOG.debug("Peer already failed for {} : {}", saveTo, pn);
      else LOG.debug("Peer not connected: {}", pn);
    }

    void start() {
      //noinspection StatementWithEmptyBody
      while (maybeFetch()) {
        // Keep fetching until none can be scheduled
      }
    }

    /** Cancels further attempts for this dependency and unregisters it from the manager. */
    public void cancel() {
      synchronized (this) {
        completed = true;
      }
      synchronized (UpdateOverMandatoryManager.this) {
        dependencyFetchers.remove(expectedHashBuffer);
      }
    }

    private boolean validDependencyFile(
        File filename, byte[] expectedHash, long size, boolean executable) {
      if (filename == null || !filename.exists()) return false;
      if (filename.length() != size) return false;
      try (InputStream fis = new FileInputStream(filename)) {
        MessageDigest md = SHA256.getMessageDigest();
        SHA256.hash(fis, md);
        byte[] hash = md.digest();
        if (Arrays.equals(hash, expectedHash)) {
          if (executable && !filename.canExecute()) {
            boolean ok = filename.setExecutable(true);
            if (!ok) LOG.warn("Failed to mark dependency as executable: {}", filename);
          }
          return true;
        }
        return false;
      } catch (IOException e) {
        return false;
      }
    }
  }
}
