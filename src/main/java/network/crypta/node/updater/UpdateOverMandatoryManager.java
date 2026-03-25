package network.crypta.node.updater;

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
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
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
import network.crypta.client.async.ClientPutterOptions;
import network.crypta.client.async.ClientPutterRequest;
import network.crypta.client.async.InsertRequestParams;
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
import network.crypta.runtime.alerts.AbstractUserAlert;
import network.crypta.runtime.alerts.UserAlert;
import network.crypta.support.HTMLNode;
import network.crypta.support.ShortBuffer;
import network.crypta.support.SizeUtil;
import network.crypta.support.WeakHashSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.api.RandomAccessBuffer;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.FileBucket;
import network.crypta.support.io.FileRandomAccessBuffer;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * Coordinates Update‑Over‑Mandatory (UoM) interactions between this node and its peers.
 *
 * <p>UoM is a fallback update path used when peers are too far apart in protocol/build versions to
 * route requests normally. It piggybacks small control messages and bulk binary transfers so a node
 * can receive critical information such as revocation certificates. The {@link
 * network.crypta.node.NodeDispatcher} forwards UoM messages to this class, which decides whether
 * and how to respond (accept, delay, or ignore) based on local policy and current update state
 * managed by {@link NodeUpdateManager}.
 *
 * <p>In the current package‑based updater flow, UoM is only used for revocation handling. Main‑jar
 * exchange is disabled.
 *
 * <p>Concurrency and state: this class is designed to be called from network/async threads; it uses
 * internal synchronization around its shared sets and maps to maintain consistency. All state
 * changes are defensive: inconsistent or malicious inputs are ignored and logged.
 *
 * <ul>
 *   <li>Responsibilities: handle announces and serve/request revocation certificates.
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

  /** Peers seen in UoM announcements and considered for dependency fetch attempts. */
  private final HashSet<PeerNode> allNodesOfferedCorePackage;

  // 2 for reliability, no more as gets very slow/wasteful
  static final int MAX_NODES_SENDING_JAR = 2;

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

  // Revocation and dependency flows only; main-jar UOM is disabled.

  private final HashMap<ShortBuffer, UOMDependencyFetcher> dependencyFetchers;

  /**
   * Creates a new manager bound to the given-updater.
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
    allNodesOfferedCorePackage = new HashSet<>();
    dependencyFetchers = new HashMap<>();
  }

  /**
   * Handles a UOM announcement from a peer and schedules any required actions.
   *
   * <p>Announcements are used for revocation signaling and as a source of candidate peers for
   * dependency fetchers. Revocation announcements are processed first and may short-circuit further
   * handling.
   *
   * @param m UOM announcement message to handle.
   * @param source The peer that sent the announcement. Must be a currently known {@link PeerNode};
   *     its connection status influences later scheduling.
   * @return Always {@code true}. Returning a value allows symmetry with other handlers and aids
   *     integration with dispatch loops that expect boolean results.
   */
  public boolean handleAnnounce(Message m, final PeerNode source) {

    String revocationKey = m.getString(DMT.REVOCATION_KEY);
    boolean haveRevocationKey = m.getBoolean(DMT.HAVE_REVOCATION_KEY);
    long revocationKeyLastTried = m.getLong(DMT.REVOCATION_KEY_TIME_LAST_TRIED);
    int revocationKeyDNFs = m.getInt(DMT.REVOCATION_KEY_DNF_COUNT);
    long revocationKeyFileLength = m.getLong(DMT.REVOCATION_KEY_FILE_LENGTH);
    int pingTime = m.getInt(DMT.PING_TIME);
    int delayTime = m.getInt(DMT.BWLIMIT_DELAY_TIME);

    // Log it

    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Update Over Mandatory offer from node {} : {}:",
          source.getPeer(),
          source.userToString());
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

      synchronized (this) {
        allNodesOfferedCorePackage.add(source);
      }
      startSomeDependencyFetchers();
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
        // Should probably also be a useralert?
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
      // Should maybe be a useralert?
      LOG.error(
          "Node {} sent us a UOMAnnouncement claiming that the auto-update key was blown, but it"
              + " had an invalid revocation URI: {}",
          source,
          revocationKey,
          e);
    } catch (NotConnectedException _) {
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

    Message msg =
        DMT.createUOMRequestRevocation(updateManager.getNode().bootstrap().random().nextLong());
    source
        .transport()
        .sendAsync(
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
        .network()
        .ticker()
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
    // so we can tell if anything weird is happening.

  }

  private void alertUser() {
    synchronized (this) {
      if (alert != null) return;
      UserAlert newAlert = new PeersSayKeyBlownAlert();
      updateManager.getNode().services().clientCore().getAlerts().register(newAlert);
      alert = newAlert;
    }
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
      LOG.info("UOM revocation request: missing local blob for peer {}", source);
      // Probably a race condition on reconnection, hopefully we'll be asked again
    }

    return true;
  }

  private void sendRevocationBlobToPeer(
      final long uid, final RandomAccessBuffer data, final PeerNode source) {
    long length = data.size();
    final PartiallyReceivedBulk prb =
        new PartiallyReceivedBulk(
            updateManager.getNode().network().usm(), length, Node.PACKET_SIZE, data, true);

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
      LOG.error("UOM revocation send setup failed: peer {} disconnected: {}", source, e, e);
      data.close();
      return null;
    }
  }

  private Runnable buildRevocationSenderRunnable(
      final BulkTransmitter btFinal, final RandomAccessBuffer data, final PeerNode source) {
    return () -> {
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
      } catch (DisconnectedException _) {
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
    };
  }

  private void sendRevocationAsync(
      final PeerNode source, final long uid, long length, final Runnable r) {
    Message msg =
        DMT.createUOMSendingRevocation(uid, length, updateManager.getRevocationURI().toString());
    try {
      source
          .transport()
          .sendAsync(
              msg,
              new AsyncMessageCallback() {

                @Override
                public void acknowledged() {
                  if (LOG.isDebugEnabled())
                    LOG.debug("UOM revocation send: starting data transfer");
                  updateManager
                      .getNode()
                      .network()
                      .executor()
                      .execute(
                          r,
                          "Revocation key send"
                              + FOR_LITERAL
                              + uid
                              + " to "
                              + source.userToString());
                }

                @Override
                public void disconnected() {
                  LOG.error(
                      "UOM revocation send aborted: peer {} disconnected before"
                          + " UOMSendingRevocation",
                      source);
                }

                @Override
                public void fatalError() {
                  LOG.error(
                      "UOM revocation send failed: fatal error before UOMSendingRevocation for peer"
                          + " {}",
                      source);
                }

                @Override
                public void sent() {
                  if (LOG.isDebugEnabled())
                    LOG.debug("UOM revocation send: message sent, data follows");
                }

                @Override
                public String toString() {
                  return super.toString() + "(" + uid + ":" + source.getPeer() + ")";
                }
              },
              updateManager.getByteCounter());
    } catch (NotConnectedException e) {
      LOG.error(
          "UOM revocation send failed: peer {} disconnected while sending UOMSendingRevocation: {}",
          source,
          e,
          e);
    }
  }

  /**
   * Handles a peer announcement that it is sending the revocation certificate to us.
   *
   * <p>Validates the advertised {@code URI} and length, checks acceptance rules and size limits,
   * and, if acceptable, schedules a bulk receiving to a temporary file followed by verification and
   * processing. If the offer is rejected or malformed, the transfer is canceled.
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
              updateManager.getNode().services().clientCore().getPersistentTempDir());
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
      LOG.error("UOM revocation fetch: downloaded blob missing for peer {}: {}", source, e, e);
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
          "UOM revocation fetch: disk I/O reading downloaded blob for peer {}: {}", source, e, e);
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
            updateManager.getNode().network().usm(), length, Node.PACKET_SIZE, raf, false);
    final BulkReceiver br = new BulkReceiver(prb, source, uid, updateManager.getByteCounter());
    updateManager
        .getNode()
        .network()
        .executor()
        .execute(
            () -> processRevocationReceive(br, temp, source),
            "Revocation key receive" + FOR_LITERAL + uid + FROM_LITERAL + source.userToString());
  }

  private void processRevocationReceive(BulkReceiver br, File temp, PeerNode source) {
    try {
      if (br.receive()) {
        processRevocationBlob(temp, source);
      } else {
        LOG.error("UOM revocation transfer failed from {}", source);
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
      LOG.error("UOM revocation transfer exception from {}", source, t);
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
            .services()
            .clientCore()
            .makeClient((short) 0, true, false)
            .getFetchContext();
    FetchContext tempContext =
        new FetchContext(seedContext, FetchContext.IDENTICAL_MASK, true, blocks);
    tempContext.setMaxOutputLength(NodeUpdateManager.MAX_REVOCATION_KEY_LENGTH);
    tempContext.setMaxTempLength(NodeUpdateManager.MAX_REVOCATION_KEY_TEMP_LENGTH);
    tempContext.setLocalRequestOnly(true);

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
      updateManager.getNode().services().clientCore().getClientContext().start(cg);
    } catch (FetchException e1) {
      LOG.error("Failed to decode UOM blob", e1);
      myCallback.onFailure(e1);
    } catch (PersistenceDisabledException _) {
      // Impossible
    }
  }

  private boolean readRevocationBlob(
      Bucket temp, String source, boolean fromDisk, SimpleBlockSet blocks) {
    try (DataInputStream dis = new DataInputStream(temp.getInputStream())) {
      BinaryBlob.readBinaryBlob(dis, blocks, true);
      return true;
    } catch (FileNotFoundException _) {
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
      public void onFailure(FetchException e) {
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
          updateManager.getRevocationChecker().onFailure(e, null, cleanedBlob);
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
            .services()
            .clientCore()
            .makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, false, false)
            .getInsertContext(true);
    ClientPutter putter =
        new ClientPutter(
            new ClientPutterRequest(
                new InsertRequestParams(callback, FreenetURI.EMPTY_CHK_URI, ctx, priority),
                bucket,
                null,
                false),
            new ClientPutterOptions(null, true, null, -1));
    try {
      updateManager.getNode().services().clientCore().getClientContext().start(putter);
    } catch (InsertException e1) {
      LOG.error("Failed to start insert of {} binary blob: {}", type, e1, e1);
    } catch (PersistenceDisabledException _) {
      // Impossible
    }
  }

  private void cancelSend(PeerNode source, long uid) {
    Message msg = DMT.createFNPBulkReceiveAborted(uid);
    try {
      source.transport().sendAsync(msg, null, updateManager.getByteCounter());
    } catch (NotConnectedException _) {
      // Ignore
    }
  }

  /**
   * Unregisters and clears the current “peers say key blown” alert, if any.
   *
   * <p>This is the best‑effort cleanup used when conditions rendering the alert obsolete are met.
   * It is safe to call even when no alert is registered.
   */
  public void killAlert() {
    synchronized (this) {
      if (alert == null) return;
      updateManager.getNode().services().clientCore().getAlerts().unregister(alert);
      alert = null;
    }
  }

  // Removed an unused method maybeInsertCorePackage: insertion is coordinated via updater flows.

  /**
   * Deletes obsolete persistent temporary files related to UoM transfers.
   *
   * <p>The method scans the persistent temp directory for known UoM patterns (revocation and
   * core-package blobs and their temporary variants). It removes files that are clearly safe to
   * delete, including old build‑number‑scoped files below the minimum acceptable build. Errors are
   * logged but otherwise ignored.
   */
  protected void removeOldTempFiles() {
    File oldTempFilesPeerDir =
        updateManager.getNode().services().clientCore().getPersistentTempDir();
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
      } catch (NoSuchFileException _) {
        LOG.info("Temporary persistent file does not exist when deleting: {}", fileToDeleteName);
      } catch (IOException _) {
        LOG.error(
            "Cannot delete temporary persistent file {} even though it exists: must be TOO"
                + " persistent :)",
            fileToDeleteName);
      }
    }

    // Caller doesn't use the result; nothing to return.
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
      } catch (NumberFormatException _) {
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
      allNodesOfferedCorePackage.remove(pn);
    }
    maybeNotRevoked();
  }

  /**
   * Reports whether at least two UoM transfers are in progress.
   *
   * <p>Main-jar UoM is disabled, so this always returns {@code false}.
   *
   * @return {@code false}
   */
  public boolean fetchingFromTwo() {
    return false;
  }

  /** {@inheritDoc} */
  @Override
  public boolean realTimeFlag() {
    return false;
  }

  /**
   * Indicates whether a legacy main-jar UoM transfer is active.
   *
   * <p>Main-jar UoM is disabled, so this always returns {@code false}.
   *
   * @return {@code false}
   */
  public boolean isFetchingMain() {
    return false;
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
    this.updateManager.getNode().network().executor().execute(f::start);
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
   * Completion is signaled through a callback.
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
            LOG.debug("UOM dependency fetch capacity reached (active peers {} )", peersFetching);
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
          uomPeers = new HashSet<>(allNodesOfferedCorePackage);
        }
        PeerNode chosen = chooseRandomPeer(uomPeers);
        if (chosen != null) return chosen;
        if (tryEverything) {
          LOG.debug("No eligible UOM peer found for dependency {}", saveTo);
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
            LOG.debug("No eligible UOM peer found for dependency {} (no offers)", saveTo);
            return null;
          }
        }
      }
    }

    private void scheduleFetch(final PeerNode fetchFrom) {
      updateManager
          .getNode()
          .network()
          .executor()
          .execute(() -> fetchDependencyFromPeer(fetchFrom));
    }

    private void fetchDependencyFromPeer(final PeerNode fetchFrom) {
      boolean failed = false;
      File tmp = null;
      try {
        LOG.info("Fetching {}{}{}", saveTo, FROM_LITERAL, fetchFrom);
        long uid = updateManager.getNode().bootstrap().fastWeakRandom().nextLong();
        fetchFrom
            .transport()
            .sendAsync(
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
      } catch (NotConnectedException _) {
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
                updateManager.getNode().network().usm(), size, Node.PACKET_SIZE, raf, false);
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
              .network()
              .ticker()
              .queueTimedJob(() -> peerMaybeFreeSlots(fetchFrom), TimeUnit.HOURS.toMillis(1));
        }
      }
    }

    private synchronized PeerNode chooseRandomPeer(Set<PeerNode> uomPeers) {
      if (completed) return null;
      if (peersFetching.size() >= MAX_NODES_SENDING_JAR) {
        LOG.debug(
            "UOM dependency peer selection blocked by capacity (active peers {} )", peersFetching);
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
          notTried.get(
              updateManager.getNode().bootstrap().fastWeakRandom().nextInt(notTried.size()));
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
      } catch (IOException _) {
        return false;
      }
    }
  }
}
