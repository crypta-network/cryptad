package network.crypta.node;

import network.crypta.crypt.HMAC;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageType;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.keys.Key;
import network.crypta.keys.NodeSSK;
import network.crypta.node.NodeStats.RejectReason;
import network.crypta.support.ShortBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Routes offered-key and noderef messages for a single {@link Node} instance.
 *
 * <p>This handler is a focused dispatch helper used by the node's messaging layer to interpret
 * inbound {@link Message} instances and trigger the corresponding routing or noderef actions. It is
 * created once per node, receives a {@link NodeStats} snapshot via {@link #start(NodeStats)}, and
 * then processes messages synchronously as they arrive. The handler never blocks on disk I/O, and
 * it delegates offer reply transfers to the {@link FailureTable} and request tracking to the {@link
 * RequestTracker}.
 *
 * <p>Thread-safety: the class stores mutable references to {@code NodeStats} and does not apply
 * internal synchronization, so callers should confine it to the node's message dispatch thread or
 * provide external synchronization. The handler is otherwise stateless; it trusts downstream
 * components to coordinate concurrency and lifecycle transitions.
 *
 * <ul>
 *   <li>Validates offer authenticators and rejects invalid requests promptly.
 *   <li>Guards against duplicate in-flight offer replies using {@link RequestTracker}.
 *   <li>Triggers noderef exchanges for darknet peers.
 * </ul>
 *
 * @see FailureTable
 * @see OfferReplyTag
 */
final class NodeOfferMessageHandler {

  /** Logger for offer-handling diagnostics; do not use it for business logic. */
  private static final Logger LOG = LoggerFactory.getLogger(NodeOfferMessageHandler.class);

  /** Debug log template used when an offer UID is already in-flight. */
  private static final String LOG_ALREADY_RUNNING =
      "Lock contention for id {}; reject (already running)";

  /** The owning node used to access routing, network, and statistics subsystems. */
  private final Node node;

  /** Request tracker used to deduplicate offer reply UIDs. */
  private final RequestTracker tracker;

  /** Statistics snapshot used for admission control decisions. */
  private NodeStats nodeStats;

  /**
   * Creates a new handler bound to the given node.
   *
   * <p>The constructor captures the routing tracker and the current network statistics reference.
   * It does not start background work or perform I/O; callers should invoke {@link
   * #start(NodeStats)} to refresh the stats reference once the node has finished bootstrapping.
   * Instances are lightweight and intended to be reused for the lifetime of the node.
   *
   * @param node owning node used to reach routing and network subsystems; must be non-null
   */
  NodeOfferMessageHandler(Node node) {
    this.node = node;
    this.tracker = node.routing().tracker();
    this.nodeStats = node.network().stats();
  }

  /**
   * Refreshes the statistics source used for admission control.
   *
   * <p>This method is typically invoked during node startup after {@link NodeStats} is fully
   * initialized. The handler does not retain historical stats; it simply swaps the reference used
   * by {@link #handle(Message, PeerNode)} when deciding whether to accept offered-key requests.
   * Calling this method is idempotent with respect to the same {@code stats} instance and has no
   * side effects beyond updating the reference.
   *
   * @param stats statistics source to use for future request rejection decisions; must be non-null
   */
  void start(NodeStats stats) {
    this.nodeStats = stats;
  }

  /**
   * Handles a single inbound message related to offered keys or noderef exchange.
   *
   * <p>The method inspects the {@link MessageType} and dispatches to the appropriate handler. It
   * validates offer authenticators, enforces duplicate UID suppression, and forwards noderef
   * requests for darknet peers. Messages that are not recognized by this handler are ignored and
   * reported via the returned {@code false} value. The handler itself does not throw checked
   * exceptions; network send failures are logged or ignored as appropriate.
   *
   * @param m inbound message to process; must be non-null and already decoded
   * @param source peer that supplied the message; must be non-null and connected
   * @return {@code true} if the message was recognized and handled, {@code false} otherwise
   */
  boolean handle(Message m, PeerNode source) {
    MessageType spec = m.getSpec();
    if (DMT.FNPOfferKey.equals(spec)) {
      return handleOfferKey(m, source);
    } else if (DMT.FNPGetOfferedKey.equals(spec)) {
      handleGetOfferedKey(m, source);
      return true;
    } else if (DMT.FNPGetYourFullNoderef.equals(spec)
        && source instanceof DarknetPeerNode peerNode) {
      peerNode.sendFullNoderef();
      return true;
    } else if (DMT.FNPMyFullNoderef.equals(spec) && source instanceof DarknetPeerNode peerNode) {
      peerNode.handleFullNoderef(m);
      return true;
    }
    return false;
  }

  /**
   * Records a received offer-key announcement with the failure table.
   *
   * <p>This method extracts the key and authenticator from the message and notifies the failure
   * table so it can track which peer offered the key. It does not perform validation because
   * offer-key announcements are passive hints rather than requests.
   *
   * @param m message carrying the offered key and authenticator; must be non-null
   * @param source peer that announced the offer; must be non-null
   * @return {@code true} always, to indicate the message was handled
   */
  private boolean handleOfferKey(Message m, PeerNode source) {
    Key key = (Key) m.getObject(DMT.KEY);
    byte[] authenticator = ((ShortBuffer) m.getObject(DMT.OFFER_AUTHENTICATOR)).getData();
    node.routing().failureTable().onOffer(key, source, authenticator);
    return true;
  }

  /**
   * Handles a request to retrieve a previously offered key.
   *
   * <p>The method validates the offer authenticator, acquires a request UID lock to prevent
   * duplicate processing, and then delegates the actual transfer to the failure table. It may
   * reject the request due to invalid authentication, duplicate in-flight processing, or local load
   * shedding as indicated by {@link NodeStats}. All rejection paths respond asynchronously and then
   * return without further work.
   *
   * @param m inbound request message containing key, UID, and flags; must be non-null
   * @param source requesting peer; must be non-null and connected
   */
  private void handleGetOfferedKey(Message m, PeerNode source) {
    Key key = (Key) m.getObject(DMT.KEY);
    byte[] authenticator = ((ShortBuffer) m.getObject(DMT.OFFER_AUTHENTICATOR)).getData();
    long uid = m.getLong(DMT.UID);
    if (invalidOfferAuthenticator(source, key, authenticator, uid)) return;
    if (LOG.isDebugEnabled()) LOG.debug("Valid GetOfferedKey (key={}, source={})", key, source);

    boolean isSSK = key instanceof NodeSSK;
    boolean realTimeFlag = DMT.getRealTimeFlag(m);
    OfferReplyTag tag = new OfferReplyTag(isSSK, source, realTimeFlag, uid, node);
    if (rejectAlreadyRunning(uid, isSSK, source, tag)) return;

    processOfferWithLock(m, source, key, isSSK, uid, tag, realTimeFlag);
  }

  /**
   * Validates the offer authenticator and emits a rejection message on failure.
   *
   * <p>Authenticators are verified using the shared HMAC key from the failure table. When the
   * verification fails, this method logs the event and sends an {@code FNPGetOfferedKeyInvalid}
   * response to the peer, unless the peer disconnects before the sending can be queued.
   *
   * @param source peer that issued the request; must be non-null
   * @param key key referenced by the request; must be non-null
   * @param authenticator raw authenticator bytes from the request; must be non-null
   * @param uid request identifier used for rejection responses
   * @return {@code true} if the authenticator is invalid and a rejection was attempted
   */
  private boolean invalidOfferAuthenticator(
      PeerNode source, Key key, byte[] authenticator, long uid) {
    if (HMAC.verifyWithSHA256(
        node.routing().failureTable().offerAuthenticatorKey, key.getFullKey(), authenticator)) {
      return false;
    }
    LOG.error("Invalid GetOfferedKey; authenticator does not verify (source={})", source);
    try {
      source
          .transport()
          .sendAsync(
              DMT.createFNPGetOfferedKeyInvalid(
                  uid, DMT.GET_OFFERED_KEY_REJECTED_BAD_AUTHENTICATOR),
              null,
              node.routing().failureTable().senderCounter);
    } catch (NotConnectedException _) {
      // Too bad.
    }
    return true;
  }

  /**
   * Rejects the request if an identical offer reply UID is already in flight.
   *
   * <p>This method uses {@link RequestTracker} to acquire a UID lock in the offer-reply namespace.
   * If the lock cannot be acquired, it sends an {@code FNPRejectedLoop} message to the peer. A
   * failure to send due to disconnect is logged and then ignored.
   *
   * @param uid request identifier to lock or reject
   * @param isSSK whether the key is an SSK; affects tracker namespace
   * @param source requesting peer; must be non-null
   * @param tag offer-reply tag associated with this request; must be non-null
   * @return {@code true} if the request was rejected due to a preexisting UID lock
   */
  private boolean rejectAlreadyRunning(
      long uid, boolean isSSK, PeerNode source, OfferReplyTag tag) {
    if (tracker.lockUID(
        uid, RequestAdmissionMode.of(false, isSSK, false, true, tag.realTimeFlag), tag)) {
      if (LOG.isDebugEnabled()) LOG.debug("Lock acquired for id {}", uid);
      return false;
    }
    if (LOG.isDebugEnabled()) LOG.debug(LOG_ALREADY_RUNNING, uid);
    Message rejected = DMT.createFNPRejectedLoop(uid);
    try {
      source.transport().sendAsync(rejected, null, node.routing().failureTable().senderCounter);
    } catch (NotConnectedException e) {
      LOG.info(
          "Reject request; sendAsync failed (peer={}, error={})", source.getPeer(), e.toString());
    }
    return true;
  }

  /**
   * Processes the offered-key request after a UID lock has been acquired.
   *
   * <p>This method performs admission control using {@link NodeStats}. A rejection results in an
   * overload response (optionally marked soft) and immediate tag unlock. If the request is
   * accepted, it delegates to {@link FailureTable#sendOfferedKey(Key, boolean, boolean, long,
   * PeerNode, OfferReplyTag, boolean)}. Any runtime errors trigger a tag unlocked before the
   * exception is rethrown.
   *
   * @param m request message containing flags and parameters; must be non-null
   * @param source requesting peer; must be non-null and connected
   * @param key requested key; must be non-null
   * @param isSSK whether the key is an SSK; influences response behavior
   * @param uid request identifier used for outgoing responses
   * @param tag offer-reply tag to unlock on completion or failure; must be non-null
   * @param realTimeFlag whether the request uses the realtime scheduling budget
   */
  @SuppressWarnings("java:S1181")
  private void processOfferWithLock(
      Message m,
      PeerNode source,
      Key key,
      boolean isSSK,
      long uid,
      OfferReplyTag tag,
      boolean realTimeFlag) {
    boolean needPubKey;
    try {
      needPubKey = m.getBoolean(DMT.NEED_PUB_KEY);
      RejectReason reject =
          nodeStats.shouldRejectRequest(
              RequestAdmissionContext.of(
                  true, false, isSSK, false, true, source, false, false, realTimeFlag, tag));
      if (reject != null) {
        LOG.info("Reject FNPGetOfferedKey (source={}, key={}, reason={})", source, key, reject);
        Message rejected = DMT.createFNPRejectedOverload(uid, true);
        if (reject.soft()) rejected.addSubMessage(DMT.createFNPRejectIsSoft());
        sendAsyncIgnoreNotConnected(source, rejected, node.routing().failureTable().senderCounter);
        tag.unlockHandler(reject.soft());
        return;
      }
    } catch (Error | RuntimeException e) {
      tag.unlockHandler();
      throw e;
    }

    try {
      node.routing()
          .failureTable()
          .sendOfferedKey(key, isSSK, needPubKey, uid, source, tag, realTimeFlag);
    } catch (NotConnectedException _) {
      // Too bad.
    }
  }

  /**
   * Sends a message asynchronously and ignores disconnect failures.
   *
   * <p>This helper centralizes the common pattern of attempting an async sending while treating
   * {@link NotConnectedException} as a non-fatal condition. It logs a concise message at INFO when
   * the sending fails. Callers should not rely on the sending to have succeeded.
   *
   * @param peer destination peer; must be non-null
   * @param msg message to send; must be non-null and fully populated
   * @param ctr byte counter for accounting; may be null if no accounting is required
   */
  private void sendAsyncIgnoreNotConnected(PeerNode peer, Message msg, ByteCounter ctr) {
    try {
      peer.transport().sendAsync(msg, null, ctr);
    } catch (NotConnectedException e) {
      if (LOG.isInfoEnabled())
        LOG.info(
            "Reject (overload) request; sendAsync failed (peer={}, error={})",
            peer.getPeer(),
            e.toString());
    }
  }
}
