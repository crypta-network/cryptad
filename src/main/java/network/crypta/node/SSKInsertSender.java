package network.crypta.node;

import static java.util.concurrent.TimeUnit.SECONDS;

import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.SHA256;
import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.PeerContext;
import network.crypta.io.comm.SlowAsyncMessageFilterCallback;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.SSKBlock;
import network.crypta.keys.SSKVerifyException;
import network.crypta.node.subsystem.NodeRoutingSubsystem.SskInsertOptions;
import network.crypta.support.ShortBuffer;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Sends an SSK insert through the network.
 *
 * <p>SSK (Signed Subspace Key) inserts differ from regular requests in a few important ways:
 *
 * <ul>
 *   <li>SSKs can collide: a different payload may already exist at the same key, requiring
 *       collision handling and potential block replacement.
 *   <li>The payload is small (approximately 1 KiB), so headers and data are sent eagerly, and the
 *       final reply does not require a long transfer window.
 *   <li>Verification depends on the publisher’s public key; the peer may request the public key and
 *       confirm it separately from the payload.
 * </ul>
 *
 * <p>This sender manages the routing, Accepted/Rejected handshake, optional public‑key transfer,
 * collision handling, and bookkeeping (bytes and status). Instances are executed by the node’s
 * executor and are not reused. Methods that expose mutable state or status are synchronized.
 */
public class SSKInsertSender extends BaseSender
    implements PrioRunnable, AnyInsertSender, ByteCounter {

  private static final Logger LOG = LoggerFactory.getLogger(SSKInsertSender.class);

  // Constants
  static final long ACCEPTED_TIMEOUT = SECONDS.toMillis(10);

  // Basics
  final NodeSSK myKey;
  final long origUID;
  final InsertTag origTag;

  /** Publisher's public key used to verify SSK blocks. */
  final DSAPublicKey pubKey;

  /** SHA‑256 of {@link #pubKey} bytes computed at construction. */
  final byte[] pubKeyHash;

  /**
   * Raw payload bytes. Initially, the local payload; may be replaced if a collision is discovered
   * and the remote block is accepted instead.
   */
  byte[] data;

  /**
   * Raw header bytes. Initially the local headers; may be replaced by remote headers on collision.
   */
  byte[] headers;

  final boolean fromStore;
  // startTime is inherited from BaseSender.
  private boolean hasCollided;
  private boolean hasRecentlyCollided;
  private SSKBlock block;

  // Class initialization currently requires no static setup.

  private final boolean forkOnCacheable;
  private final boolean preferInsert;
  private final boolean ignoreLowBackoff;
  // realTimeFlag is inherited from BaseSender.
  private InsertTag forkedRequestTag;

  private int status = -1;

  /** Status: insert is still running. */
  static final int NOT_FINISHED = -1;

  /** Status: insert completed successfully. */
  static final int SUCCESS = 0;

  /** Status: no route found (after forwarding at least once). */
  static final int ROUTE_NOT_FOUND = 1;

  /** Status: an internal error occurred. */
  static final int INTERNAL_ERROR = 3;

  /** Status: timed out while waiting for a peer response. */
  static final int TIMED_OUT = 4;

  /** Status: locally generated a {@code RejectedOverload}. */
  static final int GENERATED_REJECTED_OVERLOAD = 5;

  /**
   * Status: could not forward the request to any peer. This is promoted from {@link
   * #ROUTE_NOT_FOUND} when the insert never forwards.
   */
  static final int ROUTE_REALLY_NOT_FOUND = 6;

  public SSKInsertSender(
      SSKBlock block,
      long uid,
      InsertTag tag,
      short htl,
      PeerNode source,
      Node node,
      SskInsertOptions opts) {
    super(block.getKey(), opts.realTimeFlag, source, node, htl, uid);
    this.fromStore = opts.fromStore;
    this.origUID = uid;
    this.origTag = tag;
    myKey = block.getKey();
    data = block.getRawData();
    headers = block.getRawHeaders();
    pubKey = myKey.getPubKey();
    if (pubKey == null) throw new IllegalArgumentException("Must have pubkey to insert data!!");
    // Note: pubKey.fingerprint() is not currently equal to hash(pubKey.asBytes()).
    byte[] pubKeyAsBytes = pubKey.asBytes();
    pubKeyHash = SHA256.digest(pubKeyAsBytes);
    this.block = block;
    this.forkOnCacheable = opts.forkOnCacheable;
    this.preferInsert = opts.preferInsert;
    this.ignoreLowBackoff = opts.ignoreLowBackoff;
  }

  /**
   * Schedules this sender on the node executor.
   *
   * <p>Non‑blocking. Execution begins asynchronously on a worker thread.
   */
  public void start() {
    node.network()
        .executor()
        .execute(
            this,
            "SSKInsertSender for UID "
                + uid
                + " on "
                + node.network().darknetPortNumber()
                + " at "
                + System.currentTimeMillis());
  }

  /**
   * Runs the insert state machine on a worker thread.
   *
   * <p>Coordinates routing and termination, ensures {@code finish(...)} is called on all exit
   * paths, and updates the associated {@link InsertTag} bookkeeping.
   */
  @Override
  public void run() {
    origTag.startedSender();
    try {
      routeRequests();
    } catch (Exception t) {
      LOG.error("Caught {}", t, t);
      if (getStatus() == NOT_FINISHED) finish(INTERNAL_ERROR, null);
    } finally {
      if (LOG.isDebugEnabled()) LOG.debug("Finishing {}", this);
      if (getStatus() == NOT_FINISHED) finish(INTERNAL_ERROR, null);
      origTag.finishedSender();
      if (forkedRequestTag != null) forkedRequestTag.finishedSender();
    }
  }

  // Routing entry point. Chooses the next peer and handles optional forking when the local node
  // is allowed to cache inserts at the current HTL.

  /** Performs one routing step: adjust HTL, optionally fork, pick a peer, and continue. */
  @Override
  protected void routeRequests() {
    final boolean couldWriteStoreBefore = node.routing().canWriteDatastoreInsert(htl);

    if (adjustHtlOrFinish()) return;

    if (origTag.shouldStop()) {
      finish(SUCCESS, null);
      return;
    }

    maybeForkOnCacheable(couldWriteStoreBefore);

    PeerNode next = findNextPeer();
    if (next == null) {
      handleNoNextPeer();
      return;
    }

    InsertTag thisTag = (forkedRequestTag == null) ? origTag : forkedRequestTag;
    innerRouteRequests(next, thisTag);
  }

  private boolean adjustHtlOrFinish() {
    if (dontDecrementHTLThisTime) {
      dontDecrementHTLThisTime = false;
    } else {
      htl = node.routing().decrementHTL(hasForwarded ? lastNode.get() : source, htl);
      if (LOG.isDebugEnabled()) LOG.debug("Decremented HTL to {}", htl);
    }
    if (htl <= 0) {
      if (!hasForwarded) origTag.setNotRoutedOnwards();
      finish(SUCCESS, null);
      return true;
    }
    return false;
  }

  // Fork a local insert when we cross a store‑writable HTL boundary and forking is enabled.
  private void maybeForkOnCacheable(boolean couldWriteStoreBefore) {
    if (node.routing().canWriteDatastoreInsert(htl)
        && !couldWriteStoreBefore
        && forkOnCacheable
        && forkedRequestTag == null) {
      uid = node.services().clientCore().makeUID();
      forkedRequestTag =
          new InsertTag(true, InsertTag.START.REMOTE, source, realTimeFlag, uid, node);
      forkedRequestTag.reassignToSelf();
      forkedRequestTag.startedSender();
      forkedRequestTag.unlockHandler();
      forkedRequestTag.setAccepted();
      LOG.info("FORKING SSK INSERT {} to {}", origUID, uid);
      nodesRoutedTo.clear();
      node.routing().tracker().lockUID(forkedRequestTag);
    }
  }

  private PeerNode findNextPeer() {
    PeerRoutingSelectionParams params =
        new PeerRoutingSelectionParams(
            forkedRequestTag == null ? source : null,
            nodesRoutedTo,
            target,
            true,
            node.isAdvancedModeEnabled(),
            -1,
            null,
            2.0,
            null,
            htl,
            ignoreLowBackoff ? Node.LOW_BACKOFF : 0L,
            source == null,
            realTimeFlag,
            null,
            false,
            System.currentTimeMillis(),
            newLoadManagement);
    return node.network().peers().routingSelector().closerPeer(params);
  }

  private void handleNoNextPeer() {
    if (!hasForwarded) origTag.setNotRoutedOnwards();
    finish(ROUTE_NOT_FOUND, null);
  }

  private void handleNoPubkeyAccepted(PeerNode next, InsertTag thisTag) {
    // Peer did not acknowledge the public key within the extended window. At this point the peer
    // already has headers and data, so we propagate a local RejectedOverload and mark a fatal
    // timeout for the peer to avoid indefinite waiting.

    // Try to propagate back to source
    LOG.error("Timeout waiting for FNPSSKPubKeyAccepted on {}", next);
    next.localRejectedOverload("Timeout2", realTimeFlag);
    // This is a local timeout, they should send it immediately.
    forwardRejectedOverload();
    next.fatalTimeout(thisTag, false);
  }

  private MessageFilter makeSearchFilter(PeerNode next, int searchTimeout) {
    /* We wait for one of the terminal or progress signals from the next hop:
     * - FNPRouteNotFound: backtrack with reduced HTL
     * - FNPInsertReply: insert completed after exhausting HTL
     * - FNPRejectedOverload: propagated overload; may still succeed later
     * - FNPSSKDataFoundHeaders: collision; headers precede data
     * - FNPDataInsertRejected: validation or policy rejection
     */
    MessageFilter mfInsertReply =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(searchTimeout)
            .setType(DMT.FNPInsertReply);
    MessageFilter mfRejectedOverload =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(searchTimeout)
            .setType(DMT.FNPRejectedOverload);
    MessageFilter mfRouteNotFound =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(searchTimeout)
            .setType(DMT.FNPRouteNotFound);
    MessageFilter mfDataInsertRejected =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(searchTimeout)
            .setType(DMT.FNPDataInsertRejected);
    MessageFilter mfSSKDataFoundHeaders =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(searchTimeout)
            .setType(DMT.FNPSSKDataFoundHeaders);

    return mfRouteNotFound.or(
        mfInsertReply.or(mfRejectedOverload.or(mfDataInsertRejected.or(mfSSKDataFoundHeaders))));
  }

  private DO handleMessage(Message msg, PeerNode next, InsertTag thisTag) {
    if (DMT.FNPRejectedOverload.equals(msg.getSpec())) {
      if (handleRejectedOverload(msg, next, thisTag)) return DO.NEXT_PEER;
      else return DO.WAIT;
    }

    if (DMT.FNPRouteNotFound.equals(msg.getSpec())) {
      handleRouteNotFound(msg, next, thisTag);
      // Finished as far as this node is concerned
      return DO.NEXT_PEER;
    }

    if (DMT.FNPDataInsertRejected.equals(msg.getSpec())) {
      handleDataInsertRejected(msg, next, thisTag);
      return DO.NEXT_PEER; // What else can we do?
    }

    if (DMT.FNPSSKDataFoundHeaders.equals(msg.getSpec())) {
      return handleSSKDataFoundHeaders(msg, next, thisTag);
    }

    if (!DMT.FNPInsertReply.equals(msg.getSpec())) {
      LOG.error("Unknown reply: {}", msg);
      finish(INTERNAL_ERROR, next);
      return DO.FINISHED;
    }

    // Our task is complete
    next.successNotOverload(realTimeFlag);
    finish(SUCCESS, next);
    return DO.FINISHED;
  }

  /** Action to take after handling a received message. */
  private enum DO {
    FINISHED,
    WAIT,
    NEXT_PEER
  }

  private static final long TIMEOUT_AFTER_ACCEPTEDREJECTED_TIMEOUT = SECONDS.toMillis(60);

  /**
   * Handles a timeout waiting for Accepted/Rejected after sending the request.
   *
   * <p>We add a secondary, shorter filter window to catch a late reply and mark a fatal timeout on
   * the peer if nothing arrives. This avoids waiting indefinitely when the peer did not accept the
   * request.
   */
  @Override
  protected void handleAcceptedRejectedTimeout(final PeerNode next, final UIDTag tag) {
    // Log as WARN rather than ERROR because the sending may still be queued (async path).
    LOG.warn("Timeout awaiting Accepted/Rejected {} to {}", this, next);
    // Use the right UID here, in case we fork.
    final long uid = tag.uid;
    tag.handlingTimeout(next);
    // The node didn't accept the request. So we don't need to send them the data.
    // However, we do need to wait a bit longer to try to postpone the fatalTimeout().
    MessageFilter mf =
        makeAcceptedRejectedFilter(next, TIMEOUT_AFTER_ACCEPTEDREJECTED_TIMEOUT, tag);
    try {
      node.network()
          .usm()
          .addAsyncFilter(mf, new AcceptedRejectedTimeoutCallback(this, next, tag, uid), this);
    } catch (DisconnectedException _) {
      next.noLongerRoutingTo(tag, false);
    }
  }

  /** Callback used to handle late replies after an Accepted/Rejected timeout. */
  @SuppressWarnings("ClassCanBeRecord")
  private static final class AcceptedRejectedTimeoutCallback
      implements SlowAsyncMessageFilterCallback {
    private final SSKInsertSender sender;
    private final PeerNode next;
    private final UIDTag tag;
    private final long uid;

    AcceptedRejectedTimeoutCallback(SSKInsertSender sender, PeerNode next, UIDTag tag, long uid) {
      this.sender = sender;
      this.next = next;
      this.tag = tag;
      this.uid = uid;
    }

    /**
     * Processes a late message matching the secondary filter.
     *
     * <p>On loop/overload we simply stop routing to the peer. On Accepted we may send a {@code
     * DataInsertRejected} explaining the timeout if the request was not forked, then mark the peer
     * as no longer routing.
     */
    @Override
    public void onMatched(Message m) {
      if (DMT.FNPRejectedLoop.equals(m.getSpec()) || DMT.FNPRejectedOverload.equals(m.getSpec())) {
        next.noLongerRoutingTo(tag, false);
        return;
      }
      if (!DMT.FNPSSKAccepted.equals(m.getSpec())) {
        if (LOG.isDebugEnabled()) LOG.debug("Unexpected message in timeout handler: {}", m);
        next.noLongerRoutingTo(tag, false);
        return;
      }
      handleAcceptedAfterTimeout();
    }

    private void handleAcceptedAfterTimeout() {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Accepted after timeout on {} - will not send DataInsert, waiting for RejectedTimeout",
            sender);
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Forked timed out insert but not going to send DataInsert on {} to {}", sender, next);
      try {
        next.transport()
            .sendAsync(
                DMT.createFNPDataInsertRejected(
                    uid, DMT.DATA_INSERT_REJECTED_TIMEOUT_WAITING_FOR_ACCEPTED),
                new AsyncMessageCallback() {
                  @Override
                  public void sent() {
                    if (LOG.isDebugEnabled())
                      LOG.debug("DataInsertRejected sent after accepted timeout on {}", sender);
                  }

                  @Override
                  public void acknowledged() {
                    if (LOG.isDebugEnabled())
                      LOG.debug(
                          "DataInsertRejected acknowledged after accepted timeout on {}", sender);
                    next.noLongerRoutingTo(tag, false);
                  }

                  @Override
                  public void disconnected() {
                    if (LOG.isDebugEnabled())
                      LOG.debug(
                          "DataInsertRejected peer disconnected after accepted timeout on {}",
                          sender);
                    next.noLongerRoutingTo(tag, false);
                  }

                  @Override
                  public void fatalError() {
                    if (LOG.isDebugEnabled())
                      LOG.debug(
                          "DataInsertRejected fatal error after accepted timeout on {}", sender);
                    next.noLongerRoutingTo(tag, false);
                  }
                },
                sender);
      } catch (NotConnectedException _) {
        next.noLongerRoutingTo(tag, false);
      }
    }

    @Override
    public boolean shouldTimeout() {
      return false;
    }

    @Override
    public void onTimeout() {
      LOG.error("Fatal: No Accepted/Rejected for {}", sender);
      next.fatalTimeout(tag, false);
    }

    @Override
    public void onDisconnect(PeerContext ctx) {
      next.noLongerRoutingTo(tag, false);
    }

    @Override
    public void onRestarted(PeerContext ctx) {
      next.noLongerRoutingTo(tag, false);
    }

    @Override
    public int getPriority() {
      return NativeThread.PriorityLevel.NORM_PRIORITY.value;
    }
  }

  /**
   * Handles a {@code RejectedOverload} reply.
   *
   * @return {@code true} if we should try another peer now (local rejection), otherwise {@code
   *     false} to keep waiting for a non-local outcome.
   */
  private boolean handleRejectedOverload(Message msg, PeerNode next, InsertTag thisTag) {
    // Probably non-fatal, if so, we have time left, can try the next one
    if (msg.getBoolean(DMT.IS_LOCAL)) {
      next.localRejectedOverload("ForwardRejectedOverload4", realTimeFlag);
      if (LOG.isDebugEnabled()) LOG.debug("Local RejectedOverload, moving on to next peer");
      // Give up on this one, try another
      next.noLongerRoutingTo(thisTag, false);
      return true;
    } else {
      forwardRejectedOverload();
    }
    return false; // Wait for any further response
  }

  private void handleRouteNotFound(Message msg, PeerNode next, InsertTag thisTag) {
    if (LOG.isDebugEnabled()) LOG.debug("Rejected: RNF");
    short newHtl = msg.getShort(DMT.HTL);
    if (newHtl < 0) newHtl = 0;
    if (htl > newHtl) htl = newHtl;
    next.successNotOverload(realTimeFlag);
    next.noLongerRoutingTo(thisTag, false);
  }

  private void handleDataInsertRejected(Message msg, PeerNode next, InsertTag thisTag) {
    next.successNotOverload(realTimeFlag);
    short reason = msg.getShort(DMT.DATA_INSERT_REJECTED_REASON);
    if (LOG.isDebugEnabled()) LOG.debug("DataInsertRejected: {}", reason);
    if (reason == DMT.DATA_INSERT_REJECTED_VERIFY_FAILED && fromStore) {
      // That's odd...
      LOG.error(
          "Verify failed on next node {} for DataInsert but we were sending from the store!", next);
    }
    LOG.atError()
        .addArgument(() -> DMT.getDataInsertRejectedReason(reason))
        .log("SSK insert rejected! Reason={}");
    next.noLongerRoutingTo(thisTag, false);
  }

  /**
   * Handles an SSK collision signaled by {@code FNPSSKDataFoundHeaders}.
   *
   * @return {@link DO#WAIT} when remote headers and data were accepted, and we are waiting for the
   *     outcome; {@link DO#NEXT_PEER} if the peer disconnected or timed out; otherwise {@link
   *     DO#FINISHED} on unrecoverable error.
   */
  private DO handleSSKDataFoundHeaders(Message msg, PeerNode next, InsertTag thisTag) {

    /* The peer already stores a different block for this key: collision.
     * For SSKs we prefer the preexisting data and treat the remote as authoritative here, replacing
     * our headers/data with what the peer returns.
     */
    LOG.atInfo()
        .addArgument(myKey)
        .addArgument(uid)
        .addArgument(next::getPeer)
        .log("Got collision on {} ({}) sending to {}");

    headers = ((ShortBuffer) msg.getObject(DMT.BLOCK_HEADERS)).getData();
    // Wait for the data
    MessageFilter mfData =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(SSKInsertHandler.DATA_INSERT_TIMEOUT)
            .setType(DMT.FNPSSKDataFoundData);
    Message dataMessage;
    try {
      dataMessage = node.network().usm().waitFor(mfData, this);
    } catch (DisconnectedException _) {
      if (LOG.isDebugEnabled()) LOG.debug("Disconnected: {} getting datareply for {}", next, this);
      next.noLongerRoutingTo(thisTag, false);
      return DO.NEXT_PEER;
    }
    if (dataMessage == null) {
      LOG.error("Got headers but not data for datareply for insert from {}", this);
      next.noLongerRoutingTo(thisTag, false);
      return DO.NEXT_PEER;
    }
    // collided, overwrite data with remote data
    try {
      data = ((ShortBuffer) dataMessage.getObject(DMT.DATA)).getData();
      block = new SSKBlock(data, headers, block.getKey(), false);

      synchronized (this) {
        hasRecentlyCollided = true;
        hasCollided = true;
        notifyAll();
      }

      // The node will now propagate the new data. There is no need to move to the next node yet.
      return DO.WAIT;
    } catch (SSKVerifyException _) {
      LOG.error("Invalid SSK from remote on collusion: {}:{}", this, block);
      finish(INTERNAL_ERROR, next);
      return DO.FINISHED;
    }
  }

  /**
   * Builds the filter used to await {@code Accepted}/{@code Rejected} after the initial request.
   */
  @Override
  protected MessageFilter makeAcceptedRejectedFilter(
      PeerNode next, long acceptedTimeout, UIDTag tag) {
    // Use the right UID here, in case we fork.
    final long uid = tag.uid;
    /*
     * Because messages may be re-ordered, it is
     * entirely possible that we get a non-local RejectedOverload,
     * followed by an Accepted. So we must loop here.
     */

    MessageFilter mfAccepted =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(acceptedTimeout)
            .setType(DMT.FNPSSKAccepted);
    MessageFilter mfRejectedLoop =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(acceptedTimeout)
            .setType(DMT.FNPRejectedLoop);
    MessageFilter mfRejectedOverload =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(acceptedTimeout)
            .setType(DMT.FNPRejectedOverload);
    return mfAccepted.or(mfRejectedLoop.or(mfRejectedOverload));
  }

  private boolean hasForwardedRejectedOverload;

  synchronized boolean receivedRejectedOverload() {
    return hasForwardedRejectedOverload;
  }

  /** Forwards {@code RejectedOverload} to the originator (non‑local rejections only). */
  @Override
  protected synchronized void forwardRejectedOverload() {
    if (hasForwardedRejectedOverload) return;
    hasForwardedRejectedOverload = true;
    notifyAll();
  }

  private void finish(int code, PeerNode next) {
    LOG.atDebug()
        .addArgument(getStatusString(code))
        .addArgument(this)
        .addArgument(() -> next == null ? "(null)" : next.shortToString())
        .log("Finished: {} on {} from {}");

    notifyNoLongerRoutingTo(next);

    synchronized (this) {
      if (status != NOT_FINISHED && status != TIMED_OUT)
        throw new IllegalStateException(
            "finish() called with " + code + " when was already " + status);

      code = promoteIfRouteNotFoundAndNotForwarded(code, hasForwarded);

      if (status != TIMED_OUT) {
        status = code;
        notifyAll();
      }
    }

    if (code == SUCCESS && next != null) next.onSuccess(true, true);

    if (LOG.isDebugEnabled()) LOG.debug("Set status code: {}", getStatusString());
    // Nothing to wait for, no downstream transfers, just exit.
  }

  private void notifyNoLongerRoutingTo(PeerNode next) {
    if (next == null) return;
    if (origTag != null) next.noLongerRoutingTo(origTag, false);
    if (forkedRequestTag != null) next.noLongerRoutingTo(forkedRequestTag, false);
  }

  private static int promoteIfRouteNotFoundAndNotForwarded(int code, boolean hasForwarded) {
    return (code == ROUTE_NOT_FOUND && !hasForwarded) ? ROUTE_REALLY_NOT_FOUND : code;
  }

  // Logging templates are inlined where used to avoid unnecessary string ops.

  /** Returns the current status code. Thread‑safe. */
  @Override
  public synchronized int getStatus() {
    return status;
  }

  /** Returns the current HTL (Hop‑To‑Live). Thread‑safe. */
  @Override
  public synchronized short getHTL() {
    return htl;
  }

  /** Returns a human‑readable string for the current status. Thread‑safe. */
  @Override
  public synchronized String getStatusString() {
    return getStatusString(status);
  }

  /** Returns a human‑readable string for the given status code. */
  public static String getStatusString(int status) {
    if (status == SUCCESS) return "SUCCESS";
    if (status == ROUTE_NOT_FOUND) return "ROUTE NOT FOUND";
    if (status == NOT_FINISHED) return "NOT FINISHED";
    if (status == INTERNAL_ERROR) return "INTERNAL ERROR";
    if (status == TIMED_OUT) return "TIMED OUT";
    if (status == GENERATED_REJECTED_OVERLOAD) return "GENERATED REJECTED OVERLOAD";
    if (status == ROUTE_REALLY_NOT_FOUND) return "ROUTE REALLY NOT FOUND";
    return "UNKNOWN STATUS CODE: " + status;
  }

  /**
   * Waits up to {@code millis} for the sender to transition out of {@link #NOT_FINISHED}.
   *
   * <p>Uses the sender's intrinsic monitor and mirrors the notification pattern within this class
   * to avoid external synchronization on the parameter object.
   */
  @SuppressWarnings(
      "java:S2142") // Intentionally ignore interrupts to avoid busy-spin of polling loops
  void waitIfNotFinished(long millis) {
    if (millis < 0) throw new IllegalArgumentException("timeout value is negative");
    synchronized (this) {
      if (millis == 0) {
        while (status == NOT_FINISHED) {
          try {
            this.wait(0); // indefinite wait
          } catch (InterruptedException _) {
            // Intentionally swallow interrupts to avoid tight-loop spinning when callers
            // repeatedly wait on this monitor during shutdown/cancellation.
          }
        }
        return;
      }
      long deadlineNanos =
          System.nanoTime() + java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(millis);
      long remainingNanos = deadlineNanos - System.nanoTime();
      while (status == NOT_FINISHED && remainingNanos > 0) {
        try {
          long waitMillis = java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(remainingNanos);
          int waitNanos =
              (int)
                  (remainingNanos - java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(waitMillis));
          if (waitMillis == 0L && waitNanos > 0) {
            this.wait(0L, waitNanos);
          } else {
            this.wait(waitMillis, waitNanos);
          }
        } catch (InterruptedException _) {
          // Intentionally swallow interrupts to avoid tight-loop spinning when callers
          // repeatedly wait on this monitor during shutdown/cancellation.
        }
        remainingNanos = deadlineNanos - System.nanoTime();
      }
    }
  }

  /**
   * Returns whether this sender hasn't forwarded the request to any peer yet.
   *
   * <p>Useful to distinguish {@link #ROUTE_NOT_FOUND} from {@link #ROUTE_REALLY_NOT_FOUND}.
   */
  @Override
  public boolean sentRequest() {
    return hasForwarded;
  }

  /**
   * Returns and clears a sticky flag indicating that a collision has occurred since the last call.
   * Thread‑safe.
   */
  public synchronized boolean hasRecentlyCollided() {
    boolean recent = hasRecentlyCollided;
    hasRecentlyCollided = false;
    return recent;
  }

  /** Returns whether any collision has been observed during this insert. */
  public boolean hasCollided() {
    return hasCollided;
  }

  /**
   * Returns the byte array currently assigned to headers.
   *
   * <p>Despite the method name, this does not return the computed public‑key hash used for
   * verification. The SHA‑256 of the public key is stored in {@link #pubKeyHash}.
   */
  public byte[] getPubkeyHash() {
    return headers;
  }

  /** Returns the headers that will be (or were) sent for this insert. */
  public byte[] getHeaders() {
    return headers;
  }

  /** Returns the payload bytes for this insert. */
  public byte[] getData() {
    return data;
  }

  /** Returns the current {@link SSKBlock} (may reflect a collision replacement). */
  public SSKBlock getBlock() {
    return block;
  }

  /** Returns the unique identifier for this operation. */
  @Override
  public long getUID() {
    return uid;
  }

  private final Object totalBytesSync = new Object();
  private int totalBytesSent;

  /** Records {@code x} bytes sent on the network path and updates node stats. */
  @Override
  public void sentBytes(int x) {
    synchronized (totalBytesSync) {
      totalBytesSent += x;
    }
    node.network().stats().insertSentBytes(true, x);
  }

  /** Returns the total bytes sent so far (counters only; does not include payload accounting). */
  public int getTotalSentBytes() {
    synchronized (totalBytesSync) {
      return totalBytesSent;
    }
  }

  private int totalBytesReceived;

  /** Records {@code x} bytes received on the network path and updates node stats. */
  @Override
  public void receivedBytes(int x) {
    synchronized (totalBytesSync) {
      totalBytesReceived += x;
    }
    node.network().stats().insertReceivedBytes(true, x);
  }

  /** Returns the total bytes received so far (counters only). */
  public int getTotalReceivedBytes() {
    synchronized (totalBytesSync) {
      return totalBytesReceived;
    }
  }

  /** Records {@code x} payload bytes sent (separate from header- / counter-accounting). */
  @Override
  public void sentPayload(int x) {
    node.sentPayload(x);
    node.network().stats().insertSentBytes(true, -x);
  }

  /** Returns the scheduling priority for this sender. */
  @Override
  public int getPriority() {
    return NativeThread.PriorityLevel.HIGH_PRIORITY.value;
  }

  /** Returns a concise identifier for logging. */
  @Override
  public String toString() {
    return "SSKInsertSender:" + myKey + ":" + uid;
  }

  /** Returns a snapshot of peers this sender routed to. */
  public PeerNode[] getRoutedTo() {
    return this.nodesRoutedTo.toArray(new PeerNode[nodesRoutedTo.size()]);
  }

  /**
   * Creates the initial insert request for SSK, including optional sub‑messages controlling
   * forking, backoff, and insert preference.
   */
  @Override
  protected Message createDataRequest() {
    Message request = DMT.createFNPSSKInsertRequestNew(uid, htl, myKey);
    if (forkOnCacheable != Node.FORK_ON_CACHEABLE_DEFAULT) {
      request.addSubMessage(DMT.createFNPSubInsertForkControl(forkOnCacheable));
    }
    if (ignoreLowBackoff != Node.IGNORE_LOW_BACKOFF_DEFAULT) {
      request.addSubMessage(DMT.createFNPSubInsertIgnoreLowBackoff(ignoreLowBackoff));
    }
    if (preferInsert != Node.PREFER_INSERT_DEFAULT) {
      request.addSubMessage(DMT.createFNPSubInsertPreferInsert(preferInsert));
    }
    request.addSubMessage(DMT.createFNPRealTimeFlag(realTimeFlag));
    return request;
  }

  /** Returns the timeout in milliseconds to wait for {@code Accepted}. */
  @Override
  protected long getAcceptedTimeout() {
    return ACCEPTED_TIMEOUT;
  }

  /**
   * Handles a fatal timeout while waiting for a peer after sending the request.
   *
   * <p>Decrements HTL by the number of hops that would have been used and finishes with {@link
   * #ROUTE_NOT_FOUND} (or promotes to {@link #ROUTE_REALLY_NOT_FOUND} later if never forwarded).
   */
  @Override
  protected void timedOutWhileWaiting(double load) {
    htl -= (short) Math.max(0, hopsForFatalTimeoutWaitingForPeer());
    if (htl < 0) htl = 0;
    // Backtrack, i.e. RNF.
    if (!hasForwarded) origTag.setNotRoutedOnwards();
    finish(ROUTE_NOT_FOUND, null);
  }

  private volatile boolean needPubKey;

  /**
   * Returns {@code true} when the message is {@code FNPSSKAccepted} and caches whether the peer
   * requires the publisher’s public key.
   */
  @Override
  protected boolean isAccepted(Message msg) {
    if (DMT.FNPSSKAccepted.equals(msg.getSpec())) {
      needPubKey = msg.getBoolean(DMT.NEED_PUB_KEY);
      return true;
    } else return false;
  }

  /**
   * Sends headers and data to the accepting peer, optionally sends the public key when requested,
   * then waits for the terminal response.
   */
  @Override
  protected void onAccepted(PeerNode next) {
    if (LOG.isDebugEnabled()) LOG.debug("Got Accepted on {}", this);
    InsertTag thisTag = currentTag();
    if (!sendHeadersAndData(next, thisTag)) return;
    if (needPubKey && !sendPubKeyAndAwaitAccepted(next, thisTag)) return;
    waitForFinalResponse(next, thisTag);
  }

  private InsertTag currentTag() {
    return (forkedRequestTag == null) ? origTag : forkedRequestTag;
  }

  private boolean sendHeadersAndData(PeerNode next, InsertTag thisTag) {
    Message headersMsg = DMT.createFNPSSKInsertRequestHeaders(uid, headers, realTimeFlag);
    Message dataMsg = DMT.createFNPSSKInsertRequestData(uid, data, realTimeFlag);
    try {
      next.transport().sendAsync(headersMsg, null, this);
      next.transport().sendSync(dataMsg, this, realTimeFlag);
      sentPayload(data.length);
      return true;
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled()) LOG.debug("Not connected to {}", next);
      next.noLongerRoutingTo(thisTag, false);
      routeRequests();
      return false;
    } catch (SyncSendWaitedTooLongException _) {
      LOG.error("Waited too long to send {} to {} on {}", dataMsg, next, this);
      next.noLongerRoutingTo(thisTag, false);
      routeRequests();
      return false;
    }
  }

  private boolean sendPubKeyAndAwaitAccepted(PeerNode next, InsertTag thisTag) {
    Message pkMsg = DMT.createFNPSSKPubKey(uid, pubKey, realTimeFlag);
    try {
      next.transport().sendSync(pkMsg, this, realTimeFlag);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled()) LOG.debug("Node disconnected while sending pubkey: {}", next);
      next.noLongerRoutingTo(thisTag, false);
      routeRequests();
      return false;
    } catch (SyncSendWaitedTooLongException _) {
      LOG.warn("Took too long to send pubkey to {} on {}", next, this);
      next.noLongerRoutingTo(thisTag, false);
      routeRequests();
      return false;
    }

    // Wait for the SSKPubKeyAccepted (doubled timeout to avoid forking here)
    MessageFilter mf1 =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(ACCEPTED_TIMEOUT * 2)
            .setType(DMT.FNPSSKPubKeyAccepted);
    Message newAck;
    try {
      newAck = node.network().usm().waitFor(mf1, this);
    } catch (DisconnectedException _) {
      if (LOG.isDebugEnabled()) LOG.atDebug().log("Disconnected from {}", next);
      next.noLongerRoutingTo(thisTag, false);
      routeRequests();
      return false;
    }
    if (newAck == null) {
      handleNoPubkeyAccepted(next, thisTag);
      routeRequests();
      return false;
    }
    return true;
  }

  // Wait for a terminal response after we have sent the full request (and optional public key).
  private void waitForFinalResponse(PeerNode next, InsertTag thisTag) {
    MessageFilter mf = makeSearchFilter(next, calculateTimeout(htl));
    while (true) {
      Message msg;
      try {
        msg = node.network().usm().waitFor(mf, this);
      } catch (DisconnectedException _) {
        LOG.atInfo().log("InsertReply wait disconnected (pre-timeout) from {} on {}", next, this);
        next.noLongerRoutingTo(thisTag, false);
        routeRequests();
        return;
      }

      if (msg == null) {
        handleFirstTimeoutAndThenWait(next, thisTag, mf);
        return;
      }

      DO action = handleMessage(msg, next, thisTag);
      if (action == DO.FINISHED) return;
      if (action == DO.NEXT_PEER) {
        routeRequests();
        return;
      }
    }
  }

  // On the first timeout after Accepted, finalize locally and keep listening a bit longer to
  // surface a late terminal reply or mark a fatal timeout on the peer.
  private void handleFirstTimeoutAndThenWait(PeerNode next, InsertTag thisTag, MessageFilter mf) {
    LOG.atWarn().log("InsertReply timeout after Accepted (initial) on {} from {}", this, next);
    next.localRejectedOverload("AfterInsertAcceptedTimeout", realTimeFlag);
    forwardRejectedOverload();
    finish(TIMED_OUT, next);

    while (true) {
      Message msg;
      try {
        msg = node.network().usm().waitFor(mf, this);
      } catch (DisconnectedException _) {
        LOG.atInfo().log("InsertReply wait disconnected (post-timeout) from {} on {}", next, this);
        next.noLongerRoutingTo(thisTag, false);
        return;
      }

      if (msg == null) {
        LOG.atError().log("InsertReply timeout after Accepted (fatal) on {} from {}", this, next);
        next.fatalTimeout(thisTag, false);
        return;
      }

      DO action = handleMessage(msg, next, thisTag);
      if (action == DO.FINISHED) return;
      if (action == DO.NEXT_PEER) {
        next.noLongerRoutingTo(thisTag, false);
        return; // Don't try others
      }
    }
  }

  /** Returns {@code true}; this sender performs an insert. */
  @Override
  protected boolean isInsert() {
    return true;
  }

  /**
   * Returns the source to consider when choosing the next hop. When forked, treat the request as
   * originating locally (return {@code null}).
   */
  @Override
  protected PeerNode sourceForRouting() {
    if (forkedRequestTag != null) return null;
    return source;
  }

  /** Returns the low‑backoff threshold to apply during routing. */
  @Override
  protected long ignoreLowBackoff() {
    return ignoreLowBackoff ? Node.LOW_BACKOFF : 0;
  }
}
