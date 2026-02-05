package network.crypta.node;

import java.lang.ref.WeakReference;
import java.util.Objects;
import network.crypta.keys.NodeCHK;
import network.crypta.support.TimeUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracks lifecycle, routing, and transfer bookkeeping for a single request UID.
 *
 * <p>A {@code RequestTag} instance is created when a request is accepted or initiated and stays
 * associated with that UID until the inbound handler and any outbound routing are complete. It
 * records origin ({@link START}), request type (SSK or CHK), and whether the response was served
 * locally. It also tracks sender and handler transfer activity so {@link UIDTag} can decide when
 * unlocking is safe without losing state needed for diagnostics.
 *
 * <p>Concurrency: most state changes synchronize on the tag. The tag is mutable and not thread-safe
 * without those locks. Weak references are used for peers and senders so they can be collected; in
 * that case, call sites must tolerate {@code null} when inspecting those references.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Recording sender completion and transfer status for accounting.
 *   <li>Managing opennet wait state and routing unlock eligibility.
 *   <li>Providing detailed timeout diagnostics through {@link #logStillPresent(Long)}.
 * </ul>
 *
 * @see UIDTag
 * @see RequestSender
 * @see RequestTracker
 * @author Matthew Toseland {@literal <toad@amphibian.dyndns.org>} (0xE43DA450)
 */
public class RequestTag extends UIDTag {
  private static final Logger LOG = LoggerFactory.getLogger(RequestTag.class);

  /**
   * Identifies where the request originated for routing and accounting decisions.
   *
   * <p>The start value is set at construction and remains stable for the lifetime of the tag. It is
   * used in timeout diagnostics and accounting paths that distinguish local requests from forwarded
   * ones. Each constant describes an origin path, not a routing choice, and does not change once
   * assigned.
   *
   * <ul>
   *   <li>{@link #ASYNC_GET}: initiated by the asynchronous get path.
   *   <li>{@link #LOCAL}: started locally by this node.
   *   <li>{@link #REMOTE}: forwarded from a remote peer.
   * </ul>
   */
  public enum START {
    /**
     * Originates from the asynchronous get path, typically a locally initiated fetch.
     *
     * <p>Use this value when the request began in the async client layer and should be treated as a
     * local origin for diagnostics and accounting.
     */
    ASYNC_GET,

    /**
     * Originates from this node without an external peer.
     *
     * <p>Use for locally created operations where the source is the node itself, so accounting and
     * routing treat it as local.
     */
    LOCAL,

    /**
     * Originates from a remote peer and is forwarded into this node.
     *
     * <p>Use when the UID was received from a peer, so limits and diagnostics attribute ownership
     * externally unless reassigned.
     */
    REMOTE
  }

  final START start;
  final boolean isSSK;
  private boolean servedFromDatastore;
  private WeakReference<RequestSender> sender;
  private boolean sent;
  private int requestSenderFinishedCode = RequestSender.NOT_FINISHED;
  private Throwable handlerThrew;
  private boolean rejected;
  private boolean handlerDisconnected;
  private WeakReference<PeerNode> waitingForOpennet;
  private boolean handlerTransferring;
  private boolean senderTransferring;

  /** Set if transferring */
  private NodeCHK key;

  /**
   * Creates a tag for a single request and initializes origin metadata.
   *
   * <p>The constructor records the origin, request type, and UID, and it initializes the base
   * {@link UIDTag} with the source peer and routing tracker from {@code node}. It does not start
   * any routing or transfer activity; it simply establishes bookkeeping that other components
   * update as the request progresses. The instance is mutable and should be published only after
   * construction completes to avoid race conditions.
   *
   * @param isSSK {@code true} when the request targets an SSK; {@code false} for CHK
   * @param start origin classification describing how the request began; must be non-null
   * @param source source peer for the request, or {@code null} for local origin
   * @param realTimeFlag {@code true} for real-time priority scheduling; {@code false} otherwise
   * @param uid unique identifier for the request, used for tracker accounting
   * @param node owning node providing routing and tracker access; must be non-null
   */
  public RequestTag(
      boolean isSSK, START start, PeerNode source, boolean realTimeFlag, long uid, Node node) {
    super(source, realTimeFlag, uid, node);
    this.start = start;
    this.isSSK = isSSK;
  }

  /**
   * Records the final status from the {@link RequestSender} and unlocks if possible.
   *
   * <p>This method stores the terminal status code and then checks whether the tag can be unlocked
   * based on routing, opennet wait, and handler state. It must be called with a value other than
   * {@link RequestSender#NOT_FINISHED}; passing that sentinel indicates the sender has not finished
   * and results in an {@link IllegalArgumentException}. If unlock conditions are satisfied, it
   * delegates to {@link #innerUnlock(boolean)} outside the synchronized block.
   *
   * @param status terminal status code from {@link RequestSender}; must not be NOT_FINISHED
   * @throws IllegalArgumentException if the status equals {@link RequestSender#NOT_FINISHED}
   */
  public void setRequestSenderFinished(int status) {
    boolean unlockNow;
    boolean localNoRecordUnlock = false;
    synchronized (this) {
      if (status == RequestSender.NOT_FINISHED) throw new IllegalArgumentException();
      requestSenderFinishedCode = status;
      unlockNow = mustUnlock();
      if (unlockNow) {
        localNoRecordUnlock = this.noRecordUnlock;
      }
    }
    UIDTraceLogger.log(
        "requestSenderFinished", this, () -> "status=" + status + " unlock=" + unlockNow);
    if (!unlockNow) return;
    innerUnlock(localNoRecordUnlock);
  }

  /**
   * Associates a {@link RequestSender} with this tag.
   *
   * <p>The sender reference is stored as a weak reference to avoid retaining the sender longer than
   * necessary. If {@code coalesced} is false, the tag marks that a sender is active and expects
   * completion callbacks; if {@code coalesced} is true, the request was satisfied by coalescing and
   * no sender callbacks are expected. This affects {@link #mustUnlock()} decisions.
   *
   * @param rs sender instance responsible for outbound routing and callbacks; must be non-null
   * @param coalesced true when coalesced transfer satisfies the request; false otherwise
   */
  public synchronized void setSender(RequestSender rs, boolean coalesced) {
    // When coalesced, the RequestSender will not produce events; do not wait for it.
    if (!coalesced) {
      sent = true;
    }
    sender = new WeakReference<>(rs);
    UIDTraceLogger.log("senderSet", this, () -> "coalesced=" + coalesced);
  }

  /**
   * Determines whether the tag can be fully unlocked given sender and opennet state.
   *
   * <p>This override extends {@link UIDTag#mustUnlock()} by holding the tag locked while a sender
   * is still active or while the tag is waiting for an opennet decision. It should be invoked only
   * while holding the tag monitor, as it inspects the mutable state and updates the unlocking latch
   * in the base class. If it returns {@code true}, callers must immediately proceed to {@link
   * #innerUnlock(boolean)}.
   *
   * @return {@code true} if the tag can unlock now; {@code false} otherwise
   */
  @Override
  protected synchronized boolean mustUnlock() {
    if (sent && requestSenderFinishedCode == RequestSender.NOT_FINISHED) return false;
    if (waitingForOpennet != null && waitingForOpennet.get() != null) return false;
    return super.mustUnlock();
  }

  /**
   * Clears transfer bookkeeping and delegates to {@link UIDTag#innerUnlock(boolean)}.
   *
   * <p>This override snapshots transfer state under the tag monitor, clears handler and sender
   * transfer flags, and then calls the base unlock logic. If sender transfer tracking appears
   * active without a matching end call, it logs a warning, captures the key and sender references,
   * and then removes the transfer entry from the tracker after unlocking. This keeps tracker
   * accounting consistent even when end callbacks are missed.
   *
   * @param noRecordUnlock whether to suppress unlock record bookkeeping for this tag
   */
  @Override
  protected final void innerUnlock(boolean noRecordUnlock) {
    boolean handlerFinished;
    boolean senderFinished;
    NodeCHK k = null;
    RequestSender s = null;
    synchronized (this) {
      handlerFinished = this.handlerTransferring;
      handlerTransferring = false;
      senderFinished = this.senderTransferring;
      if (senderFinished) {
        LOG.warn("senderTransferEnds() not called for {}", this);
        k = key;
        s = sender.get();
      }
      senderTransferring = false;
    }
    super.innerUnlock(noRecordUnlock);
    if (handlerFinished) tracker.removeTransferringRequestHandler(uid);
    if (senderFinished) {
      assert (k != null);
      assert (s != null);
      tracker.removeTransferringSender(k, s);
    }
  }

  /**
   * Records a handler exception and unlocks the handler portion of the tag.
   *
   * <p>The throwable is stored for later diagnostics and included by {@link #logStillPresent(Long)}
   * if the tag remains active. This method always logs a trace entry and then calls {@link
   * #unlockHandler()} to allow routing to continue or complete. It does not rethrow the exception;
   * callers should handle error propagation separately. If invoked multiple times, the most recent
   * throwable replaces the previous one.
   *
   * @param t exception thrown by the request handler; must be non-null
   */
  public void handlerThrew(Throwable t) {
    synchronized (this) {
      this.handlerThrew = t;
    }
    UIDTraceLogger.log("handlerThrew", this, () -> "error=" + t.getClass().getSimpleName());
    // Unlock the handler after recording the throwable; synchronization remains unchanged.
    unlockHandler();
  }

  /**
   * Marks that the response was served from the local datastore.
   *
   * <p>This flag is used for diagnostics and timeout logging. Setting it does not affect routing or
   * unlock decisions; it simply records that the data was retrieved locally rather than from a
   * transfer. The method is synchronized and idempotent, so repeated calls have no additional
   * effect.
   */
  public synchronized void setServedFromDatastore() {
    servedFromDatastore = true;
  }

  /**
   * Marks that the request was rejected by the handler.
   *
   * <p>The rejected flag is reported in timeout diagnostics and can be used by callers to explain
   * why a request terminated early. Setting it does not unlock the tag or alter the routing state;
   * it is purely informational. The method is synchronized and idempotent.
   */
  public synchronized void setRejected() {
    rejected = true;
  }

  /**
   * Logs a detailed snapshot when the tag remains present beyond an expected duration.
   *
   * <p>The snapshot includes age, origin, SSK flag, datastore hit flag, sender status, transfer
   * activity, rejection state, and opennet wait information. It also appends the base tag state via
   * {@link UIDTag#toString()}. If a handler exception was recorded, the log entry uses it as the
   * cause; otherwise it logs without a cause. This method performs logging only and does not change
   * the state.
   *
   * @param uid unique identifier of the tag being reported; may be {@code null}
   */
  @Override
  public void logStillPresent(Long uid) {
    StringBuilder sb = new StringBuilder();
    sb.append("Still present after ").append(TimeUtil.formatTime(age()));
    sb.append(" : ").append(uid).append(" : start=").append(start);
    sb.append(" ssk=").append(isSSK).append(" from store=").append(servedFromDatastore);
    if (sender == null) {
      sb.append(" sender not set");
    } else {
      RequestSender s = sender.get();
      if (s == null) {
        sb.append(" sender=null");
      } else {
        sb.append(" sender=").append(s);
        sb.append(" status=");
        sb.append(s.getStatusString());
        sb.append(" transferBegun=").append(s.hasSentChkTransferBegins());
        sb.append(" transferActive=").append(s.isTransferActive());
      }
    }
    if (sent) sb.append(" sent");
    sb.append(" finishedCode=").append(requestSenderFinishedCode);
    sb.append(" rejected=").append(rejected);
    if (handlerThrew != null) sb.append(" thrown=").append(handlerThrew);
    if (handlerDisconnected) sb.append(" handlerDisconnected=true");
    if (waitingForOpennet != null) {
      PeerNode pn = waitingForOpennet.get();
      sb.append(" waitingForOpennet=");
      sb.append(pn == null ? "(null)" : pn.shortToString());
    }
    sb.append(" : ");
    sb.append(super.toString());
    if (handlerThrew != null) {
      LOG.atError().setCause(handlerThrew).log("{}", sb);
    } else {
      LOG.atError().log("{}", sb);
    }
  }

  /**
   * Records that the handler disconnected while processing the request.
   *
   * <p>This flag is used for diagnostics when the tag remains present and does not by itself stop
   * routing or unlock the tag. The method is synchronized and idempotent, allowing callers to set
   * it safely from disconnect handlers without additional coordination.
   */
  public synchronized void handlerDisconnected() {
    handlerDisconnected = true;
  }

  /**
   * Estimates how many inbound transfers are still expected for this request.
   *
   * <p>This implementation returns {@code 0} until the handler has accepted the request. Once
   * accepted, it returns {@code 1} unless {@link #setNotRoutedOnwards()} was called, in which case
   * no downstream transfer is expected. The values are conservative and intended for admission and
   * scheduling decisions rather than exact accounting. The method is synchronized to align with the
   * handler state.
   *
   * @param ignoreLocalVsRemote whether to treat local origin as remote for counting
   * @param outwardTransfersPerInsert unused for requests; provided for API symmetry
   * @param forAccept {@code true} when called from admission control paths
   * @return estimated inbound transfers remaining, either {@code 0} or {@code 1}
   */
  @Override
  public synchronized int expectedTransfersIn(
      boolean ignoreLocalVsRemote, int outwardTransfersPerInsert, boolean forAccept) {
    if (!accepted) return 0;
    return notRoutedOnwards ? 0 : 1;
  }

  /**
   * Estimates how many outbound transfers are still expected for this request.
   *
   * <p>This method returns {@code 0} when the handler has not accepted, when downstream transfers
   * are marked complete, or when acceptance accounting should not count local or restarted
   * requests. It returns {@code 1} when outbound transfer is still expected and the request should
   * be treated as remote (or {@code ignoreLocalVsRemote} forces that). The result is synchronized
   * with the mutable state.
   *
   * @param ignoreLocalVsRemote whether to count local origin as remote for scheduling
   * @param outwardTransfersPerInsert unused for requests; provided for API symmetry
   * @param forAccept {@code true} when called from admission control paths
   * @return estimated outbound transfers remaining, either {@code 0} or {@code 1}
   */
  @Override
  public synchronized int expectedTransfersOut(
      boolean ignoreLocalVsRemote, int outwardTransfersPerInsert, boolean forAccept) {
    if (!accepted) return 0;
    if (completedDownstreamTransfers) return 0;
    if (forAccept && (sourceRestarted || unlockedHandler)) return 0;
    return (!isLocal() || ignoreLocalVsRemote) ? 1 : 0;
  }

  private boolean completedDownstreamTransfers;

  /**
   * Marks that all downstream transfers have completed for this tag.
   *
   * <p>Once set, {@link #expectedTransfersOut(boolean, int, boolean)} will return {@code 0} to
   * avoid accounting for additional outbound transfers. This method does not unlock the tag by
   * itself; it only updates the completion flag. The update is synchronized and idempotent.
   */
  public synchronized void completedDownstreamTransfers() {
    this.completedDownstreamTransfers = true;
  }

  /**
   * Reports whether this tag represents an SSK request.
   *
   * <p>This implementation returns the immutable {@code isSSK} flag recorded at construction. The
   * value is used by routing, logging, and transfer estimation, and it is stable for the lifetime
   * of the tag. The method performs no synchronization because the flag never changes.
   *
   * @return {@code true} if the request targets an SSK; {@code false} for CHK
   */
  @Override
  public boolean isSSK() {
    return isSSK;
  }

  /**
   * Reports whether this tag represents an insert request.
   *
   * <p>Request tags model fetch-style requests, so this implementation always returns {@code
   * false}. Callers can rely on the value being constant for this type and use it to select
   * insert-specific routing or accounting paths.
   *
   * @return {@code false} because request tags do not represent inserts
   */
  @Override
  public boolean isInsert() {
    return false;
  }

  /**
   * Reports whether this tag represents a reply to an offer.
   *
   * <p>This implementation always returns {@code false}, because {@link RequestTag} is used for
   * request handling rather than offer replies. The value is constant for this type and can be used
   * to skip offer-reply-specific handling.
   *
   * @return {@code false} because request tags are not offer replies
   */
  @Override
  public boolean isOfferReply() {
    return false;
  }

  /**
   * Records that routing is paused while waiting for an opennet decision.
   *
   * <p>This method stores a weak reference to the peer being consulted and affects {@link
   * #mustUnlock()} and {@link #currentlyRoutingTo(PeerNode)} until cleared. If a wait is already
   * recorded, it logs an error but still replaces the stored reference with the new peer. Callers
   * should invoke {@link #finishedWaitingForOpennet(PeerNode)} when the decision arrives.
   *
   * @param next peer consulted for opennet; must be non-null
   */
  public synchronized void waitingForOpennet(PeerNode next) {
    if (waitingForOpennet != null)
      LOG.error(
          "Already waiting for opennet: {} on {}",
          waitingForOpennet.get(),
          this,
          new Exception("error"));
    this.waitingForOpennet = next.myRef;
    UIDTraceLogger.log("opennetWait", this, () -> "peer=" + next.shortToString());
  }

  /**
   * Clears the opennet wait state for the given peer and unlocks if possible.
   *
   * <p>If no wait is recorded, the method logs a debug message and returns. If the stored peer does
   * not match {@code next}, it logs an error but still clears the wait state. After clearing, it
   * reevaluates unlock conditions and may call {@link #innerUnlock(boolean)} with the current
   * {@code noRecordUnlock} flag. Logging and unlocking occur outside the synchronized block.
   *
   * @param next peer previously recorded by {@link #waitingForOpennet(PeerNode)}
   */
  public void finishedWaitingForOpennet(PeerNode next) {
    boolean unlockNow;
    boolean localNoRecordUnlock = false;
    synchronized (this) {
      if (waitingForOpennet == null) {
        if (LOG.isDebugEnabled()) LOG.debug("Not waiting for opennet");
        return;
      }
      PeerNode got = waitingForOpennet.get();
      if (!Objects.equals(got, next)) {
        LOG.error("Wait ends on {} but was waiting for {}", next, got);
      }
      waitingForOpennet = null;
      unlockNow = mustUnlock();
      if (unlockNow) {
        localNoRecordUnlock = this.noRecordUnlock;
      }
    }
    UIDTraceLogger.log(
        "opennetDone", this, () -> "peer=" + next.shortToString() + " unlock=" + unlockNow);
    if (!unlockNow) return;
    innerUnlock(localNoRecordUnlock);
  }

  /**
   * Returns routing peers for hard-timeout enforcement, including opennet wait peers.
   *
   * <p>This override starts with the base routing peers and then appends the peer recorded by
   * {@link #waitingForOpennet(PeerNode)} if it is still available and not already present. The
   * returned array is a snapshot; callers must not modify it. The method is synchronized to avoid
   * concurrent changes to routing or wait state.
   *
   * @return snapshot of peers to consider for hard-timeout enforcement
   */
  @Override
  protected synchronized PeerNode[] routingPeersForHardTimeout() {
    PeerNode[] peers = super.routingPeersForHardTimeout();
    if (waitingForOpennet == null) return peers;
    PeerNode pn = waitingForOpennet.get();
    if (pn == null) return peers;
    if (peers == null || peers.length == 0) return new PeerNode[] {pn};
    for (PeerNode peer : peers) {
      if (Objects.equals(peer, pn)) return peers;
    }
    PeerNode[] expanded = new PeerNode[peers.length + 1];
    System.arraycopy(peers, 0, expanded, 0, peers.length);
    expanded[peers.length] = pn;
    return expanded;
  }

  /**
   * Handles hard-timeout cleanup when no routing peers remain.
   *
   * <p>This implementation checks whether a sender was marked active, has not reported a finished
   * status, is not transferring, and has been garbage collected. When those conditions hold, it
   * logs a warning and forces {@link RequestSender#TIMED_OUT} by calling {@link
   * #setRequestSenderFinished(int)}. If any condition fails, it returns {@code false} so the base
   * logic can continue without forced completion.
   *
   * @param continueAge time since timeout-continue was first recorded, in milliseconds
   * @return {@code true} if a forced sender completion occurred; {@code false} otherwise
   */
  @Override
  protected boolean handleHardTimeoutWithoutPeers(long continueAge) {
    WeakReference<RequestSender> localSender;
    boolean localSent;
    int localFinishedCode;
    boolean localSenderTransferring;
    synchronized (this) {
      localSender = sender;
      localSent = sent;
      localFinishedCode = requestSenderFinishedCode;
      localSenderTransferring = senderTransferring;
    }
    if (!localSent || localFinishedCode != RequestSender.NOT_FINISHED) return false;
    if (localSenderTransferring) return false;
    if (localSender == null || localSender.get() != null) return false;
    if (LOG.isWarnEnabled()) {
      LOG.warn(
          "Hard timeout after {} for {}. Forcing sender finish: status={}",
          TimeUtil.formatTime(continueAge),
          this,
          RequestSender.getStatusString(RequestSender.TIMED_OUT));
    }
    setRequestSenderFinished(RequestSender.TIMED_OUT);
    return true;
  }

  /**
   * Reports whether this tag is currently routing to the given peer.
   *
   * <p>This override extends {@link UIDTag#currentlyRoutingTo(PeerNode)} by treating the opennet
   * decision peer as active while the tag is waiting for it. It does not indicate that a sending is
   * in flight, only that the routing state still considers the peer relevant. The method is
   * synchronized to coordinate with updates to the wait state.
   *
   * @param peer candidate peer to test against routing state; must be non-null
   * @return {@code true} if routing state includes the peer; {@code false} otherwise
   */
  @Override
  public synchronized boolean currentlyRoutingTo(PeerNode peer) {
    if (waitingForOpennet != null && waitingForOpennet == peer.myRef) return true;
    return super.currentlyRoutingTo(peer);
  }

  /**
   * Marks the beginning of handler-side transfer and registers it with the tracker.
   *
   * <p>This method sets the handler transfer flag once and then registers the UID with the tracker
   * so that transfer accounting reflects the in-progress handler work. It is safe to call multiple
   * times; further calls have no effect once the flag is set.
   */
  public void handlerTransferBegins() {
    synchronized (this) {
      if (handlerTransferring) return;
      handlerTransferring = true;
    }
    tracker.addTransferringRequestHandler(uid);
  }

  /**
   * Marks the beginning of sender-side transfer and registers it with the tracker.
   *
   * <p>The method sets the sender transfer flag, records the content key, and registers the sender
   * with the tracker for transfer accounting. It requires that {@link #setSender(RequestSender,
   * boolean)} was called with the same sender instance; otherwise it throws. If the transfer has
   * already started, the method returns without changing the state. This method does not perform
   * unlocking.
   *
   * @param k content key for the transfer; must match the end call
   * @param requestSender active sender instance; must match the sender set earlier
   * @throws IllegalStateException if the sender was not set or mismatched
   */
  public void senderTransferBegins(NodeCHK k, RequestSender requestSender) {
    synchronized (this) {
      if (senderTransferring) return;
      senderTransferring = true;
      if (this.sender == null || this.sender.get() != requestSender)
        throw new IllegalStateException("Set RequestSender first!");
      this.key = k;
    }
    tracker.addTransferringSender(k, requestSender);
  }

  /**
   * Marks the end of sender-side transfer and unregisters it from the tracker.
   *
   * <p>If the transfer was already cleared, the method returns without side effects. Otherwise, it
   * verifies that the sender and key match the values recorded by {@link
   * #senderTransferBegins(NodeCHK, RequestSender)}, clears the stored key, and then removes the
   * sender from transfer accounting. Mismatches are treated as illegal state and thrown.
   *
   * @param key content key used when the transfer began; must match the stored key
   * @param requestSender sender that initiated the transfer; must match stored sender
   * @throws IllegalStateException if the sender or key does not match
   */
  public void senderTransferEnds(NodeCHK key, RequestSender requestSender) {
    synchronized (this) {
      if (!senderTransferring)
        // Already cleared; a duplicate end signal is benign.
        return;
      senderTransferring = false;
      if (this.sender == null || this.sender.get() != requestSender) {
        throw new IllegalStateException("Unexpected RequestSender when ending transfer");
      }
      if (this.key == null || !this.key.equals(key)) {
        throw new IllegalStateException("Unexpected key when ending transfer");
      }
      this.key = null;
    }
    tracker.removeTransferringSender(key, requestSender);
  }
}
