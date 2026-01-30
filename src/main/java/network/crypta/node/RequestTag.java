package network.crypta.node;

import java.lang.ref.WeakReference;
import java.util.Objects;
import network.crypta.keys.NodeCHK;
import network.crypta.support.TimeUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracks the lifecycle and routing state for a single request.
 *
 * <p>A {@code RequestTag} encapsulates bookkeeping for one in-flight request, including where the
 * request started, whether it targets an SSK, transfer activity for the handler and the sender, and
 * whether the data was served from the local datastore. It also coordinates unlocking with the base
 * {@link UIDTag} once routing and transfer conditions are satisfied.
 *
 * <p>Thread-safety: methods that mutate state are synchronized where needed; callers should respect
 * this contract. References to collaborators such as {@link RequestSender} and {@link PeerNode} are
 * stored using {@link java.lang.ref.WeakReference} so they do not prevent garbage collection.
 *
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 */
public class RequestTag extends UIDTag {
  private static final Logger LOG = LoggerFactory.getLogger(RequestTag.class);

  /**
   * Where the request originates.
   *
   * <ul>
   *   <li>{@link #ASYNC_GET}: initiated by the asynchronous get path.
   *   <li>{@link #LOCAL}: started locally by this node.
   *   <li>{@link #REMOTE}: forwarded from a remote peer.
   * </ul>
   */
  public enum START {
    ASYNC_GET,
    LOCAL,
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
   * Creates a tag for a request.
   *
   * @param isSSK {@code true} if the request targets an SSK; {@code false} for CHK.
   * @param start Origin of the request.
   * @param source Source peer for the request; may be {@code null} for local.
   * @param realTimeFlag {@code true} if the request is real-time prioritized.
   * @param uid Unique identifier for the request, as tracked by {@link UIDTag}.
   * @param node Owning node instance.
   */
  public RequestTag(
      boolean isSSK, START start, PeerNode source, boolean realTimeFlag, long uid, Node node) {
    super(source, realTimeFlag, uid, node);
    this.start = start;
    this.isSSK = isSSK;
  }

  /**
   * Records the final status from the {@link RequestSender} and unlocks if all conditions allow it.
   *
   * @param status Final status code from {@link RequestSender}.
   * @throws IllegalArgumentException if {@code status} equals {@link RequestSender#NOT_FINISHED}.
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
   * Sets the {@link RequestSender} associated with this tag.
   *
   * @param rs The sender instance.
   * @param coalesced {@code true} if the request was satisfied by transfer coalescing and no
   *     callbacks are expected from the sender.
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
   * Returns whether the tag must remain locked based on current routing and transfer state.
   *
   * <p>The tag stays locked while a {@link RequestSender} is active or this tag is waiting for an
   * opennet decision. Otherwise, it defers to {@link UIDTag#mustUnlock()}.
   */
  @Override
  protected synchronized boolean mustUnlock() {
    if (sent && requestSenderFinishedCode == RequestSender.NOT_FINISHED) return false;
    if (waitingForOpennet != null && waitingForOpennet.get() != null) return false;
    return super.mustUnlock();
  }

  /**
   * Clears transfer-tracking state and delegates to {@link UIDTag#innerUnlock(boolean)}.
   *
   * <p>If the handler or sender was marked as transferring, this method updates the associated
   * trackers after unlocking. Callers pass through {@code noRecordUnlock} from the outer context.
   *
   * @param noRecordUnlock If {@code true}, do not record the unlock in the tracker.
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
   * Records a {@link Throwable} raised by the handler and unlocks the handler.
   *
   * <p>The throwable is retained for later diagnostics and logged by {@link #logStillPresent(Long)}
   * if the tag remains present.
   *
   * @param t Throwable thrown by the request handler; never {@code null}.
   */
  public void handlerThrew(Throwable t) {
    synchronized (this) {
      this.handlerThrew = t;
    }
    UIDTraceLogger.log("handlerThrew", this, () -> "error=" + t.getClass().getSimpleName());
    // Unlock the handler after recording the throwable; synchronization remains unchanged.
    unlockHandler();
  }

  /** Marks that the response was served from the local datastore. */
  public synchronized void setServedFromDatastore() {
    servedFromDatastore = true;
  }

  /** Marks that the request was rejected. */
  public synchronized void setRejected() {
    rejected = true;
  }

  /**
   * Logs a detailed snapshot when the tag remains present beyond an expected duration.
   *
   * <p>Outputs origin, key flags, sender status, transfer state, and recorded exceptions. Logs at
   * error level; if a {@link Throwable} was recorded via {@link #handlerThrew(Throwable)}, it is
   * attached as the cause.
   *
   * @param uid The unique identifier of the tag being reported.
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

  public synchronized void handlerDisconnected() {
    handlerDisconnected = true;
  }

  /**
   * Estimates incoming transfer count still expected for this tag.
   *
   * @param ignoreLocalVsRemote When {@code true}, treats local and remote origins equivalently.
   * @param outwardTransfersPerInsert Unused for requests; reserved for inserts.
   * @param forAccept {@code true} if called from accept-path accounting.
   * @return {@code 1} when a downstream transfer is expected, otherwise {@code 0}.
   */
  @Override
  public synchronized int expectedTransfersIn(
      boolean ignoreLocalVsRemote, int outwardTransfersPerInsert, boolean forAccept) {
    if (!accepted) return 0;
    return notRoutedOnwards ? 0 : 1;
  }

  /**
   * Estimates outgoing transfer count still expected for this tag.
   *
   * @param ignoreLocalVsRemote When {@code true}, allows a transfer even if local.
   * @param outwardTransfersPerInsert Unused for requests; reserved for inserts.
   * @param forAccept {@code true} if called from accept-path accounting.
   * @return {@code 1} when an outbound transfer is expected, otherwise {@code 0}.
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

  /** Marks that all downstream transfers have completed for this tag. */
  public synchronized void completedDownstreamTransfers() {
    this.completedDownstreamTransfers = true;
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSSK() {
    return isSSK;
  }

  /** Returns {@code false}; requests are not inserts. */
  @Override
  public boolean isInsert() {
    return false;
  }

  /** Returns {@code false}; this tag does not represent an offer reply. */
  @Override
  public boolean isOfferReply() {
    return false;
  }

  /**
   * Records that routing is paused while waiting for an opennet decision from {@code next}.
   *
   * @param next The peer consulted for opennet; must be non-null.
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
   * Clears the opennet wait state for {@code next} and unlocks if conditions allow it.
   *
   * @param next The peer previously recorded by {@link #waitingForOpennet(PeerNode)}.
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
   * Returns {@code true} if this tag is currently routing to {@code peer} (including opennet wait).
   *
   * @param peer Candidate peer.
   * @return {@code true} when routing involves {@code peer}; otherwise {@code false}.
   */
  @Override
  public synchronized boolean currentlyRoutingTo(PeerNode peer) {
    if (waitingForOpennet != null && waitingForOpennet == peer.myRef) return true;
    return super.currentlyRoutingTo(peer);
  }

  /** Marks the beginning of handler-side transfer and registers it with the tracker. */
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
   * @param k The content key for the transfer; must match {@link #senderTransferEnds(NodeCHK,
   *     RequestSender)}.
   * @param requestSender The active {@link RequestSender}; must equal the sender set via {@link
   *     #setSender(RequestSender, boolean)}.
   * @throws IllegalStateException if the sender was not set before calling this method.
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
   * @param key The content key used when the transfer began.
   * @param requestSender The {@link RequestSender} that initiated the transfer.
   * @throws IllegalStateException if {@code requestSender} or {@code key} does not match the values
   *     recorded by {@link #senderTransferBegins(NodeCHK, RequestSender)}.
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
