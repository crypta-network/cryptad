package network.crypta.node;

import static java.util.concurrent.TimeUnit.SECONDS;

import java.lang.ref.WeakReference;
import java.util.HashSet;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base class for tags that represent a single in‑flight request.
 *
 * <p>A tag tracks routing state (peers we contacted or are contacting), handler state (whether the
 * incoming side has completed), and bookkeeping required to decide when it is safe to release the
 * unique identifier (UID) for reuse. Subclasses define request‑specific behavior and logging.
 *
 * <p>Concurrency: many methods are {@code synchronized} on {@code this}. Callers must respect the
 * locking comments on helpers that assume the monitor is already held. The class itself is not
 * immutable.
 *
 * <p>Lifetime: a tag is created when a request is accepted or initiated and is unlocked when both
 * the handler (incoming) and all outstanding outbound activities are complete, or when ownership is
 * reassigned locally as part of timeout handling.
 *
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 */
public abstract class UIDTag {
  private static final Logger LOG = LoggerFactory.getLogger(UIDTag.class);
  private static final String DEBUG_EXCEPTION_MESSAGE = "debug";
  private static final String PEER_LOG_PREFIX = "peer=";
  private static final String REMOVED_LOG_FRAGMENT = " removed=";

  // No static initialization required.

  final long createdTime;
  final boolean wasLocal;
  private final WeakReference<PeerNode> sourceRef;
  final boolean realTimeFlag;
  protected final RequestTracker tracker;
  protected boolean accepted;
  protected boolean sourceRestarted;

  /** Nodes we routed to at any point during this tag's lifetime. */
  private HashSet<PeerNode> routedTo = null;

  /**
   * Nodes we are currently talking to (their side has not yet removed our UID from active
   * requests).
   */
  private HashSet<PeerNode> currentlyRoutingTo = null;

  /** Nodes we are currently fetching an offered key from. */
  private HashSet<PeerNode> fetchingOfferedKeyFrom = null;

  /**
   * Peers for which we are in the two‑stage timeout grace. When the handler is unlocked while any
   * peers remain in {@link #currentlyRoutingTo} or {@link #fetchingOfferedKeyFrom}, we log an
   * error; if those peers are also present here, we reassign the tag locally instead of logging an
   * error.
   */
  private HashSet<PeerNode> handlingTimeouts = null;

  protected boolean notRoutedOnwards;
  final long uid;

  protected boolean unlockedHandler;
  protected boolean noRecordUnlock;
  private boolean hasUnlocked;

  private boolean waitingForSlot;

  UIDTag(PeerNode source, boolean realTimeFlag, long uid, Node node) {
    createdTime = System.currentTimeMillis();
    this.sourceRef = source == null ? null : source.myRef;
    wasLocal = source == null;
    this.realTimeFlag = realTimeFlag;
    this.tracker = node.routing().tracker();
    this.uid = uid;
    if (LOG.isDebugEnabled()) LOG.debug("Create tag {}", this);
    // For locally originated requests, acceptance is immediate by design.
    if (wasLocal) accepted = true;
  }

  /**
   * Log that this tag still exists after the request timeout threshold.
   *
   * <p>Subclasses decide the logging level and include any identifiers they control.
   *
   * @param uid Optional UID to include in the log; may be {@code null} when not applicable.
   */
  public abstract void logStillPresent(Long uid);

  long age() {
    return System.currentTimeMillis() - createdTime;
  }

  /**
   * Mark that we route to, or fetch an offered key from, a peer. Call before sending the outbound
   * message so per‑peer capacity accounting is accurate.
   *
   * @param peer Peer we route to or fetch from.
   * @param offeredKey {@code true} for an offered‑key fetch; {@code false} for a normal route.
   *     Offered‑key fetches use shorter timeouts.
   * @return {@code true} if the peer was newly added to the corresponding set; {@code false} if it
   *     was already present.
   */
  public synchronized boolean addRoutedTo(PeerNode peer, boolean offeredKey) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "event=route-add peer={} tag={}{}",
          peer,
          this,
          offeredKey ? " (offered)" : "",
          new Exception(DEBUG_EXCEPTION_MESSAGE));
    if (routedTo == null) routedTo = new HashSet<>();
    routedTo.add(peer);
    boolean added;
    if (offeredKey) {
      if (fetchingOfferedKeyFrom == null) fetchingOfferedKeyFrom = new HashSet<>();
      added = fetchingOfferedKeyFrom.add(peer);
    } else {
      if (currentlyRoutingTo == null) currentlyRoutingTo = new HashSet<>();
      added = currentlyRoutingTo.add(peer);
    }
    UIDTraceLogger.log(
        "routeAdd",
        this,
        () ->
            PEER_LOG_PREFIX + peer.shortToString() + " offered=" + offeredKey + " added=" + added);
    return added;
  }

  /**
   * Whether we have ever routed to the given peer for this tag.
   *
   * @param peer Peer to test.
   * @return {@code true} if {@code peer} has been recorded in {@link #routedTo} at least once.
   */
  @SuppressWarnings("unused")
  public synchronized boolean hasRoutedTo(PeerNode peer) {
    if (routedTo == null) return false;
    return routedTo.contains(peer);
  }

  /**
   * Whether we are currently routing to the given peer.
   *
   * @param peer Peer to test.
   * @return {@code true} if {@code peer} is present in {@link #currentlyRoutingTo}.
   */
  public synchronized boolean currentlyRoutingTo(PeerNode peer) {
    if (currentlyRoutingTo == null) return false;
    return currentlyRoutingTo.contains(peer);
  }

  // We do not remove peers from these sets until the request finishes, unless a disconnection or
  // similar event occurs. This is acceptable because most transfers complete quickly. Removing on
  // transfer completion would not guarantee the UID has been freed; removal is safe only after
  // receiving an acknowledgement sent after the UID is cleared.

  /**
   * Whether we are currently fetching an offered key from the given peer.
   *
   * @param peer Peer to test.
   * @return {@code true} if {@code peer} is present in {@link #fetchingOfferedKeyFrom}.
   */
  public synchronized boolean currentlyFetchingOfferedKeyFrom(PeerNode peer) {
    if (fetchingOfferedKeyFrom == null) return false;
    return fetchingOfferedKeyFrom.contains(peer);
  }

  /**
   * Notify that we no longer fetch an offered key from a peer. Call only when the peer no longer
   * believes we route to it; see {@link #removeRoutingTo(PeerNode)} for rationale. When we are not
   * routing to any peers, not fetching offered keys, and the handler is unlocked, the UID is
   * released.
   *
   * @param next Peer we are no longer fetching an offered key from.
   */
  public void removeFetchingOfferedKeyFrom(PeerNode next) {
    boolean removed;
    boolean localNoRecordUnlock;
    synchronized (this) {
      if (fetchingOfferedKeyFrom == null) return;
      removed = fetchingOfferedKeyFrom.remove(next);
      if (handlingTimeouts != null) {
        handlingTimeouts.remove(next);
      }
      if (!mustUnlock()) {
        UIDTraceLogger.log(
            "offerRemove",
            this,
            () ->
                PEER_LOG_PREFIX
                    + next.shortToString()
                    + REMOVED_LOG_FRAGMENT
                    + removed
                    + " unlock=false");
        return;
      }
      localNoRecordUnlock = this.noRecordUnlock;
    }
    UIDTraceLogger.log(
        "offerRemove",
        this,
        () ->
            PEER_LOG_PREFIX
                + next.shortToString()
                + REMOVED_LOG_FRAGMENT
                + removed
                + " unlock="
                + true);
    if (LOG.isDebugEnabled()) LOG.debug("event=unlock-tag-after-offer-remove tag={}", this);
    innerUnlock(localNoRecordUnlock);
  }

  /**
   * Notify that we no longer route to a peer. When we are not routing to any peers (or fetching
   * offered keys) and the handler is unlocked, the tag is fully unlocked. This is most relevant to
   * incoming requests; outgoing requests only consider outbound routing.
   *
   * <p>Do not call until the peer is reasonably certain we stopped routing to it. We unlock the
   * handler as early as possible, without waiting to acknowledge our completion notice. Late on
   * sending and early on accepting avoids the peer thinking we finished when we did not, or us
   * thinking the next peer finished when it did not.
   *
   * @param next Peer we are no longer routing to.
   */
  public void removeRoutingTo(PeerNode next) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("event=route-remove peer={} tag={}", next, this);
    }
    boolean removed;
    boolean localNoRecordUnlock;
    synchronized (this) {
      if (currentlyRoutingTo == null) {
        return;
      }
      removed = currentlyRoutingTo.remove(next);
      if (!removed && LOG.isDebugEnabled()) {
        LOG.debug("Unexpected remove in {} for node {}", this, next);
      }
      if (handlingTimeouts != null) {
        handlingTimeouts.remove(next);
      }
      if (!mustUnlock()) {
        UIDTraceLogger.log(
            "routeRemove",
            this,
            () ->
                PEER_LOG_PREFIX
                    + next.shortToString()
                    + REMOVED_LOG_FRAGMENT
                    + removed
                    + " unlock=false");
        return;
      }
      localNoRecordUnlock = this.noRecordUnlock;
    }
    UIDTraceLogger.log(
        "routeRemove",
        this,
        () ->
            PEER_LOG_PREFIX
                + next.shortToString()
                + REMOVED_LOG_FRAGMENT
                + removed
                + " unlock="
                + true);
    if (LOG.isDebugEnabled()) {
      LOG.debug("event=unlock-tag-after-route-remove tag={}", this);
    }
    innerUnlock(localNoRecordUnlock);
  }

  protected void innerUnlock(boolean noRecordUnlock) {
    tracker.unlockUID(this, false, noRecordUnlock);
  }

  /**
   * Called after {@link #innerUnlock(boolean)} to notify peers that tracked this tag.
   *
   * <p>The best‑effort; missing peers are ignored.
   */
  @SuppressWarnings("unused")
  public void postUnlock() {
    PeerNode[] peers;
    synchronized (this) {
      if (routedTo != null) peers = routedTo.toArray(new PeerNode[0]);
      else peers = null;
    }
    if (peers != null) for (PeerNode p : peers) p.postUnlock(this);
  }

  /**
   * Estimate expected inbound transfers attributed to this tag.
   *
   * @param ignoreLocalVsRemote When {@code true}, treat the request as remote even if local.
   * @param outwardTransfersPerInsert Expected number of outbound transfers per insert operation.
   * @param forAccept When {@code true}, compute for admission control; when {@code false}, compute
   *     for sending decisions where we must be more conservative to avoid avoidable rejections and
   *     mandatory backoffs.
   */
  public abstract int expectedTransfersIn(
      boolean ignoreLocalVsRemote, int outwardTransfersPerInsert, boolean forAccept);

  /**
   * Estimate expected outbound transfers attributed to this tag.
   *
   * @param ignoreLocalVsRemote When {@code true}, treat the request as remote even if local.
   * @param outwardTransfersPerInsert Expected number of outbound transfers per insert operation.
   * @param forAccept When {@code true}, compute for admission control; when {@code false}, compute
   *     for sending decisions where we must be more conservative to avoid avoidable rejections and
   *     mandatory backoffs.
   */
  public abstract int expectedTransfersOut(
      boolean ignoreLocalVsRemote, int outwardTransfersPerInsert, boolean forAccept);

  /** Mark that this request will not be routed further downstream. */
  public synchronized void setNotRoutedOnwards() {
    this.notRoutedOnwards = true;
  }

  private boolean reassigned;

  /**
   * Get the effective source node for load management.
   *
   * @return The original source {@link PeerNode}, or {@code null} if the tag has been reassigned
   *     locally or originated locally.
   */
  public synchronized PeerNode getSource() {
    if (reassigned) return null;
    if (wasLocal) return null;
    return sourceRef.get();
  }

  /** Reassign the tag locally rather than attributing it to the original sender. */
  public synchronized void reassignToSelf() {
    if (wasLocal) return;
    reassigned = true;
    UIDTraceLogger.log("reassignToSelf", this);
  }

  /** Whether the request originated locally. Not affected by {@link #reassignToSelf()}. */
  public boolean wasLocal() {
    return wasLocal;
  }

  /** Whether the request is considered local now (originated locally or reassigned to self). */
  public boolean isLocal() {
    if (wasLocal) return true;
    synchronized (this) {
      return reassigned;
    }
  }

  /** Returns {@code true} if this tag represents an SSK request. */
  public abstract boolean isSSK();

  /** Returns {@code true} if this tag represents an insert request. */
  public abstract boolean isInsert();

  /** Returns {@code true} if this tag represents a reply to an offer. */
  public abstract boolean isOfferReply();

  /**
   * Caller must call innerUnlock(noRecordUnlock) immediately if this returns true. Hence, derived
   * versions should call mustUnlock() only after they have checked their own unlocking blockers.
   */
  protected synchronized boolean mustUnlock() {
    if (hasUnlocked || !unlockedHandler) {
      return false;
    }
    if (hasOutstandingRoutingTo()) {
      return false;
    }
    if (hasOutstandingOfferedKeyFetches()) {
      return false;
    }
    hasUnlocked = true;
    return true;
  }

  // Helper assumes the caller already holds the monitor on this tag.
  private boolean hasOutstandingRoutingTo() {
    if (currentlyRoutingTo == null || currentlyRoutingTo.isEmpty()) {
      return false;
    }
    if (!(reassigned || wasLocal || sourceRestarted || timedOutButContinued)) {
      boolean expected = isAnyHandlingTimeout(currentlyRoutingTo);
      if (!expected) {
        if (handlingTimeouts != null) {
          LOG.info(
              "event=unlock-handler-routing-timeout peers={} (fork may succeed while waiting for"
                  + " original)",
              currentlyRoutingTo);
        } else {
          LOG.error(
              "event=unlock-handler-routing-blocked peers={} tag={} (no reassignment)",
              currentlyRoutingTo,
              this,
              new Exception(DEBUG_EXCEPTION_MESSAGE));
        }
      } else {
        reassignToSelf();
      }
    }
    return true;
  }

  // Helper assumes the caller already holds the monitor on this tag.
  private boolean hasOutstandingOfferedKeyFetches() {
    if (fetchingOfferedKeyFrom == null || fetchingOfferedKeyFrom.isEmpty()) {
      return false;
    }
    if (!(reassigned || wasLocal)) {
      boolean expected = isAnyHandlingTimeout(fetchingOfferedKeyFrom);
      if (!expected) {
        // Fork succeeds can't happen for fetch-offered-keys.
        LOG.error(
            "event=unlock-handler-offer-fetch-blocked peers={} tag={} (no reassignment)",
            fetchingOfferedKeyFrom,
            this,
            new Exception(DEBUG_EXCEPTION_MESSAGE));
      } else {
        reassignToSelf();
      }
    }
    return true;
  }

  private boolean isAnyHandlingTimeout(Set<PeerNode> peers) {
    if (handlingTimeouts == null) {
      return false;
    }
    for (PeerNode pn : peers) {
      if (handlingTimeouts.contains(pn)) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Still wait for {} due to handling timeout in unlockHandler; reassign to self to"
                  + " resolve",
              pn.shortToString());
        }
        return true;
      }
    }
    return false;
  }

  /**
   * Unlock the handler. That is, the incoming request has finished. This method should be called
   * before the acknowledgement that the request has finished is sent downstream. Therefore, we will
   * never be waiting for an acknowledgement from downstream to release the slot it is using, during
   * which time it might think we are rejecting wrongly.
   *
   * <p>Once both the incoming and outgoing requests are unlocked, the whole tag is unlocked.
   */
  public void unlockHandler(boolean noRecord) {
    boolean canUnlock;
    synchronized (this) {
      if (unlockedHandler) return;
      noRecordUnlock = noRecord;
      unlockedHandler = true;
      canUnlock = mustUnlock();
    }
    UIDTraceLogger.log(
        "unlockHandler", this, () -> "noRecord=" + noRecord + " canUnlock=" + canUnlock);
    if (canUnlock) innerUnlock(noRecordUnlock);
    else {
      LOG.info("Defer unlock in unlockHandler; still sending requests");
    }
  }

  public void unlockHandler() {
    unlockHandler(false);
  }

  // LOCKING: Synchronized to avoid ConcurrentModificationException when reading sets for logging.
  // The UIDTag lock is always taken last in callers.
  @Override
  public synchronized String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append(super.toString());
    sb.append(":");
    sb.append(uid);
    if (unlockedHandler) sb.append(" (unlocked handler)");
    if (hasUnlocked) sb.append(" (unlocked)");
    if (noRecordUnlock) sb.append(" (don't record unlock)");
    if (currentlyRoutingTo != null && !currentlyRoutingTo.isEmpty()) {
      sb.append(" (routing to ");
      for (PeerNode pn : currentlyRoutingTo) {
        sb.append(pn.shortToString());
        sb.append(",");
      }
      sb.setLength(sb.length() - 1);
      sb.append(")");
    }
    if (fetchingOfferedKeyFrom != null)
      sb.append(" (fetch offered keys from ").append(fetchingOfferedKeyFrom.size()).append(")");
    if (sourceRestarted) sb.append(" (source restarted)");
    if (timedOutButContinued) sb.append(" (timed out but continued)");
    return sb.toString();
  }

  /**
   * Mark that we are handling a timeout for the given peer. If the handler later unlocks while the
   * peer still appears in routing/fetching sets, we will reassign this tag locally (rather than log
   * an error) and wait for the fatal timeout.
   *
   * @param next Peer for which a timeout is being handled.
   */
  public synchronized void handlingTimeout(PeerNode next) {
    if (handlingTimeouts == null) handlingTimeouts = new HashSet<>();
    handlingTimeouts.add(next);
    UIDTraceLogger.log("handlingTimeout", this, () -> PEER_LOG_PREFIX + next.shortToString());
  }

  private long loggedStillPresent;
  private static final long LOGGED_STILL_PRESENT_INTERVAL = SECONDS.toMillis(60);

  /**
   * Log that the tag is still present after the request timeout, at most once per interval.
   *
   * @param now Current time in milliseconds since the epoch.
   * @param uid Optional UID to include in the subclass log; may be {@code null}.
   */
  public void maybeLogStillPresent(long now, Long uid) {
    if (now - createdTime > RequestTracker.TIMEOUT) {
      synchronized (this) {
        if (now - loggedStillPresent < LOGGED_STILL_PRESENT_INTERVAL) return;
        loggedStillPresent = now;
      }
      logStillPresent(uid);
    }
  }

  /** Mark this request as accepted by the handler. */
  public synchronized void setAccepted() {
    accepted = true;
  }

  private boolean timedOutButContinued;

  /**
   * Set when we are going to tell downstream that the request has timed out, but can't terminate it
   * yet. We will terminate the request if we have to reroute it, and we count it towards the peer's
   * limit, but we don't stop messages to the request source.
   */
  public synchronized void timedOutToHandlerButContinued() {
    timedOutButContinued = true;
    UIDTraceLogger.log("timeoutContinue", this);
  }

  /** Mark that the handler disconnected or restarted. */
  public synchronized void onRestartOrDisconnectSource() {
    sourceRestarted = true;
  }

  // The third option is reassignToSelf(). We only use that when we actually
  // want the data and mean to continue. In that case, none of the next three
  // are appropriate.

  /**
   * Should we deduct this request from the source's limit instead of counting it towards it? A
   * normal request is counted towards it. A hidden request is deducted from it. This is used when
   * the source has restarted but also in some other cases.
   */
  public synchronized boolean countAsSourceRestarted() {
    return sourceRestarted || timedOutButContinued;
  }

  /** Whether we should continue sending messages to the source. */
  public synchronized boolean hasSourceReallyRestarted() {
    return sourceRestarted;
  }

  /**
   * Whether we should stop the request as soon as convenient. Normally {@code true} when the source
   * restarted or disconnected.
   */
  public synchronized boolean shouldStop() {
    return sourceRestarted || timedOutButContinued;
  }

  /**
   * Whether the given peer is the original source of this tag.
   *
   * @param pn Peer to compare.
   * @return {@code true} if {@code pn} is the original source and the tag was not reassigned and is
   *     not local.
   */
  public synchronized boolean isSource(PeerNode pn) {
    if (reassigned) return false;
    if (wasLocal) return false;
    if (sourceRef == null) return false;
    return sourceRef == pn.myRef;
  }

  /** Indicate that the tag is waiting for an outbound slot. */
  public synchronized void setWaitingForSlot() {
    // Consider using a counter on Node.
    // We must ensure it ALWAYS gets unset when some weird
    // error happens.
    if (waitingForSlot) return;
    waitingForSlot = true;
  }

  /** Clear the waiting‑for‑slot state. */
  public synchronized void clearWaitingForSlot() {
    // Consider using a counter on Node.
    // We must ensure it ALWAYS gets unset when some weird
    // error happens.
    // Clearing on unlocking may suffice depending on call paths.
    if (!waitingForSlot) return;
    waitingForSlot = false;
  }

  /** Returns {@code true} if the tag is currently waiting for an outbound slot. */
  public synchronized boolean isWaitingForSlot() {
    return waitingForSlot;
  }
}
