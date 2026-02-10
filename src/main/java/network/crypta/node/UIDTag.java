package network.crypta.node;

import static java.util.concurrent.TimeUnit.SECONDS;

import java.lang.ref.WeakReference;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import network.crypta.support.TimeUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracks routing and lifecycle state for a single in-flight request UID.
 *
 * <p>A {@code UIDTag} instance is created when a request is accepted or initiated and remains bound
 * to the UID until the inbound handler completes and all outbound routing or offered-key fetch work
 * has been resolved. It records which peers were contacted, which peers are still considered
 * active, and whether ownership has been reassigned locally. That state drives unlock decisions in
 * {@link RequestTracker} and determines when the UID can be safely reused.
 *
 * <p>Concurrency: most mutating operations synchronize on the tag itself. Callers must respect the
 * locking notes for helpers that assume the monitor is already held. Instances are mutable and are
 * not thread-safe without the documented synchronization.
 *
 * <p>Notable behaviors include:
 *
 * <ul>
 *   <li>Tracking outbound peers separately for routing and offered-key fetches.
 *   <li>Allowing local reassignment during timeout handling to avoid false errors.
 *   <li>Issuing deferred hard timeouts when a handler continues past the timeout.
 * </ul>
 *
 * @see PeerNode
 * @see RequestTracker
 * @see UIDTraceLogger
 * @author Matthew Toseland {@literal <toad@amphibian.dyndns.org>} (0xE43DA450)
 */
public abstract class UIDTag {
  private static final Logger LOG = LoggerFactory.getLogger(UIDTag.class);
  private static final String DEBUG_EXCEPTION_MESSAGE = "debug";
  private static final String PEER_LOG_PREFIX = "peer=";
  private static final String REMOVED_LOG_FRAGMENT = " removed=";
  private static final long HARD_TIMEOUT_AFTER_CONTINUE = RequestTracker.TIMEOUT;
  private static final PeerNode[] NO_PEERS = new PeerNode[0];

  // No static initialization required.

  final long createdTime;
  final boolean wasLocal;
  private final WeakReference<PeerNode> sourceRef;
  final boolean realTimeFlag;

  /**
   * Tracker responsible for UID lifecycle and unlock bookkeeping.
   *
   * <p>The tracker reference is established at construction from the owning node. It is stable and
   * non-null for the lifetime of the tag and is used by {@link #innerUnlock(boolean)} to release
   * the UID and update routing statistics.
   */
  protected final RequestTracker tracker;

  /**
   * Indicates whether the inbound handler has accepted the request.
   *
   * <p>This flag is set when the handler decides to process the request. Subclasses may use it to
   * reason about progress and for logging. Access is synchronized on the tag when mutated or read
   * concurrently.
   */
  protected boolean accepted;

  /**
   * Signals that the original source has restarted or disconnected.
   *
   * <p>When true, routing decisions may treat the request as restarted, and continuation behavior
   * changes to avoid sending additional messages to the original source. The value is updated while
   * the request is in flight and can be consulted by subclasses.
   */
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

  /**
   * Marks that the request should not be routed further downstream.
   *
   * <p>Handlers set this flag when they decide no additional peers should be contacted. It is
   * mutable, read by subclasses and routing policies, and is guarded by the tag monitor when
   * updates are concurrent.
   */
  protected boolean notRoutedOnwards;

  final long uid;

  /**
   * Tracks whether the inbound handler has completed and unlocked.
   *
   * <p>Once true, the UID can be released when no outbound peers remain. This flag is updated by
   * {@link #unlockHandler(boolean)} and should only be changed while holding the tag monitor.
   */
  protected boolean unlockedHandler;

  /**
   * Controls whether unlock bookkeeping should be recorded.
   *
   * <p>When true, the tag should be released without emitting certain record updates. It is set by
   * the inbound handler during unlocking to suppress record writing in specific call paths and is
   * read by {@link #innerUnlock(boolean)}.
   */
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
   * Logs that this tag remains after the request timeout threshold.
   *
   * <p>Subclasses decide the logging level, wording, and identifiers because they know the request
   * type. This callback is invoked by {@link #maybeLogStillPresent(long, Long)} once the timeout
   * has elapsed and can be called multiple times over the lifetime of the tag; rate limiting is
   * handled by the caller. Implementations should be lightweight and tolerate a {@code null} UID
   * when the subclass cannot or should not expose the identifier.
   *
   * @param uid optional UID to include; may be {@code null} in local contexts
   */
  public abstract void logStillPresent(Long uid);

  long age() {
    return System.currentTimeMillis() - createdTime;
  }

  /**
   * Records that this tag is routing to a peer or fetching an offered key.
   *
   * <p>Call this before the outbound message is sent so per-peer capacity accounting and timeout
   * handling can attribute work correctly. The peer is added to the historical {@code routedTo} set
   * and also to the active routing set that matches the {@code offeredKey} flag. The method is
   * synchronized to avoid concurrent mutations of the peer sets and returns whether the peer was
   * newly recorded for this activity.
   *
   * @param peer peer being routed to or fetched from; must be non-null
   * @param offeredKey {@code true} for offered-key fetches, {@code false} for normal routing
   * @return {@code true} if the peer was newly recorded; {@code false} if already present
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
   * Reports whether this tag has ever routed to the given peer.
   *
   * <p>This query checks the historical routing set, not just the currently active peers. It is
   * synchronized to provide a consistent view of routing history when other threads are updating
   * the sets. A {@code false} return means the peer has never been recorded for this tag, and it
   * does not imply anything about current reachability.
   *
   * @param peer peer to test against the historical routing set
   * @return {@code true} when the peer is present in the history; {@code false} otherwise
   */
  @SuppressWarnings("unused")
  public synchronized boolean hasRoutedTo(PeerNode peer) {
    if (routedTo == null) return false;
    return routedTo.contains(peer);
  }

  /**
   * Reports whether this tag is currently routing to the given peer.
   *
   * <p>The check consults the active routing set, which represents peers that still consider the
   * UID active on their side. The method is synchronized to avoid concurrent modification while
   * routing decisions or removals are in progress. It does not guarantee that an outbound sending
   * is currently in flight or that it will succeed.
   *
   * @param peer peer to test against the active routing set
   * @return {@code true} if the peer is currently active; {@code false} if not recorded
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
   * Reports whether this tag is currently fetching an offered key from a peer.
   *
   * <p>This check reads the active offered-key set, which is distinct from normal routing peers and
   * may use different timeout behavior. The method is synchronized to avoid concurrent modification
   * while updates or removals are happening. A {@code true} result means the tag still expects an
   * offered-key response, not that the transfer is guaranteed.
   *
   * @param peer peer to test against the offered-key fetch set
   * @return {@code true} if the peer is currently in the offered-key set; otherwise {@code false}
   */
  public synchronized boolean currentlyFetchingOfferedKeyFrom(PeerNode peer) {
    if (fetchingOfferedKeyFrom == null) return false;
    return fetchingOfferedKeyFrom.contains(peer);
  }

  /**
   * Marks that we no longer fetch an offered key from a peer.
   *
   * <p>Call this only once the peer is reasonably certain we stopped the offered-key fetch, similar
   * to {@link #removeRoutingTo(PeerNode)}. The peer is removed from the offered-key tracking set
   * and from timeout handling bookkeeping. If this change makes the tag eligible for unlocking and
   * the handler is already unlocked, the method triggers {@link #innerUnlock(boolean)} after
   * releasing the monitor.
   *
   * @param next peer that is no longer providing an offered key
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
   * Marks that we no longer route to a peer.
   *
   * <p>When no peers remain in the routing or offered-key sets and the handler has unlocked, the
   * tag becomes eligible for full unlocking. Call this only when the peer is reasonably certain we
   * stopped routing to it so that early unlock does not race with downstream completion. The method
   * also clears timeout bookkeeping for the peer and can trigger {@link #innerUnlock(boolean)}
   * after the synchronized section completes.
   *
   * @param next peer that is no longer being routed to
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

  /**
   * Performs the actual UID unlocking through the tracker.
   *
   * <p>This method delegates to {@link RequestTracker#unlockUID(UIDTag, boolean, boolean)} with the
   * correct flags for this tag. It should be called immediately after {@link #mustUnlock()} returns
   * {@code true} so that state and accounting remain consistent. Callers should already have
   * decided that no further outbound routing or offered-key fetches remain.
   *
   * @param noRecordUnlock whether to suppress unlock record bookkeeping for this tag
   */
  protected void innerUnlock(boolean noRecordUnlock) {
    tracker.unlockUID(this, false, noRecordUnlock);
  }

  /**
   * Notifies peers that previously tracked this tag after it has been unlocked.
   *
   * <p>This method is the best effort: it snapshots the {@code routedTo} set and invokes {@link
   * PeerNode#postUnlock(Object)} for each peer that is still reachable. Missing or already
   * disconnected peers are ignored. Callers should invoke it after {@link #innerUnlock(boolean)} to
   * allow peers to release any tag-specific bookkeeping on their side.
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
   * Estimates expected inbound transfers attributed to this tag.
   *
   * <p>The estimate is used to decide whether a request should be accepted or how aggressively it
   * should be routed. Subclasses should account for the request type, locality, and any special
   * cases that change transfer counts. The returned value is used for control decisions rather than
   * exact accounting, so it should be conservative when {@code forAccept} is {@code false}.
   *
   * @param ignoreLocalVsRemote when {@code true}, treat the request as remote
   * @param outwardTransfersPerInsert expected outbound transfers per insert operation
   * @param forAccept {@code true} for admission control; {@code false} for send decisions
   * @return estimated number of inbound transfers this tag is expected to represent
   */
  public abstract int expectedTransfersIn(
      boolean ignoreLocalVsRemote, int outwardTransfersPerInsert, boolean forAccept);

  /**
   * Estimates expected outbound transfers attributed to this tag.
   *
   * <p>The estimate informs routing and admission control decisions for outbound traffic.
   * Subclasses should incorporate request type and locality when deriving the count, and they
   * should be conservative when the result is used for sending decisions. The method is abstract,
   * so each request type can encode its specific transfer pattern.
   *
   * @param ignoreLocalVsRemote when {@code true}, treat the request as remote
   * @param outwardTransfersPerInsert expected outbound transfers per insert operation
   * @param forAccept {@code true} for admission control; {@code false} for send decisions
   * @return estimated number of outbound transfers this tag is expected to represent
   */
  public abstract int expectedTransfersOut(
      boolean ignoreLocalVsRemote, int outwardTransfersPerInsert, boolean forAccept);

  /**
   * Marks that this request will not be routed further downstream.
   *
   * <p>This flag is set by handlers that decide no additional peers should be contacted. It does
   * not itself unlock the tag, but it can influence subclass decisions and routing heuristics. The
   * method does not alter existing routing sets, and it is synchronized to keep the state
   * consistent with other routing updates.
   */
  public synchronized void setNotRoutedOnwards() {
    this.notRoutedOnwards = true;
  }

  private boolean reassigned;

  /**
   * Returns the effective source peer for load management.
   *
   * <p>The original source is returned only when the request was not local and has not been
   * reassigned to self. Because the reference is weak, the GC may also have cleared the peer, in
   * which case this method returns {@code null}. The method is synchronized to provide a consistent
   * view with reassignment updates.
   *
   * @return the original source peer, or {@code null} if local, reassigned, or collected
   */
  public synchronized PeerNode getSource() {
    if (reassigned) return null;
    if (wasLocal) return null;
    return sourceRef.get();
  }

  /**
   * Reassigns the tag locally rather than attributing it to the original sender.
   *
   * <p>When invoked for a non-local tag, the request is treated as locally owned for later load
   * management decisions. Calls are idempotent; invoking this method on a locally originated tag is
   * a no-op. After reassignment, {@link #getSource()} returns {@code null}, and accounting treats
   * the request as local. The method records the reassignment in {@link UIDTraceLogger}.
   */
  public synchronized void reassignToSelf() {
    if (wasLocal) return;
    reassigned = true;
    UIDTraceLogger.log("reassignToSelf", this);
  }

  /**
   * Reports whether the request originated locally.
   *
   * <p>This value reflects the original origin and is not affected by {@link #reassignToSelf()}.
   * The method is inexpensive and does not synchronize because the flag is immutable after
   * construction. Callers often use it to distinguish local requests from those that arrived from a
   * peer for accounting and logging.
   *
   * @return {@code true} if the request was created locally; {@code false} otherwise
   */
  public boolean wasLocal() {
    return wasLocal;
  }

  /**
   * Reports whether the request is considered local now.
   *
   * <p>A tag is considered local if it originated locally or if it has been reassigned to self as
   * part of timeout handling. The method synchronizes when checking the reassignment state to avoid
   * races with updates. It is safe to call immediately after {@link #reassignToSelf()} to reflect
   * the updated ownership.
   *
   * @return {@code true} if the request is treated as local; {@code false} otherwise
   */
  public boolean isLocal() {
    if (wasLocal) return true;
    synchronized (this) {
      return reassigned;
    }
  }

  /**
   * Reports whether this tag represents an SSK request.
   *
   * <p>Subclasses implement this to reflect the request type. The result is used by routing and
   * logging decisions that need to distinguish SSK traffic from other request classes. It also
   * informs transfer estimation for requests that have different patterns. Callers treat the value
   * as stable for the lifetime of the tag.
   *
   * @return {@code true} if the underlying request is an SSK; {@code false} otherwise
   */
  public abstract boolean isSSK();

  /**
   * Reports whether this tag represents an insert request.
   *
   * <p>Subclasses should return {@code true} when the request inserts data rather than fetching it.
   * The flag influences transfer estimation and some routing policies, so implementations should be
   * consistent with the request's primary data flow. The return value is expected to remain
   * consistent for the lifetime of the tag.
   *
   * @return {@code true} if the request inserts data; {@code false} otherwise
   */
  public abstract boolean isInsert();

  /**
   * Reports whether this tag represents a reply to an offer.
   *
   * <p>Offer replies often use different timeout handling and transfer expectations. Subclasses
   * should return {@code true} for those requests so routing decisions can reflect that behavior.
   * The result may also influence how peers are tracked for offered-key handling. Callers should
   * not assume an offer reply implies any particular routing peer set.
   *
   * @return {@code true} if the request is an offer reply; {@code false} otherwise
   */
  public abstract boolean isOfferReply();

  /**
   * Determines whether the tag can be unlocked right now.
   *
   * <p>This method checks handler state and outstanding routing or offered-key fetches. If it
   * returns {@code true}, callers must invoke {@link #innerUnlock(boolean)} immediately while still
   * honoring any subclass-specific unlocking blockers. It also latches the unlocking decision so
   * that only one caller proceeds with the actual unlocking.
   *
   * @return {@code true} if the tag is ready to unlock; {@code false} otherwise
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
   * Marks the inbound handler as complete and attempts to unlock the tag.
   *
   * <p>This method should be called before sending the completion acknowledgement downstream so the
   * peer does not assume completion while we are still holding its slot. It records the {@code
   * noRecord} preference, marks the handler as unlocked, and then checks whether outbound routing
   * or offered-key fetches remain. If none remain, it triggers {@link #innerUnlock(boolean)};
   * otherwise it logs that the unlocking is deferred.
   *
   * @param noRecord whether to suppress unlock record bookkeeping for this tag
   */
  public void unlockHandler(boolean noRecord) {
    boolean canUnlock;
    boolean localNoRecordUnlock = false;
    synchronized (this) {
      if (unlockedHandler) return;
      noRecordUnlock = noRecord;
      unlockedHandler = true;
      canUnlock = mustUnlock();
      if (canUnlock) {
        localNoRecordUnlock = this.noRecordUnlock;
      }
    }
    UIDTraceLogger.log(
        "unlockHandler", this, () -> "noRecord=" + noRecord + " canUnlock=" + canUnlock);
    if (canUnlock) innerUnlock(localNoRecordUnlock);
    else {
      LOG.info("Defer unlock in unlockHandler; still sending requests");
    }
  }

  /**
   * Convenience overload that unlocks the handler with recording enabled.
   *
   * <p>This is equivalent to calling {@link #unlockHandler(boolean)} with {@code false}. It is
   * provided for call sites that do not need to suppress unlock record bookkeeping. Repeated calls
   * are safe because the underlying method checks and returns once the handler is already unlocked.
   */
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
   * Records that a timeout is being handled for a peer.
   *
   * <p>If the handler later unlocks while the peer still appears in the routing or offered-key
   * tracking sets, this marker allows the tag to be reassigned locally instead of logging a
   * spurious error. The timeout marker is cleared when the peer is removed from tracking sets.
   * Adding the same peer more than once is harmless because the set deduplicates entries.
   *
   * @param next peer for which a timeout is being handled
   */
  public synchronized void handlingTimeout(PeerNode next) {
    if (handlingTimeouts == null) handlingTimeouts = new HashSet<>();
    handlingTimeouts.add(next);
    UIDTraceLogger.log("handlingTimeout", this, () -> PEER_LOG_PREFIX + next.shortToString());
  }

  private long loggedStillPresent;
  private static final long LOGGED_STILL_PRESENT_INTERVAL = SECONDS.toMillis(60);

  /**
   * Logs that the tag is still present after the request timeout.
   *
   * <p>This method rate-limits logging to at most once per interval and delegates to {@link
   * #logStillPresent(Long)} for the actual message. It should be called with a monotonically
   * increasing time source, typically {@link System#currentTimeMillis()}. After logging checks, it
   * also evaluates whether a deferred hard timeout should be forced.
   *
   * @param now current time in milliseconds since the epoch
   * @param uid optional UID to include in the subclass log, may be {@code null}
   */
  public void maybeLogStillPresent(long now, Long uid) {
    if (now - createdTime > RequestTracker.TIMEOUT) {
      synchronized (this) {
        if (now - loggedStillPresent < LOGGED_STILL_PRESENT_INTERVAL) return;
        loggedStillPresent = now;
      }
      logStillPresent(uid);
    }
    maybeForceHardTimeout(now);
  }

  /**
   * Marks this request as accepted by the handler.
   *
   * <p>This flag is used by subclasses to reason about progress and logging. The update is
   * synchronized to avoid races with other handler state transitions. Repeated calls are safe and
   * simply leave the flag set. The flag does not indicate anything about an outbound routing state.
   */
  public synchronized void setAccepted() {
    accepted = true;
  }

  private boolean timedOutButContinued;
  private long timeoutContinueAt;
  private boolean hardTimeoutPeersTriggered;
  private boolean hardTimeoutWithoutPeersTriggered;

  /**
   * Marks that the handler timed out but processing continues.
   *
   * <p>This state is used when we must inform downstream that the request has timed out but cannot
   * yet terminate it. The request still counts toward the peer's limit, but messages to the source
   * may continue. The method is idempotent and records the first time the timeout-continue state
   * was set so that hard timeout logic can be scheduled.
   */
  public synchronized void timedOutToHandlerButContinued() {
    if (!timedOutButContinued) {
      timedOutButContinued = true;
      timeoutContinueAt = System.currentTimeMillis();
    } else if (timeoutContinueAt == 0L) {
      timeoutContinueAt = System.currentTimeMillis();
    }
    UIDTraceLogger.log("timeoutContinue", this);
  }

  private void maybeForceHardTimeout(long now) {
    HardTimeoutContext context = resolveHardTimeoutContext(now);
    if (context == null) return;
    if (context.handleWithoutPeers()) {
      if (handleHardTimeoutWithoutPeers(context.continueAge())) {
        markHardTimeoutWithoutPeersTriggered();
      }
      return;
    }
    logAndForcePeerTimeout(context.continueAge(), context.routingPeers(), context.offeredPeers());
  }

  private HardTimeoutContext resolveHardTimeoutContext(long now) {
    PeerNode[] routingPeersArray;
    PeerNode[] offeredPeersArray;
    long continueAge;
    synchronized (this) {
      if (!timedOutButContinued || !unlockedHandler) return null;
      if (timeoutContinueAt == 0L) return null;
      continueAge = now - timeoutContinueAt;
      if (continueAge < HARD_TIMEOUT_AFTER_CONTINUE) return null;
      routingPeersArray = routingPeersForHardTimeout();
      offeredPeersArray = offeredKeyPeersForHardTimeout();
    }
    List<PeerNode> routingPeers = List.of(routingPeersArray);
    List<PeerNode> offeredPeers = List.of(offeredPeersArray);
    boolean handleWithoutPeers = routingPeers.isEmpty() && offeredPeers.isEmpty();
    if (!handleWithoutPeers) {
      if (!markHardTimeoutPeersTriggered()) return null;
    } else if (!shouldHandleHardTimeoutWithoutPeers()) {
      return null;
    }
    return new HardTimeoutContext(continueAge, routingPeers, offeredPeers, handleWithoutPeers);
  }

  private boolean markHardTimeoutPeersTriggered() {
    synchronized (this) {
      if (hardTimeoutPeersTriggered) return false;
      hardTimeoutPeersTriggered = true;
      return true;
    }
  }

  private boolean shouldHandleHardTimeoutWithoutPeers() {
    synchronized (this) {
      return !hardTimeoutWithoutPeersTriggered;
    }
  }

  private void markHardTimeoutWithoutPeersTriggered() {
    synchronized (this) {
      hardTimeoutWithoutPeersTriggered = true;
    }
  }

  private void logAndForcePeerTimeout(
      long continueAge, List<PeerNode> routingPeers, List<PeerNode> offeredPeers) {
    String routingSummary = formatPeers(routingPeers);
    String offeredSummary = formatPeers(offeredPeers);
    String elapsed = TimeUtil.formatTime(continueAge);
    UIDTraceLogger.log(
        "timeoutHard",
        this,
        () -> "elapsed=" + elapsed + " routing=" + routingSummary + " offered=" + offeredSummary);
    LOG.warn(
        "Hard timeout after {} for {}. Forcing fatal timeout: routing={} offered={}",
        elapsed,
        this,
        routingSummary,
        offeredSummary);
    for (PeerNode peer : routingPeers) {
      peer.fatalTimeout(this, false);
    }
    for (PeerNode peer : offeredPeers) {
      peer.fatalTimeout(this, true);
    }
  }

  /**
   * Returns a snapshot of peers still considered active for routing timeouts.
   *
   * <p>The returned array is built while holding the tag monitor, so it is safe to iterate without
   * concurrent modification. Callers should treat it as a snapshot for timeout forcing and logging;
   * later routing updates may change the active set. An empty array indicates there are no active
   * routing peers at the time of the snapshot.
   *
   * @return array of active routing peers, or an empty array if none remain
   */
  protected synchronized PeerNode[] routingPeersForHardTimeout() {
    if (currentlyRoutingTo == null || currentlyRoutingTo.isEmpty()) return NO_PEERS;
    return currentlyRoutingTo.toArray(new PeerNode[0]);
  }

  /**
   * Returns a snapshot of peers still considered active for offered-key timeouts.
   *
   * <p>The returned array is produced while holding the tag monitor, providing a consistent view of
   * the offered-key tracking set. It should be used for timeout enforcement and logging only, not
   * as a live view. An empty array indicates there are no active offered-key peers at the time of
   * the snapshot.
   *
   * @return array of active offered-key peers, or an empty array if none remain
   */
  protected synchronized PeerNode[] offeredKeyPeersForHardTimeout() {
    if (fetchingOfferedKeyFrom == null || fetchingOfferedKeyFrom.isEmpty()) return NO_PEERS;
    return fetchingOfferedKeyFrom.toArray(new PeerNode[0]);
  }

  /**
   * Allows subclasses to handle hard-timeout conditions when no peers remain.
   *
   * <p>This hook is invoked after a timeout-continue period elapses, and there are no routing or
   * offered-key peers left to force. Subclasses can perform request-specific cleanup or accounting
   * and return {@code true} to mark the timeout as handled. Returning {@code false} leaves handling
   * to the default path.
   *
   * @param continueAge time since timeout-continue was first recorded, in milliseconds
   * @return {@code true} if the timeout was handled and should be marked as triggered
   */
  protected boolean handleHardTimeoutWithoutPeers(long continueAge) {
    return false;
  }

  private record HardTimeoutContext(
      long continueAge,
      List<PeerNode> routingPeers,
      List<PeerNode> offeredPeers,
      boolean handleWithoutPeers) {}

  private static String formatPeers(List<PeerNode> peers) {
    if (peers.isEmpty()) return "none";
    StringBuilder sb = new StringBuilder();
    for (PeerNode peer : peers) {
      sb.append(peer.shortToString()).append(',');
    }
    sb.setLength(sb.length() - 1);
    return sb.toString();
  }

  /**
   * Marks that the original source handler disconnected or restarted.
   *
   * <p>This update affects load accounting and stop/continue decisions. Once set, the tag treats
   * the request as having a restarted source, which influences {@link #countAsSourceRestarted()}
   * and {@link #shouldStop()} decisions. The call is idempotent and simply leaves the flag set.
   * Callers typically invoke it when a disconnect or restart is detected.
   */
  public synchronized void onRestartOrDisconnectSource() {
    sourceRestarted = true;
  }

  // The third option is reassignToSelf(). We only use that when we actually
  // want the data and mean to continue. In that case, none of the next three
  // are appropriate.

  /**
   * Reports whether this request should be deducted from the source's limit.
   *
   * <p>Normal requests count toward the source's limit, but some situations such as source restarts
   * or timeout continuation are accounted for differently. This method encapsulates that policy for
   * callers that manage admission and throttling. It has no side effects and depends only on the
   * current restart and timeout state.
   *
   * @return {@code true} if the request should be deducted; {@code false} if it should count toward
   *     the source's limit
   */
  public synchronized boolean countAsSourceRestarted() {
    return sourceRestarted || timedOutButContinued;
  }

  /**
   * Reports whether the original source is considered restarted.
   *
   * <p>This is a direct accessor for the restart flag and is synchronized to provide a consistent
   * view when other threads update the flag due to disconnects. Unlike {@link
   * #countAsSourceRestarted()}, it does not consider timeout-continuation state. Callers use it to
   * decide whether messages to the source should continue.
   *
   * @return {@code true} if the source is considered restarted; {@code false} otherwise
   */
  public synchronized boolean hasSourceReallyRestarted() {
    return sourceRestarted;
  }

  /**
   * Reports whether the request should stop as soon as convenient.
   *
   * <p>Stopping is typically recommended when the source has restarted or when the request has
   * timed out but continues. The method is synchronized to reflect the latest updates to restart
   * and timeout state. It is advisory only and does not cancel work on its own.
   *
   * @return {@code true} if the request should stop; {@code false} if it may continue
   */
  public synchronized boolean shouldStop() {
    return sourceRestarted || timedOutButContinued;
  }

  /**
   * Reports whether the given peer is the original source of this tag.
   *
   * <p>The comparison returns {@code false} if the tag has been reassigned or originated locally.
   * It uses the stored weak reference to avoid retaining the source peer longer than necessary and
   * synchronizes to keep the reassignment state consistent. If the weak reference has been cleared,
   * the method returns {@code false} even when the peer was once the source.
   *
   * @param pn peer to compare against the original source; must be non-null
   * @return {@code true} if the peer is the original source, and the tag is not local or reassigned
   */
  public synchronized boolean isSource(PeerNode pn) {
    if (reassigned) return false;
    if (wasLocal) return false;
    if (sourceRef == null) return false;
    return sourceRef == pn.myRef;
  }

  /**
   * Marks that the tag is waiting for an outbound slot.
   *
   * <p>This state is used by handlers to avoid double-counting pending outbound work. The method is
   * synchronized and idempotent, and it does not itself allocate or release any slots. Callers
   * should ensure {@link #clearWaitingForSlot()} is invoked when the wait ends or on teardown.
   */
  public synchronized void setWaitingForSlot() {
    // Consider using a counter on Node.
    // We must ensure it ALWAYS gets unset when some weird
    // error happens.
    if (waitingForSlot) return;
    waitingForSlot = true;
  }

  /**
   * Clears the waiting-for-slot state.
   *
   * <p>This method is synchronized and idempotent. It is typically called when outbound work has
   * got a slot or when the request is being torn down. If the tag was not marked as waiting, the
   * call has no effect. Clearing the flag does not release any external resources.
   */
  public synchronized void clearWaitingForSlot() {
    // Consider using a counter on Node.
    // We must ensure it ALWAYS gets unset when some weird
    // error happens.
    // Clearing on unlocking may suffice depending on call paths.
    if (!waitingForSlot) return;
    waitingForSlot = false;
  }

  /**
   * Reports whether the tag is currently waiting for an outbound slot.
   *
   * <p>The return value reflects the most recent calls to {@link #setWaitingForSlot()} and {@link
   * #clearWaitingForSlot()}. The method is synchronized to avoid races with updates and does not
   * imply anything about the state of any external queues. It is purely a local bookkeeping signal.
   *
   * @return {@code true} if the tag is waiting for a slot; {@code false} otherwise
   */
  public synchronized boolean isWaitingForSlot() {
    return waitingForSlot;
  }
}
