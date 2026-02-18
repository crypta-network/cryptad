package network.crypta.node;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.keys.Key;
import network.crypta.keys.NodeCHK;
import network.crypta.keys.NodeSSK;
import network.crypta.node.PeerNodeLoadTracker.RequestLikelyAcceptedState;
import network.crypta.node.PeerNodeLoadTracker.SlotWaiter;
import network.crypta.node.PeerNodeLoadTracker.SlotWaiterFailedException;
import network.crypta.support.TimeUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.concurrent.TimeUnit.MINUTES;

/**
 * Base class for request and insert senders.
 *
 * <p>This type coordinates routing a request to a peer, including:
 *
 * <ul>
 *   <li>Choosing and contacting a {@link PeerNode} until a request is accepted.
 *   <li>Managing HTL (hop-to-live) before acceptance and stopping when it is exhausted.
 *   <li>Applying load-management policies (legacy and “new” NLM) while waiting for capacity.
 *   <li>Interpreting early control messages such as Accepted/RejectedLoop/RejectedOverload.
 * </ul>
 *
 * <p>Subclasses handle all post-accept processing by overriding {@link #onAccepted(PeerNode)} and
 * implement request-specific behavior (e.g., building the wire message via {@link
 * #createDataRequest()}).
 *
 * <p>Thread-safety: instances are used by a single routing flow; some fields/methods are
 * synchronized to protect short-lived state transitions observed by helper threads (e.g., message
 * delivery callbacks).
 */
public abstract class BaseSender implements ByteCounter, HighHtlAware {
  private static final Logger LOG = LoggerFactory.getLogger(BaseSender.class);
  private static final String TOOK_MSG = "Took {} tries in {}{}";

  protected static final AtomicIntegerFieldUpdater<BaseSender> ROUTE_ATTEMPTS_UPDATER =
      AtomicIntegerFieldUpdater.newUpdater(BaseSender.class, "routeAttempts");

  final boolean realTimeFlag;
  final Key key;

  /** The origin of the request, if known. Used to avoid routing back to the source. */
  final PeerNode source;

  final double target;
  final boolean isSSK;

  /** The initial HTL recorded at construction time. */
  protected final short origHTL;

  final Node node;

  /** Monotonic wall-clock at construction time (milliseconds since epoch). */
  protected final long startTime;

  long uid;
  static final long SEARCH_TIMEOUT_BULK = MINUTES.toMillis(10);
  static final long SEARCH_TIMEOUT_REALTIME = MINUTES.toMillis(1);
  final int incomingSearchTimeout;

  BaseSender(Key key, boolean realTimeFlag, PeerNode source, Node node, short htl, long uid) {
    this(validateConstructionState(key, realTimeFlag, node, htl), realTimeFlag, source, htl, uid);
  }

  private BaseSender(
      ConstructionState state, boolean realTimeFlag, PeerNode source, short htl, long uid) {
    Key resolvedKey = state != null ? state.key : null;
    Node resolvedNode = state != null ? state.node : null;
    double resolvedTarget = state != null ? state.target : 0.0d;
    boolean resolvedIsSSK = state != null && state.isSSK;
    boolean resolvedNewLoadManagement = state != null && state.newLoadManagement;
    int resolvedIncomingSearchTimeout = state != null ? state.incomingSearchTimeout : 0;

    startTime = System.currentTimeMillis();
    this.uid = uid;
    this.key = resolvedKey;
    this.realTimeFlag = realTimeFlag;
    this.node = resolvedNode;
    this.source = source;
    target = resolvedTarget;
    this.isSSK = resolvedIsSSK;
    this.htl = htl;
    this.origHTL = htl;
    newLoadManagement = resolvedNewLoadManagement;
    incomingSearchTimeout = resolvedIncomingSearchTimeout;
  }

  private static ConstructionState validateConstructionState(
      Key key, boolean realTimeFlag, Node node, short htl) {
    Key checkedKey = requireRoutingKey(key);
    double target = checkedKey.toNormalizedDouble();
    boolean isSSK = checkedKey instanceof NodeSSK;
    assert (isSSK || checkedKey instanceof NodeCHK);
    Node checkedNode = requireNode(node);
    boolean newLoadManagement = checkedNode.network().enableNewLoadManagement(realTimeFlag);
    int incomingSearchTimeout = calculateTimeout(realTimeFlag, htl, checkedNode);
    return new ConstructionState(
        checkedKey, checkedNode, target, isSSK, newLoadManagement, incomingSearchTimeout);
  }

  /**
   * Validates that the sender key contains a routing key before base-constructor state is built.
   *
   * @param key key used for routing
   * @return the same key when valid
   * @throws NullPointerException if the key does not contain a routing key
   */
  protected static Key requireRoutingKey(Key key) {
    if (key.getRoutingKey() == null) {
      throw new NullPointerException("Routing key must not be null");
    }
    return key;
  }

  private static Node requireNode(Node node) {
    if (node == null) {
      throw new NullPointerException("node");
    }
    return node;
  }

  private record ConstructionState(
      Key key,
      Node node,
      double target,
      boolean isSSK,
      boolean newLoadManagement,
      int incomingSearchTimeout) {}

  static final double EXTRA_HOPS_AT_BOTTOM = 1.0 / Node.DECREMENT_AT_MIN_PROB;

  /**
   * Compute the incoming-search timeout for the current HTL and mode.
   *
   * <p>The timeout scales linearly with {@code htl} over the range {@code [EXTRA_HOPS_AT_BOTTOM,
   * maxHTL + EXTRA_HOPS_AT_BOTTOM]} and uses a shorter base in realtime mode.
   *
   * @param realTimeFlag whether the request is realtime
   * @param htl hop-to-live used for the current attempt
   * @param node node providing {@link Node#maxHTL()}
   * @return timeout in milliseconds
   */
  public static int calculateTimeout(boolean realTimeFlag, short htl, Node node) {
    double timeout = realTimeFlag ? SEARCH_TIMEOUT_REALTIME : SEARCH_TIMEOUT_BULK;
    timeout = timeout * (htl + EXTRA_HOPS_AT_BOTTOM) / (EXTRA_HOPS_AT_BOTTOM + node.maxHTL());
    return (int) timeout;
  }

  /**
   * Instance helper for {@link #calculateTimeout(boolean, short, Node)} using this sender's mode
   * and node.
   *
   * @param htl hop-to-live used for the current attempt
   * @return timeout in milliseconds
   */
  protected int calculateTimeout(short htl) {
    return calculateTimeout(realTimeFlag, htl, node);
  }

  private short hopsForTime(long time) {
    double timeout = realTimeFlag ? SEARCH_TIMEOUT_REALTIME : SEARCH_TIMEOUT_BULK;
    double timePerHop = timeout / (EXTRA_HOPS_AT_BOTTOM + node.maxHTL());
    return (short) Math.min(node.maxHTL(), time / timePerHop);
  }

  /**
   * Create the outbound data request message for the current attempt.
   *
   * <p>Implementations populate any fields required by the protocol (e.g., UID/HTL/flags). The
   * returned message is sent synchronously to the selected peer.
   *
   * @return non-{@code null} request message
   */
  protected abstract Message createDataRequest();

  /** The most recent peer that this sender attempted to route to. May be {@code null}. */
  protected final AtomicReference<PeerNode> lastNode = new AtomicReference<>();

  /**
   * Return the most recent peer that this sender routed to.
   *
   * @return last routed peer, or {@code null} if none
   */
  public synchronized PeerNode routedLast() {
    return lastNode.get();
  }

  /** Set of peers this sender has attempted to route to during the current operation. */
  protected HashSet<PeerNode> nodesRoutedTo = new HashSet<>();

  /** Timestamp of the most recent sending attempt used for timeout accounting (milliseconds). */
  private long timeSentRequest;

  /**
   * Milliseconds have elapsed since the most recent sending attempt recorded by this sender.
   *
   * @return elapsed time in milliseconds
   */
  protected synchronized int timeSinceSent() {
    return (int) (System.currentTimeMillis() - timeSentRequest);
  }

  protected boolean hasForwarded;

  protected int gotMessages;
  protected String lastMessage;

  /** Current HTL for the ongoing attempt; decremented by the routing loop as appropriate. */
  protected short htl;

  /** Number of local {@code RejectedOverload} outcomes observed during this operation. */
  protected int rejectOverloads;

  /** Number of peers attempted so far (excluding soft retries on the same peer). */
  protected volatile int routeAttempts = 0;

  private HashMap<PeerNode, Integer> softRejectCount;

  /**
   * When set, the next rerouting must not decrement {@link #htl}. The caller resets the flag after
   * it observes the rerouting condition.
   */
  protected boolean dontDecrementHTLThisTime;

  final boolean newLoadManagement;

  /**
   * Main routing loop implemented by subclasses.
   *
   * <p>Responsibilities typically include: HTL decrement and termination on exhaustion; consulting
   * RecentlyFailed; handling insert forks for cacheable content; choosing a peer and delegating to
   * {@link #innerRouteRequests(PeerNode, UIDTag)}. Implementations may call back into this method
   * to try another peer.
   */
  protected abstract void routeRequests();

  /**
   * Execute a single routing attempt using either legacy or new load management.
   *
   * <p>This method routes to {@code next} (or a better alternative chosen by NLM), waits for an
   * early response (Accepted/reject), and either calls {@link #onAccepted(PeerNode)} or requests a
   * rerouting by invoking {@link #routeRequests()}.
   *
   * @param next initial peer to try
   * @param origTag routing tag used to correlate messages (may be updated in child flows)
   */
  protected void innerRouteRequests(PeerNode next, UIDTag origTag) {
    if (newLoadManagement) innerRouteRequestsNew(next, origTag);
    else innerRouteRequestsOld(next, origTag);
  }

  /**
   * Legacy load-management path. Sends the request to {@code next} and waits for an early decision
   * without the NLM waiter abstraction.
   *
   * <p>On local soft-overload this method requests a retry; on hard errors it requests rerouting
   * via {@link #routeRequests()}.
   */
  protected void innerRouteRequestsOld(PeerNode next, UIDTag origTag) {

    synchronized (this) {
      lastNode.set(next);
    }

    if (LOG.isDebugEnabled()) LOG.debug("Legacy route: sending request to {}", next);
    nodesRoutedTo.add(next);

    Message req = createDataRequest();

    // Record the earliest time we attempted to send. The sent() callback may arrive after an
    // acknowledgement under a heavy load, so this is the most conservative upper bound used by
    // timeout/RecentlyFailed logic.
    synchronized (this) {
      timeSentRequest = System.currentTimeMillis();
    }

    origTag.addRoutedTo(next, false);

    try {
      // First contact with a peer is more likely to time out. Prefer sendSync over sendAsync:
      // - sendSync measures ACCEPTED_TIMEOUT from the actual sending time and avoids inflating
      //   unclaimed FIFO queues; it may, however, consume part of the request time budget while
      //   waiting in the peer’s sending queue.
      // - sendAsync would increase ACCEPTED_TIMEOUT risk and leave many hanging requests, further
      //   overloading peers. Hence, we do NOT use sendAsync here.
      next.transport().sendSync(req, this, realTimeFlag);
      PeerNodeRoutingReporter.reportRoutedTo(
          node,
          next,
          new PeerNodeRoutingReportParams(
              key.toNormalizedDouble(), source == null, realTimeFlag, source, nodesRoutedTo, htl));
      node.network().peers().incrementSelectionSamples(next);
    } catch (NotConnectedException _) {
      LOG.debug("Legacy send failed: not connected");
      next.noLongerRoutingTo(origTag, false);
      routeRequests();
      return;
    } catch (SyncSendWaitedTooLongException _) {
      LOG.error("Legacy send timed out for {} to {}.", req, next);
      next.noLongerRoutingTo(origTag, false);
      // Try another node.
      routeRequests();
      return;
    }

    synchronized (this) {
      hasForwarded = true;
    }

    while (true) {
      DO action = waitForAccepted(null, next, origTag);
      // Here FINISHED means accepted; WAIT means try again (soft reject).
      if (action != DO.WAIT) {
        if (action == DO.NEXT_PEER) {
          routeRequests();
          return;
        } else { // FINISHED => accepted
          break;
        }
      }
    } // loadWaiterLoop

    if (LOG.isDebugEnabled()) LOG.debug("Accepted response received (legacy)");

    // Otherwise, we must have received Accepted.

    gotMessages = 0;
    lastMessage = null;

    onAccepted(next);
  }

  /**
   * Limit the number of nodes that we route to that reject the request due to looping while waiting
   * for a peer. This ensures that if there is a slow node, we don't route to all the other nodes
   * and DNF, rather than waiting, and possibly timing out, for the slow node. Note that this does
   * not cause us to stop routing, only to stop adding more nodes to wait for while waiting. This is
   * particularly an issue if we have a fast network connected to a slow network.
   */
  private static final int MAX_REJECTED_LOOPS = 3;

  private volatile boolean addedExtraNode = false;

  /**
   * New load-management path.
   *
   * <p>Starts with the provided {@code next} peer but may select a different one while waiting for
   * capacity. This method either calls {@link #onAccepted(PeerNode)} once accepted or requests a
   * rerouting via {@link #routeRequests()}.
   *
   * <p>IMPORTANT: When this method triggers a rerouting and {@link #dontDecrementHTLThisTime} is
   * set, the caller must not decrement HTL on the next attempt. This flag is used when the proposed
   * peer becomes unsuitable before we actually route to it; RecentlyFailed handling remains in the
   * outer selection loop.
   */
  protected void innerRouteRequestsNew(PeerNode next, UIDTag origTag) {
    NlmState state = new NlmState();
    state.type = isSSK ? NodeStats.RequestType.SSK_REQUEST : NodeStats.RequestType.CHK_REQUEST;
    state.startedTryingPeer = System.currentTimeMillis();
    state.next = next;

    while (true) {
      updateCanRerouteWhileWaiting(state);
      LOG.debug("NLM loop tick");
      state.now = System.currentTimeMillis();

      NextStep step = preWaitPhase(state, origTag);
      if (step == NextStep.REROUTED_OR_FINISHED) return;
      if (step != NextStep.PROCEED) continue; // one allowed continuing

      SendOutcome outcome = sendAndAwait(state, origTag);
      if (outcome == SendOutcome.ACCEPTED) {
        long delta = System.currentTimeMillis() - state.startedTryingPeer;
        logDelta(
            delta, state.tryCount, state.waitedForLoadManagement, state.retriedForLoadManagement);

        LOG.debug("Accepted response received (NLM)");
        gotMessages = 0;
        lastMessage = null;
        // We may have widened the waiting window earlier; reset for later iterations.
        addedExtraNode = false;
        state.next.acceptedAny(realTimeFlag);
        onAccepted(state.next);
        return;
      }
      if (outcome == SendOutcome.HARD_REROUTE) return;
      // SOFT_RETRY: fall through for the next tick
    }
  }

  private enum SendOutcome {
    ACCEPTED,
    SOFT_RETRY,
    HARD_REROUTE
  }

  private NextStep preWaitPhase(NlmState state, UIDTag origTag) {
    if (shouldRerouteBeforeWaiting(state, origTag)) return NextStep.REROUTED_OR_FINISHED;
    return prepareAndMaybeWait(state, origTag);
  }

  private SendOutcome sendAndAwait(NlmState state, UIDTag origTag) {
    rememberLastPrediction(state);

    synchronized (this) {
      lastNode.set(state.next);
    }

    LOG.debug("NLM route: sending request to {} realtime={}", state.next, realTimeFlag);
    nodesRoutedTo.add(state.next);

    Message req = createDataRequest();
    synchronized (this) {
      timeSentRequest = System.currentTimeMillis();
    }
    origTag.addRoutedTo(state.next, false);
    state.tryCount++;

    if (!sendToPeer(state, origTag, req)) return SendOutcome.HARD_REROUTE; // rerouted

    synchronized (this) {
      hasForwarded = true;
    }

    boolean accepted = waitUntilAccepted(state, origTag);
    if (accepted) return SendOutcome.ACCEPTED;
    return state.shouldContinueLoop ? SendOutcome.SOFT_RETRY : SendOutcome.HARD_REROUTE;
  }

  /** State bag for innerRouteRequestsNew to keep helper methods simple. */
  private static final class NlmState {
    NodeStats.RequestType type;
    int tryCount;
    long startedTryingPeer;
    boolean waitedForLoadManagement;
    boolean retriedForLoadManagement;
    SlotWaiter waiter;
    PeerNode lastNext;
    RequestLikelyAcceptedState lastExpectedAcceptState;
    RequestLikelyAcceptedState expectedAcceptState;
    boolean canRerouteWhileWaiting = true;
    long now;
    PeerNode next;
    boolean shouldContinueLoop;
    // Set when we already rerouted in this iteration and must exit the NLM loop.
    boolean rerouted;
  }

  // Reroute while waiting only when we have not exceeded the loop-rejection guard.
  private void updateCanRerouteWhileWaiting(NlmState state) {
    state.canRerouteWhileWaiting = true;
    synchronized (this) {
      if (rejectedLoops > MAX_REJECTED_LOOPS) state.canRerouteWhileWaiting = false;
    }
  }

  // Ensure a candidate peer is present; if not, request a rerouting without consuming HTL.
  private boolean ensureNextPeerPresent(NlmState state) {
    if (state.next != null) return true;
    dontDecrementHTLThisTime = true;
    routeRequests();
    return false;
  }

  // Predict whether the peer is likely to accept before sending, using its output load tracker.
  private void evaluateExpectedAcceptState(NlmState state, UIDTag origTag) {
    state.expectedAcceptState =
        state
            .next
            .outputLoadTracker(realTimeFlag)
            .tryRouteTo(origTag, RequestLikelyAcceptedState.LIKELY);

    if (state.expectedAcceptState == RequestLikelyAcceptedState.UNKNOWN) {
      if (LOG.isDebugEnabled())
        LOG.debug("NLM prediction missing: no load stats for {}", state.next);
      return;
    }

    if (state.expectedAcceptState != null) {
      LOG.debug(
          "Predicted accept state for {} : {} realtime={}",
          this,
          state.expectedAcceptState,
          realTimeFlag);
    }
  }

  // Handle cases where predictions guarantee a mismatch (e.g., guaranteed reject) before waiting.
  private boolean shouldRerouteBeforeWaiting(NlmState state, UIDTag origTag) {
    if (!ensureNextPeerPresent(state)) return true;
    evaluateExpectedAcceptState(state, origTag);
    return handleGuaranteedMismatch(state, origTag);
  }

  private enum NextStep {
    PROCEED,
    CONTINUE_LOOP,
    REROUTED_OR_FINISHED
  }

  // Prepare a waiter state and optionally widen the window by adding another candidate while
  // waiting.
  private NextStep prepareAndMaybeWait(NlmState state, UIDTag origTag) {
    // Reset per-iteration latch so a prior CONTINUE_LOOP does not spin forever.
    state.shouldContinueLoop = false;
    prepareWaitingIfNeeded(state, origTag);
    if (state.rerouted) return NextStep.REROUTED_OR_FINISHED;
    if (state.expectedAcceptState != null) return NextStep.PROCEED;
    maybeAddAnotherWhileWaiting(state);
    if (state.shouldContinueLoop) return NextStep.CONTINUE_LOOP;
    maybeAddAnotherWhileRealtime(state);
    if (state.shouldContinueLoop) return NextStep.CONTINUE_LOOP;
    maybeAddAnotherWhenExtraNode(state);
    if (state.shouldContinueLoop) return NextStep.CONTINUE_LOOP;
    if (!ensureExpectedOrWait(state)) return NextStep.REROUTED_OR_FINISHED;
    if (state.shouldContinueLoop) return NextStep.CONTINUE_LOOP;
    return NextStep.PROCEED;
  }

  private boolean handleGuaranteedMismatch(NlmState state, UIDTag origTag) {
    if (state.expectedAcceptState == null) return false;
    if (Objects.equals(state.lastNext, state.next)
        && state.lastExpectedAcceptState == RequestLikelyAcceptedState.GUARANTEED
        && state.expectedAcceptState == RequestLikelyAcceptedState.GUARANTEED) {
      LOG.warn(
          "Rejected overload (last time) yet expected state was {} is now {} from {} ({})",
          state.lastExpectedAcceptState,
          state.expectedAcceptState,
          state.next.shortToString(),
          state.next.getBuildNumber());
      state.next.rejectedGuaranteed(realTimeFlag);
      state.next.noLongerRoutingTo(origTag, false);
      state.expectedAcceptState = null;
      dontDecrementHTLThisTime = true;
      routeRequests();
      return true;
    }
    return false;
  }

  private void prepareWaitingIfNeeded(NlmState state, UIDTag origTag) {
    if (state.expectedAcceptState != null) return;
    LOG.debug("NLM wait: cannot send to {} realtime={}", state.next, realTimeFlag);
    state.waitedForLoadManagement = true;
    if (state.waiter == null) {
      state.waiter =
          PeerNodeLoadTracker.createSlotWaiter(origTag, state.type, realTimeFlag, source);
    }
    if (!state.waiter.addWaitingFor(state.next)) {
      dontDecrementHTLThisTime = true;
      routeRequests();
      // We attempted to queue a waiter, but the peer cannot accept us (unroutable/mandatory backoff
      // or queueing failed). This must short-circuit the NLM loop so the caller can pick another
      // peer instead of falling through to an empty-waiter timeout path.
      state.rerouted = true;
      state.shouldContinueLoop = false;
    }
  }

  private void maybeAddAnotherWhileWaiting(NlmState state) {
    if (state.expectedAcceptState != null) return;
    if (!state.next.isLowCapacity(realTimeFlag)) return;
    if (state.waiter.waitingForCount() != 1) return;
    if (!state.canRerouteWhileWaiting) return;

    int canWaitFor = 2; // base 1 + 1 because low capacity
    tryAddAnother(state, canWaitFor);
  }

  private void maybeAddAnotherWhileRealtime(NlmState state) {
    if (state.expectedAcceptState != null) return;
    int canWaitFor = 1;
    if (realTimeFlag) canWaitFor++;
    tryAddAnother(state, canWaitFor);
  }

  private void maybeAddAnotherWhenExtraNode(NlmState state) {
    if (state.expectedAcceptState != null) return;
    int canWaitFor = 1;
    if (addedExtraNode) canWaitFor++;
    tryAddAnother(state, canWaitFor);
  }

  // Opportunistically, add another candidate to the waiter to reduce latency under load.
  private void tryAddAnother(NlmState state, int canWaitFor) {
    if (!state.canRerouteWhileWaiting) return;
    if (state.waiter.waitingForCount() > canWaitFor) return;
    Set<PeerNode> exclude = state.waiter.waitingForList();
    exclude.addAll(nodesRoutedTo);
    PeerNode alsoWaitFor = closerPeer(exclude, state.now);
    if (alsoWaitFor == null) return;
    state.waiter.addWaitingFor(alsoWaitFor);
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Waiting for {} and {} on {} because realtime", state.next, alsoWaitFor, state.waiter);
    }
    try {
      PeerNode matched = state.waiter.waitForAny(0, false);
      if (matched != null) {
        state.expectedAcceptState = state.waiter.getAcceptedState();
        state.next = matched;
        if (LOG.isDebugEnabled())
          LOG.debug("Matched {} with {}", matched, state.expectedAcceptState);
      }
    } catch (SlotWaiterFailedException _) {
      if (LOG.isDebugEnabled()) LOG.debug("NLM waiter failed; rerouting");
      state.shouldContinueLoop = true;
    }
  }

  // If no prediction is available, block until a waiter matches or times out; optionally widen
  // once.
  private boolean ensureExpectedOrWait(NlmState state) {
    if (state.expectedAcceptState != null) return true;

    long maxWait = getLongSlotWaiterTimeout();
    if (!addedExtraNode) maxWait = getShortSlotWaiterTimeout();

    Set<PeerNode> waitedFor = state.waiter.waitingForList();
    try {
      PeerNode waited = state.waiter.waitForAny(maxWait, addedExtraNode);
      if (waited == null) {
        if (LOG.isDebugEnabled())
          LOG.debug("Timed out waiting for a peer to accept {} on {}", this, state.waiter);
        if (addedExtraNode) {
          timedOutWhileWaiting(getLoad(waitedFor));
          return false;
        }
        addedExtraNode = true;
        state.shouldContinueLoop = true;
        return true;
      }
      state.next = waited;
      state.expectedAcceptState = state.waiter.getAcceptedState();
      long endTime = System.currentTimeMillis();
      LOG.atDebug()
          .setMessage("Sending to {} after waited for {} realtime={}")
          .addArgument(state.next)
          .addArgument(() -> TimeUtil.formatTime(endTime - startTime))
          .addArgument(realTimeFlag)
          .log();
      return true;
    } catch (SlotWaiterFailedException _) {
      state.shouldContinueLoop = true;
      return true;
    }
  }

  // Capture the last prediction to correlate with later outcomes for diagnostics.
  private void rememberLastPrediction(NlmState state) {
    assert (state.expectedAcceptState != null);
    state.lastExpectedAcceptState = state.expectedAcceptState;
    state.lastNext = state.next;
    LOG.debug(
        "Leaving NLM block: Predicted state for {} : {} realtime={} for {}",
        this,
        state.expectedAcceptState,
        realTimeFlag,
        state.next);
  }

  // Sending synchronously to the chosen peer. On failure, request a rerouting.
  private boolean sendToPeer(NlmState state, UIDTag origTag, Message req) {
    if (origTag.hasSourceReallyRestarted()) {
      origTag.removeRoutingTo(state.next);
      routeRequests();
      return false;
    }
    try {
      state.next.transport().sendSync(req, this, realTimeFlag);
      PeerNodeRoutingReporter.reportRoutedTo(
          node,
          state.next,
          new PeerNodeRoutingReportParams(
              key.toNormalizedDouble(), source == null, realTimeFlag, source, nodesRoutedTo, htl));
      node.network().peers().incrementSelectionSamples(state.next);
      return true;
    } catch (NotConnectedException _) {
      LOG.debug("NLM send failed: not connected");
      state.next.noLongerRoutingTo(origTag, false);
      routeRequests();
      return false;
    } catch (SyncSendWaitedTooLongException _) {
      LOG.error("NLM send timed out for {} to {}.", req, state.next);
      state.next.noLongerRoutingTo(origTag, false);
      routeRequests();
      return false;
    }
  }

  // Wait for an early decision and translate it into loop control for the NLM driver.
  private boolean waitUntilAccepted(NlmState state, UIDTag origTag) {
    DO action = waitForAccepted(state.expectedAcceptState, state.next, origTag);
    switch (action) {
      case WAIT:
        // Soft local overload: break out to re-enter the NLM block and try again.
        state.retriedForLoadManagement = true;
        state.expectedAcceptState = null; // force prepare/wait on the next outer tick
        state.shouldContinueLoop = true;
        return false;
      case NEXT_PEER:
        routeRequests();
        return false;
      case FINISHED:
      default:
        return true; // accepted
    }
  }

  private PeerNode closerPeer(Set<PeerNode> exclude, long now) {
    PeerRoutingSelectionParams params =
        new PeerRoutingSelectionParams(
            sourceForRouting(),
            exclude,
            target,
            true,
            node.isAdvancedModeEnabled(),
            -1,
            null,
            2.0,
            isInsert() ? null : key,
            htl,
            ignoreLowBackoff(),
            source == null,
            realTimeFlag,
            null,
            false,
            now,
            newLoadManagement);
    return node.network().peers().routingSelector().closerPeer(params);
  }

  /**
   * Source used when computing routing choices (e.g., to avoid selecting the origin).
   *
   * <p>The base implementation returns {@link #source}. Insert senders may override to null out the
   * source in forked scenarios where the origin must be ignored.
   *
   * @return peer considered the source for routing heuristics; may be {@code null}
   */
  protected PeerNode sourceForRouting() {
    return source;
  }

  private double getLoad(Set<PeerNode> waitedFor) {
    if (waitedFor == null || waitedFor.isEmpty()) return 0.0;
    double total = 0.0;
    for (PeerNode pn : waitedFor) {
      total += pn.outputLoadTracker(realTimeFlag).proportionTimingOutFatallyInWait();
    }
    return total / waitedFor.size();
  }

  /**
   * Maximum time to wait for any peer to offer capacity when using a slot waiter.
   *
   * @return timeout in milliseconds (shorter in realtime mode)
   */
  protected long getLongSlotWaiterTimeout() {
    return (realTimeFlag ? SEARCH_TIMEOUT_REALTIME : SEARCH_TIMEOUT_BULK) / 5;
  }

  /**
   * Initial, shorter wait for capacity before widening the waiter window.
   *
   * @return timeout in milliseconds (shorter in realtime mode)
   */
  protected long getShortSlotWaiterTimeout() {
    return (realTimeFlag ? SEARCH_TIMEOUT_REALTIME : SEARCH_TIMEOUT_BULK) / 20;
  }

  /**
   * Convert a fatal slot-wait timeout into an equivalent hop budget used by failure accounting.
   *
   * @return number of hops corresponding to {@link #getLongSlotWaiterTimeout()}
   */
  protected short hopsForFatalTimeoutWaitingForPeer() {
    return hopsForTime(getLongSlotWaiterTimeout());
  }

  private void logDelta(
      long delta, int tryCount, boolean waitedForLoadManagement, boolean retriedForLoadManagement) {
    long longTimeout = getLongSlotWaiterTimeout();
    String suffix = buildDeltaSuffix(waitedForLoadManagement, retriedForLoadManagement);
    String time = TimeUtil.formatTime(delta, 2, true);
    if (delta > longTimeout || tryCount > 3) {
      LOG.error(TOOK_MSG, tryCount, time, suffix);
    } else if (delta > longTimeout / 5 || tryCount > 1) {
      LOG.warn(TOOK_MSG, tryCount, time, suffix);
    } else if (waitedForLoadManagement || retriedForLoadManagement) {
      LOG.debug(TOOK_MSG, tryCount, time, suffix);
    }
    node.network().stats().reportNLMDelay(delta, realTimeFlag, source == null);
  }

  private String buildDeltaSuffix(
      boolean waitedForLoadManagement, boolean retriedForLoadManagement) {
    return " waited="
        + waitedForLoadManagement
        + " retried="
        + retriedForLoadManagement
        + (realTimeFlag ? " (realtime)" : " (bulk)")
        + (source == null ? " (local)" : " (remote)");
  }

  private int rejectedLoops;

  /** Here FINISHED means accepted; WAIT means try again (soft reject). */
  private DO waitForAccepted(
      RequestLikelyAcceptedState expectedAcceptState, PeerNode next, UIDTag origTag) {
    MessageFilter mf = makeAcceptedRejectedFilter(next, getAcceptedTimeout(), origTag);
    while (true) {
      WaitResult wr = waitOnceForAccepted(mf, next, origTag);
      switch (wr.kind) {
        case DISCONNECTED:
          return DO.NEXT_PEER;
        case TIMEOUT:
          return onAcceptedTimeout(next, origTag);
        case RECEIVED:
        default:
          DO res = handleReceivedMessage(wr.msg, expectedAcceptState, next, origTag);
          if (res == DO.KEEP_WAITING) continue; // remote overload: keep waiting in place
          return res;
      }
    }
  }

  private enum WaitKind {
    RECEIVED,
    DISCONNECTED,
    TIMEOUT
  }

  private record WaitResult(WaitKind kind, Message msg) {}

  private WaitResult waitOnceForAccepted(MessageFilter mf, PeerNode next, UIDTag origTag) {
    try {
      Message msg = node.network().usm().waitFor(mf, this);
      LOG.debug("Accepted-wait received message {}", msg);
      return (msg == null)
          ? new WaitResult(WaitKind.TIMEOUT, null)
          : new WaitResult(WaitKind.RECEIVED, msg);
    } catch (DisconnectedException _) {
      LOG.info("Accepted-wait disconnected from {} while waiting on {}", next, uid);
      next.noLongerRoutingTo(origTag, false);
      return new WaitResult(WaitKind.DISCONNECTED, null);
    }
  }

  private DO handleReceivedMessage(
      Message msg, RequestLikelyAcceptedState expectedAcceptState, PeerNode next, UIDTag origTag) {
    // Delegate acceptance detection to isAccepted(...) so subclasses can define
    // protocol-specific Accepted messages (e.g., FNPSSKAccepted for SSK inserts).
    if (isAccepted(msg)) {
      next.resetMandatoryBackoff(realTimeFlag);
      next.outputLoadTracker(realTimeFlag).clearDontSendUnlessGuaranteed();
      return DO.FINISHED;
    }
    if (DMT.FNPRejectedLoop.equals(msg.getSpec())) {
      return onRejectedLoop(next, origTag);
    }
    if (DMT.FNPRejectedOverload.equals(msg.getSpec())) {
      return onRejectedOverload(msg, expectedAcceptState, next, origTag);
    }
    LOG.error("Accepted-wait received unrecognized message: {}", msg);
    return DO.NEXT_PEER;
  }

  private DO onAcceptedTimeout(PeerNode next, UIDTag origTag) {
    LOG.debug("Accepted-wait timed out for {}", this);
    next.localRejectedOverload("AcceptedTimeout", realTimeFlag);
    forwardRejectedOverload();
    int t = timeSinceSent();
    node.routing().failureTable().onFailed(key, next, htl, t, t);
    synchronized (this) {
      rejectedLoops++;
    }
    handleAcceptedRejectedTimeout(next, origTag);
    return DO.NEXT_PEER;
  }

  private DO onRejectedLoop(PeerNode next, UIDTag origTag) {
    LOG.debug("Rejected: loop detected");
    next.successNotOverload(realTimeFlag);
    int t = timeSinceSent();
    node.routing().failureTable().onFailed(key, next, htl, t, t);
    next.noLongerRoutingTo(origTag, false);
    return DO.NEXT_PEER;
  }

  private DO onRejectedOverload(
      Message msg, RequestLikelyAcceptedState expectedAcceptState, PeerNode next, UIDTag origTag) {
    LOG.debug("Rejected: overload response");
    if (msg.getBoolean(DMT.IS_LOCAL)) {
      LOG.debug("Rejected overload is local");
      boolean isSoft = msg.getSubMessage(DMT.FNPRejectIsSoft) != null;
      if (isSoft && expectedAcceptState != null) {
        LOG.debug("Soft local overload: waiting to resend");
        if (expectedAcceptState == RequestLikelyAcceptedState.GUARANTEED)
          LOG.info("Local overload despite expected state {}", expectedAcceptState);
        nodesRoutedTo.remove(next);
        next.noLongerRoutingTo(origTag, false);
        recordSoftReject(next);
        return DO.WAIT;
      }

      forwardRejectedOverload();
      next.localRejectedOverload("ForwardRejectedOverload", realTimeFlag);
      int t = timeSinceSent();
      node.routing().failureTable().onFailed(key, next, htl, t, t);
      LOG.debug("Local overload: moving on to next peer");
      next.noLongerRoutingTo(origTag, false);
      return DO.NEXT_PEER;
    }
    forwardRejectedOverload();
    return DO.KEEP_WAITING; // keep waiting for another response without resending
  }

  private void recordSoftReject(PeerNode next) {
    if (softRejectCount == null) softRejectCount = new HashMap<>();
    Integer count = softRejectCount.get(next);
    int newCount = (count == null ? 1 : count + 1);
    softRejectCount.put(next, newCount);
    if (newCount > 3) {
      LOG.error("Rejected repeatedly ({}) by {} : {}", newCount, next, this);
      next.outputLoadTracker(realTimeFlag).setDontSendUnlessGuaranteed();
    }
  }

  protected abstract void handleAcceptedRejectedTimeout(final PeerNode next, final UIDTag origTag);

  /**
   * Determine whether the given message represents an early “accepted” signal for this sender.
   *
   * <p>The base implementation treats {@code FNPAccepted} as the acceptance signal. Subclasses may
   * override if their protocol uses a different early-accept indication.
   *
   * @param msg message received while waiting for acceptance
   * @return {@code true} if the message signals acceptance
   */
  @SuppressWarnings("unused")
  protected boolean isAccepted(Message msg) {
    return DMT.FNPAccepted.equals(msg.getSpec());
  }

  /**
   * Timeout for waiting on an early acceptance from the contacted peer.
   *
   * @return timeout in milliseconds
   */
  protected abstract long getAcceptedTimeout();

  /**
   * Called when waiting for capacity across candidate peers times out.
   *
   * @param load the average proportion of fatal timeouts reported by the peers we waited for; used
   *     by callers to tune RecentlyFailed persistence
   */
  protected abstract void timedOutWhileWaiting(double load);

  /**
   * Invoked when the request is accepted by a peer. Subclasses continue the operation from here
   * (e.g., sending/receiving payload, handling replies). Implementations must complete or arrange a
   * reroute/finish as appropriate.
   *
   * @param next the peer that accepted the request
   */
  protected abstract void onAccepted(PeerNode next);

  /**
   * Driver actions for the send/wait loop.
   *
   * <ul>
   *   <li>{@link #FINISHED}: acceptance observed; proceed to {@link #onAccepted(PeerNode)}.
   *   <li>{@link #WAIT}: soft local overload; retry the same peer without decrementing HTL.
   *   <li>{@link #KEEP_WAITING}: remote overload; continue waiting without resending.
   *   <li>{@link #NEXT_PEER}: hard failure or loop; pick another peer.
   * </ul>
   */
  protected enum DO {
    FINISHED,
    WAIT,
    KEEP_WAITING,
    NEXT_PEER
  }

  /**
   * Build a filter for messages that indicate early acceptance or rejection from {@code next}.
   *
   * @param next peer we are awaiting a response from
   * @param acceptedTimeout timeout in milliseconds to wait for the response
   * @param tag tag whose UID must match; some flows retag after hops, so callers may pass an older
   *     tag to match late confirmations
   * @return a filter to use with the {@code USM.waitFor} facility
   */
  protected abstract MessageFilter makeAcceptedRejectedFilter(
      PeerNode next, long acceptedTimeout, UIDTag tag);

  /**
   * Propagate a local/remote {@code RejectedOverload} outcome to the controlling logic (e.g., for
   * statistics or backpressure). Implementations should be quick and non-blocking.
   */
  protected abstract void forwardRejectedOverload();

  /**
   * Whether this sender performs an insert operation (as opposed to a request/fetch).
   *
   * @return {@code true} for insert senders; {@code false} for request senders
   */
  protected abstract boolean isInsert();

  /**
   * High-HTL indicator used by routing heuristics.
   *
   * @return {@code true} when {@code htl >= maxHTL - 1}
   */
  @Override
  public boolean isHighHtl() {
    return htl >= (node.maxHTL() - 1);
  }

  /**
   * Hint to peer selection on whether low-backoff peers can be ignored.
   *
   * <p>The base implementation returns {@code 0} (do not ignore). Insert senders may override to
   * return {@link Node#LOW_BACKOFF} when appropriate.
   *
   * @return advisory value interpreted by peer selection; {@code 0} means no override
   */
  protected long ignoreLowBackoff() {
    return 0;
  }
}
