package network.crypta.node;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.TreeMap;
import network.crypta.node.NodeStats.RequestType;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracks per-peer load state and coordinates slot waiting for outbound routing decisions.
 *
 * <p>This class aggregates incoming load reports from a {@link PeerNode}, maintains lightweight
 * counters for recent allocation outcomes, and arbitrates whether new requests should be routed or
 * queued for a slot. It is consulted by routing paths that need to decide between immediate
 * acceptance, waiting for capacity, or rejecting a route based on current bandwidth and transfer
 * limits. The tracker keeps separate accounting for real-time and bulk traffic so that different
 * scheduling policies can be applied without duplicating state.
 *
 * <p>State is mutable and updated by multiple code paths; synchronization is internal and relies on
 * a dedicated lock for shared load data plus per-waiter monitors for blocking waits. Callers should
 * avoid holding unrelated locks when invoking methods that can block. The tracker does not manage
 * lifecycle itself; it expects the owning {@link PeerNode} to create, keep, and tear it down
 * alongside other routing structures.
 *
 * <ul>
 *   <li>Evaluates load stats to compute a likely acceptance state for a route.
 *   <li>Queues {@link SlotWaiter} instances when a request must wait for capacity.
 *   <li>Wakes waiters when updated load stats indicate capacity has freed.
 * </ul>
 *
 * @see PeerNode
 * @see PeerLoadStats
 * @see SlotWaiter
 */
public final class PeerNodeLoadTracker {
  private static final Logger LOG = LoggerFactory.getLogger(PeerNodeLoadTracker.class);
  private static final String STR_FOR = " for ";
  private static final String STR_REALTIME_EQ = " realtime=";
  private static final String STR_ACCEPT_STATE_IS = "Accept state is ";
  private static final String STR_WAITED = "Waited ";
  private static final String STR_MS_FOR = "ms for ";
  private static final RequestType[] RequestType_values = RequestType.values();

  private final PeerNode peer;
  private final Object routedToLock = new Object();
  private final OutputLoadTracker outputLoadTrackerRealTime;
  private final OutputLoadTracker outputLoadTrackerBulk;

  PeerNodeLoadTracker(PeerNode peer) {
    this.peer = peer;
    this.outputLoadTrackerRealTime = new OutputLoadTracker(true);
    this.outputLoadTrackerBulk = new OutputLoadTracker(false);
  }

  /**
   * Summary of incoming load and capacity numbers for a peer at a point in time.
   *
   * <p>This value object is derived from the most recent {@link PeerLoadStats} plus a snapshot of
   * local running requests. It normalizes the mixed sources into byte-based capacity and usage
   * figures so callers can render status or make higher-level decisions without re-reading the raw
   * structures. All fields are immutable and expressed in bytes unless otherwise stated.
   */
  public static class IncomingLoadSummaryStats {
    /**
     * Creates a summary from raw limits and usage data.
     *
     * <p>The constructor performs only unit normalization and assignment. It does not validate
     * ranges, and it assumes the provided limits and usage values were computed from the same
     * sampling window.
     *
     * @param totalRequests total number of running requests in the snapshot; non-negative count
     * @param limits capacity limits for peer and total scopes, in bytes per second
     * @param used locally observed usage for this peer, in bytes per second
     * @param othersUsed usage attributed to other peers, in bytes per second
     */
    public IncomingLoadSummaryStats(
        int totalRequests, Limits limits, Usage used, Usage othersUsed) {
      runningRequestsTotal = totalRequests;
      peerCapacityOutputBytes = (int) limits.peerOutput;
      peerCapacityInputBytes = (int) limits.peerInput;
      totalCapacityOutputBytes = (int) limits.totalOutput;
      totalCapacityInputBytes = (int) limits.totalInput;
      usedCapacityOutputBytes = (int) used.output;
      usedCapacityInputBytes = (int) used.input;
      othersUsedCapacityOutputBytes = (int) othersUsed.output;
      othersUsedCapacityInputBytes = (int) othersUsed.input;
    }

    /**
     * Total number of running requests observed in the snapshot.
     *
     * <p>This count includes local activity directed at the peer and is used for higher-level
     * diagnostics rather than routing thresholds.
     */
    public final int runningRequestsTotal;

    /**
     * Per-peer output capacity limit in bytes per second.
     *
     * <p>This is the limit that applies to outbound traffic directed at the peer itself, not the
     * aggregate network. It is immutable after construction.
     */
    public final int peerCapacityOutputBytes;

    /**
     * Per-peer input capacity limit in bytes per second.
     *
     * <p>This reflects inbound capacity as reported by the peer and is used alongside output limits
     * when estimating acceptance.
     */
    public final int peerCapacityInputBytes;

    /**
     * Aggregate output capacity limit in bytes per second.
     *
     * <p>This represents total outbound capacity across peers, used for "likely" acceptance when
     * per-peer limits are exceeded but global capacity remains.
     */
    public final int totalCapacityOutputBytes;

    /**
     * Aggregate input capacity limit in bytes per second.
     *
     * <p>This mirrors {@link #totalCapacityOutputBytes} for inbound traffic and is based on the
     * peer's reported limits.
     */
    public final int totalCapacityInputBytes;

    /**
     * Local output usage attributed to this peer, in bytes per second.
     *
     * <p>The value is derived from a running request snapshot and is used when comparing against
     * per-peer output limits.
     */
    public final int usedCapacityOutputBytes;

    /**
     * Local input usage attributed to this peer, in bytes per second.
     *
     * <p>This is the inbound counterpart to {@link #usedCapacityOutputBytes} and reflects local
     * demand.
     */
    public final int usedCapacityInputBytes;

    /**
     * Output usage reported for other peers, in bytes per second.
     *
     * <p>This is an aggregate from the peer's own load reports and is used to evaluate total
     * capacity thresholds.
     */
    public final int othersUsedCapacityOutputBytes;

    /**
     * Input usage reported for other peers, in bytes per second.
     *
     * <p>This is combined with {@link #usedCapacityInputBytes} when evaluating total input
     * capacity.
     */
    public final int othersUsedCapacityInputBytes;
  }

  // Small containers to reduce constructor parameter count
  /**
   * Capacity limits expressed in bytes per second.
   *
   * <p>The fields are copied directly from {@link PeerLoadStats} and represent both per-peer and
   * overall limits. Values are expected to be non-negative and may be fractional if derived from
   * averaged measurements.
   *
   * @param peerOutput per-peer output limit in bytes per second, for this peer only
   * @param peerInput per-peer input limit in bytes per second, for this peer only
   * @param totalOutput aggregate output limit in bytes per second across all peers
   * @param totalInput aggregate input limit in bytes per second across all peers
   */
  public record Limits(
      double peerOutput, double peerInput, double totalOutput, double totalInput) {}

  /**
   * Usage counters expressed in bytes per second.
   *
   * <p>Values are derived from running request snapshots and are used to compare against capacity
   * limits when deciding whether to accept or queue a request.
   *
   * @param output outbound usage in bytes per second
   * @param input inbound usage in bytes per second
   */
  public record Usage(double output, double input) {}

  enum RequestLikelyAcceptedState {
    GUARANTEED, // guaranteed to be accepted, under the per-peer guaranteed limit
    LIKELY, // likely to be accepted even though above the per-peer guaranteed limit, as overall is
    // below the overall lower limit
    UNLIKELY, // not likely to be accepted; peer is over the per-peer guaranteed limit, and global
    // is over the overall lower limit
    UNKNOWN // no data but accepting anyway
  }

  // Consider adding LOW_CAPACITY/BROKEN status when capacity is far below median.

  OutputLoadTracker outputLoadTracker(boolean realTime) {
    return realTime ? outputLoadTrackerRealTime : outputLoadTrackerBulk;
  }

  void reportLoadStatus(PeerLoadStats stat) {
    outputLoadTracker(stat.realTime).reportLoadStatus(stat);
  }

  void failSlotWaiters(boolean realTime) {
    outputLoadTracker(realTime).failSlotWaiters();
  }

  void maybeNotifySlotWaiter(boolean realTime) {
    outputLoadTracker(realTime).maybeNotifySlotWaiter();
  }

  PeerLoadStats getLastIncomingLoadStats(boolean realTime) {
    return outputLoadTracker(realTime).getLastIncomingLoadStats();
  }

  IncomingLoadSummaryStats getIncomingLoadStats(boolean realTime) {
    return outputLoadTracker(realTime).getIncomingLoadStats();
  }

  void postUnlock(Object tag) {
    if (!(tag instanceof UIDTag uidTag)) {
      throw new IllegalArgumentException("Expected UIDTag");
    }
    maybeNotifySlotWaiter(uidTag.realTimeFlag);
  }

  void noLongerRoutingTo(Object tag, boolean offeredKey) {
    if (!(tag instanceof UIDTag uidTag)) {
      throw new IllegalArgumentException("Expected UIDTag");
    }
    if (offeredKey && !(uidTag instanceof RequestTag)) {
      throw new IllegalArgumentException("Only requests can have offeredKey=true");
    }
    noLongerRoutingTo(uidTag, offeredKey);
  }

  void noLongerRoutingTo(UIDTag tag, boolean offeredKey) {
    synchronized (routedToLock) {
      if (offeredKey) tag.removeFetchingOfferedKeyFrom(peer);
      else tag.removeRoutingTo(peer);
    }
    maybeNotifySlotWaiter(tag.realTimeFlag);
  }

  static SlotWaiter createSlotWaiter(
      UIDTag tag, RequestType type, boolean realTime, PeerNode source) {
    return new SlotWaiter(tag, type, realTime, source);
  }

  /**
   * Tracks a request waiting for a routing slot on one or more peers.
   *
   * <p>A {@code SlotWaiter} represents a pending routing attempt for a single {@link UIDTag} and
   * {@link RequestType}. Callers enqueue it on candidate peers and then either block waiting for a
   * wake-up or query its current state. The waiter encapsulates the coordination needed to
   * unregister from peers once one accepts the request, and it records whether a failure occurred
   * while waiting. The ordering counter preserves fairness across retries by keeping the original
   * enqueue order.
   *
   * <p>Instances are stateful and synchronized internally. Callers should not hold unrelated locks
   * while invoking methods that can block or that unregister other waiters.
   */
  public static class SlotWaiter {

    final PeerNode source;
    private final HashSet<PeerNode> waitingFor;
    private PeerNode acceptedBy;
    private RequestLikelyAcceptedState acceptedState;
    final UIDTag tag;
    // Offered-key path not used in this SlotWaiter creation flow; always handles normal routing.
    final RequestType requestType;
    private boolean failed;
    private SlotWaiterFailedException fe;
    final boolean realTime;

    // Note: the counter preserves original ordering even after failures (transfer
    // failures, backoffs). A future enhancement could make the wait loop in
    // RequestSender asynchronous and rely on callbacks instead.

    final long counter;
    private static long waiterCounter;

    SlotWaiter(UIDTag tag, RequestType type, boolean realTime, PeerNode source) {
      this.tag = tag;
      this.requestType = type;
      this.waitingFor = new HashSet<>();
      this.realTime = realTime;
      this.source = source;
      synchronized (SlotWaiter.class) {
        counter = waiterCounter++;
      }
    }

    /**
     * Adds a peer to the set being waited on for a slot.
     *
     * <p>If the waiter has already been accepted or failed, the peer is treated as already
     * satisfied and the method returns {@code true}. Otherwise, the peer is queued unless it is not
     * routable or is currently in mandatory backoff. The method is idempotent for the same peer and
     * sets the tag's waiting-for-slot flag when a new peer is queued.
     *
     * @param peer candidate peer to wait on; must be routable and not in backoff
     * @return {@code true} if queued or already satisfied; {@code false} if queuing is not viable
     */
    public boolean addWaitingFor(PeerNode peer) {
      boolean cantQueue =
          (!peer.isRoutable()) || peer.isInMandatoryBackoff(System.currentTimeMillis(), realTime);
      synchronized (this) {
        if (acceptedBy != null) {
          if (LOG.isDebugEnabled())
            LOG.debug("Not adding {} because already matched on {}", peer.shortToString(), this);
          return true;
        }
        if (failed) {
          if (LOG.isDebugEnabled())
            LOG.debug("Not adding {} because already failed on {}", peer.shortToString(), this);
          return true;
        }
        if (waitingFor.contains(peer)) return true;
        // Race condition if contains() && cantQueue (i.e. it was accepted then it became backed
        // off), but probably not serious.
        if (cantQueue) return false;
        waitingFor.add(peer);
        tag.setWaitingForSlot();
      }
      if (!peer.outputLoadTracker(realTime).queueSlotWaiter(this)) {
        synchronized (this) {
          waitingFor.remove(peer);
          if (acceptedBy != null || failed) return true;
        }
        return false;
      } else return true;
    }

    /**
     * First part of wake-up callback. If this returns null, we have already woken up, but if it
     * returns a PeerNode[], the SlotWaiter has been woken up, and the caller **must** call
     * unregister() with the returned data.
     *
     * @param peer The peer waking up the SlotWaiter.
     * @param state The accept state we are waking up with.
     * @return Null if already woken up or not waiting for this peer, otherwise an array of all the
     *     PeerNode's the slot was registered on, which *must* be passed to unregister() as soon as
     *     the caller has unlocked everything that reasonably can be unlocked.
     */
    synchronized PeerNode[] innerOnWaited(PeerNode peer, RequestLikelyAcceptedState state) {
      if (LOG.isDebugEnabled()) LOG.debug("Waking slot waiter {} on {}", this, peer);
      if (acceptedBy != null) {
        if (LOG.isDebugEnabled()) LOG.debug("Already accepted on {}", this);
        removeTagForPeerIfDifferent(peer);
        return new PeerNode[0];
      }
      if (!waitingFor.contains(peer)) {
        if (LOG.isDebugEnabled()) LOG.debug("Not waiting for peer {} on {}", peer, this);
        removeTagForPeerIfDifferent(peer);
        return new PeerNode[0];
      }
      acceptedBy = peer;
      acceptedState = state;
      if (!tag.addRoutedTo(peer, false)) {
        LOG.info("onWaited for {} added on {} but already added - race condition?", this, tag);
      }
      notifyAll();
      // Because we are no longer in the slot queue we must remove it.
      // If we want to wait for it again it must be re-queued.
      PeerNode[] toUnreg = waitingFor.toArray(new PeerNode[0]);
      waitingFor.clear();
      tag.clearWaitingForSlot();
      return toUnreg;
    }

    private void removeTagForPeerIfDifferent(PeerNode peer) {
      if (acceptedBy != peer) {
        tag.removeRoutingTo(peer);
      }
    }

    /**
     * Caller should not hold locks while calling this.
     *
     * @param exclude only set when the caller already removed the slot waiter for this peer
     * @param all set of peers from which to unregister the slot waiter
     */
    void unregister(PeerNode exclude, PeerNode[] all) {
      for (PeerNode p : all) {
        if (p != exclude) p.outputLoadTracker(realTime).unqueueSlotWaiter(this);
      }
    }

    /**
     * Some sort of failure.
     *
     * @param peer the peer for which routing likely failed or should be reconsidered
     */
    void onFailed(PeerNode peer) {
      if (LOG.isDebugEnabled()) LOG.debug("onFailed() on {}", this);
      synchronized (this) {
        if (acceptedBy != null) {
          if (LOG.isDebugEnabled()) LOG.debug("Already matched on {}", this);
          return;
        }
        // Always wake up.
        // Whether it's a backoff or a disconnect, we probably want to add another peer.
        // Note: retained for compatibility with existing call sites.
        failed = true;
        fe = new SlotWaiterFailedException(peer, true);
        tag.clearWaitingForSlot();
        notifyAll();
      }
    }

    /**
     * Returns a snapshot of peers this waiter is currently waiting on.
     *
     * <p>The returned set is a defensive copy and is safe to iterate without holding any locks. It
     * reflects the state at the moment of the call and will not update as new peers are queued or
     * removed.
     *
     * @return snapshot set of peers still being waited on, possibly empty
     */
    public java.util.Set<PeerNode> waitingForList() {
      synchronized (this) {
        return new HashSet<>(waitingFor);
      }
    }

    /**
     * Wait for any of the PeerNode's we have queued on to accept (locally i.e. to allocate a local
     * slot to) this request.
     *
     * @param maxWait The time to wait for. Can be 0, but if it is 0, this is a "peek", i.e. if we
     *     return null, the queued slots remain live. Whereas if maxWait is not 0, we will
     *     unregister when we time out.
     * @param timeOutIsFatal If true, if we time out, count it for each node involved as a fatal
     *     timeout.
     * @return A matched node, or null.
     * @throws SlotWaiterFailedException If a peer actually failed.
     */
    PeerNode waitForAny(long maxWait, boolean timeOutIsFatal) throws SlotWaiterFailedException {
      PreGrabResult pre = preGrabAndSnapshot();
      if (pre.grabbed) {
        unregister(pre.ret, pre.all);
        if (pre.f != null && pre.ret == null) throw pre.f;
        return pre.ret;
      }
      if (pre.all.length == 0) {
        if (LOG.isDebugEnabled()) LOG.debug("None to wait for on {}", this);
        return null;
      }
      // Double-check before blocking, prevent race condition.
      EarlyResult early = tryImmediateAccept(pre.all);
      if (early.accepted != null) return early.accepted;
      if (maxWait == 0) return null;
      if (!early.anyValid) return handleNoValidAndReturn();
      WaitOutcome w = performTimedWait(maxWait);
      if (timeOutIsFatal) {
        for (PeerNode pn : w.toUnregister) {
          pn.outputLoadTracker(realTime).reportFatalTimeoutInWait(isLocal());
        }
      }
      unregister(w.ret, w.toUnregister);
      return w.ret;
    }

    private PreGrabResult preGrabAndSnapshot() {
      PeerNode[] all;
      PeerNode ret = null;
      boolean grabbed = false;
      SlotWaiterFailedException f = null;
      synchronized (this) {
        if (shouldGrab()) {
          if (LOG.isDebugEnabled()) LOG.debug("Already matched on {}", this);
          ret = grab();
          grabbed = true;
        }
        if (fe != null) {
          f = fe;
          fe = null;
          grabbed = true;
        }
        all = waitingFor.toArray(new PeerNode[0]);
        // Clear waiter registrations regardless of whether a peer was actually returned.
        // This ensures that after a failure (grab() returns null but we were marked as grabbed),
        // we do not keep stale entries that prevent re-queuing on subsequent attempts.
        if (grabbed) waitingFor.clear();
        if (grabbed || all.length == 0) tag.clearWaitingForSlot();
      }
      return new PreGrabResult(all, ret, grabbed, f);
    }

    private EarlyResult tryImmediateAccept(PeerNode[] all) {
      boolean anyValid = false;
      long now = System.currentTimeMillis();
      for (PeerNode p : all) {
        if ((!p.isRoutable()) || p.isInMandatoryBackoff(now, realTime)) {
          if (LOG.isDebugEnabled()) LOG.debug("Peer is not valid in waitForAny(): {}", p);
          continue;
        }
        anyValid = true;
        RequestLikelyAcceptedState accept =
            p.outputLoadTracker(realTime).tryRouteTo(tag, RequestLikelyAcceptedState.LIKELY);
        if (accept != null) return new EarlyResult(true, processPreAccept(p, accept));
      }
      return new EarlyResult(anyValid, null);
    }

    private PeerNode processPreAccept(PeerNode p, RequestLikelyAcceptedState accept) {
      if (LOG.isDebugEnabled()) LOG.debug("tryRouteTo() pre-wait check returned {}", accept);
      PeerNode[] unreg;
      PeerNode other = null;
      synchronized (this) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "tryRouteTo() succeeded to {} on {} with {} - checking whether we have already"
                  + " accepted.",
              p,
              this,
              accept);
        unreg = innerOnWaited(p, accept);
        if (unreg.length == 0 && shouldGrab()) {
          other = grab();
        }
        if (other == null) {
          if (LOG.isDebugEnabled()) LOG.debug("Trying the original tryRouteTo() on {}", this);
          acceptedBy = null;
          failed = false;
          fe = null;
        }
        tag.clearWaitingForSlot();
      }
      if (unreg.length > 0) unregister(null, unreg);
      if (other != null) {
        LOG.info(
            "Race condition: tryRouteTo() succeeded on {} but already matched on {} on {}",
            p.shortToString(),
            other.shortToString(),
            this);
        tag.removeRoutingTo(p);
        return other;
      }
      p.outputLoadTracker(realTime).reportAllocated(isLocal());
      return p;
    }

    private PeerNode handleNoValidAndReturn() throws SlotWaiterFailedException {
      PeerNode[] all;
      PeerNode ret;
      SlotWaiterFailedException fLocal = null;
      synchronized (this) {
        if (fe != null) {
          fLocal = fe;
          fe = null;
        }
        ret = shouldGrab() ? grab() : null;
        all = waitingFor.toArray(new PeerNode[0]);
        waitingFor.clear();
        failed = false;
        acceptedBy = null;
      }
      if (LOG.isDebugEnabled()) LOG.debug("None valid to wait for on {}", this);
      unregister(ret, all);
      if (fLocal != null && ret == null) throw fLocal;
      tag.clearWaitingForSlot();
      return ret;
    }

    private WaitOutcome performTimedWait(long maxWait) {
      PeerNode ret;
      PeerNode[] all;
      long waitStart;
      boolean timedOut;
      synchronized (this) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Waiting for any node to wake up {} : {} (for up to {}ms)",
              this,
              Arrays.toString(waitingFor.toArray()),
              maxWait);
        waitStart = System.currentTimeMillis();
        long deadline = waitStart + maxWait;
        timedOut = runTimedWaitLoop(deadline, maxWait);
        logWaitDurationIfNeeded(waitStart, timedOut);
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Returning after waiting: accepted by {} waiting for {} failed {} on {}",
              acceptedBy,
              waitingFor.size(),
              failed,
              this);
        ret = acceptedBy;
        acceptedBy = null; // Allow for it to wait again if necessary
        all = waitingFor.toArray(new PeerNode[0]);
        waitingFor.clear();
        failed = false;
        fe = null;
        tag.clearWaitingForSlot();
      }
      return new WaitOutcome(ret, all);
    }

    private synchronized boolean runTimedWaitLoop(long deadline, long maxWait) {
      if (maxWait == Long.MAX_VALUE) {
        while (shouldContinueWaiting()) {
          try {
            wait();
          } catch (InterruptedException _) {
            Thread.currentThread().interrupt();
          }
        }
        return false;
      }
      boolean timedOut = false;
      while (shouldContinueWaiting()) {
        try {
          long remaining = deadline - System.currentTimeMillis();
          if (remaining <= 0) {
            timedOut = onDeadlineElapsed();
            break;
          }
          int millis = (int) Math.min(Integer.MAX_VALUE, remaining);
          wait(millis);
          if (LOG.isDebugEnabled()) LOG.debug("Maximum wait time exceeded on {}", this);
        } catch (InterruptedException _) {
          Thread.currentThread().interrupt();
        }
      }
      return timedOut;
    }

    private boolean shouldContinueWaiting() {
      return acceptedBy == null && (!waitingFor.isEmpty()) && !failed;
    }

    private boolean onDeadlineElapsed() {
      if (!shouldGrab()) {
        waitingFor.clear();
        return true;
      }
      return false;
    }

    private void logWaitDurationIfNeeded(long waitStart, boolean timedOut) {
      if (timedOut) return;
      long waitEnd = System.currentTimeMillis();
      long waited = waitEnd - waitStart;
      if (waited > (realTime ? 6000 : 60000)) {
        LOG.warn(STR_WAITED + "{}" + STR_MS_FOR + "{}", waited, this);
      } else if (waited > (realTime ? 1000 : 10000)) {
        LOG.info(STR_WAITED + "{}" + STR_MS_FOR + "{}", waited, this);
      } else {
        if (LOG.isDebugEnabled()) LOG.debug(STR_WAITED + "{}" + STR_MS_FOR + "{}", waited, this);
      }
    }

    private record PreGrabResult(
        PeerNode[] all, PeerNode ret, boolean grabbed, SlotWaiterFailedException f) {
      @Override
      public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PreGrabResult(var otherAll, var otherRet, var otherGrabbed, var otherF)))
          return false;
        return grabbed == otherGrabbed
            && java.util.Objects.equals(ret, otherRet)
            && java.util.Objects.equals(f, otherF)
            && java.util.Arrays.equals(all, otherAll);
      }

      @Override
      public int hashCode() {
        int result = java.util.Objects.hash(ret, grabbed, f);
        result = 31 * result + java.util.Arrays.hashCode(all);
        return result;
      }

      @Override
      public @NotNull String toString() {
        return "PreGrabResult[all="
            + java.util.Arrays.toString(all)
            + ", ret="
            + ret
            + ", grabbed="
            + grabbed
            + ", f="
            + f
            + "]";
      }
    }

    private record EarlyResult(boolean anyValid, PeerNode accepted) {}

    private record WaitOutcome(PeerNode ret, PeerNode[] toUnregister) {
      @Override
      public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof WaitOutcome(var otherRet, var otherToUnregister))) return false;
        return java.util.Objects.equals(ret, otherRet)
            && java.util.Arrays.equals(toUnregister, otherToUnregister);
      }

      @Override
      public int hashCode() {
        int result = java.util.Objects.hash(ret);
        result = 31 * result + java.util.Arrays.hashCode(toUnregister);
        return result;
      }

      @Override
      public @NotNull String toString() {
        return "WaitOutcome[ret="
            + ret
            + ", toUnregister="
            + java.util.Arrays.toString(toUnregister)
            + "]";
      }
    }

    final boolean isLocal() {
      return source == null;
    }

    private boolean shouldGrab() {
      return acceptedBy != null || waitingFor.isEmpty() || failed;
    }

    private synchronized PeerNode grab() {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Returning in first check: accepted by {} waiting for {} failed {} accepted state {}",
            acceptedBy,
            waitingFor.size(),
            failed,
            acceptedState);
      failed = false;
      PeerNode got = acceptedBy;
      acceptedBy = null; // Allow for it to wait again if necessary
      return got;
    }

    synchronized RequestLikelyAcceptedState getAcceptedState() {
      return acceptedState;
    }

    @Override
    public String toString() {
      return super.toString() + ":" + counter + ":" + requestType + ":" + realTime;
    }

    /**
     * Returns the current number of peers being waited on.
     *
     * <p>This count is derived from the internal wait list and reflects the moment of the call. It
     * is useful for diagnostics and does not imply that all peers remain routable.
     *
     * @return number of peers in the wait list at call time
     */
    public synchronized int waitingForCount() {
      return waitingFor.size();
    }
  }

  static class SlotWaiterFailedException extends Exception {
    final transient PeerNode pn;
    final boolean fatal;

    SlotWaiterFailedException(PeerNode p, boolean f) {
      this.pn = p;
      this.fatal = f;
      // Optimization: consider arranging for empty stack trace.
    }
  }

  static class SlotWaiterList {

    private final LinkedHashMap<PeerNode, TreeMap<Long, SlotWaiter>> lru = new LinkedHashMap<>();

    public synchronized void put(SlotWaiter waiter) {
      PeerNode source = waiter.source;
      TreeMap<Long, SlotWaiter> map = lru.computeIfAbsent(source, _ -> new TreeMap<>());
      map.put(waiter.counter, waiter);
    }

    public synchronized void remove(SlotWaiter waiter) {
      PeerNode source = waiter.source;
      TreeMap<Long, SlotWaiter> map = lru.get(source);
      if (map == null) {
        if (LOG.isDebugEnabled()) LOG.debug("SlotWaiter {} was not queued", waiter);
        return;
      }
      map.remove(waiter.counter);
      if (map.isEmpty()) lru.remove(source);
    }

    public synchronized boolean isEmpty() {
      return lru.isEmpty();
    }

    public synchronized SlotWaiter removeFirst() {
      if (lru.isEmpty()) return null;
      // Consider using LRUMap; would need to update to use Iterator and other modern APIs.
      PeerNode source = lru.keySet().iterator().next();
      TreeMap<Long, SlotWaiter> map = lru.get(source);
      Long key = map.firstKey();
      SlotWaiter ret = map.get(key);
      map.remove(key);
      lru.remove(source);
      if (!map.isEmpty()) lru.put(source, map);
      return ret;
    }

    public synchronized List<SlotWaiter> values() {
      ArrayList<SlotWaiter> list = new ArrayList<>();
      for (TreeMap<Long, SlotWaiter> map : lru.values()) {
        list.addAll(map.values());
      }
      return list;
    }

    public String toString() {
      return super.toString() + ":peers=" + lru.size();
    }
  }

  /**
   * Uses the information we receive on the load on the target node to determine whether we can
   * route to it and when we can route to it.
   */
  class OutputLoadTracker {

    final boolean realTime;

    private PeerLoadStats lastIncomingLoadStats;

    private boolean dontSendUnlessGuaranteed;

    // These only count remote timeouts.
    // Strictly local and remote should be the same in new load management, but
    // local often produces more load than can be handled by our peers.
    // Fair sharing in SlotWaiterList ensures that this doesn't cause excessive
    // timeouts for others, but we want the stats that determine their RecentlyFailed
    // times to be based on remote requests only. Also, local requests by definition
    // do not cause downstream problems.
    private long totalFatalTimeouts;
    private long totalAllocated;

    void reportLoadStatus(PeerLoadStats stat) {
      if (LOG.isDebugEnabled()) LOG.debug("Got load status : {}", stat);
      synchronized (routedToLock) {
        lastIncomingLoadStats = stat;
      }
      maybeNotifySlotWaiter();
    }

    synchronized /* lock only used for counter */ void reportFatalTimeoutInWait(boolean local) {
      if (!local) totalFatalTimeouts++;
      peer.node.network().stats().reportFatalTimeoutInWait(local);
    }

    synchronized /* lock only used for counter */ void reportAllocated(boolean local) {
      if (!local) totalAllocated++;
      peer.node.network().stats().reportAllocatedSlot(local);
    }

    public synchronized double proportionTimingOutFatallyInWait() {
      if (totalFatalTimeouts == 1 && totalAllocated == 0)
        return 0.5; // Limit impact if the first one is rejected.
      return (double) totalFatalTimeouts / ((double) (totalFatalTimeouts + totalAllocated));
    }

    public PeerLoadStats getLastIncomingLoadStats() {
      synchronized (routedToLock) {
        return lastIncomingLoadStats;
      }
    }

    OutputLoadTracker(boolean realTime) {
      this.realTime = realTime;
    }

    public IncomingLoadSummaryStats getIncomingLoadStats() {
      PeerLoadStats loadStats;
      synchronized (routedToLock) {
        if (lastIncomingLoadStats == null) return null;
        loadStats = lastIncomingLoadStats;
      }
      RunningRequestsSnapshot runningRequests =
          peer.node.network().stats().getRunningRequestsTo(peer, realTime);
      RunningRequestsSnapshot otherRunningRequests = loadStats.getOtherRunningRequests();
      boolean ignoreLocalVsRemoteBandwidthLiability =
          peer.node.network().stats().ignoreLocalVsRemoteBandwidthLiability();
      Limits limits =
          new Limits(
              loadStats.outputBandwidthPeerLimit,
              loadStats.inputBandwidthPeerLimit,
              loadStats.outputBandwidthUpperLimit,
              loadStats.inputBandwidthUpperLimit);
      Usage used =
          new Usage(
              runningRequests.calculate(ignoreLocalVsRemoteBandwidthLiability, false),
              runningRequests.calculate(ignoreLocalVsRemoteBandwidthLiability, true));
      Usage othersUsed =
          new Usage(
              otherRunningRequests.calculate(ignoreLocalVsRemoteBandwidthLiability, false),
              otherRunningRequests.calculate(ignoreLocalVsRemoteBandwidthLiability, true));
      return new IncomingLoadSummaryStats(
          runningRequests.totalRequests(), limits, used, othersUsed);
    }

    /**
     * Can we route the tag to this peer? If so (including if we are accepting because we don't have
     * any load stats), and we haven't already, addRoutedTo() and return the accepted state.
     * Otherwise, return null.
     *
     * @param tag request identifier
     * @param worstAcceptable lowest acceptable state to consider a route viable
     * @return the decided accept state, or {@code null} if routing is not viable
     */
    public RequestLikelyAcceptedState tryRouteTo(
        UIDTag tag, RequestLikelyAcceptedState worstAcceptable) {
      PeerLoadStats loadStats;
      boolean ignoreLocalVsRemote =
          peer.node.network().stats().ignoreLocalVsRemoteBandwidthLiability();
      if (!peer.isRoutable()) return null;
      if (peer.isInMandatoryBackoff(System.currentTimeMillis(), realTime)) return null;
      synchronized (routedToLock) {
        loadStats = lastIncomingLoadStats;
        if (loadStats == null) {
          LOG.error(
              "Accepting because no load stats from {} ({})",
              peer.shortToString(),
              peer.getBuildNumber());
          if (tag.addRoutedTo(peer, false)) {
            // Consider waiting a bit or checking the other side's version first.
            return RequestLikelyAcceptedState.UNKNOWN;
          } else return null;
        }
        if (dontSendUnlessGuaranteed) worstAcceptable = RequestLikelyAcceptedState.GUARANTEED;
        // Requests already running to this node
        RunningRequestsSnapshot runningRequests =
            peer.node.network().stats().getRunningRequestsTo(peer, realTime);
        runningRequests.log(peer);
        // Requests running from its other peers
        RunningRequestsSnapshot otherRunningRequests = loadStats.getOtherRunningRequests();
        RequestLikelyAcceptedState acceptState =
            getRequestLikelyAcceptedState(
                runningRequests, otherRunningRequests, ignoreLocalVsRemote, loadStats);
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Predicted acceptance state for request: {} must beat {}",
              acceptState,
              worstAcceptable);
        if (acceptState.ordinal() > worstAcceptable.ordinal()) return null;
        if (tag.addRoutedTo(peer, false)) return acceptState;
        else {
          if (LOG.isDebugEnabled()) LOG.debug("Already routed to peer");
          return null;
        }
      }
    }

    // Consider responding to capacity/backoff changes by adding another peer.node.

    private final EnumMap<RequestType, SlotWaiterList> slotWaiters =
        new EnumMap<>(RequestType.class);

    boolean queueSlotWaiter(SlotWaiter waiter) {
      if (!canQueueNow()) return false;
      QueueResult r = enqueueOrWake(waiter);
      if (r.wokeUpImmediately()) {
        reportAllocated(waiter.isLocal());
        waiter.unregister(null, r.toUnregister);
        return true;
      }
      // If we queued but conditions changed, fail fast
      if (r.queued
          && ((!peer.isRoutable())
              || (peer.isInMandatoryBackoff(System.currentTimeMillis(), realTime)))) {
        if (LOG.isDebugEnabled())
          LOG.debug("Queued but not routable or in mandatory backoff, failing");
        waiter.onFailed(peer);
        return false;
      }
      return r.queued;
    }

    private boolean canQueueNow() {
      if (!peer.isRoutable()) {
        if (LOG.isDebugEnabled()) LOG.debug("Not routable, so not queueing");
        return false;
      }
      if (peer.isInMandatoryBackoff(System.currentTimeMillis(), realTime)) {
        if (LOG.isDebugEnabled()) LOG.debug("In mandatory backoff, so not queueing");
        return false;
      }
      return true;
    }

    private record QueueResult(boolean queued, PeerNode[] toUnregister) {

      boolean wokeUpImmediately() {
        return toUnregister.length > 0;
      }

      @Override
      public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof QueueResult(var otherQueued, var otherToUnregister))) return false;
        return queued == otherQueued && java.util.Arrays.equals(toUnregister, otherToUnregister);
      }

      @Override
      public int hashCode() {
        int result = java.lang.Boolean.hashCode(queued);
        result = 31 * result + java.util.Arrays.hashCode(toUnregister);
        return result;
      }

      @Override
      public @NotNull String toString() {
        return "QueueResult[queued="
            + queued
            + ", toUnregister="
            + java.util.Arrays.toString(toUnregister)
            + "]";
      }
    }

    private QueueResult enqueueOrWake(SlotWaiter waiter) {
      boolean queued = false;
      PeerNode[] all = new PeerNode[0];
      synchronized (routedToLock) {
        boolean noLoadStats = (this.lastIncomingLoadStats == null);
        if (!noLoadStats) {
          SlotWaiterList list = makeSlotWaiters(waiter.requestType);
          list.put(waiter);
          if (LOG.isDebugEnabled())
            LOG.debug(
                "Queued slot {} waiter for {} on {} on {}" + STR_FOR + "{}",
                waiter,
                waiter.requestType,
                list,
                this,
                peer);
          queued = true;
        } else {
          if (LOG.isDebugEnabled()) LOG.debug("Not waiting for {} as no load stats", this);
          all = waiter.innerOnWaited(peer, RequestLikelyAcceptedState.UNKNOWN);
        }
      }
      return new QueueResult(queued, all);
    }

    private SlotWaiterList makeSlotWaiters(RequestType requestType) {
      return slotWaiters.computeIfAbsent(requestType, _ -> new SlotWaiterList());
    }

    void unqueueSlotWaiter(SlotWaiter waiter) {
      synchronized (routedToLock) {
        SlotWaiterList map = slotWaiters.get(waiter.requestType);
        if (map == null) return;
        map.remove(waiter);
      }
    }

    private void failSlotWaiters() {
      for (RequestType type : RequestType_values) {
        SlotWaiterList slots;
        synchronized (routedToLock) {
          slots = slotWaiters.get(type);
          if (slots == null) continue;
          slotWaiters.remove(type);
        }
        for (SlotWaiter w : slots.values()) w.onFailed(peer);
      }
    }

    private int slotWaiterTypeCounter = 0;

    private void maybeNotifySlotWaiter() {
      if (!peer.isRoutable()) return;
      boolean ignoreLocalVsRemote =
          peer.node.network().stats().ignoreLocalVsRemoteBandwidthLiability();
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Maybe waking up slot waiters for {}" + STR_REALTIME_EQ + "{}" + STR_FOR + "{}",
            this,
            realTime,
            peer.shortToString());
      while (true) {
        int typeNum;
        PeerLoadStats loadStats;
        synchronized (routedToLock) {
          loadStats = lastIncomingLoadStats;
          if (slotWaiters.isEmpty()) {
            if (LOG.isDebugEnabled()) LOG.debug("No slot waiters for {}", this);
            return;
          }
          typeNum = slotWaiterTypeCounter;
        }
        typeNum = nextTypeIndex(typeNum);
        if (!processCycle(loadStats, ignoreLocalVsRemote, typeNum)) return;
      }
    }

    private boolean processCycle(
        PeerLoadStats loadStats, boolean ignoreLocalVsRemote, int typeNumStart) {
      boolean foundAny = false;
      int typeNum = typeNumStart;
      for (int i = 0; i < RequestType_values.length; i++) {
        RequestType type = RequestType_values[typeNum];
        if (LOG.isDebugEnabled()) LOG.debug("Checking slot waiter list for {}", type);
        Decision d = evaluateForType(type, loadStats, ignoreLocalVsRemote, typeNum);
        if (d == null) return false; // early-exit conditions inside evaluator
        if (d.slot != null) {
          d.slot.unregister(peer, d.peersForSuccessfulSlot);
          if (LOG.isDebugEnabled())
            LOG.debug(
                STR_ACCEPT_STATE_IS + "{}" + STR_FOR + "{} - waking up", d.acceptState, d.slot);
        }
        foundAny = foundAny || d.foundOne;
        typeNum = nextTypeIndex(typeNum);
      }
      return foundAny;
    }

    private int nextTypeIndex(int current) {
      current++;
      if (current == RequestType_values.length) current = 0;
      return current;
    }

    private record Decision(
        SlotWaiter slot,
        RequestLikelyAcceptedState acceptState,
        PeerNode[] peersForSuccessfulSlot,
        boolean foundOne) {

      private Decision(
          SlotWaiter slot,
          RequestLikelyAcceptedState acceptState,
          PeerNode[] peersForSuccessfulSlot,
          boolean foundOne) {
        this.slot = slot;
        this.acceptState = acceptState;
        this.peersForSuccessfulSlot =
            peersForSuccessfulSlot == null ? new PeerNode[0] : peersForSuccessfulSlot;
        this.foundOne = foundOne;
      }

      @Override
      public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o
            instanceof
            Decision(
                var otherSlot,
                var otherAcceptState,
                var otherPeersForSuccessfulSlot,
                var otherFoundOne))) return false;
        return foundOne == otherFoundOne
            && java.util.Objects.equals(slot, otherSlot)
            && acceptState == otherAcceptState
            && java.util.Arrays.equals(peersForSuccessfulSlot, otherPeersForSuccessfulSlot);
      }

      @Override
      public int hashCode() {
        int result = java.util.Objects.hash(slot, acceptState, foundOne);
        result = 31 * result + java.util.Arrays.hashCode(peersForSuccessfulSlot);
        return result;
      }

      @Override
      public @NotNull String toString() {
        return "Decision[slot="
            + slot
            + ", acceptState="
            + acceptState
            + ", peersForSuccessfulSlot="
            + java.util.Arrays.toString(peersForSuccessfulSlot)
            + ", foundOne="
            + foundOne
            + "]";
      }
    }

    private Decision evaluateForType(
        RequestType type, PeerLoadStats loadStats, boolean ignoreLocalVsRemote, int typeNum) {
      SlotWaiterList list;
      SlotWaiter slot = null;
      RequestLikelyAcceptedState acceptState;
      PeerNode[] peersForSuccessfulSlot = null;
      synchronized (routedToLock) {
        list = slotWaiters.get(type);
        if (list == null || list.isEmpty()) {
          if (LOG.isDebugEnabled()) LOG.debug(list == null ? "No list" : "List empty");
          return new Decision(null, null, null, false);
        }
        if (LOG.isDebugEnabled()) LOG.debug("Checking slot waiters for {}", type);
        RunningRequestsSnapshot runningRequests =
            peer.node.network().stats().getRunningRequestsTo(peer, realTime);
        runningRequests.log(peer);
        RunningRequestsSnapshot otherRunningRequests = loadStats.getOtherRunningRequests();
        acceptState =
            computeAcceptState(
                runningRequests, otherRunningRequests, ignoreLocalVsRemote, loadStats);
        if (shouldEarlyExit(acceptState, type)) return null; // early exit
        if (!list.isEmpty()) {
          SlotWakeResult r = maybePopSlot(list, acceptState, typeNum);
          slot = r.slot;
          peersForSuccessfulSlot = r.peersForSuccessfulSlot;
        }
      }
      return new Decision(slot, acceptState, peersForSuccessfulSlot, true);
    }

    private RequestLikelyAcceptedState computeAcceptState(
        RunningRequestsSnapshot runningRequests,
        RunningRequestsSnapshot otherRunningRequests,
        boolean ignoreLocalVsRemote,
        PeerLoadStats loadStats) {
      return getRequestLikelyAcceptedState(
          runningRequests, otherRunningRequests, ignoreLocalVsRemote, loadStats);
    }

    private boolean shouldEarlyExit(RequestLikelyAcceptedState acceptState, RequestType type) {
      if (acceptState == RequestLikelyAcceptedState.UNLIKELY) {
        if (LOG.isDebugEnabled())
          LOG.debug(STR_ACCEPT_STATE_IS + "{} - not waking up - type is {}", acceptState, type);
        return true;
      }
      if (dontSendUnlessGuaranteed && acceptState != RequestLikelyAcceptedState.GUARANTEED) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Not accepting until guaranteed for {}" + STR_REALTIME_EQ + "{}", peer, realTime);
        return true;
      }
      return false;
    }

    private record SlotWakeResult(SlotWaiter slot, PeerNode[] peersForSuccessfulSlot) {
      @Override
      public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SlotWakeResult(var otherSlot, var otherPeers))) return false;
        return java.util.Objects.equals(slot, otherSlot)
            && java.util.Arrays.equals(peersForSuccessfulSlot, otherPeers);
      }

      @Override
      public int hashCode() {
        int result = java.util.Objects.hash(slot);
        result = 31 * result + java.util.Arrays.hashCode(peersForSuccessfulSlot);
        return result;
      }

      @Override
      public @NotNull String toString() {
        return "SlotWakeResult[slot="
            + slot
            + ", peersForSuccessfulSlot="
            + java.util.Arrays.toString(peersForSuccessfulSlot)
            + "]";
      }
    }

    private SlotWakeResult maybePopSlot(
        SlotWaiterList list, RequestLikelyAcceptedState acceptState, int typeNum) {
      SlotWaiter slot = list.removeFirst();
      if (LOG.isDebugEnabled())
        LOG.debug(
            STR_ACCEPT_STATE_IS + "{}" + STR_FOR + "{} - waking up on {}", acceptState, slot, this);
      PeerNode[] peersForSuccessfulSlot = slot.innerOnWaited(peer, acceptState);
      if (peersForSuccessfulSlot.length > 0) {
        reportAllocated(slot.isLocal());
        slotWaiterTypeCounter = typeNum;
        return new SlotWakeResult(slot, peersForSuccessfulSlot);
      }
      return new SlotWakeResult(null, new PeerNode[0]);
    }

    /**
     * LOCKING: Call inside routedToLock.
     *
     * @param runningRequests snapshot of this peer's running requests
     * @param otherRunningRequests snapshot of other peers' running requests
     * @param ignoreLocalVsRemote whether to ignore local vs remote origin when evaluating
     * @param stats most recent load statistics for this peer
     */
    private RequestLikelyAcceptedState getRequestLikelyAcceptedState(
        RunningRequestsSnapshot runningRequests,
        RunningRequestsSnapshot otherRunningRequests,
        boolean ignoreLocalVsRemote,
        PeerLoadStats stats) {
      RequestLikelyAcceptedState outputState =
          getRequestLikelyAcceptedStateBandwidth(
              false, runningRequests, otherRunningRequests, ignoreLocalVsRemote, stats);
      RequestLikelyAcceptedState inputState =
          getRequestLikelyAcceptedStateBandwidth(
              true, runningRequests, otherRunningRequests, ignoreLocalVsRemote, stats);
      RequestLikelyAcceptedState transfersState =
          getRequestLikelyAcceptedStateTransfers(runningRequests, otherRunningRequests, stats);
      RequestLikelyAcceptedState ret = inputState;

      if (outputState.ordinal() > ret.ordinal()) ret = outputState;
      if (transfersState.ordinal() > ret.ordinal()) ret = transfersState;
      return ret;
    }

    private RequestLikelyAcceptedState getRequestLikelyAcceptedStateBandwidth(
        boolean input,
        RunningRequestsSnapshot runningRequests,
        RunningRequestsSnapshot otherRunningRequests,
        boolean ignoreLocalVsRemote,
        PeerLoadStats stats) {
      double ourUsage = runningRequests.calculate(ignoreLocalVsRemote, input);
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Our usage is {} peer limit is {} lower limit is {} realtime {} input {}",
            ourUsage,
            stats.peerLimit(input),
            stats.lowerLimit(input),
            realTime,
            input);
      if (ourUsage < stats.peerLimit(input)) return RequestLikelyAcceptedState.GUARANTEED;
      otherRunningRequests.log(peer);
      double theirUsage = otherRunningRequests.calculate(ignoreLocalVsRemote, input);
      if (LOG.isDebugEnabled()) LOG.debug("Their usage is {}", theirUsage);
      if (ourUsage + theirUsage < stats.lowerLimit(input)) return RequestLikelyAcceptedState.LIKELY;
      else return RequestLikelyAcceptedState.UNLIKELY;
    }

    private RequestLikelyAcceptedState getRequestLikelyAcceptedStateTransfers(
        RunningRequestsSnapshot runningRequests,
        RunningRequestsSnapshot otherRunningRequests,
        PeerLoadStats stats) {

      int ourUsage = runningRequests.totalOutTransfers();
      int maxTransfersOutPeerLimit =
          Math.min(stats.maxTransfersOutPeerLimit, stats.maxTransfersOut);
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Our usage is {} peer limit is {} lower limit is {} realtime {}",
            ourUsage,
            maxTransfersOutPeerLimit,
            stats.maxTransfersOutLowerLimit,
            realTime);
      if (ourUsage < maxTransfersOutPeerLimit) return RequestLikelyAcceptedState.GUARANTEED;
      otherRunningRequests.log(peer);
      int theirUsage = otherRunningRequests.totalOutTransfers();
      if (LOG.isDebugEnabled()) LOG.debug("Their usage is {}", theirUsage);
      if (ourUsage + theirUsage < stats.maxTransfersOutLowerLimit)
        return RequestLikelyAcceptedState.LIKELY;
      else return RequestLikelyAcceptedState.UNLIKELY;
    }

    public void setDontSendUnlessGuaranteed() {
      synchronized (routedToLock) {
        if (!dontSendUnlessGuaranteed) {
          LOG.error(
              "Setting don't-send-unless-guaranteed for {}" + STR_REALTIME_EQ + "{}",
              peer,
              realTime);
          dontSendUnlessGuaranteed = true;
        }
      }
    }

    public void clearDontSendUnlessGuaranteed() {
      synchronized (routedToLock) {
        if (dontSendUnlessGuaranteed) {
          LOG.error(
              "Clearing don't-send-unless-guaranteed for {}" + STR_REALTIME_EQ + "{}",
              peer,
              realTime);
          dontSendUnlessGuaranteed = false;
        }
      }
    }
  }
}
