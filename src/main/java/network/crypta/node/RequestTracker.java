package network.crypta.node;

import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import network.crypta.keys.NodeCHK;
import network.crypta.support.Ticker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracks running requests by UID and exposes lightweight counters.
 *
 * <p>This class maintains separate registries for CHK/SSK requests, inserts, and offer replies,
 * split across real-time and bulk modes. For locality-aware accounting, each category keeps an
 * overall map and a secondary map for locally originated operations. Methods provide visibility
 * into counts and transfer expectations without exposing internal synchronization primitives.
 *
 * <p>Thread-safety: individual maps are used as intrinsic locks. For locality-tracked maps, the
 * overall map is locked when accessing the corresponding local map to preserve invariants (every
 * local-tagged request also appears in the overall map). Callers must not hold locks across
 * external calls.
 *
 * <p>Side effects: periodic liveness checks are scheduled via {@link Ticker}; completed request IDs
 * are periodically propagated to peers to allow queue cleanup.
 */
public class RequestTracker {
  private static final Logger LOG = LoggerFactory.getLogger(RequestTracker.class);
  private static final String DEBUG_EXCEPTION_MESSAGE = "debug";

  // The runningLocal* are secondary. That is, we take the lock on the
  // corresponding running* when accessing runningLocal*. Local requests
  // have a tag in *both*.

  private final HashMap<Long, RequestTag> runningCHKGetUIDsBulk;
  private final HashMap<Long, RequestTag> runningLocalCHKGetUIDsBulk;
  private final HashMap<Long, RequestTag> runningSSKGetUIDsBulk;
  private final HashMap<Long, RequestTag> runningLocalSSKGetUIDsBulk;
  private final HashMap<Long, InsertTag> runningCHKPutUIDsBulk;
  private final HashMap<Long, InsertTag> runningLocalCHKPutUIDsBulk;
  private final HashMap<Long, InsertTag> runningSSKPutUIDsBulk;
  private final HashMap<Long, InsertTag> runningLocalSSKPutUIDsBulk;
  private final HashMap<Long, OfferReplyTag> runningCHKOfferReplyUIDsBulk;
  private final HashMap<Long, OfferReplyTag> runningSSKOfferReplyUIDsBulk;

  private final HashMap<Long, RequestTag> runningCHKGetUIDsRT;
  private final HashMap<Long, RequestTag> runningLocalCHKGetUIDsRT;
  private final HashMap<Long, RequestTag> runningSSKGetUIDsRT;
  private final HashMap<Long, RequestTag> runningLocalSSKGetUIDsRT;
  private final HashMap<Long, InsertTag> runningCHKPutUIDsRT;
  private final HashMap<Long, InsertTag> runningLocalCHKPutUIDsRT;
  private final HashMap<Long, InsertTag> runningSSKPutUIDsRT;
  private final HashMap<Long, InsertTag> runningLocalSSKPutUIDsRT;
  private final HashMap<Long, OfferReplyTag> runningCHKOfferReplyUIDsRT;
  private final HashMap<Long, OfferReplyTag> runningSSKOfferReplyUIDsRT;

  private final PeerManager peers;
  private final Ticker ticker;

  /** RequestSender instances currently transferring, keyed by CHK. */
  private final HashMap<NodeCHK, RequestSender> transferringRequestSendersRT;

  private final HashMap<NodeCHK, RequestSender> transferringRequestSendersBulk;

  /** UIDs of RequestHandler instances currently transferring. */
  private final HashSet<Long> transferringRequestHandlers;

  /**
   * Creates a request tracker for the given peer manager and ticker.
   *
   * @param peers peer manager used to derive routing context
   * @param ticker scheduler for periodic cleanup tasks
   */
  public RequestTracker(PeerManager peers, Ticker ticker) {
    this.peers = peers;
    this.ticker = ticker;
    runningCHKGetUIDsRT = new HashMap<>();
    runningLocalCHKGetUIDsRT = new HashMap<>();
    runningSSKGetUIDsRT = new HashMap<>();
    runningLocalSSKGetUIDsRT = new HashMap<>();
    runningCHKPutUIDsRT = new HashMap<>();
    runningLocalCHKPutUIDsRT = new HashMap<>();
    runningSSKPutUIDsRT = new HashMap<>();
    runningLocalSSKPutUIDsRT = new HashMap<>();
    runningCHKOfferReplyUIDsRT = new HashMap<>();
    runningSSKOfferReplyUIDsRT = new HashMap<>();

    runningCHKGetUIDsBulk = new HashMap<>();
    runningLocalCHKGetUIDsBulk = new HashMap<>();
    runningSSKGetUIDsBulk = new HashMap<>();
    runningLocalSSKGetUIDsBulk = new HashMap<>();
    runningCHKPutUIDsBulk = new HashMap<>();
    runningLocalCHKPutUIDsBulk = new HashMap<>();
    runningSSKPutUIDsBulk = new HashMap<>();
    runningLocalSSKPutUIDsBulk = new HashMap<>();
    runningCHKOfferReplyUIDsBulk = new HashMap<>();
    runningSSKOfferReplyUIDsBulk = new HashMap<>();

    transferringRequestSendersRT = new HashMap<>();
    transferringRequestSendersBulk = new HashMap<>();
    transferringRequestHandlers = new HashSet<>();
  }

  /**
   * Register and lock a request UID based on the properties carried by the tag.
   *
   * <p>Determines the appropriate tracker maps (CHK/SSK, get/put/offer, local/remote,
   * real-time/bulk) from the supplied {@code tag} and records the UID if not already owned by a
   * different tag.
   *
   * @param tag The {@link UIDTag} describing the request being started.
   * @return {@code true} when the UID is recorded (either newly added or already present for the
   *     same tag), {@code false} when the UID is owned by a different tag.
   */
  public boolean lockUID(UIDTag tag) {
    return lockUID(
        tag.uid,
        tag.isSSK(),
        tag.isInsert(),
        tag.isOfferReply(),
        tag.wasLocal(),
        tag.realTimeFlag,
        tag);
  }

  /**
   * Register and lock a request UID.
   *
   * <p>Records the UID in the overall map for the requested category and, when {@code local} is
   * true, in the corresponding local map as well. When the UID already exists for a different tag,
   * the method returns {@code false} and leaves maps unchanged.
   *
   * <p>Thread-safety: synchronizes on the chosen overall map; the local map, when used, is only
   * accessed while holding the overall map lock.
   *
   * @param uid Unique request identifier.
   * @param ssk {@code true} for SSK, {@code false} for CHK.
   * @param insert {@code true} for inserts, {@code false} for requests (gets).
   * @param offerReply {@code true} to operate on offer replies (takes precedence over {@code
   *     insert}).
   * @param local {@code true} if the request originated locally.
   * @param realTimeFlag {@code true} for real-time mode, {@code false} for bulk mode.
   * @param tag The tag instance to record for this UID.
   * @return {@code true} if recorded (or already present for the same tag), {@code false} if a
   *     different tag already owns the UID.
   */
  public boolean lockUID(
      long uid,
      boolean ssk,
      boolean insert,
      boolean offerReply,
      boolean local,
      boolean realTimeFlag,
      UIDTag tag) {
    // If these are switched around, we must remember to remove from both.
    if (offerReply) {
      // local irrelevant for OfferReplyTag's.
      HashMap<Long, OfferReplyTag> map = getOfferTracker(ssk, realTimeFlag);
      synchronized (map) {
        return doLock(map, null, (OfferReplyTag) tag, uid, false);
      }
    } else if (insert) {
      HashMap<Long, InsertTag> overallMap = getInsertTracker(ssk, false, realTimeFlag);
      HashMap<Long, InsertTag> localMap = local ? getInsertTracker(ssk, true, realTimeFlag) : null;
      synchronized (overallMap) {
        return doLock(overallMap, localMap, (InsertTag) tag, uid, local);
      }
    } else {
      HashMap<Long, RequestTag> overallMap = getRequestTracker(ssk, false, realTimeFlag);
      HashMap<Long, RequestTag> localMap =
          local ? getRequestTracker(ssk, true, realTimeFlag) : null;
      synchronized (overallMap) {
        return doLock(overallMap, localMap, (RequestTag) tag, uid, local);
      }
    }
  }

  private <T extends UIDTag> boolean doLock(
      HashMap<Long, T> overallMap, HashMap<Long, T> localMap, T tag, Long uid, boolean local) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Acquire UID lock uid={} local={} size={}",
          uid,
          local,
          overallMap.size(),
          new Exception(DEBUG_EXCEPTION_MESSAGE));
    T oldTag = overallMap.get(uid);
    if (oldTag != null && oldTag != tag) {
      return false;
    }
    if (oldTag != null) {
      LOG.warn("Tag already registered tag={}", tag);
    }
    overallMap.put(uid, tag);
    if (LOG.isDebugEnabled())
      LOG.debug("UID locked uid={} local={} size={}", uid, local, overallMap.size());
    return !local || lockLocal(localMap, overallMap, uid, tag);
  }

  private <T extends UIDTag> boolean lockLocal(
      HashMap<Long, T> localMap, HashMap<Long, T> overallMap, Long uid, T tag) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Acquire UID lock (local) uid={} local={} size={}",
          uid,
          true,
          localMap.size(),
          new Exception(DEBUG_EXCEPTION_MESSAGE));
    T oldTag = localMap.get(uid);
    if (oldTag != null) {
      if (oldTag == tag) {
        LOG.warn("Tag already registered (local): {}", tag);
      } else {
        // Violates the invariant that local requests are always registered on the main
        // (non-local) map too.
        LOG.error("Different tag already registered (local) although missing on main map: {}", tag);
        overallMap.remove(uid);
        return false;
      }
    }
    localMap.put(uid, tag);
    if (LOG.isDebugEnabled())
      LOG.debug("UID locked (local) uid={} local={} size={}", uid, true, localMap.size());
    return true;
  }

  /**
   * Unlock and unregister a request UID using the supplied tag context.
   *
   * <p>Delegates to the parameterized {@code unlockUID(...)} after extracting properties from
   * {@code tag}. When {@code noRecord} is {@code false}, marks the UID as completed to allow peer
   * queues to discard pending items.
   *
   * @param tag The tag describing the request to unlock.
   * @param canFail When {@code true}, tolerate missing or mismatched entries (no error log).
   * @param noRecord When {@code true}, do not record completion for peer cleanup.
   */
  void unlockUID(UIDTag tag, boolean canFail, boolean noRecord) {
    unlockUID(
        tag.uid,
        tag.isSSK(),
        tag.isInsert(),
        canFail,
        tag.isOfferReply(),
        tag.wasLocal(),
        tag.realTimeFlag,
        tag,
        noRecord);
  }

  /**
   * Unlock and unregister a request UID.
   *
   * <p>Removes the UID from the overall map and, when {@code local} is {@code true}, from the local
   * map as well. When {@code canFail} is {@code true}, missing entries are treated as benign and a
   * debug message is emitted instead of an error.
   *
   * @param uid Unique request identifier.
   * @param ssk {@code true} for SSK, {@code false} for CHK.
   * @param insert {@code true} for inserts, {@code false} for requests (gets).
   * @param canFail When {@code true}, tolerate missing or mismatched entries.
   * @param offerReply {@code true} to operate on offer replies (takes precedence over {@code
   *     insert}).
   * @param local {@code true} if the request originated locally.
   * @param realTimeFlag {@code true} for real-time mode, {@code false} for bulk mode.
   * @param tag The tag instance to remove for this UID.
   * @param noRecord When {@code true}, do not record completion for peer cleanup.
   */
  protected void unlockUID(
      long uid,
      boolean ssk,
      boolean insert,
      boolean canFail,
      boolean offerReply,
      boolean local,
      boolean realTimeFlag,
      UIDTag tag,
      boolean noRecord) {
    if (!noRecord) completed(uid);

    if (offerReply) {
      HashMap<Long, OfferReplyTag> map = getOfferTracker(ssk, realTimeFlag);
      synchronized (map) {
        doUnlock(map, null, (OfferReplyTag) tag, uid, false, canFail);
      }
    } else if (insert) {
      HashMap<Long, InsertTag> overallMap = getInsertTracker(ssk, false, realTimeFlag);
      HashMap<Long, InsertTag> localMap = local ? getInsertTracker(ssk, true, realTimeFlag) : null;
      synchronized (overallMap) {
        doUnlock(overallMap, localMap, (InsertTag) tag, uid, local, canFail);
      }
    } else {
      HashMap<Long, RequestTag> overallMap = getRequestTracker(ssk, false, realTimeFlag);
      HashMap<Long, RequestTag> localMap =
          local ? getRequestTracker(ssk, true, realTimeFlag) : null;
      synchronized (overallMap) {
        doUnlock(overallMap, localMap, (RequestTag) tag, uid, local, canFail);
      }
    }
  }

  /**
   * Do the actual unlock.
   *
   * @param <T> The type of the tag.
   * @param overallMap The overall map for this group of requests. LOCKING: We use the overallMap as
   *     lock for both.
   * @param localMap The local map if any. We check on overallMap and then remove from both.
   * @param tag The tag to remove.
   * @param uid The UID of the tag.
   * @param local Whether it is local. If it is local we use both maps. If it is not we expect the
   *     latter to be null.
   * @param canFail If true, tolerate missing entries and log at debug level instead of error.
   */
  private <T extends UIDTag> void doUnlock(
      HashMap<Long, T> overallMap,
      HashMap<Long, T> localMap,
      T tag,
      Long uid,
      boolean local,
      boolean canFail) {
    debugUnlocking(uid, local, overallMap.size());
    removeFromMap(overallMap, tag, uid, canFail, false);
    debugUnlocked(false, uid, local, overallMap.size());
    handleLocalAfterUnlock(localMap, tag, uid, local, canFail);
  }

  private void debugUnlocking(Long uid, boolean local, int size) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Release UID lock uid={} local={} size={}",
          uid,
          local,
          size,
          new Exception(DEBUG_EXCEPTION_MESSAGE));
  }

  private <T extends UIDTag> void handleLocalAfterUnlock(
      HashMap<Long, T> localMap, T tag, Long uid, boolean local, boolean canFail) {
    if (local) {
      removeFromMap(localMap, tag, uid, canFail, true);
      debugUnlocked(true, uid, true, localMap.size());
    } else {
      assert (localMap == null);
    }
  }

  private <T extends UIDTag> void removeFromMap(
      HashMap<Long, T> map, T tag, Long uid, boolean canFail, boolean isLocal) {
    T current = map.get(uid);
    if (current == tag) {
      map.remove(uid);
      return;
    }
    if (canFail) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Removal allowed to fail{}: expected={} actual={} uid={}",
            isLocal ? " (local)" : "",
            tag,
            current,
            uid);
      return;
    }
    if (isLocal) LOG.error("Remove expected={} uid={} found (local) {}", tag, uid, current);
    else LOG.error("Remove expected={} uid={} found {}", tag, uid, current);
  }

  private void debugUnlocked(boolean isLocal, Long uid, boolean local, int size) {
    if (LOG.isDebugEnabled()) {
      if (isLocal) LOG.debug("UID unlocked (local) uid={} local={} size={}", uid, local, size);
      else LOG.debug("UID unlocked uid={} local={} size={}", uid, local, size);
    }
  }

  public static class CountedRequests {
    private int total;
    private int expectedTransfersOut;
    private int expectedTransfersIn;

    /** Total number of matching requests. */
    public int total() {
      return total;
    }

    /** Expected outgoing transfers across all counted requests. */
    public int expectedTransfersOut() {
      return expectedTransfersOut;
    }

    /** Expected incoming transfers across all counted requests. */
    public int expectedTransfersIn() {
      return expectedTransfersIn;
    }
  }

  /**
   * Count all running requests that match the given filters and accumulate transfer estimates.
   *
   * @param local If true, include only locally originated requests; otherwise include all.
   * @param ssk If true, count SSK; if false, count CHK.
   * @param insert If true, count inserts; otherwise count gets (requests).
   * @param offer If true, count offer replies (takes precedence over {@code insert}).
   * @param realTimeFlag If true, count real-time requests; otherwise count bulk.
   * @param transfersPerInsert Average outgoing transfers to assume per insert.
   * @param ignoreLocalVsRemote If true, treat local requests as remote for transfer estimation.
   * @param counter Accumulator for totals and transfer estimates.
   * @param counterSourceRestarted Optional accumulator for requests counted as source-restarted.
   */
  public void countRequests(
      boolean local,
      boolean ssk,
      boolean insert,
      boolean offer,
      boolean realTimeFlag,
      int transfersPerInsert,
      boolean ignoreLocalVsRemote,
      CountedRequests counter,
      CountedRequests counterSourceRestarted) {
    HashMap<Long, ? extends UIDTag> map = getTracker(local, ssk, insert, offer, realTimeFlag);
    // Map is locked by the non-local version, although we're counting from the local version.
    synchronized (local ? getTracker(false, ssk, insert, offer, realTimeFlag) : map) {
      CountTotals totals =
          accumulateCounts(
              map, local, ignoreLocalVsRemote, transfersPerInsert, counterSourceRestarted != null);
      counter.total += totals.count;
      counter.expectedTransfersIn += totals.in;
      counter.expectedTransfersOut += totals.out;
      if (counterSourceRestarted != null) {
        counterSourceRestarted.total += totals.countSR;
        counterSourceRestarted.expectedTransfersIn += totals.inSR;
        counterSourceRestarted.expectedTransfersOut += totals.outSR;
      }
    }
  }

  private static final class CountTotals {
    int count;
    int out;
    int in;
    int countSR;
    int outSR;
    int inSR;
  }

  private CountTotals accumulateCounts(
      Map<Long, ? extends UIDTag> map,
      boolean local,
      boolean ignoreLocalVsRemote,
      int transfersPerInsert,
      boolean includeSourceRestarted) {
    CountTotals totals = new CountTotals();
    for (Map.Entry<Long, ? extends UIDTag> entry : map.entrySet()) {
      UIDTag tag = entry.getValue();
      // The overall running* map can include local. But the local map can't include non-local.
      if ((!local) && tag.wasLocal) continue;
      int out = tag.expectedTransfersOut(ignoreLocalVsRemote, transfersPerInsert, true);
      int in = tag.expectedTransfersIn(ignoreLocalVsRemote, transfersPerInsert, true);
      totals.count++;
      totals.out += out;
      totals.in += in;
      if (includeSourceRestarted && tag.countAsSourceRestarted()) {
        totals.countSR++;
        totals.outSR += out;
        totals.inSR += in;
      }
      if (LOG.isDebugEnabled())
        LOG.debug("Count uid={} out={} in={}", entry.getKey(), totals.out, totals.in);
    }
    return totals;
  }

  /**
   * Count requests routed to a peer or accepted from a peer and accumulate transfer estimates.
   *
   * <p>Performance note: maps are partitioned by request type (local, SSK, etc.) but not by peer. A
   * single pass per peer is used here; future aggregation strategies may optimize multi-peer
   * computations.
   *
   * @param source Peer from which requests were accepted or to which they were routed.
   * @param requestsToNode If true, count requests sent to {@code source} and currently running;
   *     otherwise count requests originating from {@code source}.
   * @param local If true, include only locally originated requests; otherwise include all.
   * @param ssk If true, count SSK; if false, count CHK.
   * @param insert If true, count inserts; otherwise count gets (requests).
   * @param offer If true, count offer replies (takes precedence over {@code insert}).
   * @param realTimeFlag If true, count real-time; otherwise count bulk.
   * @param transfersPerInsert Average outgoing transfers to assume per insert.
   * @param ignoreLocalVsRemote If true, treat local requests as remote for transfer estimation.
   * @param counter Accumulator for totals and transfer estimates.
   * @param counterSR Optional accumulator for requests counted as source-restarted.
   */
  public void countRequests(
      PeerNode source,
      boolean requestsToNode,
      boolean local,
      boolean ssk,
      boolean insert,
      boolean offer,
      boolean realTimeFlag,
      int transfersPerInsert,
      boolean ignoreLocalVsRemote,
      CountedRequests counter,
      CountedRequests counterSR) {
    HashMap<Long, ? extends UIDTag> map = getTracker(local, ssk, insert, offer, realTimeFlag);
    // Map is locked by the non-local version, although we're counting from the local version.
    synchronized (local ? getTracker(false, ssk, insert, offer, realTimeFlag) : map) {
      if (!requestsToNode) {
        countRequestsFromSource(
            map, local, source, ignoreLocalVsRemote, transfersPerInsert, counter, counterSR);
      } else {
        countRequestsToNode(
            map,
            local,
            source,
            ignoreLocalVsRemote,
            transfersPerInsert,
            counter,
            ssk,
            insert,
            offer);
      }
    }
  }

  private void countRequestsFromSource(
      Map<Long, ? extends UIDTag> map,
      boolean local,
      PeerNode source,
      boolean ignoreLocalVsRemote,
      int transfersPerInsert,
      CountedRequests counter,
      CountedRequests counterSR) {
    // If a request is adopted by us as a result of a timeout, it can be in the
    // remote map despite having source == null. However, if a request is in the
    // local map it will always have source == null.
    if (source != null && local) return;
    CountTotals totals =
        accumulateCountsFromSource(
            map, local, source, ignoreLocalVsRemote, transfersPerInsert, counterSR != null);
    if (LOG.isDebugEnabled())
      LOG.debug("Count totals count={} in={} out={}", totals.count, totals.in, totals.out);
    counter.total += totals.count;
    counter.expectedTransfersIn += totals.in;
    counter.expectedTransfersOut += totals.out;
    if (counterSR != null) {
      counterSR.total += totals.countSR;
      counterSR.expectedTransfersIn += totals.inSR;
      counterSR.expectedTransfersOut += totals.outSR;
    }
  }

  private void countRequestsToNode(
      Map<Long, ? extends UIDTag> map,
      boolean local,
      PeerNode source,
      boolean ignoreLocalVsRemote,
      int transfersPerInsert,
      CountedRequests counter,
      boolean ssk,
      boolean insert,
      boolean offer) {
    // hasSourceRestarted is irrelevant for requests *to* a node.
    // Consider improving efficiency if measurements indicate a bottleneck.
    CountTotals totals =
        accumulateCountsToNode(map, local, source, ignoreLocalVsRemote, transfersPerInsert);
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Count to node scope={} keyType={} opType={} offer={} count={} of={} peer={}",
          local ? "local" : "remote",
          ssk ? "ssk" : "chk",
          insert ? "insert" : "request",
          offer ? "offer" : "",
          totals.count,
          map.size(),
          source);
    counter.total += totals.count;
    counter.expectedTransfersIn += totals.in;
    counter.expectedTransfersOut += totals.out;
  }

  private CountTotals accumulateCountsFromSource(
      Map<Long, ? extends UIDTag> map,
      boolean local,
      PeerNode source,
      boolean ignoreLocalVsRemote,
      int transfersPerInsert,
      boolean includeSourceRestarted) {
    CountTotals totals = new CountTotals();
    for (Map.Entry<Long, ? extends UIDTag> entry : map.entrySet()) {
      UIDTag tag = entry.getValue();
      if ((!local) && tag.wasLocal) continue;
      if (tag.getSource() == source) {
        int out = tag.expectedTransfersOut(ignoreLocalVsRemote, transfersPerInsert, true);
        int in = tag.expectedTransfersIn(ignoreLocalVsRemote, transfersPerInsert, true);
        totals.count++;
        totals.out += out;
        totals.in += in;
        if (includeSourceRestarted && tag.countAsSourceRestarted()) {
          totals.countSR++;
          totals.outSR += out;
          totals.inSR += in;
        }
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Count from source tag={} uid={} source={} count={} out={} in={}",
              tag,
              entry.getKey(),
              source,
              totals.count,
              totals.out,
              totals.in);
      } else if (LOG.isTraceEnabled()) {
        LOG.trace("Skip uid={}", entry.getKey());
      }
    }
    return totals;
  }

  private CountTotals accumulateCountsToNode(
      Map<Long, ? extends UIDTag> map,
      boolean local,
      PeerNode source,
      boolean ignoreLocalVsRemote,
      int transfersPerInsert) {
    CountTotals totals = new CountTotals();
    for (Map.Entry<Long, ? extends UIDTag> entry : map.entrySet()) {
      UIDTag tag = entry.getValue();
      if ((!local) && tag.wasLocal) continue;
      if (tag.currentlyFetchingOfferedKeyFrom(source)) {
        if (LOG.isDebugEnabled()) LOG.debug("Count to peer tag={} uid={}", tag, entry.getKey());
        totals.out += tag.expectedTransfersOut(ignoreLocalVsRemote, transfersPerInsert, false);
        totals.in += tag.expectedTransfersIn(ignoreLocalVsRemote, transfersPerInsert, false);
        totals.count++;
      } else if (tag.currentlyRoutingTo(source)) {
        if (LOG.isDebugEnabled()) LOG.debug("Count to peer tag={} uid={}", tag, entry.getKey());
        totals.out += tag.expectedTransfersOut(ignoreLocalVsRemote, transfersPerInsert, false);
        totals.in += tag.expectedTransfersIn(ignoreLocalVsRemote, transfersPerInsert, false);
        totals.count++;
      } else if (LOG.isTraceEnabled()) {
        LOG.trace("Skip uid={}", entry.getKey());
      }
    }
    return totals;
  }

  /**
   * Count all requests grouped by the peer that originated the request.
   *
   * @param requestsToNode If true, count requests sent to the node; otherwise count those
   *     originating from peers.
   * @param local If true, include only locally originated requests; otherwise include all.
   * @param ssk If true, count SSK; if false, count CHK.
   * @param insert If true, count inserts; otherwise count gets (requests).
   * @param offer If true, count offer replies (takes precedence over {@code insert}).
   * @param realTimeFlag If true, count real-time; otherwise count bulk.
   * @param transfersPerInsert Average outgoing transfers to assume per insert.
   * @param ignoreLocalVsRemote If true, treat local requests as remote for transfer estimation.
   * @param counterMap Destination map from {@link PeerNode} (may be {@code null}) to counters.
   *     {@code null} is used for local requests, adopted requests after source restart, and
   *     requests whose originator is not currently in the routing table.
   */
  @SuppressWarnings("unused")
  public void countAllRequestsByIncomingPeer(
      boolean requestsToNode,
      boolean local,
      boolean ssk,
      boolean insert,
      boolean offer,
      boolean realTimeFlag,
      int transfersPerInsert,
      boolean ignoreLocalVsRemote,
      Map<PeerNode, CountedRequests> counterMap) {
    HashMap<Long, ? extends UIDTag> map = getTracker(local, ssk, insert, offer, realTimeFlag);
    // Map is locked by the non-local version, although we're counting from the local version.
    synchronized (local ? getTracker(false, ssk, insert, offer, realTimeFlag) : map) {
      if (!requestsToNode) {
        // If a request is adopted by us as a result of a timeout, it can be in the
        // remote map despite having source == null. However, if a request is in the
        // local map it will always have source == null.
        for (Map.Entry<Long, ? extends UIDTag> entry : map.entrySet()) {
          UIDTag tag = entry.getValue();
          // The overall running* map can include local. But the local map can't include non-local.
          if ((!local) && tag.wasLocal) continue;
          PeerNode source = tag.getSource(); // Can be null in various cases
          CountedRequests counter = counterMap.computeIfAbsent(source, k -> new CountedRequests());
          int out = tag.expectedTransfersOut(ignoreLocalVsRemote, transfersPerInsert, true);
          int in = tag.expectedTransfersIn(ignoreLocalVsRemote, transfersPerInsert, true);
          counter.total++;
          counter.expectedTransfersIn += in;
          counter.expectedTransfersOut += out;
        }
      }
    }
  }

  /** Summary of requests waiting for execution slots. */
  public static class WaitingForSlots {
    /** Number of locally originated requests waiting for a slot. */
    int local;

    /** Number of remotely originated requests waiting for a slot. */
    int remote;
  }

  /**
   * Count requests that are waiting for an execution slot.
   *
   * @return Summary with {@code local} and {@code remote} counts of requests queued for a slot.
   */
  public WaitingForSlots countRequestsWaitingForSlots() {
    WaitingForSlots slots = new WaitingForSlots();
    synchronized (runningSSKGetUIDsRT) {
      accumulateWaitingForSlots(runningSSKGetUIDsRT, slots);
    }
    synchronized (runningCHKGetUIDsRT) {
      accumulateWaitingForSlots(runningCHKGetUIDsRT, slots);
    }
    synchronized (runningSSKPutUIDsRT) {
      accumulateWaitingForSlots(runningSSKPutUIDsRT, slots);
    }
    synchronized (runningCHKPutUIDsRT) {
      accumulateWaitingForSlots(runningCHKPutUIDsRT, slots);
    }
    synchronized (runningSSKOfferReplyUIDsRT) {
      accumulateWaitingForSlots(runningSSKOfferReplyUIDsRT, slots);
    }
    synchronized (runningCHKOfferReplyUIDsRT) {
      accumulateWaitingForSlots(runningCHKOfferReplyUIDsRT, slots);
    }
    synchronized (runningSSKGetUIDsBulk) {
      accumulateWaitingForSlots(runningSSKGetUIDsBulk, slots);
    }
    synchronized (runningCHKGetUIDsBulk) {
      accumulateWaitingForSlots(runningCHKGetUIDsBulk, slots);
    }
    synchronized (runningSSKPutUIDsBulk) {
      accumulateWaitingForSlots(runningSSKPutUIDsBulk, slots);
    }
    synchronized (runningCHKPutUIDsBulk) {
      accumulateWaitingForSlots(runningCHKPutUIDsBulk, slots);
    }
    return slots;
  }

  private void accumulateWaitingForSlots(
      HashMap<Long, ? extends UIDTag> runningUIDs, WaitingForSlots slots) {
    // Note: a counter could be used here, but would require ensuring it is always decremented
    // when something goes wrong.
    for (UIDTag tag : runningUIDs.values()) {
      if (!tag.isWaitingForSlot()) continue;
      if (tag.isLocal()) slots.local++;
      else slots.remote++;
    }
  }

  void reassignTagToSelf(UIDTag tag) {
    // The tag remains marked as remote; flag as adopted by this node.
    tag.reassignToSelf();
  }

  private HashMap<Long, ? extends UIDTag> getTracker(
      boolean local, boolean ssk, boolean insert, boolean offer, boolean realTimeFlag) {
    if (offer) return getOfferTracker(ssk, realTimeFlag);
    else if (insert) return getInsertTracker(ssk, local, realTimeFlag);
    else return getRequestTracker(ssk, local, realTimeFlag);
  }

  private HashMap<Long, RequestTag> getRequestTracker(
      boolean ssk, boolean local, boolean realTimeFlag) {
    return realTimeFlag ? getRequestTrackerRT(ssk, local) : getRequestTrackerBulk(ssk, local);
  }

  private HashMap<Long, RequestTag> getRequestTrackerRT(boolean ssk, boolean local) {
    if (ssk) {
      return local ? runningLocalSSKGetUIDsRT : runningSSKGetUIDsRT;
    }
    return local ? runningLocalCHKGetUIDsRT : runningCHKGetUIDsRT;
  }

  private HashMap<Long, RequestTag> getRequestTrackerBulk(boolean ssk, boolean local) {
    if (ssk) {
      return local ? runningLocalSSKGetUIDsBulk : runningSSKGetUIDsBulk;
    }
    return local ? runningLocalCHKGetUIDsBulk : runningCHKGetUIDsBulk;
  }

  private HashMap<Long, InsertTag> getInsertTracker(
      boolean ssk, boolean local, boolean realTimeFlag) {
    return realTimeFlag ? getInsertTrackerRT(ssk, local) : getInsertTrackerBulk(ssk, local);
  }

  private HashMap<Long, InsertTag> getInsertTrackerRT(boolean ssk, boolean local) {
    if (ssk) {
      return local ? runningLocalSSKPutUIDsRT : runningSSKPutUIDsRT;
    }
    return local ? runningLocalCHKPutUIDsRT : runningCHKPutUIDsRT;
  }

  private HashMap<Long, InsertTag> getInsertTrackerBulk(boolean ssk, boolean local) {
    if (ssk) {
      return local ? runningLocalSSKPutUIDsBulk : runningSSKPutUIDsBulk;
    }
    return local ? runningLocalCHKPutUIDsBulk : runningCHKPutUIDsBulk;
  }

  private HashMap<Long, OfferReplyTag> getOfferTracker(boolean ssk, boolean realTimeFlag) {
    if (realTimeFlag) return ssk ? runningSSKOfferReplyUIDsRT : runningCHKOfferReplyUIDsRT;
    else return ssk ? runningSSKOfferReplyUIDsBulk : runningCHKOfferReplyUIDsBulk;
  }

  // Must include bulk inserts so fairly long.
  // 21 minutes is enough for a fatal timeout.
  static final long TIMEOUT = MINUTES.toMillis(21);

  /** Schedule the periodic dead-UID checker task. */
  void startDeadUIDChecker() {
    ticker.queueTimedJob(deadUIDChecker, TIMEOUT);
  }

  private final Runnable deadUIDChecker =
      new Runnable() {
        @Override
        public void run() {
          try {
            checkUIDsForSSKGetRT();
            checkUIDsForCHKGetRT();
            checkUIDsForSSKPutRT();
            checkUIDsForCHKPutRT();
            checkUIDsForSSKOfferRT();
            checkUIDsForCHKOfferRT();
            checkUIDsForSSKGetBulk();
            checkUIDsForCHKGetBulk();
            checkUIDsForSSKPutBulk();
            checkUIDsForCHKPutBulk();
            checkUIDsForSSKOfferBulk();
            checkUIDsForCHKOfferBulk();
          } finally {
            ticker.queueTimedJob(this, SECONDS.toMillis(60));
          }
        }

        private void checkUIDsForSSKGetRT() {
          Long[] uids;
          UIDTag[] tags;
          synchronized (runningSSKGetUIDsRT) {
            uids = runningSSKGetUIDsRT.keySet().toArray(new Long[0]);
            tags = runningSSKGetUIDsRT.values().toArray(new UIDTag[0]);
          }
          long now = System.currentTimeMillis();
          for (int i = 0; i < uids.length; i++) tags[i].maybeLogStillPresent(now, uids[i]);
        }

        private void checkUIDsForCHKGetRT() {
          Long[] uids;
          UIDTag[] tags;
          synchronized (runningCHKGetUIDsRT) {
            uids = runningCHKGetUIDsRT.keySet().toArray(new Long[0]);
            tags = runningCHKGetUIDsRT.values().toArray(new UIDTag[0]);
          }
          long now = System.currentTimeMillis();
          for (int i = 0; i < uids.length; i++) tags[i].maybeLogStillPresent(now, uids[i]);
        }

        private void checkUIDsForSSKPutRT() {
          Long[] uids;
          UIDTag[] tags;
          synchronized (runningSSKPutUIDsRT) {
            uids = runningSSKPutUIDsRT.keySet().toArray(new Long[0]);
            tags = runningSSKPutUIDsRT.values().toArray(new UIDTag[0]);
          }
          long now = System.currentTimeMillis();
          for (int i = 0; i < uids.length; i++) tags[i].maybeLogStillPresent(now, uids[i]);
        }

        private void checkUIDsForCHKPutRT() {
          Long[] uids;
          UIDTag[] tags;
          synchronized (runningCHKPutUIDsRT) {
            uids = runningCHKPutUIDsRT.keySet().toArray(new Long[0]);
            tags = runningCHKPutUIDsRT.values().toArray(new UIDTag[0]);
          }
          long now = System.currentTimeMillis();
          for (int i = 0; i < uids.length; i++) tags[i].maybeLogStillPresent(now, uids[i]);
        }

        private void checkUIDsForSSKOfferRT() {
          Long[] uids;
          UIDTag[] tags;
          synchronized (runningSSKOfferReplyUIDsRT) {
            uids = runningSSKOfferReplyUIDsRT.keySet().toArray(new Long[0]);
            tags = runningSSKOfferReplyUIDsRT.values().toArray(new UIDTag[0]);
          }
          long now = System.currentTimeMillis();
          for (int i = 0; i < uids.length; i++) tags[i].maybeLogStillPresent(now, uids[i]);
        }

        private void checkUIDsForCHKOfferRT() {
          Long[] uids;
          UIDTag[] tags;
          synchronized (runningCHKOfferReplyUIDsRT) {
            uids = runningCHKOfferReplyUIDsRT.keySet().toArray(new Long[0]);
            tags = runningCHKOfferReplyUIDsRT.values().toArray(new UIDTag[0]);
          }
          long now = System.currentTimeMillis();
          for (int i = 0; i < uids.length; i++) tags[i].maybeLogStillPresent(now, uids[i]);
        }

        private void checkUIDsForSSKGetBulk() {
          Long[] uids;
          UIDTag[] tags;
          synchronized (runningSSKGetUIDsBulk) {
            uids = runningSSKGetUIDsBulk.keySet().toArray(new Long[0]);
            tags = runningSSKGetUIDsBulk.values().toArray(new UIDTag[0]);
          }
          long now = System.currentTimeMillis();
          for (int i = 0; i < uids.length; i++) tags[i].maybeLogStillPresent(now, uids[i]);
        }

        private void checkUIDsForCHKGetBulk() {
          Long[] uids;
          UIDTag[] tags;
          synchronized (runningCHKGetUIDsBulk) {
            uids = runningCHKGetUIDsBulk.keySet().toArray(new Long[0]);
            tags = runningCHKGetUIDsBulk.values().toArray(new UIDTag[0]);
          }
          long now = System.currentTimeMillis();
          for (int i = 0; i < uids.length; i++) tags[i].maybeLogStillPresent(now, uids[i]);
        }

        private void checkUIDsForSSKPutBulk() {
          Long[] uids;
          UIDTag[] tags;
          synchronized (runningSSKPutUIDsBulk) {
            uids = runningSSKPutUIDsBulk.keySet().toArray(new Long[0]);
            tags = runningSSKPutUIDsBulk.values().toArray(new UIDTag[0]);
          }
          long now = System.currentTimeMillis();
          for (int i = 0; i < uids.length; i++) tags[i].maybeLogStillPresent(now, uids[i]);
        }

        private void checkUIDsForCHKPutBulk() {
          Long[] uids;
          UIDTag[] tags;
          synchronized (runningCHKPutUIDsBulk) {
            uids = runningCHKPutUIDsBulk.keySet().toArray(new Long[0]);
            tags = runningCHKPutUIDsBulk.values().toArray(new UIDTag[0]);
          }
          long now = System.currentTimeMillis();
          for (int i = 0; i < uids.length; i++) tags[i].maybeLogStillPresent(now, uids[i]);
        }

        private void checkUIDsForSSKOfferBulk() {
          Long[] uids;
          UIDTag[] tags;
          synchronized (runningSSKOfferReplyUIDsBulk) {
            uids = runningSSKOfferReplyUIDsBulk.keySet().toArray(new Long[0]);
            tags = runningSSKOfferReplyUIDsBulk.values().toArray(new UIDTag[0]);
          }
          long now = System.currentTimeMillis();
          for (int i = 0; i < uids.length; i++) tags[i].maybeLogStillPresent(now, uids[i]);
        }

        private void checkUIDsForCHKOfferBulk() {
          Long[] uids;
          UIDTag[] tags;
          synchronized (runningCHKOfferReplyUIDsBulk) {
            uids = runningCHKOfferReplyUIDsBulk.keySet().toArray(new Long[0]);
            tags = runningCHKOfferReplyUIDsBulk.values().toArray(new UIDTag[0]);
          }
          long now = System.currentTimeMillis();
          for (int i = 0; i < uids.length; i++) tags[i].maybeLogStillPresent(now, uids[i]);
        }
      };

  /**
   * Notify all tags that a peer restarted or disconnected.
   *
   * @param pn The peer whose state changed. Tags that use {@code pn} as their source update their
   *     accounting to reflect adoption semantics.
   */
  public void onRestartOrDisconnect(PeerNode pn) {
    synchronized (runningSSKGetUIDsRT) {
      notifyOnSourceRestart(runningSSKGetUIDsRT.values(), pn);
    }
    synchronized (runningCHKGetUIDsRT) {
      notifyOnSourceRestart(runningCHKGetUIDsRT.values(), pn);
    }
    synchronized (runningSSKPutUIDsRT) {
      notifyOnSourceRestart(runningSSKPutUIDsRT.values(), pn);
    }
    synchronized (runningCHKPutUIDsRT) {
      notifyOnSourceRestart(runningCHKPutUIDsRT.values(), pn);
    }
    synchronized (runningSSKOfferReplyUIDsRT) {
      notifyOnSourceRestart(runningSSKOfferReplyUIDsRT.values(), pn);
    }
    synchronized (runningCHKOfferReplyUIDsRT) {
      notifyOnSourceRestart(runningCHKOfferReplyUIDsRT.values(), pn);
    }
    synchronized (runningSSKGetUIDsBulk) {
      notifyOnSourceRestart(runningSSKGetUIDsBulk.values(), pn);
    }
    synchronized (runningCHKGetUIDsBulk) {
      notifyOnSourceRestart(runningCHKGetUIDsBulk.values(), pn);
    }
    synchronized (runningSSKPutUIDsBulk) {
      notifyOnSourceRestart(runningSSKPutUIDsBulk.values(), pn);
    }
    synchronized (runningCHKPutUIDsBulk) {
      notifyOnSourceRestart(runningCHKPutUIDsBulk.values(), pn);
    }
    synchronized (runningSSKOfferReplyUIDsBulk) {
      notifyOnSourceRestart(runningSSKOfferReplyUIDsBulk.values(), pn);
    }
    synchronized (runningCHKOfferReplyUIDsBulk) {
      notifyOnSourceRestart(runningCHKOfferReplyUIDsBulk.values(), pn);
    }
  }

  private void notifyOnSourceRestart(Iterable<? extends UIDTag> tags, PeerNode pn) {
    for (UIDTag tag : tags) {
      if (tag.isSource(pn)) tag.onRestartOrDisconnectSource();
    }
  }

  /**
   * Count all SSK requests currently running (local and remote, real-time and bulk).
   *
   * @return Number of running SSK gets.
   */
  public int getNumSSKRequests() {
    int total = 0;
    // running* include all requests, local and remote.
    synchronized (runningSSKGetUIDsBulk) {
      total += runningSSKGetUIDsBulk.size();
    }
    synchronized (runningSSKGetUIDsRT) {
      total += runningSSKGetUIDsRT.size();
    }
    return total;
  }

  /**
   * Count all CHK requests currently running (local and remote, real-time and bulk).
   *
   * @return Number of running CHK gets.
   */
  public int getNumCHKRequests() {
    int total = 0;
    synchronized (runningCHKGetUIDsBulk) {
      total += runningCHKGetUIDsBulk.size();
    }
    synchronized (runningCHKGetUIDsRT) {
      total += runningCHKGetUIDsRT.size();
    }
    return total;
  }

  /**
   * Count all SSK inserts currently running (local and remote, real-time and bulk).
   *
   * @return Number of running SSK inserts.
   */
  public int getNumSSKInserts() {
    int total = 0;
    synchronized (runningSSKPutUIDsBulk) {
      total += runningSSKPutUIDsBulk.size();
    }
    synchronized (runningSSKPutUIDsRT) {
      total += runningSSKPutUIDsRT.size();
    }
    return total;
  }

  /**
   * Count all CHK inserts currently running (local and remote, real-time and bulk).
   *
   * @return Number of running CHK inserts.
   */
  public int getNumCHKInserts() {
    int total = 0;
    synchronized (runningCHKPutUIDsBulk) {
      total += runningCHKPutUIDsBulk.size();
    }
    synchronized (runningCHKPutUIDsRT) {
      total += runningCHKPutUIDsRT.size();
    }
    return total;
  }

  /**
   * Count locally originated SSK requests currently running (real-time and bulk).
   *
   * @return Number of running local SSK gets.
   */
  public int getNumLocalSSKRequests() {
    int total = 0;
    synchronized (runningSSKGetUIDsBulk) {
      total += runningLocalSSKGetUIDsBulk.size();
    }
    synchronized (runningSSKGetUIDsRT) {
      total += runningLocalSSKGetUIDsRT.size();
    }
    return total;
  }

  /**
   * Count locally originated CHK requests currently running (real-time and bulk).
   *
   * @return Number of running local CHK gets.
   */
  public int getNumLocalCHKRequests() {
    int total = 0;
    synchronized (runningCHKGetUIDsBulk) {
      total += runningLocalCHKGetUIDsBulk.size();
    }
    synchronized (runningCHKGetUIDsRT) {
      total += runningLocalCHKGetUIDsRT.size();
    }
    return total;
  }

  /**
   * Count remotely originated CHK requests currently running (real-time and bulk).
   *
   * @return Number of running remote CHK gets.
   */
  public int getNumRemoteCHKRequests() {
    int total = 0;
    synchronized (runningCHKGetUIDsBulk) {
      total += runningCHKGetUIDsBulk.size();
      total -= runningLocalCHKGetUIDsBulk.size();
    }
    synchronized (runningCHKGetUIDsRT) {
      total += runningCHKGetUIDsRT.size();
      total -= runningLocalCHKGetUIDsRT.size();
    }
    return total;
  }

  /**
   * Count remotely originated SSK requests currently running (real-time and bulk).
   *
   * @return Number of running remote SSK gets.
   */
  public int getNumRemoteSSKRequests() {
    int total = 0;
    synchronized (runningSSKGetUIDsBulk) {
      total += runningSSKGetUIDsBulk.size();
      total -= runningLocalSSKGetUIDsBulk.size();
    }
    synchronized (runningSSKGetUIDsRT) {
      total += runningSSKGetUIDsRT.size();
      total -= runningLocalSSKGetUIDsRT.size();
    }
    return total;
  }

  /**
   * Count locally originated CHK inserts currently running (real-time and bulk).
   *
   * @return Number of running local CHK inserts.
   */
  public int getNumLocalCHKInserts() {
    int total = 0;
    synchronized (runningCHKPutUIDsBulk) {
      total += runningLocalCHKPutUIDsBulk.size();
    }
    synchronized (runningCHKPutUIDsRT) {
      total += runningLocalCHKPutUIDsRT.size();
    }
    return total;
  }

  /**
   * Count locally originated SSK inserts currently running (real-time and bulk).
   *
   * @return Number of running local SSK inserts.
   */
  public int getNumLocalSSKInserts() {
    int total = 0;
    synchronized (runningSSKPutUIDsBulk) {
      total += runningLocalSSKPutUIDsBulk.size();
    }
    synchronized (runningSSKPutUIDsRT) {
      total += runningLocalSSKPutUIDsRT.size();
    }
    return total;
  }

  /**
   * Count remotely originated CHK inserts currently running (real-time and bulk).
   *
   * @return Number of running remote CHK inserts.
   */
  public int getNumRemoteCHKInserts() {
    int total = 0;
    synchronized (runningCHKPutUIDsBulk) {
      total += runningCHKPutUIDsBulk.size() - runningLocalCHKPutUIDsBulk.size();
    }
    synchronized (runningCHKPutUIDsRT) {
      total += runningCHKPutUIDsRT.size() - runningLocalCHKPutUIDsRT.size();
    }
    return total;
  }

  /**
   * Count remotely originated SSK inserts currently running (real-time and bulk).
   *
   * @return Number of running remote SSK inserts.
   */
  public int getNumRemoteSSKInserts() {
    int total = 0;
    synchronized (runningSSKPutUIDsRT) {
      total += runningSSKPutUIDsRT.size() - runningLocalSSKPutUIDsRT.size();
    }
    synchronized (runningSSKPutUIDsBulk) {
      total += runningSSKPutUIDsBulk.size() - runningLocalSSKPutUIDsBulk.size();
    }
    return total;
  }

  /**
   * Count SSK offer replies currently running (real-time and bulk).
   *
   * @return Number of running SSK offer replies.
   */
  public int getNumSSKOfferReplies() {
    int total = 0;
    synchronized (runningSSKOfferReplyUIDsRT) {
      total += runningSSKOfferReplyUIDsRT.size();
    }
    synchronized (runningSSKOfferReplyUIDsBulk) {
      total += runningSSKOfferReplyUIDsBulk.size();
    }
    return total;
  }

  /**
   * Count CHK offer replies currently running (real-time and bulk).
   *
   * @return Number of running CHK offer replies.
   */
  public int getNumCHKOfferReplies() {
    int total = 0;
    synchronized (runningCHKOfferReplyUIDsRT) {
      total += runningCHKOfferReplyUIDsRT.size();
    }
    synchronized (runningCHKOfferReplyUIDsBulk) {
      total += runningCHKOfferReplyUIDsBulk.size();
    }
    return total;
  }

  /**
   * Count SSK offer replies for the selected mode.
   *
   * @param realTimeFlag {@code true} for real-time; {@code false} for bulk.
   * @return Number of running SSK offer replies for the chosen mode.
   */
  @SuppressWarnings("unused")
  public int getNumSSKOfferReplies(boolean realTimeFlag) {
    return realTimeFlag ? runningSSKOfferReplyUIDsRT.size() : runningSSKOfferReplyUIDsBulk.size();
  }

  /**
   * Count CHK offer replies for the selected mode.
   *
   * @param realTimeFlag {@code true} for real-time; {@code false} for bulk.
   * @return Number of running CHK offer replies for the chosen mode.
   */
  @SuppressWarnings("unused")
  public int getNumCHKOfferReplies(boolean realTimeFlag) {
    return realTimeFlag ? runningCHKOfferReplyUIDsRT.size() : runningCHKOfferReplyUIDsBulk.size();
  }

  /**
   * Append all running UIDs (all categories) to the given list.
   *
   * @param list Destination list to receive all running UIDs.
   */
  public void addRunningUIDs(List<Long> list) {
    synchronized (runningSSKGetUIDsRT) {
      list.addAll(runningSSKGetUIDsRT.keySet());
    }
    synchronized (runningCHKGetUIDsRT) {
      list.addAll(runningCHKGetUIDsRT.keySet());
    }
    synchronized (runningSSKPutUIDsRT) {
      list.addAll(runningSSKPutUIDsRT.keySet());
    }
    synchronized (runningCHKPutUIDsRT) {
      list.addAll(runningCHKPutUIDsRT.keySet());
    }
    synchronized (runningSSKOfferReplyUIDsRT) {
      list.addAll(runningSSKOfferReplyUIDsRT.keySet());
    }
    synchronized (runningCHKOfferReplyUIDsRT) {
      list.addAll(runningCHKOfferReplyUIDsRT.keySet());
    }
    synchronized (runningSSKGetUIDsBulk) {
      list.addAll(runningSSKGetUIDsBulk.keySet());
    }
    synchronized (runningCHKGetUIDsBulk) {
      list.addAll(runningCHKGetUIDsBulk.keySet());
    }
    synchronized (runningSSKPutUIDsBulk) {
      list.addAll(runningSSKPutUIDsBulk.keySet());
    }
    synchronized (runningCHKPutUIDsBulk) {
      list.addAll(runningCHKPutUIDsBulk.keySet());
    }
    synchronized (runningSSKOfferReplyUIDsBulk) {
      list.addAll(runningSSKOfferReplyUIDsBulk.keySet());
    }
    synchronized (runningCHKOfferReplyUIDsBulk) {
      list.addAll(runningCHKOfferReplyUIDsBulk.keySet());
    }
  }

  /**
   * Count all running UIDs across all categories (alternative fast path).
   *
   * @return Total number of running UIDs in all maps.
   */
  public int getTotalRunningUIDsAlt() {
    return this.runningCHKGetUIDsRT.size()
        + this.runningCHKPutUIDsRT.size()
        + this.runningSSKGetUIDsRT.size()
        + this.runningSSKPutUIDsRT.size()
        + this.runningSSKOfferReplyUIDsRT.size()
        + this.runningCHKOfferReplyUIDsRT.size()
        + this.runningCHKGetUIDsBulk.size()
        + this.runningCHKPutUIDsBulk.size()
        + this.runningSSKGetUIDsBulk.size()
        + this.runningSSKPutUIDsBulk.size()
        + this.runningSSKOfferReplyUIDsBulk.size()
        + this.runningCHKOfferReplyUIDsBulk.size();
  }

  private final ArrayList<Long> completedBuffer = new ArrayList<>();

  // Every this many slots, we tell all the PeerMessageQueue's to remove the old Items for the ID's
  // in question.
  // This prevents memory DoS amongst other things.
  static final int COMPLETED_THRESHOLD = 128;

  /** A request completed (regardless of success). */
  void completed(long id) {
    Long[] list;
    synchronized (completedBuffer) {
      completedBuffer.add(id);
      if (completedBuffer.size() < COMPLETED_THRESHOLD) return;
      list = completedBuffer.toArray(new Long[0]);
      completedBuffer.clear();
    }
    for (PeerNode pn : peers.myPeers()) {
      if (!pn.isRoutingCompatible()) continue;
      pn.removeUIDsFromMessageQueues(list);
    }
  }

  /**
   * Look up a currently transferring {@link RequestSender} by CHK.
   *
   * @param key The content key.
   * @param realTimeFlag {@code true} for real-time map; {@code false} for bulk map.
   * @return The transferring sender or {@code null} if none is registered.
   */
  public RequestSender getTransferringRequestSenderByKey(NodeCHK key, boolean realTimeFlag) {
    if (realTimeFlag) {
      synchronized (transferringRequestSendersRT) {
        return transferringRequestSendersRT.get(key);
      }
    } else {
      synchronized (transferringRequestSendersBulk) {
        return transferringRequestSendersBulk.get(key);
      }
    }
  }

  /** Add a transferring RequestSender to the appropriate map. Should only be called by UIDTag. */
  public void addTransferringSender(NodeCHK key, RequestSender sender) {
    if (sender.realTimeFlag) {
      synchronized (transferringRequestSendersRT) {
        transferringRequestSendersRT.put(key, sender);
      }
    } else {
      synchronized (transferringRequestSendersBulk) {
        transferringRequestSendersBulk.put(key, sender);
      }
    }
  }

  /** Register a transferring RequestHandler by ID. Should only be called by RequestTag. */
  void addTransferringRequestHandler(long id) {
    synchronized (transferringRequestHandlers) {
      transferringRequestHandlers.add(id);
    }
  }

  /** Unregister a transferring RequestHandler by ID. Should only be called by RequestTag. */
  void removeTransferringRequestHandler(long id) {
    synchronized (transferringRequestHandlers) {
      transferringRequestHandlers.remove(id);
    }
  }

  /** Remove a sender from the set of currently transferring senders. */
  public void removeTransferringSender(NodeCHK key, RequestSender sender) {
    if (sender.realTimeFlag) {
      synchronized (transferringRequestSendersRT) {
        if (transferringRequestSendersRT.get(key) == sender) {
          transferringRequestSendersRT.remove(key);
        }
      }
    } else {
      synchronized (transferringRequestSendersBulk) {
        if (transferringRequestSendersBulk.get(key) == sender) {
          transferringRequestSendersBulk.remove(key);
        }
      }
    }
  }

  /**
   * Count all {@link RequestSender} instances currently transferring (real-time and bulk).
   *
   * @return Number of transferring senders.
   */
  public int getNumTransferringRequestSenders() {
    int total = 0;
    synchronized (transferringRequestSendersRT) {
      total += transferringRequestSendersRT.size();
    }
    synchronized (transferringRequestSendersBulk) {
      total += transferringRequestSendersBulk.size();
    }
    return total;
  }

  /**
   * Count all RequestHandler instances currently transferring.
   *
   * @return Number of transferring handlers.
   */
  public int getNumTransferringRequestHandlers() {
    synchronized (transferringRequestHandlers) {
      return transferringRequestHandlers.size();
    }
  }
}
