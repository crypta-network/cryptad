package network.crypta.node;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracks peer status counters, routing backoff reasons, and periodic status summaries.
 *
 * <p>This class centralizes bookkeeping for {@link PeerNode} status transitions, routing backoff
 * reasons, and timed summary snapshots so that {@link PeerManager} can focus on coordination rather
 * than on per-peer accounting. Typical usage is that the manager calls {@link
 * #onPeerAdded(PeerNode)} when a peer joins, {@link #onPeerRemoved(PeerNode)} when it leaves, and
 * invokes the periodic methods from a scheduler or main loop to refresh cached summaries.
 *
 * <p>State is maintained in in-memory trackers keyed by status values or reason strings. Timed
 * updates are guarded by a shared lock supplied by the caller to keep roster snapshots and timer
 * checks consistent, but the per-status trackers are synchronized internally. The class does not
 * mutate {@link PeerNode} state; it only reads from peers and keeps derived counters and snapshots.
 *
 * <p>Notable behaviors include:
 *
 * <ul>
 *   <li>Separate tracking for all peers versus darknet-only peers.
 *   <li>Distinct routing backoff reason sets for real-time and bulk streams.
 *   <li>Cached computations that update on fixed millisecond intervals.
 * </ul>
 *
 * @see PeerManager
 * @see PeerRoster
 * @see PeerStatusTracker
 */
public class PeerStatusBook {
  private static final Logger LOG = LoggerFactory.getLogger(PeerStatusBook.class);

  private final PeerRoster roster;
  private final Object lock;

  private final PeerStatusTracker<Integer> allPeersStatuses = new PeerStatusTracker<>();
  private final PeerStatusTracker<Integer> darknetPeersStatuses = new PeerStatusTracker<>();
  private final PeerStatusTracker<String> peerNodeRoutingBackoffReasonsRT =
      new PeerStatusTracker<>();
  private final PeerStatusTracker<String> peerNodeRoutingBackoffReasonsBulk =
      new PeerStatusTracker<>();

  private volatile long oldestNeverConnectedDarknetPeerAge = 0L;
  private long nextOldestNeverConnectedDarknetPeerAgeUpdateTime = -1L;
  private volatile long nextPeerNodeStatusLogTime = -1L;
  private long nextRoutableConnectionStatsUpdateTime = -1L;

  /**
   * Creates a status book bound to a roster and shared lock.
   *
   * <p>The provided roster supplies peer snapshots for status queries and periodic summaries. The
   * lock must be the same monitor used by the owning manager when it mutates or snapshots the
   * roster; this ensures that time-gated updates observe a consistent roster and timer state. The
   * instance starts with empty counters and inactive timers; the first updates occur on the first
   * relevant method call.
   *
   * <pre>{@code
   * var book = new PeerStatusBook(roster, managerLock);
   * book.onPeerAdded(peer);
   * }</pre>
   *
   * @param roster peer roster used to get peer snapshots; must be non-null
   * @param lock shared monitor guarding roster snapshots and timer updates; must be non-null
   */
  public PeerStatusBook(PeerRoster roster, Object lock) {
    this.roster = roster;
    this.lock = lock;
  }

  /**
   * Adds initial status tracking for a newly added peer.
   *
   * <p>This method inspects the peer's current status and, when {@link PeerNode#recordStatus()}
   * indicates that status should be tracked, registers it in the internal counters. Darknet peers
   * contribute to both the global tracker and the darknet-only tracker, while opennet peers only
   * affect the global tracker. The call is idempotent from the perspective of the trackers, though
   * duplicate additions may be logged by the underlying status tracker.
   *
   * @param peer peer instance whose current status is registered; must be non-null
   */
  public void onPeerAdded(PeerNode peer) {
    if (peer.recordStatus()) addPeerNodeStatus(peer.getPeerNodeStatus(), peer);
  }

  /**
   * Removes tracked status and routing backoff entries for a removed peer.
   *
   * <p>The method removes the peer from the status trackers when {@link PeerNode#recordStatus()} is
   * true and also removes any previously recorded routing backoff reasons for both real-time and
   * bulk streams. If no prior reason is recorded, the removal step is skipped. This call does not
   * mutate peer state; it only removes bookkeeping data held by this instance.
   *
   * @param peer peer instance being removed; must be non-null and previously tracked
   */
  public void onPeerRemoved(PeerNode peer) {
    int peerNodeStatus = peer.getPeerNodeStatus();
    if (peer.recordStatus()) removePeerNodeStatus(peerNodeStatus, peer);
    String prevReasonRt = peer.getPreviousBackoffReason(true);
    if (prevReasonRt != null) removePeerNodeRoutingBackoffReason(prevReasonRt, peer, true);
    String prevReasonBulk = peer.getPreviousBackoffReason(false);
    if (prevReasonBulk != null) removePeerNodeRoutingBackoffReason(prevReasonBulk, peer, false);
  }

  /**
   * Updates status counters when a peer changes status.
   *
   * <p>This method moves the peer from its old status bucket to the new status bucket in the global
   * tracker, and in the darknet-only tracker when the peer is not an opennet peer. The operation is
   * performed atomically within each tracker. When {@code noLog} is {@code true}, duplicate or
   * absent membership messages from the tracker are suppressed.
   *
   * @param peer peer whose status has changed; must be non-null
   * @param oldStatus previous status value, typically a {@link PeerManager} constant
   * @param newStatus new status value, typically a {@link PeerManager} constant
   * @param noLog when true, suppresses duplicate and missing-status error logs
   */
  public void changePeerNodeStatus(PeerNode peer, int oldStatus, int newStatus, boolean noLog) {
    allPeersStatuses.changePeerNodeStatus(peer, oldStatus, newStatus, noLog);
    if (!peer.isOpennet()) {
      darknetPeersStatuses.changePeerNodeStatus(peer, oldStatus, newStatus, noLog);
    }
  }

  /** Adds a PeerNode status to the trackers. */
  private void addPeerNodeStatus(int status, PeerNode peer) {
    allPeersStatuses.addStatus(status, peer, false);
    if (!peer.isOpennet()) darknetPeersStatuses.addStatus(status, peer, false);
  }

  /** Removes a PeerNode status from the trackers. */
  private void removePeerNodeStatus(int status, PeerNode peer) {
    allPeersStatuses.removeStatus(status, peer, false);
    if (!peer.isOpennet()) darknetPeersStatuses.removeStatus(status, peer, false);
  }

  /**
   * Counts peers with a particular status in the requested tracker.
   *
   * <p>The count is derived from a weakly referenced set, so it reflects the current bookkeeping
   * snapshot and may shrink if peers become only weakly reachable. The method is read-only and does
   * not trigger any updates or logging.
   *
   * @param status status key to count, usually from {@link PeerManager} constants
   * @param darknet when true, use the darknet-only tracker instead of global
   * @return number of peers currently recorded with the requested status
   */
  public int getPeerNodeStatusSize(int status, boolean darknet) {
    return darknet ? darknetPeersStatuses.statusSize(status) : allPeersStatuses.statusSize(status);
  }

  /**
   * Adds a routing backoff reason for a peer.
   *
   * <p>The reason string is tracked independently for real-time and bulk streams. If the same peer
   * is added twice for the same reason, the underlying tracker treats it as a duplicate and may log
   * an error unless suppressed elsewhere. This method does not interpret or normalize the reason
   * text; it uses the provided string as the key.
   *
   * @param reason backoff reason identifier; must be non-null and stable for grouping
   * @param peer peer instance associated with the reason; must be non-null
   * @param realTime true for real-time routing, false for bulk routing
   */
  public void addPeerNodeRoutingBackoffReason(String reason, PeerNode peer, boolean realTime) {
    PeerStatusTracker<String> tracker =
        realTime ? peerNodeRoutingBackoffReasonsRT : peerNodeRoutingBackoffReasonsBulk;
    tracker.addStatus(reason, peer, false);
  }

  /**
   * Removes a routing backoff reason for a peer.
   *
   * <p>The removal affects only the tracker selected by {@code realTime}. If the peer is not
   * currently associated with the reason, the underlying tracker may log an error. The reason key
   * is removed entirely when no peers remain associated with it.
   *
   * @param reason backoff reason identifier; must match the previously added key
   * @param peer peer instance associated with the reason; must be non-null
   * @param realTime true for real-time routing, false for bulk routing
   */
  public void removePeerNodeRoutingBackoffReason(String reason, PeerNode peer, boolean realTime) {
    PeerStatusTracker<String> tracker =
        realTime ? peerNodeRoutingBackoffReasonsRT : peerNodeRoutingBackoffReasonsBulk;
    tracker.removeStatus(reason, peer, false);
  }

  /**
   * Returns the currently tracked routing backoff reasons.
   *
   * <p>The returned array contains the distinct reason keys currently known to the selected
   * tracker. No ordering is guaranteed because the keys are derived from a hash map. The snapshot
   * is taken at call time and is not backed by the underlying data structures.
   *
   * @param realTime true to query real-time routing reasons, false for bulk
   * @return array of distinct reason identifiers, possibly empty but never null
   */
  public String[] getPeerNodeRoutingBackoffReasons(boolean realTime) {
    List<String> list = new ArrayList<>();
    PeerStatusTracker<String> tracker =
        realTime ? peerNodeRoutingBackoffReasonsRT : peerNodeRoutingBackoffReasonsBulk;
    tracker.addStatusList(list);
    return list.toArray(new String[0]);
  }

  /**
   * Returns the count of peers with a specific routing backoff reason.
   *
   * <p>The count reflects the current tracker snapshot and may change as peers are added or
   * removed. The reason key is matched exactly; this method does not normalize or interpret the
   * string.
   *
   * @param reason backoff reason identifier to count; must be non-null
   * @param realTime true to query real-time routing reasons, false for bulk
   * @return number of peers recorded for the provided reason key
   */
  public int getPeerNodeRoutingBackoffReasonSize(String reason, boolean realTime) {
    PeerStatusTracker<String> tracker =
        realTime ? peerNodeRoutingBackoffReasonsRT : peerNodeRoutingBackoffReasonsBulk;
    return tracker.statusSize(reason);
  }

  /**
   * Returns a snapshot of statuses for all peers in the roster.
   *
   * <p>The method iterates over the current roster snapshot and calls {@link
   * PeerNode#getStatus(boolean)} on each peer. The resulting array preserves the roster order and
   * is independent of later roster changes. The method performs no filtering beyond the roster
   * snapshot it receives.
   *
   * @param noHeavy whether to omit heavy-weight fields from the status snapshot
   * @return array of status snapshots, one per peer in roster order
   */
  public PeerNodeStatus[] getPeerNodeStatuses(boolean noHeavy) {
    PeerNode[] peers = roster.myPeers();
    PeerNodeStatus[] statuses = new PeerNodeStatus[peers.length];
    for (int i = 0; i < peers.length; i++) {
      statuses[i] = peers[i].getStatus(noHeavy);
    }
    return statuses;
  }

  /**
   * Returns a snapshot of statuses for darknet peers.
   *
   * <p>The method selects only darknet peers from the roster and returns their status snapshots in
   * the same order as the filtered roster. It expects each returned status to be a {@link
   * DarknetPeerNodeStatus} instance because it invokes {@link PeerNode#getStatus(boolean)} on a
   * {@link DarknetPeerNode}.
   *
   * @param noHeavy whether to omit heavy-weight fields from the status snapshot
   * @return array of darknet peer status snapshots, possibly empty but never null
   */
  public DarknetPeerNodeStatus[] getDarknetPeerNodeStatuses(boolean noHeavy) {
    DarknetPeerNode[] peers = roster.getDarknetPeers();
    DarknetPeerNodeStatus[] statuses = new DarknetPeerNodeStatus[peers.length];
    for (int i = 0; i < peers.length; i++) {
      statuses[i] = (DarknetPeerNodeStatus) peers[i].getStatus(noHeavy);
    }
    return statuses;
  }

  /**
   * Returns a snapshot of statuses for opennet peers.
   *
   * <p>The method filters the roster to opennet peers and returns their status snapshots in the
   * same order as the filtered roster. Each status is expected to be an {@link
   * OpennetPeerNodeStatus} because the snapshots are created from {@link OpennetPeerNode}
   * instances.
   *
   * @param noHeavy whether to omit heavy-weight fields from the status snapshot
   * @return array of opennet peer status snapshots, possibly empty but never null
   */
  public OpennetPeerNodeStatus[] getOpennetPeerNodeStatuses(boolean noHeavy) {
    OpennetPeerNode[] peers = roster.getOpennetPeers();
    OpennetPeerNodeStatus[] statuses = new OpennetPeerNodeStatus[peers.length];
    for (int i = 0; i < peers.length; i++) {
      statuses[i] = (OpennetPeerNodeStatus) peers[i].getStatus(noHeavy);
    }
    return statuses;
  }

  /**
   * Updates the cached oldest never-connected darknet peer age when the timer elapses.
   *
   * <p>The method checks the last update time under the shared lock and returns early if the
   * interval has not expired. When an update is due, it scans the current roster snapshot and
   * computes the maximum {@code now - peerAddedTime} among darknet peers that are in {@link
   * PeerManager#PEER_NODE_STATUS_NEVER_CONNECTED}. The cached value is expressed in milliseconds
   * and is reset to {@code 0} when no matching peers are found.
   *
   * @param now current time in milliseconds, typically {@code System.currentTimeMillis()}
   */
  public void maybeUpdateOldestNeverConnectedDarknetPeerAge(long now) {
    PeerNode[] peerList;
    synchronized (lock) {
      if (now <= nextOldestNeverConnectedDarknetPeerAgeUpdateTime) return;
      nextOldestNeverConnectedDarknetPeerAgeUpdateTime =
          now + OLDEST_NEVER_CONNECTED_DARKNET_PEER_AGE_UPDATE_INTERVAL;
      peerList = roster.myPeers();
    }
    oldestNeverConnectedDarknetPeerAge = 0L;
    for (PeerNode peer : peerList) {
      if (!peer.isDarknet()) continue;
      if (peer.getPeerNodeStatus() == PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED) {
        long age = now - peer.getPeerAddedTime();
        if (age > oldestNeverConnectedDarknetPeerAge) oldestNeverConnectedDarknetPeerAge = age;
      }
    }
    if (oldestNeverConnectedDarknetPeerAge > 0 && LOG.isDebugEnabled()) {
      LOG.debug("Oldest never connected peer is {}ms old", oldestNeverConnectedDarknetPeerAge);
    }
    nextOldestNeverConnectedDarknetPeerAgeUpdateTime =
        now + OLDEST_NEVER_CONNECTED_DARKNET_PEER_AGE_UPDATE_INTERVAL;
  }

  /**
   * Returns the cached age of the oldest never-connected darknet peer.
   *
   * <p>The value is updated only when {@link #maybeUpdateOldestNeverConnectedDarknetPeerAge(long)}
   * runs and the update interval has elapsed. The age is measured in milliseconds and is zero when
   * no qualifying peers exist or when the cache has not yet been populated.
   *
   * @return cached age in milliseconds; zero when no matching peers are present
   */
  public long getOldestNeverConnectedDarknetPeerAge() {
    return oldestNeverConnectedDarknetPeerAge;
  }

  /**
   * Logs the current peer status summary when the timer has expired.
   *
   * <p>The method checks whether the periodic interval has elapsed and, if so, collects a roster
   * snapshot and computes a count of peers in each status bucket. It then emits a single summary
   * log line containing all counts. If the logging schedule is significantly late, it also emits an
   * error indicating potential congestion in the sender loop.
   *
   * @param now current time in milliseconds, typically {@code System.currentTimeMillis()}
   */
  public void maybeLogPeerNodeStatusSummary(long now) {
    if (!shouldLogPeerStatus(now)) return;
    PeerNode[] peers = roster.myPeers();
    PeerStatusSummary summary = computePeerStatusSummary(peers);
    logPeerStatusSummary(summary);
    nextPeerNodeStatusLogTime = now + PEER_NODE_STATUS_LOG_INTERVAL;
  }

  private boolean shouldLogPeerStatus(long now) {
    if (now <= nextPeerNodeStatusLogTime) return false;
    if ((now - nextPeerNodeStatusLogTime) > TimeUnit.SECONDS.toMillis(10)
        && nextPeerNodeStatusLogTime > 0) {
      LOG.error(
          "PeerNode status summary late by {} ms; PacketSender may be congested",
          now - nextPeerNodeStatusLogTime);
    }
    return true;
  }

  private record PeerStatusSummary(PeerStatusCounts counts) {}

  private PeerStatusSummary computePeerStatusSummary(PeerNode[] peers) {
    int numberOfConnected = 0;
    int numberOfRoutingBackedOff = 0;
    int numberOfTooNew = 0;
    int numberOfTooOld = 0;
    int numberOfDisconnected = 0;
    int numberOfNeverConnected = 0;
    int numberOfDisabled = 0;
    int numberOfListenOnly = 0;
    int numberOfListening = 0;
    int numberOfBursting = 0;
    int numberOfClockProblem = 0;
    int numberOfConnError = 0;
    int numberOfDisconnecting = 0;
    int numberOfRoutingDisabled = 0;
    int numberOfNoLoadStats = 0;

    for (PeerNode peer : peers) {
      int status = peer.getPeerNodeStatus();
      switch (status) {
        case PeerManager.PEER_NODE_STATUS_CONNECTED -> numberOfConnected++;
        case PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF -> numberOfRoutingBackedOff++;
        case PeerManager.PEER_NODE_STATUS_TOO_NEW -> numberOfTooNew++;
        case PeerManager.PEER_NODE_STATUS_TOO_OLD -> numberOfTooOld++;
        case PeerManager.PEER_NODE_STATUS_DISCONNECTED -> numberOfDisconnected++;
        case PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED -> numberOfNeverConnected++;
        case PeerManager.PEER_NODE_STATUS_DISABLED -> numberOfDisabled++;
        case PeerManager.PEER_NODE_STATUS_LISTEN_ONLY -> numberOfListenOnly++;
        case PeerManager.PEER_NODE_STATUS_LISTENING -> numberOfListening++;
        case PeerManager.PEER_NODE_STATUS_BURSTING -> numberOfBursting++;
        case PeerManager.PEER_NODE_STATUS_CLOCK_PROBLEM -> numberOfClockProblem++;
        case PeerManager.PEER_NODE_STATUS_CONN_ERROR -> numberOfConnError++;
        case PeerManager.PEER_NODE_STATUS_DISCONNECTING -> numberOfDisconnecting++;
        case PeerManager.PEER_NODE_STATUS_ROUTING_DISABLED -> numberOfRoutingDisabled++;
        case PeerManager.PEER_NODE_STATUS_NO_LOAD_STATS -> numberOfNoLoadStats++;
        default -> LOG.error("Unknown peer status value: {}", status);
      }
    }

    PeerStatusCounts counts =
        new PeerStatusCounts(
            numberOfConnected,
            numberOfRoutingBackedOff,
            numberOfTooNew,
            numberOfTooOld,
            numberOfDisconnected,
            numberOfNeverConnected,
            numberOfDisabled,
            numberOfBursting,
            numberOfListening,
            numberOfListenOnly,
            0,
            0,
            numberOfRoutingDisabled,
            numberOfClockProblem,
            numberOfConnError,
            numberOfDisconnecting,
            numberOfNoLoadStats);
    return new PeerStatusSummary(counts);
  }

  private void logPeerStatusSummary(PeerStatusSummary summary) {
    LOG.info(
        "Connected={} RoutingBackedOff={} TooNew={} TooOld={} Disconnected={} NeverConnected={}"
            + " Disabled={} Bursting={} Listening={} ListenOnly={} ClockProblem={}"
            + " ConnectionProblem={} Disconnecting={} RoutingDisabled={} NoLoadStats={}",
        summary.counts.connected(),
        summary.counts.routingBackedOff(),
        summary.counts.tooNew(),
        summary.counts.tooOld(),
        summary.counts.disconnected(),
        summary.counts.neverConnected(),
        summary.counts.disabled(),
        summary.counts.bursting(),
        summary.counts.listening(),
        summary.counts.listenOnly(),
        summary.counts.clockProblem(),
        summary.counts.connError(),
        summary.counts.disconnecting(),
        summary.counts.routingDisabled(),
        summary.counts.noLoadStats());
  }

  /**
   * Updates per-peer routable-connection counters when the timer elapses.
   *
   * <p>The method first checks the update interval under the shared lock. When an update is due, it
   * retrieves a roster snapshot and invokes {@link PeerNode#checkRoutableConnectionStatus()} on
   * each peer. If the interval has not elapsed, no peer methods are called and the roster is not
   * read, keeping the method cheap for frequent polling.
   *
   * @param now current time in milliseconds, typically {@code System.currentTimeMillis()}
   */
  public void maybeUpdatePeerNodeRoutableConnectionStats(long now) {
    PeerNode[] peersToUpdate = prepareRoutableStatsUpdate(now);
    for (PeerNode peer : peersToUpdate) {
      peer.checkRoutableConnectionStatus();
    }
  }

  private PeerNode[] prepareRoutableStatsUpdate(long now) {
    synchronized (lock) {
      if (now <= nextRoutableConnectionStatsUpdateTime) return new PeerNode[0];
      nextRoutableConnectionStatsUpdateTime = now + ROUTABLE_CONNECTION_STATS_UPDATE_INTERVAL;
      return roster.myPeers();
    }
  }

  private static final long OLDEST_NEVER_CONNECTED_DARKNET_PEER_AGE_UPDATE_INTERVAL = 5000L;
  private static final long PEER_NODE_STATUS_LOG_INTERVAL = 5000L;
  private static final long ROUTABLE_CONNECTION_STATS_UPDATE_INTERVAL =
      TimeUnit.SECONDS.toMillis(7);
}
