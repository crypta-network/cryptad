package network.crypta.node;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracks peer status counters, routing backoff reasons, and periodic status summaries.
 *
 * <p>This class centralizes status bookkeeping to keep {@link PeerManager} focused on coordination
 * rather than tracking details.
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

  private long oldestNeverConnectedDarknetPeerAge = 0L;
  private long nextOldestNeverConnectedDarknetPeerAgeUpdateTime = -1L;
  private long nextPeerNodeStatusLogTime = -1L;
  private long nextRoutableConnectionStatsUpdateTime = -1L;

  public PeerStatusBook(PeerRoster roster, Object lock) {
    this.roster = roster;
    this.lock = lock;
  }

  /** Adds initial status tracking for a newly added peer. */
  public void onPeerAdded(PeerNode peer) {
    if (peer.recordStatus()) addPeerNodeStatus(peer.getPeerNodeStatus(), peer);
  }

  /** Removes tracked status and routing backoff entries for a removed peer. */
  public void onPeerRemoved(PeerNode peer) {
    int peerNodeStatus = peer.getPeerNodeStatus();
    if (peer.recordStatus()) removePeerNodeStatus(peerNodeStatus, peer);
    String prevReasonRt = peer.getPreviousBackoffReason(true);
    if (prevReasonRt != null) removePeerNodeRoutingBackoffReason(prevReasonRt, peer, true);
    String prevReasonBulk = peer.getPreviousBackoffReason(false);
    if (prevReasonBulk != null) removePeerNodeRoutingBackoffReason(prevReasonBulk, peer, false);
  }

  /** Updates status counts when a peer changes status. */
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

  /** Counts PeerNodes with a particular status. */
  public int getPeerNodeStatusSize(int status, boolean darknet) {
    return darknet ? darknetPeersStatuses.statusSize(status) : allPeersStatuses.statusSize(status);
  }

  /** Adds a routing backoff reason for a peer. */
  public void addPeerNodeRoutingBackoffReason(String reason, PeerNode peer, boolean realTime) {
    PeerStatusTracker<String> tracker =
        realTime ? peerNodeRoutingBackoffReasonsRT : peerNodeRoutingBackoffReasonsBulk;
    tracker.addStatus(reason, peer, false);
  }

  /** Removes a routing backoff reason for a peer. */
  public void removePeerNodeRoutingBackoffReason(String reason, PeerNode peer, boolean realTime) {
    PeerStatusTracker<String> tracker =
        realTime ? peerNodeRoutingBackoffReasonsRT : peerNodeRoutingBackoffReasonsBulk;
    tracker.removeStatus(reason, peer, false);
  }

  /** Returns the currently tracked routing backoff reasons. */
  public String[] getPeerNodeRoutingBackoffReasons(boolean realTime) {
    List<String> list = new ArrayList<>();
    PeerStatusTracker<String> tracker =
        realTime ? peerNodeRoutingBackoffReasonsRT : peerNodeRoutingBackoffReasonsBulk;
    tracker.addStatusList(list);
    return list.toArray(new String[0]);
  }

  /** Returns the count of peers with a specific routing backoff reason. */
  public int getPeerNodeRoutingBackoffReasonSize(String reason, boolean realTime) {
    PeerStatusTracker<String> tracker =
        realTime ? peerNodeRoutingBackoffReasonsRT : peerNodeRoutingBackoffReasonsBulk;
    return tracker.statusSize(reason);
  }

  /** Returns a snapshot of statuses for all peers. */
  public PeerNodeStatus[] getPeerNodeStatuses(boolean noHeavy) {
    PeerNode[] peers = roster.myPeers();
    PeerNodeStatus[] statuses = new PeerNodeStatus[peers.length];
    for (int i = 0; i < peers.length; i++) {
      statuses[i] = peers[i].getStatus(noHeavy);
    }
    return statuses;
  }

  /** Returns a snapshot of statuses for darknet peers. */
  public DarknetPeerNodeStatus[] getDarknetPeerNodeStatuses(boolean noHeavy) {
    DarknetPeerNode[] peers = roster.getDarknetPeers();
    DarknetPeerNodeStatus[] statuses = new DarknetPeerNodeStatus[peers.length];
    for (int i = 0; i < peers.length; i++) {
      statuses[i] = (DarknetPeerNodeStatus) peers[i].getStatus(noHeavy);
    }
    return statuses;
  }

  /** Returns a snapshot of statuses for opennet peers. */
  public OpennetPeerNodeStatus[] getOpennetPeerNodeStatuses(boolean noHeavy) {
    OpennetPeerNode[] peers = roster.getOpennetPeers();
    OpennetPeerNodeStatus[] statuses = new OpennetPeerNodeStatus[peers.length];
    for (int i = 0; i < peers.length; i++) {
      statuses[i] = (OpennetPeerNodeStatus) peers[i].getStatus(noHeavy);
    }
    return statuses;
  }

  /** Update oldest never-connected darknet peer age if the timer has expired. */
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

  /** Returns the cached age of the oldest never-connected darknet peer. */
  public long getOldestNeverConnectedDarknetPeerAge() {
    return oldestNeverConnectedDarknetPeerAge;
  }

  /** Log the current PeerNode status summary if the timer has expired. */
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

  private static final class PeerStatusSummary {
    private final int connected;
    private final int routingBackedOff;
    private final int tooNew;
    private final int tooOld;
    private final int disconnected;
    private final int neverConnected;
    private final int disabled;
    private final int bursting;
    private final int listening;
    private final int listenOnly;
    private final int clockProblem;
    private final int connError;
    private final int disconnecting;
    private final int routingDisabled;
    private final int noLoadStats;

    private PeerStatusSummary(
        int connected,
        int routingBackedOff,
        int tooNew,
        int tooOld,
        int disconnected,
        int neverConnected,
        int disabled,
        int bursting,
        int listening,
        int listenOnly,
        int clockProblem,
        int connError,
        int disconnecting,
        int routingDisabled,
        int noLoadStats) {
      this.connected = connected;
      this.routingBackedOff = routingBackedOff;
      this.tooNew = tooNew;
      this.tooOld = tooOld;
      this.disconnected = disconnected;
      this.neverConnected = neverConnected;
      this.disabled = disabled;
      this.bursting = bursting;
      this.listening = listening;
      this.listenOnly = listenOnly;
      this.clockProblem = clockProblem;
      this.connError = connError;
      this.disconnecting = disconnecting;
      this.routingDisabled = routingDisabled;
      this.noLoadStats = noLoadStats;
    }
  }

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

    return new PeerStatusSummary(
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
        numberOfClockProblem,
        numberOfConnError,
        numberOfDisconnecting,
        numberOfRoutingDisabled,
        numberOfNoLoadStats);
  }

  private void logPeerStatusSummary(PeerStatusSummary summary) {
    LOG.info(
        "Connected={} RoutingBackedOff={} TooNew={} TooOld={} Disconnected={} NeverConnected={}"
            + " Disabled={} Bursting={} Listening={} ListenOnly={} ClockProblem={}"
            + " ConnectionProblem={} Disconnecting={} RoutingDisabled={} NoLoadStats={}",
        summary.connected,
        summary.routingBackedOff,
        summary.tooNew,
        summary.tooOld,
        summary.disconnected,
        summary.neverConnected,
        summary.disabled,
        summary.bursting,
        summary.listening,
        summary.listenOnly,
        summary.clockProblem,
        summary.connError,
        summary.disconnecting,
        summary.routingDisabled,
        summary.noLoadStats);
  }

  /** Updates per-peer routable-connection counters when the timer elapses. */
  public void maybeUpdatePeerNodeRoutableConnectionStats(long now) {
    PeerNode[] peersToUpdate = prepareRoutableStatsUpdate(now);
    if (peersToUpdate.length == 0) return;
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
