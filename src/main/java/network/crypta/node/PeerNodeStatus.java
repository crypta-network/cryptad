package network.crypta.node;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.Map;
import network.crypta.clients.http.DarknetConnectionsToadlet;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.Peer;
import network.crypta.io.xfer.PacketThrottle;
import network.crypta.node.PeerNodeLoadTracker.IncomingLoadSummaryStats;

/**
 * Immutable snapshot of a {@link PeerNode}'s observable state.
 *
 * <p>Instances are constructed from a live {@link PeerNode} and copy the values required by
 * presentation and diagnostics (for example {@link DarknetConnectionsToadlet}). Copying avoids
 * reading mutable state from the node while rendering and therefore reduces race conditions.
 *
 * <p>Threading: this object is read-only and thread-safe after construction. No synchronization is
 * required by callers.
 *
 * <p>Nullability: some address fields may be {@code null} when the peer is not known yet or the
 * address cannot be resolved.
 *
 * @author David 'Bombe' Roden &lt;bombe@freenetproject.org&gt;
 * @version $Id$
 */
public class PeerNodeStatus {

  /** Preferred string form of the peer address (may be hostname or numeric). */
  private final String peerAddress;

  /** Numeric IP address string, or {@code null} if unresolved. */
  private final String peerAddressNumerical;

  /** Raw IP address bytes (length 4 for IPv4 or 16 for IPv6), or {@code null}. */
  private final byte[] peerAddressBytes;

  private final int peerPort;

  private final int statusValue;

  private final String statusName;

  private final String statusCSSName;

  private final double location;
  private final double[] peersLocation;

  private final String version;

  private final int simpleVersion;

  private final long routingBackoffLengthRT;
  private final long routingBackoffLengthBulk;

  private final long routingBackedOffUntilRT;
  private final long routingBackedOffUntilBulk;

  private final boolean connected;

  private final boolean routable;

  private final boolean isFetchingARK;

  private final boolean isOpennet;

  private final double averagePingTime;
  private final double averagePingTimeCorrected;

  private final boolean publicInvalidVersion;

  private final boolean publicReverseInvalidVersion;

  private final double backedOffPercentRT;
  private final double backedOffPercentBulk;

  private final String lastBackoffReasonRT;
  private final String lastBackoffReasonBulk;

  private final long timeLastRoutable;

  private final long timeLastConnectionCompleted;

  private final long peerAddedTime;

  private final Map<String, Long> localMessagesReceived;

  private final Map<String, Long> localMessagesSent;

  private final int hashCode;

  /** Stable identity for equality: SHA‑256 of the peer's ECDSA public key. */
  private final byte[] peerPubKeyHash;

  private final double pReject;

  private final long totalBytesIn;

  private final long totalBytesOut;

  private final long totalBytesInSinceStartup;

  private final long totalBytesOutSinceStartup;

  private final double percentTimeRoutableConnection;

  private final PacketThrottle throttle;

  private final long clockDelta;

  private final boolean recordStatus;

  private final boolean isSeedServer;

  private final boolean isSeedClient;

  private final boolean isSearchable;

  private final long resendBytesSent;

  private final int reportedUptimePercentage;

  private final double selectionRate;

  private final long messageQueueLengthBytes;

  private final long messageQueueLengthTime;

  // int's because that's what they are transferred as

  /**
   * Aggregate "real‑time" inbound load view for this peer.
   *
   * <p>Fields expose capacity and usage counters in bytes. Intended for UI and diagnostics and may
   * be {@code null} when the constructor was invoked with {@code noHeavy=true} on the source node.
   */
  public final IncomingLoadSummaryStats incomingLoadStatsRealTime;

  /**
   * Aggregate "bulk" inbound load view for this peer.
   *
   * <p>Fields expose capacity and usage counters in bytes. Intended for UI and diagnostics and may
   * be {@code null} when the constructor was invoked with {@code noHeavy=true} on the source node.
   */
  public final IncomingLoadSummaryStats incomingLoadStatsBulk;

  /**
   * Whether the local node holds the full node reference for this peer.
   *
   * <p>When {@code false}, only a partial/volatile reference is available (e.g., for opennet peers)
   * and certain metadata will be missing.
   */
  public final boolean hasFullNoderef;

  PeerNodeStatus(PeerNode peerNode, boolean noHeavy) {
    Peer p = peerNode.getPeer();
    if (p == null) {
      peerAddress = null;
      peerAddressNumerical = null;
      peerAddressBytes = null;
      peerPort = -1;
    } else {
      FreenetInetAddress a = p.getFreenetAddress();
      peerAddress = a.toString();
      InetAddress i = a.getAddress(false);
      if (i != null) {
        peerAddressNumerical = i.getHostAddress();
        peerAddressBytes = i.getAddress();
      } else {
        peerAddressNumerical = null;
        peerAddressBytes = null;
      }
      peerPort = p.getPort();
    }
    this.selectionRate = peerNode.selectionRate();
    this.statusValue = peerNode.getPeerNodeStatus();
    this.statusName = peerNode.getPeerNodeStatusString();
    this.statusCSSName = peerNode.getPeerNodeStatusCSSClassName();
    this.location = peerNode.getLocation();
    this.peersLocation = peerNode.getPeersLocationArray();
    this.version = peerNode.getVersion();
    this.simpleVersion = peerNode.getSimpleVersion();
    this.routingBackoffLengthRT = peerNode.getRoutingBackoffLength(true);
    this.routingBackoffLengthBulk = peerNode.getRoutingBackoffLength(false);
    this.routingBackedOffUntilRT = peerNode.getRoutingBackedOffUntil(true);
    this.routingBackedOffUntilBulk = peerNode.getRoutingBackedOffUntil(false);
    this.connected = peerNode.isConnected();
    this.routable = peerNode.isRoutable();
    this.isFetchingARK = peerNode.isFetchingARK();
    this.isOpennet = peerNode.isOpennet();
    this.averagePingTime = peerNode.averagePingTime();
    this.averagePingTimeCorrected = peerNode.averagePingTimeCorrected();
    this.publicInvalidVersion = peerNode.publicInvalidVersion();
    this.publicReverseInvalidVersion = peerNode.publicReverseInvalidVersion();
    this.backedOffPercentRT = peerNode.getBackedOffPercentRT();
    this.backedOffPercentBulk = peerNode.getBackedOffPercentBulk();
    this.lastBackoffReasonRT = peerNode.getLastBackoffReason(true);
    this.lastBackoffReasonBulk = peerNode.getLastBackoffReason(false);
    this.timeLastRoutable = peerNode.timeLastRoutable();
    this.timeLastConnectionCompleted = peerNode.timeLastConnectionCompleted();
    this.peerAddedTime = peerNode.getPeerAddedTime();
    if (!noHeavy) {
      this.localMessagesReceived = peerNode.getLocalNodeReceivedMessagesFromStatistic();
      this.localMessagesSent = peerNode.getLocalNodeSentMessagesToStatistic();
    } else {
      this.localMessagesReceived = null;
      this.localMessagesSent = null;
    }
    this.hashCode = peerNode.hashCode;
    // Use the actual 32-byte public key hash for equality to avoid collisions on the 32-bit
    // hashCode value. Copy defensively to keep this snapshot immutable.
    byte[] pkh = peerNode.getPubKeyHash();
    this.peerPubKeyHash = (pkh == null ? null : pkh.clone());
    this.pReject = peerNode.getPRejected();
    this.totalBytesIn = peerNode.getTotalInputBytes();
    this.totalBytesOut = peerNode.getTotalOutputBytes();
    this.totalBytesInSinceStartup = peerNode.getTotalInputSinceStartup();
    this.totalBytesOutSinceStartup = peerNode.getTotalOutputSinceStartup();
    this.percentTimeRoutableConnection = peerNode.getPercentTimeRoutableConnection();
    this.throttle = peerNode.transport().getThrottle();
    this.clockDelta = peerNode.getClockDelta();
    this.recordStatus = peerNode.recordStatus();
    this.isSeedClient = peerNode instanceof SeedClientPeerNode;
    this.isSeedServer = peerNode instanceof SeedServerPeerNode;
    this.isSearchable = peerNode.isRealConnection();
    this.resendBytesSent = peerNode.getResendBytesSent();
    this.reportedUptimePercentage = peerNode.getUptime();
    messageQueueLengthBytes = peerNode.getMessageQueueLengthBytes();
    messageQueueLengthTime = peerNode.getProbableSendQueueTime();
    incomingLoadStatsRealTime = peerNode.getIncomingLoadStats(true);
    incomingLoadStatsBulk = peerNode.getIncomingLoadStats(false);
    hasFullNoderef = peerNode.hasFullNoderef();
  }

  /**
   * Returns the approximate size of the outbound message queue for this peer.
   *
   * @return number of bytes currently queued for send; monotonically decreases as data is sent and
   *     increases as messages are enqueued
   */
  public long getMessageQueueLengthBytes() {
    return messageQueueLengthBytes;
  }

  /**
   * Returns a rough estimate of how long it will take to drain the outbound queue.
   *
   * @return estimated time to empty the send queue in milliseconds
   */
  public long getMessageQueueLengthTime() {
    return messageQueueLengthTime;
  }

  /**
   * Returns per-message-type counters received locally from this peer.
   *
   * <p>Available only when the snapshot was built with {@code noHeavy=false}; otherwise returns
   * {@code null}.
   *
   * @return a map of message type to count, or {@code null}
   */
  public Map<String, Long> getLocalMessagesReceived() {
    return localMessagesReceived;
  }

  /**
   * Returns per-message-type counters sent locally to this peer.
   *
   * <p>Available only when the snapshot was built with {@code noHeavy=false}; otherwise returns
   * {@code null}.
   *
   * @return a map of message type to count, or {@code null}
   */
  public Map<String, Long> getLocalMessagesSent() {
    return localMessagesSent;
  }

  /**
   * Returns when this peer was first added to the peer manager.
   *
   * @return timestamp in milliseconds since the epoch, or {@code 0} if unknown/not persisted
   */
  public long getPeerAddedTime() {
    return peerAddedTime;
  }

  /**
   * Counts the peers in {@code peerNodeStatuses} that report the given status value.
   *
   * @param peerNodeStatuses the snapshot array to inspect
   * @param status the numeric status code to count
   * @return number of entries whose {@link #getStatusValue()} equals {@code status}
   */
  public static int getPeerStatusCount(PeerNodeStatus[] peerNodeStatuses, int status) {
    int count = 0;
    for (PeerNodeStatus peerNodeStatus : peerNodeStatuses) {
      if (peerNodeStatus.getStatusValue() == status) {
        count++;
      }
    }
    return count;
  }

  /**
   * Returns when a connection last reached the "connected" state.
   *
   * @return timestamp in milliseconds since the epoch, or {@code 0} if never connected
   */
  public long getTimeLastConnectionCompleted() {
    return timeLastConnectionCompleted;
  }

  /**
   * Returns the fraction of recent time during which this peer was in routing backoff.
   *
   * @param realTime {@code true} for real‑time traffic; {@code false} for bulk traffic
   * @return fraction in {@code [0.0, 1.0]}
   */
  public double getBackedOffPercent(boolean realTime) {
    return realTime ? backedOffPercentRT : backedOffPercentBulk;
  }

  /**
   * Returns the most recent textual reason for entering routing backoff.
   *
   * @param realTime {@code true} for real‑time traffic; {@code false} for bulk traffic
   * @return a short, human‑readable reason string (never {@code null})
   */
  public String getLastBackoffReason(boolean realTime) {
    return realTime ? lastBackoffReasonRT : lastBackoffReasonBulk;
  }

  /**
   * Returns when this peer was last routable.
   *
   * @return timestamp in milliseconds since the epoch, or {@code 0} if never routable
   */
  public long getTimeLastRoutable() {
    return timeLastRoutable;
  }

  /**
   * Indicates whether our version is considered invalid by the peer according to public exchange.
   *
   * @return {@code true} if the peer reported our version as invalid
   */
  public boolean isPublicInvalidVersion() {
    return publicInvalidVersion;
  }

  /**
   * Indicates whether this peer's version is considered invalid according to our checks.
   *
   * @return {@code true} if we reported the peer's version as invalid
   */
  public boolean isPublicReverseInvalidVersion() {
    return publicReverseInvalidVersion;
  }

  /**
   * Returns the running average round‑trip time (RTT) to this peer.
   *
   * @return RTT in milliseconds
   */
  public double getAveragePingTime() {
    return averagePingTime;
  }

  /**
   * Returns the retransmission timeout (RTO) derived from RTT variance.
   *
   * <p>Calculated per RFC&nbsp;2988 and used for scheduling retransmissions.
   *
   * @return RTO in milliseconds
   */
  public double getAveragePingTimeCorrected() {
    return averagePingTimeCorrected;
  }

  /**
   * Returns the deadline until which routing remains backed off.
   *
   * @param realTime {@code true} for real‑time traffic; {@code false} for bulk traffic
   * @return timestamp in milliseconds since the epoch; values in the past indicate no active
   *     backoff
   */
  public long getRoutingBackedOffUntil(boolean realTime) {
    return realTime ? routingBackedOffUntilRT : routingBackedOffUntilBulk;
  }

  /**
   * Returns the peer's location on the routing ring.
   *
   * @return a double in {@code [0.0, 1.0)}
   */
  public double getLocation() {
    return location;
  }

  /**
   * Returns sampled locations of this peer's neighbors.
   *
   * @return an array of ring locations, or {@code null} if not available
   */
  public double[] getPeersLocation() {
    return peersLocation;
  }

  /**
   * Returns the address in its preferred string form.
   *
   * @return hostname or numeric address; may be {@code null}
   */
  public String getPeerAddress() {
    return peerAddress;
  }

  /**
   * Returns the numeric IP address if known.
   *
   * @return numeric IP string, or {@code null} if unresolved
   */
  public String getPeerAddressNumerical() {
    return peerAddressNumerical;
  }

  /**
   * Returns the raw IP address bytes if known.
   *
   * @return a 4‑byte (IPv4) or 16‑byte (IPv6) array, or {@code null}
   */
  public byte[] getPeerAddressBytes() {
    return peerAddressBytes;
  }

  /**
   * Returns the UDP port used by this peer.
   *
   * @return port number in {@code [0, 65535]}, or {@code -1} when unknown
   */
  public int getPeerPort() {
    return peerPort;
  }

  /**
   * Returns {@link #getPeerAddress()} combined with {@link #getPeerPort()}.
   *
   * <p>IPv6 addresses are wrapped in {@code []}, e.g., {@code [2001:db8::1]:12345}.
   *
   * @return address and port formatted for display
   */
  public String getPeerAddressAndPort() {
    if (peerAddressBytes != null && peerAddressBytes.length == 16) { // IPv6 address have [] around
      return '[' + peerAddress + "]:" + peerPort;
    } else {
      return peerAddress + ':' + peerPort;
    }
  }

  /**
   * Returns the configured routing backoff duration.
   *
   * @param realTime {@code true} for real‑time traffic; {@code false} for bulk traffic
   * @return duration in milliseconds
   */
  public long getRoutingBackoffLength(boolean realTime) {
    return realTime ? routingBackoffLengthRT : routingBackoffLengthBulk;
  }

  /**
   * Returns the CSS class name that represents the current status in UI components.
   *
   * @return a stable, lowercase CSS class identifier
   */
  public String getStatusCSSName() {
    return statusCSSName;
  }

  /**
   * Returns the human‑readable status string.
   *
   * @return a localized or fixed string describing the connection state
   */
  public String getStatusName() {
    return statusName;
  }

  /**
   * Returns the numeric status code defined by {@link PeerManager}.
   *
   * @return an integer constant representing the connection state
   */
  public int getStatusValue() {
    return statusValue;
  }

  /**
   * Returns the peer's advertised software version string.
   *
   * @return a version identifier, never {@code null}
   */
  public String getVersion() {
    return version;
  }

  /**
   * Indicates whether a transport connection is currently established.
   *
   * @return {@code true} if connected
   */
  public boolean isConnected() {
    return connected;
  }

  /**
   * Indicates whether the peer is currently usable for routing.
   *
   * @return {@code true} if the node considers this peer routable
   */
  public boolean isRoutable() {
    return routable;
  }

  /**
   * Indicates whether the peer is actively fetching its ARK.
   *
   * @return {@code true} if ARK retrieval is in progress
   */
  public boolean isFetchingARK() {
    return isFetchingARK;
  }

  /**
   * Indicates whether the connection belongs to the opennet (not darknet).
   *
   * @return {@code true} for opennet peers
   */
  public boolean isOpennet() {
    return isOpennet;
  }

  /**
   * Returns a simplified, comparable version number derived from {@link #getVersion()}.
   *
   * @return an integer for coarse version comparisons
   */
  public int getSimpleVersion() {
    return simpleVersion;
  }

  @Override
  public String toString() {
    return statusName
        + ' '
        + getPeerAddressAndPort()
        + ' '
        + location
        + ' '
        + version
        + " RT backoff: "
        + routingBackoffLengthRT
        + " ("
        + (Math.max(routingBackedOffUntilRT - System.currentTimeMillis(), 0))
        + " ) bulk backoff: "
        + routingBackoffLengthBulk
        + " ("
        + (Math.max(routingBackedOffUntilBulk - System.currentTimeMillis(), 0))
        + ')';
  }

  @Override
  public int hashCode() {
    return hashCode;
  }

  /**
   * Equality is based on the underlying peer's public key hash.
   *
   * <p>This object is a moment‑in‑time snapshot for a specific {@link PeerNode}. Two snapshots are
   * considered equal if and only if they refer to the same peer identity. We compare on the 32‑byte
   * SHA‑256 of the peer's ECDSA public key rather than the cached 32‑bit {@code hashCode} value to
   * avoid false equality on integer hash collisions.
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (!(obj instanceof PeerNodeStatus other)) return false;
    if (this.peerPubKeyHash != null && other.peerPubKeyHash != null)
      return Arrays.equals(this.peerPubKeyHash, other.peerPubKeyHash);
    // Fallback for tests or degenerate cases where the pubkey hash is not available:
    // compare on the cached identity-based integer hash. This preserves previous behavior while
    // avoiding NPEs when mocks do not provide key material.
    return this.hashCode == other.hashCode;
  }

  /**
   * Returns the probability that requests to this peer are locally rejected or time out.
   *
   * @return fraction in {@code [0.0, 1.0]}
   */
  public double getPReject() {
    return pReject;
  }

  /**
   * Returns the total number of bytes received from this peer.
   *
   * @return cumulative bytes (all time)
   */
  public long getTotalInputBytes() {
    return totalBytesIn;
  }

  /**
   * Returns the total number of bytes sent to this peer.
   *
   * @return cumulative bytes (all time)
   */
  public long getTotalOutputBytes() {
    return totalBytesOut;
  }

  /**
   * Returns the number of bytes received from this peer since the node started.
   *
   * @return cumulative bytes since current process start
   */
  public long getTotalInputSinceStartup() {
    return totalBytesInSinceStartup;
  }

  /**
   * Returns the number of bytes sent to this peer since the node started.
   *
   * @return cumulative bytes since current process start
   */
  public long getTotalOutputSinceStartup() {
    return totalBytesOutSinceStartup;
  }

  /**
   * Returns the fraction of recent time that a routable connection has existed.
   *
   * @return fraction in {@code [0.0, 1.0]}
   */
  public double getPercentTimeRoutableConnection() {
    return percentTimeRoutableConnection;
  }

  /**
   * Returns the throttle associated with this peer, if any.
   *
   * @return the {@link PacketThrottle} used for rate limiting, or {@code null}
   */
  public PacketThrottle getThrottle() {
    return throttle;
  }

  /**
   * Returns the estimated clock difference between this peer and the local node.
   *
   * @return time delta in milliseconds ({@code remoteTime - localTime})
   */
  public long getClockDelta() {
    return clockDelta;
  }

  /**
   * Indicates whether status changes for this peer are recorded for statistics/logging.
   *
   * @return {@code true} if the node records this peer's status history
   */
  public boolean recordStatus() {
    return recordStatus;
  }

  /**
   * Indicates that this peer is a seed server.
   *
   * @return {@code true} if this snapshot represents a seed server
   */
  public boolean isSeedServer() {
    return isSeedServer;
  }

  /**
   * Indicates that this peer is a seed client.
   *
   * @return {@code true} if this snapshot represents a seed client
   */
  public boolean isSeedClient() {
    return isSeedClient;
  }

  /**
   * Indicates whether the peer should appear in search and selection UIs.
   *
   * @return {@code true} if the connection is a real, searchable link
   */
  @SuppressWarnings("BooleanMethodIsAlwaysInverted")
  public boolean isSearchable() {
    return isSearchable;
  }

  /**
   * Returns the number of bytes sent that were retransmissions.
   *
   * @return cumulative bytes resent
   */
  public long getResendBytesSent() {
    return resendBytesSent;
  }

  /**
   * Returns the uptime reported by the peer as a percentage.
   *
   * @return integer percentage in {@code [0, 100]}
   */
  public int getReportedUptimePercentage() {
    return reportedUptimePercentage;
  }

  /**
   * Returns how often the peer has been selected since connecting.
   *
   * @return a rate expressed as selections per millisecond
   */
  public double getSelectionRate() {
    return selectionRate;
  }
}
