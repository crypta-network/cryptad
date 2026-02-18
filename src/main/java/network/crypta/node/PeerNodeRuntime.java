package network.crypta.node;

import java.lang.ref.WeakReference;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.Random;
import network.crypta.io.comm.Peer;
import network.crypta.keys.Key;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Aggregates peer-runtime helper components and exposes a narrow façade for {@link PeerNode}.
 *
 * <p>This class wires together the specialized support helpers that manage noderef parsing,
 * transport operations, ARK lifecycle, routing statistics, load tracking, and handshake completion.
 * Most methods are thin delegations that keep {@link PeerNode} focused on state and policy while
 * moving subsystem-specific logic behind stable entry points. Callers typically create one instance
 * per peer and reuse it throughout the peer lifetime.
 *
 * <p>Mutability is intentional: packet format and connection state evolve as sessions renegotiate,
 * while helper collaborators remain stable references after construction. Thread-safety is provided
 * by delegated components and selective synchronization (for example, packet-format reading during
 * sending). This class does not introduce a global lock and therefore preserves the existing
 * peer-level lock ordering.
 *
 * <ul>
 *   <li>Centralizes helper composition for the peer runtime path.
 *   <li>Provides packet send/handshake adapter methods used by {@link PeerNode}.
 *   <li>Exposes load, location, and routing metrics through delegated readers.
 * </ul>
 */
final class PeerNodeRuntime {
  private static final Logger LOG = LoggerFactory.getLogger(PeerNodeRuntime.class);

  private final PeerNode peerNode;
  private final Node node;
  private final PeerNodeReferenceSupport referenceSupport;
  private final PeerNodeOfferSupport offerSupport;
  private final PeerNodeTransport transport;
  private final PeerNodeArkManager arkManager;
  private final PeerNodeAddressManager addressManager;
  private final PeerNodeRoutingStats routingStats;
  private final PeerLocation location;
  private final PeerNodeLoadTracker loadTracker;
  private final PeerNodeHandshakeLifecycle handshakeLifecycle;
  private final PeerNodeJfkNonces jfkNoncesSent = new PeerNodeJfkNonces();

  private PeerNodeConnectionState connectionState = new PeerNodeConnectionState(0);
  private PacketFormat packetFormat;

  /**
   * Creates a backoff checker runnable for a peer reference.
   *
   * @param peerRef weak reference to the peer whose backoff status should be refreshed
   * @return runnable checker that safely does nothing when the reference has been cleared
   */
  static Runnable createBackoffStatusChecker(WeakReference<PeerNode> peerRef) {
    return PeerNodeHandshakeLifecycle.createBackoffStatusChecker(peerRef);
  }

  /**
   * Creates a runtime façade and initializes all peer-scoped helper components.
   *
   * @param peerNode owning peer used by delegated helpers
   * @param node node context used for routing, stats, and network services
   * @param locationString serialized peer location used to initialize location state
   */
  PeerNodeRuntime(PeerNode peerNode, Node node, String locationString) {
    this.peerNode = peerNode;
    this.node = node;
    referenceSupport = new PeerNodeReferenceSupport(peerNode);
    offerSupport = new PeerNodeOfferSupport(peerNode);
    transport = new PeerNodeTransport(peerNode);
    arkManager = new PeerNodeArkManager(peerNode);
    addressManager = new PeerNodeAddressManager(peerNode);
    routingStats = new PeerNodeRoutingStats(node);
    location = new PeerLocation(locationString);
    loadTracker = new PeerNodeLoadTracker(peerNode);
    handshakeLifecycle = new PeerNodeHandshakeLifecycle(peerNode, node, this);
  }

  /**
   * Derives the incoming setup key material used by handshake logic.
   *
   * @param crypto crypto context supplying key-derivation material
   * @param identityHashHash double-hashed identity bytes used by the derivation
   * @return derived setup key bytes for incoming handshake traffic
   */
  byte[] computeIncomingSetupKey(NodeCrypto crypto, byte[] identityHashHash) {
    return referenceSupport.computeIncomingSetupKey(crypto, identityHashHash);
  }

  /**
   * Derives the outgoing setup key material used by handshake logic.
   *
   * @param crypto crypto context supplying key-derivation material
   * @param identityHash hashed peer identity bytes used by the derivation
   * @return derived setup key bytes for outgoing handshake traffic
   */
  byte[] computeOutgoingSetupKey(NodeCrypto crypto, byte[] identityHash) {
    return referenceSupport.computeOutgoingSetupKey(crypto, identityHash);
  }

  /**
   * Formats a duration for diagnostics.
   *
   * @param millis duration in milliseconds
   * @return human-readable duration string suitable for logs
   */
  String formatDuration(long millis) {
    return referenceSupport.formatDuration(millis);
  }

  /**
   * Formats a peer key hash for diagnostics.
   *
   * @param hash key-hash bytes to format
   * @return compact string representation of the provided hash bytes
   */
  String formatPeerKeyHash(byte[] hash) {
    return referenceSupport.formatPeerKeyHash(hash);
  }

  /**
   * Verifies the noderef signature.
   *
   * @param fs noderef fields containing signature and signed data
   * @return {@code true} when signature verification succeeds
   * @throws FSParseException when verification fails or underlying parsing throws
   */
  boolean verifyReferenceSignature(SimpleFieldSet fs) throws FSParseException {
    try {
      return referenceSupport.verifyReferenceSignature(fs);
    } catch (Exception e) {
      throw new FSParseException("Invalid signature", e);
    }
  }

  /**
   * Parses a single peer address string.
   *
   * @param phys textual peer endpoint representation
   * @return parsed peer endpoint, or {@code null} when parsing fails
   */
  Peer tryParsePeer(String phys) {
    return referenceSupport.tryParsePeer(phys);
  }

  /**
   * Validates testnet and opennet flags from noderef content.
   *
   * @param fs noderef fields to validate
   * @param forDiffNodeRef whether fields came from a differential noderef update
   * @param forFullNodeRef whether fields came from a full noderef update
   * @throws FSParseException when required flags are missing or invalid
   */
  void checkTestnetAndOpennet(SimpleFieldSet fs, boolean forDiffNodeRef, boolean forFullNodeRef)
      throws FSParseException {
    referenceSupport.checkTestnetAndOpennet(fs, forDiffNodeRef, forFullNodeRef);
  }

  /**
   * Validates identity fields from noderef content.
   *
   * @param fs noderef fields containing identity material
   * @param forDiffNodeRef whether fields came from a differential noderef update
   * @param forFullNodeRef whether fields came from a full noderef update
   * @throws FSParseException when identity data is malformed or inconsistent
   */
  void validateIdentity(SimpleFieldSet fs, boolean forDiffNodeRef, boolean forFullNodeRef)
      throws FSParseException {
    referenceSupport.validateIdentity(fs, forDiffNodeRef, forFullNodeRef);
  }

  /**
   * Parses ECDSA noderef fields.
   *
   * @param fs noderef fields containing ECDSA values
   * @throws FSParseException when ECDSA fields are missing or malformed
   */
  void parseEcdsaFields(SimpleFieldSet fs) throws FSParseException {
    referenceSupport.parseEcdsaFields(fs);
  }

  /**
   * Writes ECDSA noderef fields.
   *
   * @param fs destination field set to receive ECDSA fields
   * @param key ECDSA public key to serialize
   */
  void putEcdsaFields(SimpleFieldSet fs, ECPublicKey key) {
    referenceSupport.putEcdsaFields(fs, key);
  }

  /**
   * Parses ARK fields from noderef content.
   *
   * @param fs noderef fields that may contain ARK metadata
   * @param onStartup whether parsing is running during startup initialization
   * @param forDiffNodeRef whether fields came from a differential noderef update
   * @return {@code true} when ARK state changed, otherwise {@code false}
   */
  boolean parseArk(SimpleFieldSet fs, boolean onStartup, boolean forDiffNodeRef) {
    return arkManager.parseArk(fs, onStartup, forDiffNodeRef);
  }

  /**
   * Appends ARK fields to a noderef field set.
   *
   * @param fs destination field set for ARK metadata
   */
  void appendArkFields(SimpleFieldSet fs) {
    arkManager.appendArkFields(fs);
  }

  /**
   * Applies a fetched ARK update.
   *
   * @param fs fetched noderef content to process
   * @param fetchedEdition ARK edition number associated with the fetched content
   */
  void handleArkUpdate(SimpleFieldSet fs, long fetchedEdition) {
    arkManager.handleArkUpdate(fs, fetchedEdition);
  }

  /**
   * Reports whether an ARK fetcher is active.
   *
   * @return {@code true} when ARK fetching is currently running
   */
  boolean isFetchingArk() {
    return arkManager.isFetching();
  }

  /** Starts ARK fetching for this peer. */
  void startArkFetcher() {
    arkManager.startFetcher();
  }

  /** Stops ARK fetching for this peer. */
  void stopArkFetcher() {
    arkManager.stopFetcher();
  }

  /**
   * Sends a key offer to this peer.
   *
   * @param key key to offer to use the peer-offer protocol
   */
  void offer(Key key) {
    offerSupport.offer(key);
  }

  /**
   * Notifies opennet manager of a disconnect event when available.
   *
   * @param node node context used to look up the opennet manager
   */
  void notifyOpennetOnDisconnect(Node node) {
    OpennetManager om = node.network().opennet();
    if (om != null) om.onDisconnect();
  }

  /**
   * Notifies opennet manager of a connected peer when available.
   *
   * @param node node context used to look up the opennet manager
   * @param peerNode connected peer instance to pass to opennet manager
   */
  void notifyOpennetOnConnect(Node node, PeerNode peerNode) {
    OpennetManager om = node.network().opennet();
    if (om != null) {
      // OpennetManager must be notified of a new connection even if it is a darknet peer.
      om.onConnectedPeer(peerNode);
    }
  }

  /** Resets throttling state for handshake IP refresh attempts. */
  void resetHandshakeIpUpdateTimer() {
    addressManager.resetHandshakeIpUpdateTimer();
  }

  /**
   * Parses a detected peer address from metadata.
   *
   * @param metadata metadata field set that may contain detected address values
   * @return parsed detected peer address, or {@code null} when absent/invalid
   */
  Peer parseDetectedPeer(SimpleFieldSet metadata) {
    return addressManager.parseDetectedPeer(metadata);
  }

  /**
   * Parses compatibility peer-address syntax into concrete peers.
   *
   * @param phys physical address entry from noderef data
   * @param fromLocal whether this entry originates from local persisted data
   * @return parsed peers in encounter order, possibly empty when parsing fails
   */
  List<Peer> parsePeerEntryCompat(String phys, boolean fromLocal) {
    return referenceSupport.parsePeerEntryCompat(phys, fromLocal);
  }

  /**
   * Refreshes handshake IP candidates.
   *
   * @param ignoreHostnames whether hostname lookups should be skipped for this pass
   */
  void maybeUpdateHandshakeIPs(boolean ignoreHostnames) {
    addressManager.maybeUpdateHandshakeIPs(ignoreHostnames);
  }

  /**
   * Selects the next handshake IP candidate.
   *
   * @return selected handshake peer endpoint, or {@code null} when none are available
   */
  Peer getHandshakeIP() {
    return addressManager.getHandshakeIP();
  }

  /**
   * Records when handshake-IP refresh was attempted.
   *
   * @param now wall-clock timestamp in milliseconds
   */
  void markHandshakeIpUpdateAttempted(long now) {
    addressManager.markHandshakeIpUpdateAttempted(now);
  }

  /**
   * Creates handshake state using pre-derived setup keys.
   *
   * @param incomingSetupKey setup key for inbound handshake processing
   * @param outgoingSetupKey setup key for outbound handshake processing
   * @param anonymousInitiatorKey setup key used for anonymous initiator mode
   * @return initialized handshake-state object bound to this peer
   */
  PeerNode.HandshakeState createHandshakeState(
      byte[] incomingSetupKey, byte[] outgoingSetupKey, byte[] anonymousInitiatorKey) {
    return new PeerNodeHandshake(
        peerNode, incomingSetupKey, outgoingSetupKey, anonymousInitiatorKey);
  }

  /**
   * Determines whether traffic to this peer should be throttled.
   *
   * @return {@code true} when local throttling policy indicates throttling should apply
   */
  boolean shouldThrottle() {
    return PeerNodeAddressManager.shouldThrottle(peerNode.getPeer(), node);
  }

  /**
   * Returns the current connection state.
   *
   * @return {@code true} when peer connection state is currently connected
   */
  boolean isConnected() {
    return connectionState.isConnected();
  }

  /**
   * Updates connection state.
   *
   * @param connected new connection-state flag to apply
   * @param now timestamp used for transition tracking
   * @return previous connection-state value before update
   */
  boolean setConnected(boolean connected, long now) {
    return connectionState.setConnected(connected, now);
  }

  /**
   * Returns the most recent connected timestamp.
   *
   * @param now fallback timestamp when currently connected
   * @return last-connected timestamp for this peer
   */
  long timeLastConnected(long now) {
    return connectionState.timeLastConnected(now);
  }

  /**
   * Determines whether burst-only handshakes should be used.
   *
   * @param outgoingMangler mangler used to query connectivity status
   * @param random random source used for probabilistic burst decisions
   * @return {@code true} when burst-only behavior is currently enabled
   */
  boolean isBurstOnly(OutgoingPacketMangler outgoingMangler, Random random) {
    return connectionState.isBurstOnly(outgoingMangler, random);
  }

  /**
   * Registers a peer-status change listener.
   *
   * @param listener listener object expected to implement peer-status callback interface
   * @throws ClassCastException if {@code listener} is not a compatible listener implementation
   */
  void registerStatusChangeListener(Object listener) {
    connectionState.registerStatusChangeListener((PeerManager.PeerStatusChangeListener) listener);
  }

  /** Notifies registered peer-status listeners. */
  void notifyStatusChangeListeners() {
    connectionState.notifyStatusChangeListeners();
  }

  /**
   * Reinitializes connection-state tracking with a persisted timestamp.
   *
   * @param lastConnectedTime last-known connection timestamp to seed the tracker
   */
  void initConnectionState(long lastConnectedTime) {
    connectionState = new PeerNodeConnectionState(lastConnectedTime);
  }

  /**
   * Returns the peer transport adapter.
   *
   * @return transport component used for message and packet operations
   */
  PeerTransport transport() {
    return transport;
  }

  /** Notifies transport throttle state after disconnect-related transitions. */
  void maybeDisconnected() {
    transport.getThrottle().maybeDisconnected();
  }

  /**
   * Returns current transport bandwidth estimate.
   *
   * @return current bandwidth estimate from the transport throttle
   */
  double bandwidth() {
    return transport.getThrottle().getBandwidth();
  }

  /** Sends the local IP-address announcement message. */
  void sendIPAddressMessage() {
    transport.sendIPAddressMessage();
  }

  /** Sends post-connection initial messages. */
  void sendInitialMessages() {
    transport.sendInitialMessages();
  }

  /**
   * Sends a node-to-node message via transport.
   *
   * @param fs message payload fields
   * @param n2nType node-to-node message type identifier
   * @param includeSentTime whether send timestamp should be included in the payload
   * @param now current wall-clock timestamp in milliseconds
   * @param queueOnNotConnected whether the message may be queued while disconnected
   */
  void sendNodeToNodeMessage(
      SimpleFieldSet fs,
      int n2nType,
      boolean includeSentTime,
      long now,
      boolean queueOnNotConnected) {
    transport.sendNodeToNodeMessage(fs, n2nType, includeSentTime, now, queueOnNotConnected);
  }

  /**
   * Returns total resent bytes recorded by transport.
   *
   * @return cumulative count of resent bytes for this peer transport
   */
  long getResendBytesSent() {
    return transport.getResendBytesSent();
  }

  /**
   * Records resent bytes on the transport counters.
   *
   * @param bytesToResend number of bytes resent
   */
  void resendBytes(int bytesToResend) {
    transport.resendBytes(bytesToResend);
  }

  /**
   * Returns the nonce tracker used by JFK handshake processing.
   *
   * @return nonce tracker maintaining recently seen JFK nonces
   */
  @SuppressWarnings("unused")
  PeerNodeJfkNonces jfkNoncesSent() {
    return jfkNoncesSent;
  }

  /** Clears cached JFK nonces for this peer. */
  void clearJfkNoncesSent() {
    jfkNoncesSent.clear();
  }

  /**
   * Remembers JFK nonce for replay detection.
   *
   * @param nonce nonce bytes to cache
   * @param maxNoncesPerPeer maximum nonce entries to retain for this peer
   */
  void rememberJfkNonce(byte[] nonce, int maxNoncesPerPeer) {
    jfkNoncesSent.rememberNonce(nonce, maxNoncesPerPeer);
  }

  /**
   * Finds previously stored JFK nonce by nonce-hash.
   *
   * @param nonceHash hash bytes of the nonce to look up
   * @return original nonce bytes when present, otherwise {@code null}
   */
  byte[] findOriginalJfkNonceByHash(byte[] nonceHash) {
    return jfkNoncesSent.findOriginalNonceByHash(nonceHash);
  }

  /**
   * Sets the active packet format implementation.
   *
   * @param packetFormat packet format instance to activate, or {@code null} to clear externally
   */
  void setPacketFormat(PacketFormat packetFormat) {
    this.packetFormat = packetFormat;
  }

  /** Clears the active packet-format reference. */
  void clearPacketFormat() {
    packetFormat = null;
  }

  /**
   * Returns the currently active packet format.
   *
   * @return active packet format instance, or {@code null} when no format is installed
   */
  PacketFormat packetFormat() {
    return packetFormat;
  }

  /**
   * Attempts to send a packet using the active packet format.
   *
   * @param now current timestamp in milliseconds
   * @param ackOnly whether only acknowledgment/maintenance packets may be sent
   * @return {@code true} when a packet was sent, otherwise {@code false}
   */
  boolean maybeSendPacket(long now, boolean ackOnly) {
    PacketFormat pf;
    synchronized (peerNode) {
      pf = packetFormat;
      if (pf == null) return false;
    }
    try {
      return pf.maybeSendPacket(now, ackOnly);
    } catch (BlockedTooLongException e) {
      LOG.error(
          "Packet number allocation blocked {} (peer={}, version={}) - disconnecting",
          formatDuration(e.delta),
          peerNode,
          peerNode.getBuildNumber());
      peerNode.forceDisconnect();
      return false;
    }
  }

  /**
   * Reports incoming load status from a peer message.
   *
   * @param stat load-status object expected to be a {@link PeerLoadStats} instance
   * @throws ClassCastException if {@code stat} is not a {@link PeerLoadStats}
   */
  void reportLoadStatus(Object stat) {
    loadTracker.reportLoadStatus((PeerLoadStats) stat);
  }

  /**
   * Signals that a routing tag no longer routes through this peer.
   *
   * @param tag routing tag previously associated with this peer
   * @param offeredKey whether the tag originated from offered-key routing
   */
  void noLongerRoutingTo(Object tag, boolean offeredKey) {
    loadTracker.noLongerRoutingTo(tag, offeredKey);
  }

  /**
   * Notifies waiting slot selectors that capacity may have changed.
   *
   * @param realTime whether to notify real-time or bulk waiters
   */
  void maybeNotifySlotWaiter(boolean realTime) {
    loadTracker.maybeNotifySlotWaiter(realTime);
  }

  /**
   * Performs post-unlock load-tracker housekeeping for a routing tag.
   *
   * @param tag routing tag that was just unlocked
   */
  void postUnlock(Object tag) {
    loadTracker.postUnlock(tag);
  }

  /**
   * Returns the output-load tracker for a traffic class.
   *
   * @param realTime {@code true} for real-time tracker, {@code false} for bulk tracker
   * @return output-load tracker associated with the requested traffic class
   */
  PeerNodeLoadTracker.OutputLoadTracker outputLoadTracker(boolean realTime) {
    return loadTracker.outputLoadTracker(realTime);
  }

  /**
   * Returns summarized incoming-load statistics.
   *
   * @param realTime {@code true} for real-time summary, {@code false} for bulk summary
   * @return immutable summary stats for the requested traffic class
   */
  PeerNodeLoadTracker.IncomingLoadSummaryStats getIncomingLoadStats(boolean realTime) {
    return loadTracker.getIncomingLoadStats(realTime);
  }

  /**
   * Indicates whether no incoming-load sample is currently cached.
   *
   * @param realTime {@code true} to query real-time stats, {@code false} for bulk stats
   * @return {@code true} when no prior incoming-load sample exists
   */
  boolean missingLastIncomingLoadStats(boolean realTime) {
    return loadTracker.getLastIncomingLoadStats(realTime) == null;
  }

  /**
   * Evaluates whether this peer currently appears low-capacity.
   *
   * @param isRealtime {@code true} for real-time thresholds, {@code false} for bulk thresholds
   * @return {@code true} when either directional threshold exceeds peer-advertised capacity
   */
  boolean isLowCapacity(boolean isRealtime) {
    PeerLoadStats stats = loadTracker.getLastIncomingLoadStats(isRealtime);
    if (stats == null) return false;
    if (node.network().stats().nodePinger.capacityThreshold(isRealtime, true)
        > stats.peerLimit(true)) return true;
    return node.network().stats().nodePinger.capacityThreshold(isRealtime, false)
        > stats.peerLimit(false);
  }

  /**
   * Returns the ping-time cap used for peer selection and diagnostics.
   *
   * @return configured maximum peer ping time, or a conservative fallback when stats are missing
   */
  long maxPeerPingTime() {
    if (node == null) return NodeStats.DEFAULT_MAX_PING_TIME * 2L;
    NodeStats stats = node.network().stats();
    if (stats == null) return NodeStats.DEFAULT_MAX_PING_TIME * 2L;
    return stats.maxPeerPingTime();
  }

  /**
   * Fails queued slot waiters for the selected traffic class.
   *
   * @param realTime {@code true} to fail real-time waiters, {@code false} for bulk waiters
   */
  void failSlotWaiters(boolean realTime) {
    loadTracker.failSlotWaiters(realTime);
  }

  /**
   * Updates peer-neighbor location samples.
   *
   * @param peerLocationsString serialized peer-neighbor locations, possibly {@code null}
   */
  void setPeerLocations(String[] peerLocationsString) {
    location.setPeerLocations(peerLocationsString);
  }

  /**
   * Returns this peer's current location on the routing ring.
   *
   * @return location value in ring space
   */
  double getLocation() {
    return location.getLocation();
  }

  /**
   * Returns peer-neighbor location samples.
   *
   * @return array of neighbor locations, or {@code null} when unknown
   */
  double[] getPeersLocationArray() {
    return location.getPeersLocationArray();
  }

  /**
   * Returns the timestamp of the most recent location update.
   *
   * @return wall-clock timestamp in milliseconds for the last location change
   */
  long getLocationSetTime() {
    return location.getLocationSetTime();
  }

  /**
   * Indicates whether the current location value is valid.
   *
   * @return {@code true} when the location is inside valid bounds
   */
  boolean isValidLocation() {
    return location.isValidLocation();
  }

  /**
   * Returns the known degree of peer-neighbor location samples.
   *
   * @return count of known peer-neighbor locations
   */
  int getLocationDegree() {
    return location.getDegree();
  }

  /**
   * Updates both primary and neighbor locations.
   *
   * @param newLoc new primary location value
   * @param newLocs new neighbor-location array
   * @return {@code true} when the update changed stored values
   */
  boolean updateLocation(double newLoc, double[] newLocs) {
    return location.updateLocation(newLoc, newLocs);
  }

  /**
   * Sets the primary location value.
   *
   * @param newLoc new primary location value
   * @return previous location value before update
   */
  double setLocation(double newLoc) {
    return location.setLocation(newLoc);
  }

  /**
   * Parses location from noderef fields and updates peer-count refresh hints.
   *
   * @param fs noderef fields that may contain a location string
   * @param shouldUpdatePeerCounts single-element flag array toggled when the unknown location
   *     becomes known
   * @return {@code true} when location state changed, otherwise {@code false}
   */
  boolean parseLocationAndMaybePeerCounts(SimpleFieldSet fs, boolean[] shouldUpdatePeerCounts) {
    boolean changedAnything = false;
    String locationString = fs.get(PeerNode.SFS_KEY_LOCATION);
    if (locationString != null) {
      double newLoc = Location.getLocation(locationString);
      if (!Location.isValid(newLoc)) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Invalid or null location, waiting for FNPLocChangeNotification: locationString={}",
              locationString);
      } else {
        double oldLoc = setLocation(newLoc);
        if (!Location.equals(oldLoc, newLoc)) {
          if (!Location.isValid(oldLoc)) shouldUpdatePeerCounts[0] = true;
          changedAnything = true;
        }
      }
    }
    return changedAnything;
  }

  /**
   * Returns the location string used in short diagnostics.
   *
   * @return string representation of the current location state
   */
  String locationToString() {
    return location.toString();
  }

  /**
   * Returns an atomic location snapshot.
   *
   * @return two-element array containing raw location bits and location-set timestamp
   */
  long[] getLocationSnapshot() {
    synchronized (location) {
      return new long[] {
        Double.doubleToRawLongBits(location.getLocation()), location.getLocationSetTime()
      };
    }
  }

  /**
   * Returns the closest known peer-neighbor location to a target.
   *
   * @param target target ring location
   * @param excludeLocations optional set of locations to exclude, expected as {@code Set<Double>}
   * @return closest eligible location to {@code target}
   * @throws ClassCastException if {@code excludeLocations} is non-null and not a {@code
   *     Set<Double>}
   */
  @SuppressWarnings("unchecked")
  double getClosestPeerLocation(double target, Object excludeLocations) {
    java.util.Set<Double> exclude = null;
    if (excludeLocations != null) {
      exclude = (java.util.Set<Double>) excludeLocations;
    }
    return location.getClosestPeerLocation(target, exclude);
  }

  /**
   * Reports interval between successive swap events.
   *
   * @param timeSinceLastTime elapsed milliseconds since the prior swap interval sample
   */
  void reportSwapInterval(long timeSinceLastTime) {
    routingStats.reportSwapInterval(timeSinceLastTime);
  }

  /**
   * Returns average swap interval.
   *
   * @return smoothed swap interval in milliseconds
   */
  double averageSwapInterval() {
    return routingStats.averageSwapInterval();
  }

  /**
   * Reports interval between successive probe events.
   *
   * @param timeSinceLastTime elapsed milliseconds since the prior probe interval sample
   */
  void reportProbeInterval(long timeSinceLastTime) {
    routingStats.reportProbeInterval(timeSinceLastTime);
  }

  /**
   * Returns average probe interval.
   *
   * @return smoothed probe interval in milliseconds
   */
  double averageProbeInterval() {
    return routingStats.averageProbeInterval();
  }

  /**
   * Returns combined backoff percentage.
   *
   * @return backoff proportion in the range {@code 0.0..1.0}
   */
  double backedOffPercent() {
    return routingStats.backedOffPercent();
  }

  /**
   * Reports current routing-backoff window endpoints.
   *
   * @param now current wall-clock timestamp in milliseconds
   * @param routingBackedOffUntilRT end timestamp for real-time routing backoff
   * @param routingBackedOffUntilBulk end timestamp for bulk routing backoff
   */
  void reportBackoffStatus(long now, long routingBackedOffUntilRT, long routingBackedOffUntilBulk) {
    routingStats.reportBackoffStatus(now, routingBackedOffUntilRT, routingBackedOffUntilBulk);
  }

  /** Reports an overload rejection sample. */
  void reportRejectedOverload() {
    routingStats.reportRejectedOverload();
  }

  /** Reports a non-rejected overload sample. */
  void reportNotRejectedOverload() {
    routingStats.reportNotRejectedOverload();
  }

  /**
   * Returns estimated overload rejection probability.
   *
   * @return overload rejection probability in the range {@code 0.0..1.0}
   */
  double pRejected() {
    return routingStats.pRejected();
  }

  /**
   * Returns average ping latency estimate.
   *
   * @return smoothed ping latency value in milliseconds
   */
  double averagePingTime() {
    return routingStats.averagePingTime();
  }

  /**
   * Reports a ping latency sample.
   *
   * @param t measured ping latency in milliseconds
   */
  void reportPing(long t) {
    routingStats.reportPing(t);
  }

  /**
   * Returns real-time backoff percentage.
   *
   * @return real-time backoff proportion in the range {@code 0.0..1.0}
   */
  double backedOffPercentRT() {
    return routingStats.backedOffPercentRT();
  }

  /**
   * Returns bulk backoff percentage.
   *
   * @return bulk backoff proportion in the range {@code 0.0..1.0}
   */
  double backedOffPercentBulk() {
    return routingStats.backedOffPercentBulk();
  }

  /**
   * Completes handshake finalization through the lifecycle coordinator.
   *
   * @param paramsObject handshake parameters expected by lifecycle completion logic
   * @return tracker identifier on success or negative value when completion failed
   */
  long completeHandshake(Object paramsObject) {
    return handshakeLifecycle.completeHandshake(paramsObject);
  }
}
