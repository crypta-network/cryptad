package network.crypta.node;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.PeerParseException;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates address discovery, handshake address selection, and IP matching for a {@link
 * PeerNode}.
 *
 * <p>This helper centralizes the small but policy-heavy decisions around which addresses should be
 * considered for handshakes, when to refresh cached DNS resolution, and how to match incoming
 * addresses against the peer roster. It is invoked during periodic maintenance and connection setup
 * paths, and it feeds back into {@link PeerNode} through {@link PeerNode#applyHandshakeIPs(Peer[],
 * Peer, Peer)}. The class is intentionally lightweight: it holds only a few mutable counters and
 * relies on the owning {@code PeerNode} for persistent state.
 *
 * <p>Thread-safety is achieved by synchronizing on the owning {@code PeerNode} when reading or
 * updating shared state, such as handshake candidate arrays and the last DNS refresh time. Callers
 * should treat instances as tied to their {@code PeerNode} and avoid sharing across nodes. The
 * helper favors deterministic ordering and conservative filtering over aggressive discovery to
 * reduce unnecessary DNS traffic and to avoid selecting addresses that would be rejected by routing
 * policy.
 *
 * <ul>
 *   <li><strong>Handshake address refresh:</strong> throttles DNS lookups and deduplicates
 *       candidates
 *   <li><strong>Selection:</strong> filters candidates for policy and rotates among valid choices
 *   <li><strong>Matching:</strong> compares incoming addresses using strict or relaxed semantics
 *   <li><strong>Throttling:</strong> treats local-only addresses differently from public ones
 * </ul>
 *
 * @see PeerNode
 * @see PeerRoster
 */
final class PeerNodeAddressManager {
  /** Logger for handshake resolution and filtering decisions. */
  private static final Logger LOG = LoggerFactory.getLogger(PeerNodeAddressManager.class);

  /** Metadata key used to read a detected UDP address from {@link SimpleFieldSet} entries. */
  private static final String SFS_KEY_DETECTED_UDP = "detected.udp";

  /** Log prefix used when describing handshake candidates that are rejected. */
  private static final String STR_NOT_SENDING_HANDSHAKE_TO = "Not sending handshake to ";

  /** Log infix that introduces the contextual peer description. */
  private static final String STR_FOR = " for ";

  /** Owning peer node; serves as the synchronization anchor for mutable state. */
  private final PeerNode peer;

  /** The last time we attempted to update handshake IPs. Guarded by {@code peer}. */
  private long lastAttemptedHandshakeIPUpdateTime;

  /** Alternator used to pick a single handshake address when multiple addresses are available. */
  private int handshakeIPAlternator;

  /**
   * Creates a new manager bound to a specific peer node.
   *
   * <p>The instance does not perform any work eagerly. It records the provided peer node, which is
   * subsequently used for both synchronization and access to the cached address state. The caller
   * is responsible for ensuring the same {@code PeerNodeAddressManager} is reused for the same peer
   * node to keep the throttling counters meaningful.
   *
   * @param peer the owning peer node that supplies address state and synchronization.
   */
  PeerNodeAddressManager(PeerNode peer) {
    this.peer = peer;
  }

  /**
   * Clears the handshake refresh timer so the next update attempt is not throttled.
   *
   * <p>This method is idempotent and only affects the timestamp used to suppress rapid DNS
   * refreshes. It does not alter the current handshake candidate list or detect peer values.
   *
   * @see #markHandshakeIpUpdateAttempted(long)
   */
  void resetHandshakeIpUpdateTimer() {
    synchronized (peer) {
      lastAttemptedHandshakeIPUpdateTime = 0;
    }
  }

  /**
   * Records the most recent handshake-IP update attempt time.
   *
   * <p>The stored timestamp is used to throttle further DNS resolution attempts. Callers should
   * pass a millisecond value consistent with {@link System#currentTimeMillis()} to preserve the
   * expected five-minute backoff logic in {@link #maybeUpdateHandshakeIPs(boolean)}.
   *
   * @param now current time in milliseconds since the epoch.
   */
  void markHandshakeIpUpdateAttempted(long now) {
    synchronized (peer) {
      lastAttemptedHandshakeIPUpdateTime = now;
    }
  }

  /**
   * Performs DNS resolution for handshake addresses when hostnames are allowed.
   *
   * <p>Removes duplicates after lookup.
   *
   * @param localHandshakeIPs candidate addresses to resolve and de-duplicate
   * @param ignoreHostnames when true, skips hostname resolution
   * @return the updated, deduplicated address array
   */
  private Peer[] resolveAndDedupe(Peer[] localHandshakeIPs, boolean ignoreHostnames) {
    for (Peer localHandshakeIP : localHandshakeIPs) {
      if (ignoreHostnames) {
        // Don't do a DNS request on the first cycle through PeerNodes by DNSRequest
        // upon startup (I suspect the following won't do anything, but just in case)
        if (LOG.isDebugEnabled())
          LOG.debug(
              "resolveAndDedupe: calling getAddress(false) on Peer '{}' for {} ({})",
              localHandshakeIP,
              peer.shortToString(),
              true);
        localHandshakeIP.getAddress(false);
      } else {
        // Actually do the DNS request for the member Peer of localHandshakeIPs
        if (LOG.isDebugEnabled())
          LOG.debug(
              "resolveAndDedupe: calling getHandshakeAddress() on Peer '{}' for {} ({})",
              localHandshakeIP,
              peer.shortToString(),
              false);
        localHandshakeIP.getHandshakeAddress();
      }
    }
    // De-dupe while preserving encounter order.
    return Arrays.stream(localHandshakeIPs).distinct().toArray(Peer[]::new);
  }

  /**
   * Refreshes the cached set of candidate handshake addresses.
   *
   * <p>Combines the detected address (if any) with advertised addresses from the noderef and
   * host-derived candidates. When {@code ignoreHostnames} is true, skips DNS lookups and relies on
   * already-resolved or literal IP addresses.
   *
   * @param ignoreHostnames whether to avoid hostname resolution while refreshing
   */
  void maybeUpdateHandshakeIPs(boolean ignoreHostnames) {
    long now = System.currentTimeMillis();
    Peer localDetectedPeer = peer.getPeer();
    synchronized (peer) {
      if ((now - lastAttemptedHandshakeIPUpdateTime) < TimeUnit.MINUTES.toMillis(5)) return;
      if (!ignoreHostnames) lastAttemptedHandshakeIPUpdateTime = now;
    }
    if (LOG.isDebugEnabled())
      LOG.debug("Updating handshake IPs for peer '{}' ({})", peer.shortToString(), ignoreHostnames);

    Peer[] myNominalPeer;
    synchronized (peer) {
      AtomicReference<List<Peer>> nominalPeerRef = peer.nominalPeer;
      List<Peer> localNominalPeer = nominalPeerRef == null ? null : nominalPeerRef.get();
      myNominalPeer =
          localNominalPeer == null ? new Peer[0] : localNominalPeer.toArray(new Peer[0]);
    }
    if (handleNoNominalPeersCase(localDetectedPeer, myNominalPeer, ignoreHostnames)) return;

    FreenetInetAddress localhost = peer.node.network().freenetLocalhostAddress();
    Peer[] nodePeers = peer.getOutgoingMangler().getPrimaryIPAddress();
    List<Peer> basePeers;
    synchronized (peer) {
      AtomicReference<List<Peer>> nominalPeerRef = peer.nominalPeer;
      List<Peer> localNominalPeer = nominalPeerRef == null ? null : nominalPeerRef.get();
      basePeers = localNominalPeer == null ? new ArrayList<>() : new ArrayList<>(localNominalPeer);
    }
    PeersBuildResult build =
        prepareLocalPeers(myNominalPeer, localDetectedPeer, nodePeers, localhost, basePeers);
    Peer[] localHandshakeIPs =
        resolveAndDedupe(build.localPeers.toArray(new Peer[0]), ignoreHostnames);
    peer.applyHandshakeIPs(localHandshakeIPs, localDetectedPeer, build.detectedDuplicate);
  }

  /**
   * Handles the fast path when no nominal peers are configured.
   *
   * <p>If no nominal peers exist, this method either clears the handshake IP cache (when there is
   * no detected peer) or rebuilds it from the detected peer only. Returning {@code true} tells the
   * caller that the refresh work is complete and no further processing is required.
   *
   * @param localDetectedPeer most recently detected peer address; may be {@code null}.
   * @param myNominalPeer snapshot of nominal peers; never {@code null}.
   * @param ignoreHostnames whether hostname resolution should be skipped.
   * @return {@code true} if the no-nominal case was applied and handled.
   */
  private boolean handleNoNominalPeersCase(
      Peer localDetectedPeer, Peer[] myNominalPeer, boolean ignoreHostnames) {
    if (myNominalPeer.length != 0) return false;
    if (localDetectedPeer == null) {
      peer.applyHandshakeIPs(null, null, null);
      return true;
    }
    Peer[] localHandshakeIPs = resolveAndDedupe(new Peer[] {localDetectedPeer}, ignoreHostnames);
    peer.applyHandshakeIPs(localHandshakeIPs, localDetectedPeer, null);
    return true;
  }

  /**
   * Builds the base list of local handshake candidates from nominal and detected peers.
   *
   * <p>The method filters duplicate entries, optionally injects a localhost peer when the nominal
   * peer matches one of the node's primary addresses, and records when a nominal peer is an equal
   * copy of the detected peer. The input list is mutated in-place to preserve encounter order.
   *
   * @param myNominalPeer snapshot of nominal peers to traverse and filter.
   * @param localDetectedPeer detected peer address used to find duplicates; may be {@code null}.
   * @param nodePeers primary node addresses used to detect localhost substitutions.
   * @param localhost canonical localhost address for the node.
   * @param localPeers mutable list that receives the filtered candidates.
   * @return a result containing the populated list and any detected duplicate.
   */
  private PeersBuildResult prepareLocalPeers(
      Peer[] myNominalPeer,
      Peer localDetectedPeer,
      Peer[] nodePeers,
      FreenetInetAddress localhost,
      List<Peer> localPeers) {
    boolean addedLocalhost = false;
    Peer detectedDuplicate = null;
    for (Peer p : myNominalPeer) {
      if (p == null) continue;
      if (isDuplicateLocalDetectedPeer(p, localDetectedPeer)) detectedDuplicate = p;
      FreenetInetAddress addr = p.getFreenetAddress();
      boolean skip = shouldSkipForLocalhost(addr, localhost, addedLocalhost);
      if (!skip) {
        addedLocalhost =
            maybeAddLocalhostPeerWhenMatch(
                addr, nodePeers, addedLocalhost, localPeers, localhost, p.getPort());
        if (!localPeers.contains(p)) localPeers.add(p);
      }
    }
    return new PeersBuildResult(localPeers, detectedDuplicate);
  }

  /**
   * Checks whether an address equals any of the node's primary peer addresses.
   *
   * @param addr address to compare against the primary node peers.
   * @param nodePeers primary peer array supplied by the outgoing mangler.
   * @return {@code true} if any primary peer has the same address.
   */
  private boolean addressMatchesNodePeers(FreenetInetAddress addr, Peer[] nodePeers) {
    for (Peer nodePeer : nodePeers) {
      FreenetInetAddress myAddr = nodePeer.getFreenetAddress();
      if (myAddr.equals(addr)) return true;
    }
    return false;
  }

  /**
   * Returns whether a nominal peer duplicates the detected peer by value.
   *
   * <p>Equality is based on address and port, so both identical instances and distinct instances
   * representing the same endpoint are treated as duplicates.
   *
   * @param p nominal peer candidate to compare.
   * @param localDetectedPeer detected peer address; may be {@code null}.
   * @return {@code true} if {@code p} is a value-equal duplicate of the detected peer.
   */
  private boolean isDuplicateLocalDetectedPeer(Peer p, Peer localDetectedPeer) {
    return p.equals(localDetectedPeer);
  }

  /**
   * Determines whether a nominal peer should be skipped because localhost was already added.
   *
   * @param addr address of the nominal peer under consideration.
   * @param localhost canonical localhost address used for comparison.
   * @param addedLocalhost whether a localhost peer has already been inserted.
   * @return {@code true} if {@code addr} is localhost and it was already added.
   */
  private boolean shouldSkipForLocalhost(
      FreenetInetAddress addr, FreenetInetAddress localhost, boolean addedLocalhost) {
    if (!addr.equals(localhost)) return false;
    return addedLocalhost; // skip when we've already added localhost once
  }

  /**
   * Adds a localhost peer when the nominal address matches one of the node's primary addresses.
   *
   * <p>The insertion preserves ordering by appending the localhost peer before the nominal peer
   * itself is added. The method returns whether localhost is now present, allowing callers to
   * suppress further localhost insertions.
   *
   * @param addr address of the nominal peer under consideration.
   * @param nodePeers primary node peers used to detect localhost substitution.
   * @param addedLocalhost whether a localhost peer has already been inserted.
   * @param localPeers mutable list that receives the localhost peer when needed.
   * @param localhost canonical localhost address used for the inserted peer.
   * @param port port number to use for the inserted localhost peer.
   * @return {@code true} if localhost is present after this call; otherwise {@code false}.
   */
  private boolean maybeAddLocalhostPeerWhenMatch(
      FreenetInetAddress addr,
      Peer[] nodePeers,
      boolean addedLocalhost,
      List<Peer> localPeers,
      FreenetInetAddress localhost,
      int port) {
    if (addressMatchesNodePeers(addr, nodePeers) && !addedLocalhost) {
      localPeers.add(new Peer(localhost, port));
      return true;
    }
    return addedLocalhost;
  }

  /**
   * Holds the intermediate results of composing handshake candidates.
   *
   * @param localPeers an ordered list of candidate peers after filtering and augmentation.
   * @param detectedDuplicate nominal peer that duplicates the detected peer, if found.
   */
  private record PeersBuildResult(List<Peer> localPeers, Peer detectedDuplicate) {}

  /**
   * Selects a single handshake candidate from the current cached list.
   *
   * <p>The method first validates the cached handshake candidates against DNS resolution,
   * local-address policy, and connection policy. If multiple candidates survive filtering, the
   * selection rotates in a round-robin fashion to spread attempts across available addresses. The
   * method returns {@code null} when handshakes are suppressed, when no candidates are available,
   * or when all candidates are rejected by policy.
   *
   * @return the selected handshake peer, or {@code null} if no candidate is eligible.
   */
  Peer getHandshakeIP() {
    if (!peer.shouldSendHandshake()) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            STR_NOT_SENDING_HANDSHAKE_TO + "{} because pn.shouldSendHandshake() returned false",
            peer.getPeer());
      return null;
    }
    Peer[] localHandshakeIPs = peer.getHandshakeIPs();
    if (localHandshakeIPs == null || localHandshakeIPs.length == 0) return null;

    List<Peer> validIPs = new ArrayList<>(localHandshakeIPs.length);
    boolean allowLocalAddresses = peer.allowLocalAddresses();
    for (Peer candidate : localHandshakeIPs) {
      if (isValidHandshakePeer(candidate, allowLocalAddresses)) validIPs.add(candidate);
    }

    if (validIPs.isEmpty()) return null;
    if (validIPs.size() == 1) return validIPs.getFirst();

    handshakeIPAlternator %= validIPs.size();
    Peer ret = validIPs.get(handshakeIPAlternator);
    handshakeIPAlternator++;
    return ret;
  }

  /**
   * Applies handshake eligibility checks to a candidate peer.
   *
   * <p>The candidate must have a resolved address, pass the "real Internet address" test (unless
   * local addresses are allowed), and satisfy the outgoing mangler's connection policy when the
   * peer is not currently connected. Failures are logged at debug level and result in rejection.
   *
   * @param peerAddr candidate peer to validate and potentially filter.
   * @param allowLocalAddressesFlag whether local/private addresses are considered valid.
   * @return {@code true} if the peer is eligible for handshake attempts.
   */
  private boolean isValidHandshakePeer(Peer peerAddr, boolean allowLocalAddressesFlag) {
    FreenetInetAddress addr = peerAddr.getFreenetAddress();
    if (peerAddr.getAddress(false) == null) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            STR_NOT_SENDING_HANDSHAKE_TO
                + "{}"
                + STR_FOR
                + "{} because the DNS lookup failed or it's a currently unsupported IPv6 address",
            peerAddr,
            peer.getPeer());
      return false;
    }
    if (!peerAddr.isRealInternetAddress(false, false, allowLocalAddressesFlag)) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            STR_NOT_SENDING_HANDSHAKE_TO
                + "{}"
                + STR_FOR
                + "{} because it's not a real Internet address and metadata.allowLocalAddresses is"
                + " not true",
            peerAddr,
            peer.getPeer());
      return false;
    }
    // If we are connected, we are rekeying. We have separate code to boot out connections.
    if (!peer.isConnected()
        && !peer.getOutgoingMangler().allowConnection(peer.selfPeerNode(), addr)) {
      if (LOG.isDebugEnabled())
        LOG.debug(STR_NOT_SENDING_HANDSHAKE_TO + "{}" + STR_FOR + "{}", peerAddr, peer);
      return false;
    }
    return true;
  }

  /**
   * Determines whether an address matches the detected or nominal addresses of a peer.
   *
   * <p>This is a convenience wrapper that delegates to {@link
   * PeerNode#matchesIP(FreenetInetAddress, boolean)} so callers get a consistent, synchronized view
   * of the peer's address state. Strict matching uses full equality semantics, while non-strict
   * matching uses relaxed hostname/IP comparison.
   *
   * @param peerNode peer whose detected and nominal addresses are searched.
   * @param addr address to compare against the peer's known addresses.
   * @param strict whether to require strict equality rather than relaxed matching.
   * @return {@code true} if the address matches under the chosen semantics.
   */
  static boolean matchesIP(PeerNode peerNode, FreenetInetAddress addr, boolean strict) {
    return peerNode.matchesIP(addr, strict);
  }

  /**
   * Performs strict address matching against a peer's detected and nominal addresses.
   *
   * <p>This helper assumes the caller holds an appropriate lock on {@code peerNode} to prevent
   * concurrent mutation of the address lists. Strict matching relies on {@link
   * FreenetInetAddress#equals(Object)} and does not allow relaxed hostname/IP equivalence.
   *
   * @param peerNode peer whose address lists will be searched.
   * @param addr address to compare using strict equality semantics.
   * @return {@code true} if a detected or nominal address equals {@code addr}.
   */
  static boolean strictMatch(PeerNode peerNode, FreenetInetAddress addr) {
    return matchesPeerAddress(peerNode.getPeer(), addr, true)
        || matchesNominalPeers(peerNode.nominalPeer, addr, true);
  }

  /**
   * Performs relaxed address matching against a peer's detected and nominal addresses.
   *
   * <p>This helper assumes the caller holds an appropriate lock on {@code peerNode} to prevent
   * concurrent mutation of the address lists. Relaxed matching uses {@link
   * FreenetInetAddress#laxEquals(FreenetInetAddress)}, which can match hostnames to resolved IP
   * addresses when appropriate.
   *
   * @param peerNode peer whose address lists will be searched.
   * @param addr address to compare using relaxed equality semantics.
   * @return {@code true} if a detected or nominal address matches {@code addr} laxly.
   */
  static boolean nonStrictMatch(PeerNode peerNode, FreenetInetAddress addr) {
    return matchesPeerAddress(peerNode.getPeer(), addr, false)
        || matchesNominalPeers(peerNode.nominalPeer, addr, false);
  }

  private static boolean matchesNominalPeers(
      AtomicReference<List<Peer>> nominalPeerRef, FreenetInetAddress addr, boolean strict) {
    List<Peer> localNominalPeer = nominalPeerRef == null ? null : nominalPeerRef.get();
    if (localNominalPeer == null) return false;
    for (Peer peer : localNominalPeer) {
      if (matchesPeerAddress(peer, addr, strict)) return true;
    }
    return false;
  }

  private static boolean matchesPeerAddress(Peer peer, FreenetInetAddress addr, boolean strict) {
    if (peer == null) return false;
    FreenetInetAddress peerAddress = peer.getFreenetAddress();
    if (peerAddress == null) return false;
    if (strict) return peerAddress.equals(addr);
    return peerAddress.laxEquals(addr);
  }

  /**
   * Determines whether traffic to the peer should be throttled based on locality.
   *
   * <p>Throttle decisions are conservative: if the node is configured to throttle local data, or if
   * the peer or its resolved address is missing, this method returns {@code true}. Otherwise, it
   * delegates to {@link PeerNodeReferenceSupport#isValidAddress(InetAddress)}; public addresses are
   * treated as throttled, while local-only addresses are not.
   *
   * @param peer peer whose resolved address should be evaluated; may be {@code null}.
   * @param node the owning node that provides configuration flags for throttling.
   * @return {@code true} when throttling should be applied; {@code false} otherwise.
   */
  static boolean shouldThrottle(Peer peer, Node node) {
    if (node.network().isThrottleLocalData()) return true;
    if (peer == null) return true; // presumably
    InetAddress addr = peer.getAddress(false);
    if (addr == null) return true; // presumably
    return PeerNodeReferenceSupport.isValidAddress(addr);
  }

  /**
   * Parses the detected UDP address from noderef metadata.
   *
   * <p>The method reads the {@code detected.udp} field from the provided {@link SimpleFieldSet}.
   * When present, the value is parsed as a {@code host:port} pair with relaxed hostname handling.
   * Invalid formats or resolution failures are logged and result in {@code null}, leaving the
   * detected peer unchanged.
   *
   * @param metadata noderef metadata container that may hold {@code detected.udp}.
   * @return a parsed {@link Peer} instance, or {@code null} if missing or invalid.
   */
  Peer parseDetectedPeer(SimpleFieldSet metadata) {
    try {
      String detectedUDPString = metadata.get(SFS_KEY_DETECTED_UDP);
      if (detectedUDPString == null) return null;
      return new Peer(detectedUDPString, false);
    } catch (UnknownHostException | PeerParseException e) {
      LOG.error("detected.udp = {} - {}", metadata.get(SFS_KEY_DETECTED_UDP), e, e);
      return null;
    }
  }
}
