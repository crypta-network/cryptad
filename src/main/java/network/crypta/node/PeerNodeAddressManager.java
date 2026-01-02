package network.crypta.node;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.PeerParseException;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Address and handshake-IP management for {@link PeerNode}.
 *
 * <p>This helper owns:
 *
 * <ul>
 *   <li>Handshake IP computation and DNS refresh throttling
 *   <li>Handshake IP selection and filtering
 *   <li>IP matching used by the peer roster
 *   <li>Throttle/local-address decisions based on resolved IP
 * </ul>
 */
final class PeerNodeAddressManager {
  private static final Logger LOG = LoggerFactory.getLogger(PeerNodeAddressManager.class);
  private static final String SFS_KEY_DETECTED_UDP = "detected.udp";
  private static final String STR_NOT_SENDING_HANDSHAKE_TO = "Not sending handshake to ";
  private static final String STR_FOR = " for ";

  private final PeerNode peer;

  /** The last time we attempted to update handshake IPs. Guarded by {@code peer}. */
  private long lastAttemptedHandshakeIPUpdateTime;

  /** Alternator used to pick a single handshake address when multiple are available. */
  private int handshakeIPAlternator;

  PeerNodeAddressManager(PeerNode peer) {
    this.peer = peer;
  }

  void resetHandshakeIpUpdateTimer() {
    synchronized (peer) {
      lastAttemptedHandshakeIPUpdateTime = 0;
    }
  }

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
   * @return the updated, de-duplicated address array
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
      myNominalPeer = peer.nominalPeer.toArray(new Peer[0]);
    }
    if (handleNoNominalPeersCase(localDetectedPeer, myNominalPeer, ignoreHostnames)) return;

    FreenetInetAddress localhost = peer.node.getFreenetLocalhostAddress();
    Peer[] nodePeers = peer.getOutgoingMangler().getPrimaryIPAddress();
    List<Peer> basePeers;
    synchronized (peer) {
      basePeers = new ArrayList<>(peer.nominalPeer);
    }
    PeersBuildResult build =
        prepareLocalPeers(myNominalPeer, localDetectedPeer, nodePeers, localhost, basePeers);
    Peer[] localHandshakeIPs =
        resolveAndDedupe(build.localPeers.toArray(new Peer[0]), ignoreHostnames);
    peer.applyHandshakeIPs(localHandshakeIPs, localDetectedPeer, build.detectedDuplicate);
  }

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

  private boolean addressMatchesNodePeers(FreenetInetAddress addr, Peer[] nodePeers) {
    for (Peer nodePeer : nodePeers) {
      FreenetInetAddress myAddr = nodePeer.getFreenetAddress();
      if (myAddr.equals(addr)) return true;
    }
    return false;
  }

  private boolean isDuplicateLocalDetectedPeer(Peer p, Peer localDetectedPeer) {
    return localDetectedPeer != null && (p != localDetectedPeer) && p.equals(localDetectedPeer);
  }

  private boolean shouldSkipForLocalhost(
      FreenetInetAddress addr, FreenetInetAddress localhost, boolean addedLocalhost) {
    if (!addr.equals(localhost)) return false;
    return addedLocalhost; // skip when we've already added localhost once
  }

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

  private record PeersBuildResult(List<Peer> localPeers, Peer detectedDuplicate) {}

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

  static boolean matchesIP(PeerNode peerNode, FreenetInetAddress addr, boolean strict) {
    synchronized (peerNode) {
      if (strict) return strictMatch(peerNode, addr);
      return nonStrictMatch(peerNode, addr);
    }
  }

  private static boolean strictMatch(PeerNode peerNode, FreenetInetAddress addr) {
    Peer p = peerNode.getPeer();
    if (p != null) {
      FreenetInetAddress a = p.getFreenetAddress();
      if (a != null && a.equals(addr)) return true;
    }
    if (peerNode.nominalPeer != null) {
      for (Peer np : peerNode.nominalPeer) {
        if (np != null) {
          FreenetInetAddress a = np.getFreenetAddress();
          if (a != null && a.equals(addr)) return true;
        }
      }
    }
    return false;
  }

  private static boolean nonStrictMatch(PeerNode peerNode, FreenetInetAddress addr) {
    Peer p = peerNode.getPeer();
    if (p != null) {
      FreenetInetAddress a = p.getFreenetAddress();
      if (a != null && a.laxEquals(addr)) return true;
    }
    if (peerNode.nominalPeer != null) {
      for (Peer np : peerNode.nominalPeer) {
        if (np != null) {
          FreenetInetAddress a = np.getFreenetAddress();
          if (a != null && a.laxEquals(addr)) return true;
        }
      }
    }
    return false;
  }

  static boolean shouldThrottle(Peer peer, Node node) {
    if (node.isThrottleLocalData()) return true;
    if (peer == null) return true; // presumably
    InetAddress addr = peer.getAddress(false);
    if (addr == null) return true; // presumably
    return PeerNodeReferenceSupport.isValidAddress(addr);
  }

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
