package network.crypta.node;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.Peer;
import network.crypta.support.transport.ip.IPUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Computes the node's externally reachable {@link Peer} endpoints.
 *
 * <p>This component combines IP addresses detected by {@link NodeIPDetector} with the local listen
 * port from {@link NodeCrypto}, then augments the result with per-connection observations reported
 * by existing peers. The outcome is a set of candidate address/port pairs that other nodes may use
 * to contact this node. Results are cached for reuse and for ARK publishing.
 *
 * <p>Side effects: none beyond updating the cached {@code lastPeers} used by {@link
 * #getPrimaryPeers()}.
 *
 * @author toad
 */
public class NodeIPPortDetector {
  private static final Logger LOG = LoggerFactory.getLogger(NodeIPPortDetector.class);

  /** Determines the node's primary IP address; does not infer the port. */
  final NodeIPDetector ipDetector;

  /** Provides the node's listen port and access to the current peer set. */
  final NodeCrypto crypto;

  /** ARK inserter. */
  private final NodeARKInserter arkPutter;

  /** Last computed candidate peers (address + port). May be {@code null} until detection runs. */
  Peer[] lastPeers;

  NodeIPPortDetector(Node node, NodeIPDetector ipDetector, NodeCrypto crypto, boolean enableARKs) {
    this.ipDetector = ipDetector;
    this.crypto = crypto;
    arkPutter = new NodeARKInserter(node, crypto, this, enableARKs);
    ipDetector.addPortDetector(this);
  }

  /**
   * Combines addresses from {@link NodeIPDetector} with binding constraints.
   *
   * <p>If the node is bound to a real Internet address, only that address is returned (multihomed
   * hosts often require a single explicit bind). Otherwise, primary addresses are detected from the
   * environment. Returned addresses do not include ports.
   */
  FreenetInetAddress[] detectPrimaryIPAddress() {
    FreenetInetAddress addr = crypto.getBindTo();
    if (addr.isRealInternetAddress(false, true, ipDetector.allowBindToLocalhost)) {
      // Bound to a real Internet address: prefer only this address.
      // Common on multi-homed hosts where a single IP should be advertised.
      return new FreenetInetAddress[] {addr};
    }
    return ipDetector.detectPrimaryIPAddress(!crypto.getConfig().includeLocalAddressesInNoderefs());
  }

  /**
   * Detects candidate peers (address + port) for this node.
   *
   * <p>Starts from the primary addresses, pairs them with the local listen port, and folds in
   * address/port pairs observed by connected peers. When behind a NAT, observed ports may differ
   * from the local listen port. Symmetric NATs can yield inconsistent ports across connections.
   */
  Peer[] detectPrimaryPeers() {
    List<Peer> addresses = new ArrayList<>();
    FreenetInetAddress[] addrs = detectPrimaryIPAddress();
    addPrimaryPeers(addresses, addrs);

    PeerNode[] peerList = crypto.getPeerNodes();
    if (peerList != null) {
      Map<Peer, Integer> countsByPeer = countDetectedPeers(peerList);
      updateAddressesFromCounts(addresses, countsByPeer, addrs.length);
    }

    lastPeers = addresses.toArray(new Peer[0]);
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Computed primary peers for port {}: {}",
          crypto.getPortNumber(),
          Arrays.toString(lastPeers));
    }
    return lastPeers;
  }

  private void addPrimaryPeers(List<Peer> out, FreenetInetAddress[] addrs) {
    for (FreenetInetAddress addr : addrs) {
      out.add(new Peer(addr, crypto.getPortNumber()));
      if (LOG.isDebugEnabled()) {
        LOG.debug("Add candidate address {}", addr);
      }
    }
  }

  private Map<Peer, Integer> countDetectedPeers(PeerNode[] peerList) {
    Map<Peer, Integer> countsByPeer = new HashMap<>();
    for (PeerNode pn : peerList) {
      Peer p = pn.getRemoteDetectedPeer();
      if ((p == null) || p.isNull() || !IPUtil.isValidAddress(p.getAddress(true), false)) continue;
      if (LOG.isDebugEnabled()) {
        LOG.debug("Peer {} reports our endpoint as {}", pn.getPeer(), p);
      }
      if (countsByPeer.containsKey(p)) {
        countsByPeer.put(p, countsByPeer.get(p) + 1);
      } else {
        countsByPeer.put(p, 1);
      }
    }
    return countsByPeer;
  }

  private void updateAddressesFromCounts(
      List<Peer> addresses, Map<Peer, Integer> countsByPeer, int addrsLength) {
    if (countsByPeer.size() == 1) {
      handleSingleCount(addresses, countsByPeer);
    } else if (countsByPeer.size() > 1) {
      handleMultipleCounts(addresses, countsByPeer, addrsLength);
    }
  }

  private void handleSingleCount(List<Peer> addresses, Map<Peer, Integer> countsByPeer) {
    Iterator<Peer> it = countsByPeer.keySet().iterator();
    Peer p = it.next();
    LOG.debug("Consensus on detected peer {}", p);
    addIfAbsent(addresses, p);
  }

  private void handleMultipleCounts(
      List<Peer> addresses, Map<Peer, Integer> countsByPeer, int addrsLength) {
    TopTwo top = findTopTwo(countsByPeer);
    if (top.best == null) return;
    if (!((top.bestPopularity > 1) || (addrsLength == 0))) return;

    addIfAbsentWithLog(
        addresses, top.best, "Selected best peer {} (popularity={})", top.bestPopularity);

    if ((top.secondBest == null) || (top.secondBestPopularity <= 1)) return;

    addIfAbsentWithLog(
        addresses,
        top.secondBest,
        "Selected second best peer {} (popularity={})",
        top.secondBestPopularity);

    if (top.best.getAddress().equals(top.secondBest.getAddress()) && top.bestPopularity == 1) {
      LOG.error("Possible symmetric NAT detected; connections may be unreliable.");
      ipDetector.setMaybeSymmetric();

      Peer p = new Peer(top.best.getFreenetAddress(), crypto.getPortNumber());
      addIfAbsent(addresses, p);
    }
  }

  private void addIfAbsent(List<Peer> addresses, Peer p) {
    if (!addresses.contains(p)) {
      addresses.add(p);
    }
  }

  private void addIfAbsentWithLog(List<Peer> addresses, Peer p, String msg, int popularity) {
    if (!addresses.contains(p)) {
      LOG.info(msg, p, popularity);
      addresses.add(p);
    }
  }

  private TopTwo findTopTwo(Map<Peer, Integer> countsByPeer) {
    Peer best = null;
    Peer secondBest = null;
    int bestPopularity = 0;
    int secondBestPopularity = 0;
    for (Map.Entry<Peer, Integer> entry : countsByPeer.entrySet()) {
      Peer cur = entry.getKey();
      int curPop = entry.getValue();
      LOG.info("Counted detected peer {} popularity {}", cur, curPop);
      if (curPop >= bestPopularity) {
        secondBestPopularity = bestPopularity;
        bestPopularity = curPop;
        secondBest = best;
        best = cur;
      }
    }
    return new TopTwo(best, bestPopularity, secondBest, secondBestPopularity);
  }

  private record TopTwo(Peer best, int bestPopularity, Peer secondBest, int secondBestPopularity) {}

  void update() {
    arkPutter.update();
  }

  void startARK() {
    arkPutter.start();
  }

  /**
   * Returns candidate peers for this node.
   *
   * <p>If no prior detection has run, this method triggers detection. The returned array is never
   * {@code null}; it may be empty when no suitable address is detected.
   *
   * @return array of {@link Peer} entries representing address/port pairs
   */
  public Peer[] getPrimaryPeers() {
    if (lastPeers == null) return detectPrimaryPeers();
    return lastPeers;
  }

  /**
   * Checks whether the given address is part of the current primary address set.
   *
   * <p>Ports are not considered. Detection runs if no cached result exists.
   *
   * @param addr address to test; {@code null} is treated as absent
   * @return {@code true} if present in the most recent detection result; otherwise {@code false}
   */
  public boolean includes(FreenetInetAddress addr) {
    FreenetInetAddress[] a = detectPrimaryIPAddress();
    for (FreenetInetAddress ai : a) if (ai.equals(addr)) return true;
    return false;
  }
}
