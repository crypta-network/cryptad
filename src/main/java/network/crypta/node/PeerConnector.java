package network.crypta.node;

import java.util.Arrays;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.support.SimpleFieldSet;

/**
 * Creates and registers darknet peers from serialized references.
 *
 * <p>This helper translates a {@link SimpleFieldSet} noderef into a {@link DarknetPeerNode} and
 * adds it to the owning {@link PeerManager} when the peer is not already present. It is a small
 * coordination layer that keeps the reference parsing, duplicate detection, and registration steps
 * in one place so that callers do not need to know the peer list internals. Typical use is during
 * UI-driven friend adding, configuration import, or any path that receives a noderef and needs to
 * enroll it in the darknet peer set.
 *
 * <p>The duplicate check is based on the peer's ECDSA public-key hash, which is stable for the
 * lifetime of a reference. If an existing peer shares that hash, the method performs no mutation
 * and returns immediately. This class is intentionally state-light: it stores references to the
 * owning {@link Node} and {@link PeerManager} but keeps no additional cache or lifecycle state.
 *
 * <p>Thread-safety depends on the {@link PeerManager} and {@link Node} implementations. This class
 * performs a read of {@link PeerManager#myPeers()} followed by a conditional {@link
 * PeerManager#addPeer(PeerNode)}; callers should ensure appropriate synchronization if peer list
 * mutations can occur concurrently.
 *
 * <ul>
 *   <li>Responsibilities: build a peer instance, detect duplicates, and register new peers.
 *   <li>Notable behavior: duplicates are identified by public-key hash, not by noderef bytes.
 * </ul>
 */
public class PeerConnector {
  private final Node node;
  private final PeerManager peerManager;

  PeerConnector(Node node, PeerManager peerManager) {
    this.node = node;
    this.peerManager = peerManager;
  }

  /**
   * Connects to a darknet peer described by the provided noderef.
   *
   * <p>This method parses the {@code noderef} into a new {@link DarknetPeerNode} using the supplied
   * trust and visibility settings, then checks the current peer list for an existing peer with the
   * same ECDSA public-key hash. If a duplicate is found, the method performs no further work and
   * returns without modifying the peer manager. Otherwise, it registers the newly created peer.
   *
   * <p>The call is idempotent with respect to the peer's public-key hash: repeated calls with
   * references that resolve to the same hash will not create additional peers. The method does not
   * validate or normalize the {@link SimpleFieldSet} beyond what {@link
   * NodeNetworkSubsystem#createNewDarknetNode} performs, and it does not retry on failures.
   *
   * <pre>{@code
   * PeerConnector connector = new PeerConnector(node, peerManager);
   * connector.connect(noderef, FRIEND_TRUST.NORMAL, FRIEND_VISIBILITY.YES);
   * }</pre>
   *
   * @param noderef serialized noderef field set for the peer; must be parseable and non-null.
   * @param trust trust level to assign for routing and policy decisions; must be non-null.
   * @param visibility visibility preference to store for the peer; must be non-null.
   * @throws FSParseException if the noderef fields cannot be parsed into required values.
   * @throws PeerParseException if the noderef is syntactically invalid or inconsistent.
   * @throws ReferenceSignatureVerificationException if a noderef signature is present but invalid.
   * @throws PeerTooOldException if the peer's version is older than the supported minimum.
   */
  public void connect(SimpleFieldSet noderef, FRIEND_TRUST trust, FRIEND_VISIBILITY visibility)
      throws FSParseException,
          PeerParseException,
          ReferenceSignatureVerificationException,
          PeerTooOldException {
    PeerNode pn = node.network().createNewDarknetNode(noderef, trust, visibility);
    PeerNode[] peerList = peerManager.myPeers();
    for (PeerNode mp : peerList) {
      if (Arrays.equals(mp.peerECDSAPubKeyHash, pn.peerECDSAPubKeyHash)) return;
    }
    peerManager.addPeer(pn);
  }
}
