package network.crypta.node;

import java.util.Arrays;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import network.crypta.support.SimpleFieldSet;

/** Handles creating and adding darknet peers from serialized references. */
public class PeerConnector {
  private final Node node;
  private final PeerManager peerManager;

  PeerConnector(Node node, PeerManager peerManager) {
    this.node = node;
    this.peerManager = peerManager;
  }

  /**
   * Connects to a darknet peer from its serialized reference.
   *
   * <p>Creates a new {@link DarknetPeerNode} from the provided field set and adds it if a peer with
   * the same public key hash is not already present.
   *
   * @throws FSParseException If the field set cannot be parsed.
   * @throws PeerParseException If the noderef is syntactically invalid.
   * @throws ReferenceSignatureVerificationException If the reference signature fails verification.
   * @throws PeerTooOldException If the peer is older than the supported minimum.
   */
  public void connect(SimpleFieldSet noderef, FRIEND_TRUST trust, FRIEND_VISIBILITY visibility)
      throws FSParseException,
          PeerParseException,
          ReferenceSignatureVerificationException,
          PeerTooOldException {
    PeerNode pn = node.createNewDarknetNode(noderef, trust, visibility);
    PeerNode[] peerList = peerManager.myPeers();
    for (PeerNode mp : peerList) {
      if (Arrays.equals(mp.peerECDSAPubKeyHash, pn.peerECDSAPubKeyHash)) return;
    }
    peerManager.addPeer(pn);
  }
}
