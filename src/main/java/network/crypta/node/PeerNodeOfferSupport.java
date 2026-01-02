package network.crypta.node;

import network.crypta.crypt.HMAC;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.keys.Key;

/** Handles authenticated key offers for {@link PeerNode}. */
final class PeerNodeOfferSupport {
  private final PeerNode peer;

  PeerNodeOfferSupport(PeerNode peer) {
    this.peer = peer;
  }

  void offer(Key key) {
    byte[] keyBytes = key.getFullKey();
    // Note: authenticator size is 32 bytes for HMAC-SHA256.
    byte[] authenticator =
        HMAC.macWithSHA256(peer.node.getFailureTable().offerAuthenticatorKey, keyBytes);
    Message msg = DMT.createFNPOfferKey(key, authenticator);
    try {
      peer.sendAsync(msg, null, peer.node.getNodeStats().sendOffersCtr);
    } catch (NotConnectedException _) {
      // Ignore
    }
  }
}
