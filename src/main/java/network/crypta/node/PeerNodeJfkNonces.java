package network.crypta.node;

import java.security.MessageDigest;
import java.util.LinkedList;
import network.crypta.crypt.SHA256;

/**
 * Tracks recently sent JFK initiator nonces for replay/validation during handshake.
 *
 * <p>The initiator sends {@code SHA256(nonce)} on the wire and must later match the responder's
 * echo against the original nonce value. This helper retains a bounded list of original nonces and
 * provides lookup by hashed value.
 */
final class PeerNodeJfkNonces {
  private final LinkedList<byte[]> nonces = new LinkedList<>();

  void rememberNonce(byte[] nonce, int maxNonces) {
    synchronized (nonces) {
      nonces.add(nonce);
      if (nonces.size() > maxNonces) nonces.removeFirst();
    }
  }

  byte[] findOriginalNonceByHash(byte[] nonceHash) {
    synchronized (nonces) {
      for (byte[] nonce : nonces) {
        if (MessageDigest.isEqual(nonceHash, SHA256.digest(nonce))) return nonce;
      }
    }
    return null;
  }

  void clear() {
    synchronized (nonces) {
      nonces.clear();
    }
  }
}
