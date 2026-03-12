package network.crypta.node;

import network.crypta.crypt.HMAC;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.keys.Key;

/**
 * Handles authenticated key offers for {@link PeerNode}.
 *
 * <p>This helper builds and transmits the offer message used by the peer-to-peer key-offer
 * protocol. It computes an HMAC authenticator over the offered key, constructs the {@code
 * FNPOfferKey} message, and hands it to the peer transport for asynchronous delivery. Callers use
 * this component when they need to advertise a key to a specific peer before any fetch begins.
 *
 * <p>The class is intentionally small and delegates all state and policy decisions to the owning
 * {@link PeerNode} and its {@link FailureTable} and {@link NodeStats}. It does not maintain mutable
 * state of its own and performs no retries; if the peer disconnects, the offer is simply skipped.
 * Thread-safety follows the thread-safety of the associated {@code PeerNode} and its collaborators.
 *
 * <p><strong>Responsibilities:</strong>
 *
 * <ul>
 *   <li>Compute an HMAC-SHA256 authenticator over the offered key bytes.
 *   <li>Create a correctly typed {@link Message} for the offer.
 *   <li>Dispatch the offer asynchronously and ignore disconnect races.
 * </ul>
 *
 * @see PeerNode
 * @see DMT#createFNPOfferKey(Key, byte[])
 */
final class PeerNodeOfferSupport {
  /** Owning peer providing transport, stats counters, and authenticator material. */
  private final PeerNode peer;

  /**
   * Creates a new helper bound to a specific peer.
   *
   * <p>The provided {@link PeerNode} supplies the HMAC key, accounting counters, and transport used
   * when sending offers. This class stores only a reference to the peer and does not validate
   * connection state at construction time. It is expected that the peer reference remains valid for
   * the lifetime of this helper.
   *
   * @param peer owning peer used for transport access and offer authentication; must be non-null
   */
  PeerNodeOfferSupport(PeerNode peer) {
    this.peer = peer;
  }

  /**
   * Offers a key to the remote peer using an authenticated offer message.
   *
   * <p>This method serializes the key into its full binary form, computes an HMAC-SHA256
   * authenticator using the node's offer-authenticator key, and sends a {@code FNPOfferKey} message
   * asynchronously. The send is fire-and-forget; if the peer disconnects concurrently, the {@link
   * NotConnectedException} is swallowed and no retry is attempted. The method performs no
   * deduplication and is not idempotent at the protocol level; repeated calls send repeated offers
   * with the same authenticator bytes for the same key.
   *
   * <pre>{@code
   * PeerNodeOfferSupport support = new PeerNodeOfferSupport(peer);
   * support.offer(key);
   * }</pre>
   *
   * @param key offered key whose full bytes are authenticated; must be non-null
   * @throws NullPointerException if {@code key} is {@code null}
   */
  void offer(Key key) {
    byte[] keyBytes = key.getFullKey();
    // Note: authenticator size is 32 bytes for HMAC-SHA256.
    byte[] authenticator =
        HMAC.macWithSHA256(peer.node.routing().failureTable().offerAuthenticatorKey, keyBytes);
    Message msg = DMT.createFNPOfferKey(key, authenticator);
    try {
      peer.transport().sendAsync(msg, null, peer.node.network().stats().sendOffersCtr);
    } catch (NotConnectedException _) {
      // Ignore
    }
  }
}
