package network.crypta.node.runtime;

import java.util.Objects;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.Node;
import network.crypta.node.PeerNode;
import network.crypta.runtime.spi.DarknetPeerRequiredException;
import network.crypta.runtime.spi.UnknownPeerException;

/**
 * Resolves detached darknet peer identities against the live daemon peer list.
 *
 * <p>This helper keeps the legacy identity-to-peer lookup used by the friends-page companion
 * adapters in one place without widening the runtime SPI surface or introducing a broader daemon
 * refactor. It resolves by exact peer identity string and preserves the daemon's distinction
 * between a missing peer and a resolved non-darknet peer.
 *
 * <p>The resolver is intentionally request-scoped and stateless apart from the daemon root
 * reference. It does not cache peers between calls, so callers see the current roster at the time
 * they attempt the operation rather than a stale snapshot.
 */
final class LegacyDarknetPeerResolver {
  /** Live daemon root whose current peer roster is searched for detached identities. */
  private final Node node;

  /**
   * Creates a resolver rooted at the current daemon instance.
   *
   * @param node live daemon root used for peer-list lookup
   */
  LegacyDarknetPeerResolver(Node node) {
    this.node = Objects.requireNonNull(node, "node");
  }

  /**
   * Resolves one detached peer identity to a live darknet peer.
   *
   * <p>The lookup walks the current daemon peer list and matches on the exact identity string used
   * in detached runtime snapshots. If the identity resolves to a non-darknet peer, the caller gets
   * a distinct exception so higher layers can preserve the daemon's existing error semantics.
   *
   * @param nodeIdentifier detached peer identity captured from the runtime snapshot
   * @return live darknet peer instance that corresponds to the supplied detached identity
   * @throws UnknownPeerException if no current peer matches the supplied detached identity
   * @throws DarknetPeerRequiredException if the identity resolves to a non-darknet peer
   */
  DarknetPeerNode resolveByIdentity(String nodeIdentifier)
      throws UnknownPeerException, DarknetPeerRequiredException {
    Objects.requireNonNull(nodeIdentifier, "nodeIdentifier");
    for (PeerNode peer : node.network().peerNodes()) {
      if (!nodeIdentifier.equals(peer.getIdentityString())) {
        continue;
      }
      if (peer instanceof DarknetPeerNode darknetPeer) {
        return darknetPeer;
      }
      throw new DarknetPeerRequiredException(nodeIdentifier);
    }
    throw new UnknownPeerException(nodeIdentifier);
  }
}
