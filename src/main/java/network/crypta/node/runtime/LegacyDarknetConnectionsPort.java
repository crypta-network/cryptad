package network.crypta.node.runtime;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.Node;
import network.crypta.node.PeerManager;
import network.crypta.node.PeerNode;
import network.crypta.runtime.spi.DarknetConnectionPeerSnapshot;
import network.crypta.runtime.spi.DarknetConnectionsPort;
import network.crypta.runtime.spi.DarknetPeerRequiredException;
import network.crypta.runtime.spi.NodeFieldSet;
import network.crypta.runtime.spi.NodeReferenceSnapshot;
import network.crypta.runtime.spi.UnknownPeerException;
import network.crypta.support.SimpleFieldSet;

/**
 * Adapts the legacy darknet friends-page peer traversal to the runtime SPI companion port.
 *
 * <p>This bridge preserves the current friends-page hash-token scheme inside the daemon root module
 * while exposing only detached peer identity, display-name, private-note, remove-policy, noderef,
 * and transfer-decision data to the HTTP layer. It is intentionally narrow and exists only to
 * migrate the remaining legacy darknet friends-page actions away from direct live-daemon peer
 * access.
 *
 * <p>The adapter reads the live peer list on demand and immediately converts it into detached
 * values. That means it does not cache peer objects between requests and does not try to hide
 * normal race conditions such as a peer disappearing after the page renders. Its job is narrower:
 * preserve encounter order, preserve the legacy selection token behavior, and provide just enough
 * data for the migrated HTTP paths to act on the intended peer without traversing daemon internals
 * directly.
 */
final class LegacyDarknetConnectionsPort implements DarknetConnectionsPort {
  /** Age threshold after which the legacy friends page skips the force-remove confirmation. */
  private static final long REMOVE_WITHOUT_FORCE_AGE_MILLIS = TimeUnit.DAYS.toMillis(7);

  /** Live daemon node whose darknet peer inventory backs this adapter. */
  private final Node node;

  /**
   * Creates a legacy-backed companion port for the darknet friends page.
   *
   * @param node live daemon node that exposes the current darknet peers
   */
  LegacyDarknetConnectionsPort(Node node) {
    this.node = Objects.requireNonNull(node);
  }

  /** {@inheritDoc} */
  @Override
  public List<DarknetConnectionPeerSnapshot> listPeers() {
    DarknetPeerNode[] peers = node.network().darknetConnections();
    List<DarknetConnectionPeerSnapshot> snapshots = new ArrayList<>(peers.length);
    long removableWithoutForceCutoff = System.currentTimeMillis() - REMOVE_WITHOUT_FORCE_AGE_MILLIS;
    for (DarknetPeerNode peer : peers) {
      snapshots.add(
          new DarknetConnectionPeerSnapshot(
              peer.hashCode(),
              peer.getIdentityString(),
              Objects.requireNonNullElse(peer.getName(), ""),
              Objects.requireNonNullElse(peer.getPrivateDarknetCommentNote(), ""),
              removableWithoutForce(peer, removableWithoutForceCutoff)));
    }
    return List.copyOf(snapshots);
  }

  /** {@inheritDoc} */
  @Override
  public Optional<NodeReferenceSnapshot> exportPeerReference(int selectionToken) {
    for (DarknetPeerNode peer : node.network().darknetConnections()) {
      if (peer.hashCode() != selectionToken) {
        continue;
      }

      SimpleFieldSet fieldSet = peer.getFullNoderef();
      if (fieldSet == null) {
        return Optional.empty();
      }
      return Optional.of(new NodeReferenceSnapshot(toNodeFieldSet(fieldSet)));
    }
    return Optional.empty();
  }

  /** {@inheritDoc} */
  @Override
  public void acceptTransfer(String nodeIdentifier, long transferId)
      throws UnknownPeerException, DarknetPeerRequiredException {
    resolveDarknetPeerByIdentity(nodeIdentifier).acceptTransfer(transferId);
  }

  /** {@inheritDoc} */
  @Override
  public void rejectTransfer(String nodeIdentifier, long transferId)
      throws UnknownPeerException, DarknetPeerRequiredException {
    resolveDarknetPeerByIdentity(nodeIdentifier).rejectTransfer(transferId);
  }

  private static boolean removableWithoutForce(
      DarknetPeerNode peer, long removableWithoutForceCutoff) {
    return peer.timeLastConnectionCompleted() < removableWithoutForceCutoff
        || peer.getPeerNodeStatus() == PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED;
  }

  private DarknetPeerNode resolveDarknetPeerByIdentity(String nodeIdentifier)
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

  /**
   * Converts one legacy {@link SimpleFieldSet} noderef tree into the detached SPI field-set model.
   *
   * <p>The conversion keeps direct values and direct subsets in encounter order so later HTTP
   * serialization produces stable output. Empty subsets are dropped because the detached
   * representation does not need to retain placeholder branches that carry no values.
   *
   * @param fieldSet legacy noderef field-set tree exported by the daemon
   * @return detached field-set tree with the same direct values and non-empty subsets
   */
  private static NodeFieldSet toNodeFieldSet(SimpleFieldSet fieldSet) {
    if (fieldSet.isEmpty()) {
      return NodeFieldSet.empty();
    }

    LinkedHashMap<String, String> directValues = new LinkedHashMap<>(fieldSet.directKeyValues());
    LinkedHashMap<String, NodeFieldSet> directSubsets = new LinkedHashMap<>();
    for (Map.Entry<String, SimpleFieldSet> entry : fieldSet.directSubsets().entrySet()) {
      NodeFieldSet subset = toNodeFieldSet(entry.getValue());
      if (!subset.isEmpty()) {
        directSubsets.put(entry.getKey(), subset);
      }
    }
    return new NodeFieldSet(directValues, directSubsets);
  }
}
