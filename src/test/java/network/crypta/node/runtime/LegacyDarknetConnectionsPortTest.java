package network.crypta.node.runtime;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.Node;
import network.crypta.node.PeerNode;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.runtime.spi.DarknetConnectionPeerSnapshot;
import network.crypta.runtime.spi.DarknetPeerRequiredException;
import network.crypta.runtime.spi.NodeFieldSet;
import network.crypta.runtime.spi.NodeReferenceSnapshot;
import network.crypta.runtime.spi.UnknownPeerException;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LegacyDarknetConnectionsPortTest {

  @Mock private Node node;

  @Mock private NodeNetworkSubsystem network;

  @Mock private DarknetPeerNode peerOne;

  @Mock private DarknetPeerNode peerTwo;

  @Mock private PeerNode nonDarknetPeer;

  @Test
  void listPeers_whenDarknetPeersPresent_returnsDetachedSnapshotsInEncounterOrder() {
    LegacyDarknetConnectionsPort port = newPort();
    when(network.darknetConnections()).thenReturn(new DarknetPeerNode[] {peerOne, peerTwo});
    when(peerOne.getIdentityString()).thenReturn("peer-1");
    when(peerOne.getName()).thenReturn("Alice");
    when(peerOne.getPrivateDarknetCommentNote()).thenReturn("note-one");
    when(peerOne.timeLastConnectionCompleted()).thenReturn(System.currentTimeMillis());
    when(peerOne.getPeerNodeStatus()).thenReturn(0);
    when(peerTwo.getIdentityString()).thenReturn("peer-2");
    when(peerTwo.getName()).thenReturn("Bob");
    when(peerTwo.getPrivateDarknetCommentNote()).thenReturn("note-two");
    when(peerTwo.timeLastConnectionCompleted())
        .thenReturn(System.currentTimeMillis() - TimeUnit.DAYS.toMillis(8));

    List<DarknetConnectionPeerSnapshot> snapshots = port.listPeers();

    assertEquals(
        List.of(
            new DarknetConnectionPeerSnapshot(
                peerOne.hashCode(), "peer-1", "Alice", "note-one", false),
            new DarknetConnectionPeerSnapshot(
                peerTwo.hashCode(), "peer-2", "Bob", "note-two", true)),
        snapshots);
  }

  @Test
  void acceptTransfer_whenIdentityResolvesToDarknetPeer_delegatesToPeer() throws Exception {
    LegacyDarknetConnectionsPort port = newPort();
    when(network.peerNodes()).thenReturn(new PeerNode[] {peerOne});
    when(peerOne.getIdentityString()).thenReturn("peer-1");

    port.acceptTransfer("peer-1", 42L);

    verify(peerOne).acceptTransfer(42L);
  }

  @Test
  void rejectTransfer_whenIdentityResolvesToDarknetPeer_delegatesToPeer() throws Exception {
    LegacyDarknetConnectionsPort port = newPort();
    when(network.peerNodes()).thenReturn(new PeerNode[] {peerOne});
    when(peerOne.getIdentityString()).thenReturn("peer-1");

    port.rejectTransfer("peer-1", 84L);

    verify(peerOne).rejectTransfer(84L);
  }

  @Test
  void acceptTransfer_whenPeerIdentityIsUnknown_throwsUnknownPeerException() {
    LegacyDarknetConnectionsPort port = newPort();
    when(network.peerNodes()).thenReturn(new PeerNode[0]);

    assertThrows(UnknownPeerException.class, () -> port.acceptTransfer("missing-peer", 42L));
  }

  @Test
  void rejectTransfer_whenResolvedPeerIsNotDarknet_throwsDarknetPeerRequiredException() {
    LegacyDarknetConnectionsPort port = newPort();
    when(network.peerNodes()).thenReturn(new PeerNode[] {nonDarknetPeer});
    when(nonDarknetPeer.getIdentityString()).thenReturn("peer-1");

    assertThrows(DarknetPeerRequiredException.class, () -> port.rejectTransfer("peer-1", 84L));
  }

  @Test
  void exportPeerReference_whenPeerHasFullNoderef_returnsDetachedSnapshot() {
    LegacyDarknetConnectionsPort port = newPort();
    SimpleFieldSet noderef = new SimpleFieldSet(true);
    noderef.putSingle("identity", "peer-1");
    SimpleFieldSet physical = new SimpleFieldSet(true);
    physical.putSingle("host", "127.0.0.1");
    noderef.put("physical", physical);
    when(network.darknetConnections()).thenReturn(new DarknetPeerNode[] {peerOne});
    when(peerOne.getFullNoderef()).thenReturn(noderef);

    Optional<NodeReferenceSnapshot> snapshot = port.exportPeerReference(peerOne.hashCode());

    assertEquals(
        Optional.of(
            new NodeReferenceSnapshot(
                new NodeFieldSet(
                    Map.of("identity", "peer-1"),
                    Map.of("physical", new NodeFieldSet(Map.of("host", "127.0.0.1"), Map.of()))))),
        snapshot);
  }

  @Test
  void exportPeerReference_whenSelectionTokenDoesNotResolve_returnsEmptyOptional() {
    LegacyDarknetConnectionsPort port = newPort();
    when(network.darknetConnections()).thenReturn(new DarknetPeerNode[] {peerOne});

    int missingToken =
        peerOne.hashCode() == Integer.MAX_VALUE ? Integer.MIN_VALUE : peerOne.hashCode() + 1;

    assertTrue(port.exportPeerReference(missingToken).isEmpty());
  }

  @Test
  void exportPeerReference_whenPeerHasNoFullNoderef_returnsEmptyOptional() {
    LegacyDarknetConnectionsPort port = newPort();
    when(network.darknetConnections()).thenReturn(new DarknetPeerNode[] {peerOne});
    when(peerOne.getFullNoderef()).thenReturn(null);

    assertTrue(port.exportPeerReference(peerOne.hashCode()).isEmpty());
  }

  private LegacyDarknetConnectionsPort newPort() {
    when(node.network()).thenReturn(network);
    return new LegacyDarknetConnectionsPort(node);
  }
}
