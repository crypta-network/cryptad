package network.crypta.node;

import java.util.List;
import java.util.Set;
import network.crypta.support.ByteArrayWrapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SeedPeerQueriesTest {

  @Test
  void getConnectedSeedServerPeersVector_whenExcludeNull_returnsOnlyConnectedSeedServerPeers() {
    PeerManager peerManager = mock(PeerManager.class);
    SeedServerPeerNode connectedSeed = mockSeedServerPeer();
    SeedServerPeerNode disconnectedSeed = mockSeedServerPeer();
    PeerNode regularPeer = mock(PeerNode.class);
    when(connectedSeed.isConnected()).thenReturn(true);
    when(disconnectedSeed.isConnected()).thenReturn(false);
    when(peerManager.myPeers())
        .thenReturn(new PeerNode[] {connectedSeed, disconnectedSeed, regularPeer});
    SeedPeerQueries queries = new SeedPeerQueries(peerManager);

    List<SeedServerPeerNode> result = queries.getConnectedSeedServerPeersVector(null);

    assertEquals(1, result.size());
    assertSame(connectedSeed, result.getFirst());
  }

  @Test
  void getConnectedSeedServerPeersVector_whenExcludeContainsHash_excludesMatchingPeer() {
    PeerManager peerManager = mock(PeerManager.class);
    byte[] hash1 = new byte[] {9, 9, 9};
    byte[] hash2 = new byte[] {8, 8, 8};
    SeedServerPeerNode excludedSeed = mockSeedServerPeer();
    SeedServerPeerNode includedSeed = mockSeedServerPeer();
    doReturn(hash1).when(excludedSeed).getPubKeyHash();
    doReturn(hash2).when(includedSeed).getPubKeyHash();
    when(includedSeed.isConnected()).thenReturn(true);
    when(peerManager.myPeers()).thenReturn(new PeerNode[] {excludedSeed, includedSeed});
    SeedPeerQueries queries = new SeedPeerQueries(peerManager);
    Set<ByteArrayWrapper> exclude = Set.of(new ByteArrayWrapper(hash1));

    List<SeedServerPeerNode> result = queries.getConnectedSeedServerPeersVector(exclude);

    assertEquals(List.of(includedSeed), result);
  }

  @Test
  void getSeedServerPeersVector_whenMixedPeers_returnsAllSeedServerPeersInOrder() {
    PeerManager peerManager = mock(PeerManager.class);
    SeedServerPeerNode firstSeed = mockSeedServerPeer();
    SeedServerPeerNode secondSeed = mockSeedServerPeer();
    PeerNode regularPeer = mock(PeerNode.class);
    when(peerManager.myPeers()).thenReturn(new PeerNode[] {firstSeed, regularPeer, secondSeed});
    SeedPeerQueries queries = new SeedPeerQueries(peerManager);

    List<SeedServerPeerNode> result = queries.getSeedServerPeersVector();

    assertIterableEquals(List.of(firstSeed, secondSeed), result);
  }

  @Test
  void getSeedServerPeersVector_whenNoPeers_returnsEmptyList() {
    PeerManager peerManager = mock(PeerManager.class);
    when(peerManager.myPeers()).thenReturn(new PeerNode[0]);
    SeedPeerQueries queries = new SeedPeerQueries(peerManager);

    List<SeedServerPeerNode> result = queries.getSeedServerPeersVector();

    assertEquals(List.of(), result);
  }

  private static SeedServerPeerNode mockSeedServerPeer() {
    return mock(SeedServerPeerNode.class);
  }
}
