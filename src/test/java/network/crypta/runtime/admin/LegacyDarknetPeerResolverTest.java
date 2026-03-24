package network.crypta.runtime.admin;

import network.crypta.node.DarknetPeerNode;
import network.crypta.node.Node;
import network.crypta.node.PeerNode;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.runtime.spi.DarknetPeerRequiredException;
import network.crypta.runtime.spi.UnknownPeerException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LegacyDarknetPeerResolverTest {

  @Mock private Node node;

  @Mock private NodeNetworkSubsystem network;

  @Mock private PeerNode otherPeer;

  @Mock private PeerNode nonDarknetPeer;

  @Mock private DarknetPeerNode darknetPeer;

  @Test
  void constructor_whenNodeIsNull_throwsNullPointerException() {
    NullPointerException exception =
        assertThrows(NullPointerException.class, () -> new LegacyDarknetPeerResolver(null));

    assertEquals("node", exception.getMessage());
  }

  @Test
  void resolveByIdentity_whenIdentifierIsNull_throwsNullPointerException() {
    LegacyDarknetPeerResolver resolver = new LegacyDarknetPeerResolver(node);

    NullPointerException exception =
        assertThrows(NullPointerException.class, () -> resolver.resolveByIdentity(null));

    assertEquals("nodeIdentifier", exception.getMessage());
  }

  @Test
  void resolveByIdentity_whenDarknetPeerMatches_returnsDarknetPeer() throws Exception {
    LegacyDarknetPeerResolver resolver = newResolver();
    when(network.peerNodes()).thenReturn(new PeerNode[] {otherPeer, darknetPeer});
    when(otherPeer.getIdentityString()).thenReturn("peer-0");
    when(darknetPeer.getIdentityString()).thenReturn("peer-1");

    DarknetPeerNode resolvedPeer = resolver.resolveByIdentity("peer-1");

    assertSame(darknetPeer, resolvedPeer);
  }

  @Test
  void resolveByIdentity_whenMatchingPeerIsNotDarknet_throwsDarknetPeerRequiredException() {
    LegacyDarknetPeerResolver resolver = newResolver();
    when(network.peerNodes()).thenReturn(new PeerNode[] {nonDarknetPeer});
    when(nonDarknetPeer.getIdentityString()).thenReturn("peer-1");

    DarknetPeerRequiredException exception =
        assertThrows(
            DarknetPeerRequiredException.class, () -> resolver.resolveByIdentity("peer-1"));

    assertEquals("peer-1", exception.nodeIdentifier());
  }

  @Test
  void resolveByIdentity_whenNoPeerMatches_throwsUnknownPeerException() {
    LegacyDarknetPeerResolver resolver = newResolver();
    when(network.peerNodes()).thenReturn(new PeerNode[] {otherPeer});
    when(otherPeer.getIdentityString()).thenReturn("peer-0");

    UnknownPeerException exception =
        assertThrows(UnknownPeerException.class, () -> resolver.resolveByIdentity("peer-1"));

    assertEquals("peer-1", exception.nodeIdentifier());
  }

  private LegacyDarknetPeerResolver newResolver() {
    when(node.network()).thenReturn(network);
    return new LegacyDarknetPeerResolver(node);
  }
}
