package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import network.crypta.io.comm.PeerParseException;
import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PeerConnectorTest {

  @Test
  void connect_whenPeerNotPresent_addsPeer() throws Exception {
    // Arrange
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    PeerManager peerManager = mock(PeerManager.class);
    SimpleFieldSet noderef = mock(SimpleFieldSet.class);
    DarknetPeerNode newPeer = mock(DarknetPeerNode.class);
    PeerNode existingPeer = mock(PeerNode.class);
    byte[] newPeerHash = new byte[] {1, 2, 3};
    byte[] existingPeerHash = new byte[] {9, 9, 9};
    setPeerHash(newPeer, newPeerHash);
    setPeerHash(existingPeer, existingPeerHash);

    FRIEND_TRUST trust = FRIEND_TRUST.NORMAL;
    FRIEND_VISIBILITY visibility = FRIEND_VISIBILITY.YES;

    when(node.network().createNewDarknetNode(noderef, trust, visibility)).thenReturn(newPeer);
    when(peerManager.myPeers()).thenReturn(new PeerNode[] {existingPeer});

    PeerConnector connector = new PeerConnector(node, peerManager);

    // Act
    connector.connect(noderef, trust, visibility);

    // Assert
    verify(peerManager).addPeer(newPeer);
  }

  @Test
  void connect_whenPeerAlreadyPresent_doesNotAddPeer() throws Exception {
    // Arrange
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    PeerManager peerManager = mock(PeerManager.class);
    SimpleFieldSet noderef = mock(SimpleFieldSet.class);
    DarknetPeerNode newPeer = mock(DarknetPeerNode.class);
    PeerNode existingPeer = mock(PeerNode.class);
    byte[] peerHash = new byte[] {4, 5, 6};
    setPeerHash(newPeer, peerHash);
    setPeerHash(existingPeer, peerHash);

    FRIEND_TRUST trust = FRIEND_TRUST.HIGH;
    FRIEND_VISIBILITY visibility = FRIEND_VISIBILITY.NAME_ONLY;

    when(node.network().createNewDarknetNode(noderef, trust, visibility)).thenReturn(newPeer);
    when(peerManager.myPeers()).thenReturn(new PeerNode[] {existingPeer});

    PeerConnector connector = new PeerConnector(node, peerManager);

    // Act
    connector.connect(noderef, trust, visibility);

    // Assert
    verify(peerManager, never()).addPeer(newPeer);
  }

  @Test
  void connect_whenPeerListEmpty_addsPeer() throws Exception {
    // Arrange
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    PeerManager peerManager = mock(PeerManager.class);
    SimpleFieldSet noderef = mock(SimpleFieldSet.class);
    DarknetPeerNode newPeer = mock(DarknetPeerNode.class);
    setPeerHash(newPeer, new byte[] {7, 8, 9});

    FRIEND_TRUST trust = FRIEND_TRUST.LOW;
    FRIEND_VISIBILITY visibility = FRIEND_VISIBILITY.NO;

    when(node.network().createNewDarknetNode(noderef, trust, visibility)).thenReturn(newPeer);
    when(peerManager.myPeers()).thenReturn(new PeerNode[0]);

    PeerConnector connector = new PeerConnector(node, peerManager);

    // Act
    connector.connect(noderef, trust, visibility);

    // Assert
    verify(peerManager).addPeer(newPeer);
  }

  @Test
  void connect_whenCreateNewDarknetNodeThrows_propagatesAndSkipsPeerManager() throws Exception {
    // Arrange
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    PeerManager peerManager = mock(PeerManager.class);
    SimpleFieldSet noderef = mock(SimpleFieldSet.class);

    FRIEND_TRUST trust = FRIEND_TRUST.NORMAL;
    FRIEND_VISIBILITY visibility = FRIEND_VISIBILITY.YES;

    PeerParseException failure = new PeerParseException("bad noderef");
    when(node.network().createNewDarknetNode(noderef, trust, visibility)).thenThrow(failure);

    PeerConnector connector = new PeerConnector(node, peerManager);

    // Act & Assert
    assertThrows(PeerParseException.class, () -> connector.connect(noderef, trust, visibility));

    verifyNoInteractions(peerManager);
  }

  @SuppressWarnings("java:S3011")
  private static void setPeerHash(PeerNode peer, byte[] hash) throws Exception {
    Field field = PeerNode.class.getField("peerECDSAPubKeyHash");
    field.setAccessible(true);
    field.set(peer, hash);
  }
}
