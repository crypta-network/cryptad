package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import network.crypta.node.Node;
import network.crypta.node.PeerNode;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class RemovePeerTest {

  @Mock private FCPConnectionHandler handler;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private PeerNode peerNode;

  @Test
  void constructor_removesIdentifierFromFieldSet() {
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    fieldSet.putSingle("Identifier", "id-123");
    fieldSet.putSingle("NodeIdentifier", "node-abc");

    RemovePeer removePeer = new RemovePeer(fieldSet);

    assertNull(fieldSet.get("Identifier"));
    assertEquals("node-abc", fieldSet.get("NodeIdentifier"));
    assertEquals("id-123", removePeer.messageIdentifier);
    assertSame(fieldSet, removePeer.fs);
  }

  @Test
  void getName_returnsRemovePeer() {
    RemovePeer removePeer = new RemovePeer(buildFieldSet("node-abc", "id-1"));

    assertEquals("RemovePeer", removePeer.getName());
  }

  @Test
  void getFieldSet_returnsEmptyFieldSet() {
    RemovePeer removePeer = new RemovePeer(buildFieldSet("node-abc", "id-1"));

    SimpleFieldSet result = removePeer.getFieldSet();

    assertNotNull(result);
    assertNull(result.get("Identifier"));
    assertNull(result.get("NodeIdentifier"));
  }

  @Test
  void run_whenNoFullAccess_throwsAccessDenied() {
    when(handler.hasFullAccess()).thenReturn(false);
    RemovePeer removePeer = new RemovePeer(buildFieldSet("node-abc", "id-123"));

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> removePeer.run(handler, node));

    assertEquals(ProtocolErrorMessage.ACCESS_DENIED, exception.protocolCode);
    assertEquals("RemovePeer requires full access", exception.getMessage());
    assertEquals("id-123", exception.ident);
    assertFalse(exception.global);
    verify(handler).hasFullAccess();
    verifyNoMoreInteractions(handler);
    verifyNoMoreInteractions(node);
  }

  @Test
  void run_whenNodeIdentifierMissing_throwsMissingField() {
    when(handler.hasFullAccess()).thenReturn(true);
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    fieldSet.putSingle("Identifier", "id-456");
    RemovePeer removePeer = new RemovePeer(fieldSet);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> removePeer.run(handler, node));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode);
    assertEquals("Error: NodeIdentifier field missing", exception.getMessage());
    assertEquals("id-456", exception.ident);
    assertFalse(exception.global);
    verify(handler).hasFullAccess();
    verifyNoMoreInteractions(handler);
    verifyNoMoreInteractions(node);
  }

  @Test
  void run_whenPeerUnknown_sendsUnknownNodeIdentifierMessage() throws MessageInvalidException {
    when(handler.hasFullAccess()).thenReturn(true);
    network.crypta.node.subsystem.NodeNetworkSubsystem network =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.getPeerNode("node-missing")).thenReturn(null);
    RemovePeer removePeer = new RemovePeer(buildFieldSet("node-missing", "id-789"));

    removePeer.run(handler, node);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).hasFullAccess();
    verify(network).getPeerNode("node-missing");
    verify(handler).send(captor.capture());
    verify(network, never()).removePeerConnection(any(PeerNode.class));
    verifyNoMoreInteractions(handler, node);

    FCPMessage sent = captor.getValue();
    assertInstanceOf(UnknownNodeIdentifierMessage.class, sent);
    SimpleFieldSet sentFields = sent.getFieldSet();
    assertEquals("node-missing", sentFields.get("NodeIdentifier"));
    assertEquals("id-789", sentFields.get("Identifier"));
  }

  @Test
  void run_whenPeerPresent_removesPeerAndSendsPeerRemoved() throws MessageInvalidException {
    when(handler.hasFullAccess()).thenReturn(true);
    network.crypta.node.subsystem.NodeNetworkSubsystem network =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.getPeerNode("node-123")).thenReturn(peerNode);
    when(peerNode.getIdentityString()).thenReturn("identity-xyz");
    RemovePeer removePeer = new RemovePeer(buildFieldSet("node-123", "id-555"));

    removePeer.run(handler, node);

    verify(handler).hasFullAccess();
    verify(network).getPeerNode("node-123");
    verify(peerNode).getIdentityString();
    verify(network).removePeerConnection(peerNode);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(captor.capture());
    verifyNoMoreInteractions(handler, node, peerNode);

    FCPMessage sent = captor.getValue();
    assertInstanceOf(PeerRemoved.class, sent);
    SimpleFieldSet sentFields = sent.getFieldSet();
    assertEquals("identity-xyz", sentFields.get("Identity"));
    assertEquals("node-123", sentFields.get("NodeIdentifier"));
    assertEquals("id-555", sentFields.get("Identifier"));
  }

  private SimpleFieldSet buildFieldSet(String nodeIdentifier, String identifier) {
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    fieldSet.putSingle("Identifier", identifier);
    fieldSet.putSingle("NodeIdentifier", nodeIdentifier);
    return fieldSet;
  }
}
