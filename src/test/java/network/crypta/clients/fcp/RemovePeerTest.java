package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.runtime.spi.PeerPort;
import network.crypta.runtime.spi.RemovedPeerSnapshot;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.runtime.spi.UnknownPeerException;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class RemovePeerTest {

  @Mock private FCPConnectionHandler handler;

  @Mock private Node node;

  @Mock private FCPServer server;

  @Mock private RuntimePorts runtimePorts;

  @Mock private PeerPort peerPort;

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
        assertThrows(MessageInvalidException.class, () -> removePeer.run(handler));

    assertEquals(ProtocolErrorMessage.ACCESS_DENIED, exception.protocolCode);
    assertEquals("RemovePeer requires full access", exception.getMessage());
    assertEquals("id-123", exception.ident);
    assertFalse(exception.global);
    verifyNoInteractions(server, runtimePorts, peerPort, node);
  }

  @Test
  void run_whenNodeIdentifierMissing_throwsMissingField() {
    when(handler.hasFullAccess()).thenReturn(true);
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    fieldSet.putSingle("Identifier", "id-456");
    RemovePeer removePeer = new RemovePeer(fieldSet);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> removePeer.run(handler));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode);
    assertEquals("Error: NodeIdentifier field missing", exception.getMessage());
    assertEquals("id-456", exception.ident);
    assertFalse(exception.global);
    verifyNoInteractions(server, runtimePorts, peerPort, node);
  }

  @Test
  void run_whenPeerUnknown_sendsUnknownNodeIdentifierMessage() throws Exception {
    when(handler.hasFullAccess()).thenReturn(true);
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.peer()).thenReturn(peerPort);
    when(peerPort.remove("node-missing")).thenThrow(new UnknownPeerException("node-missing"));
    RemovePeer removePeer = new RemovePeer(buildFieldSet("node-missing", "id-789"));

    removePeer.run(handler);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(captor.capture());

    FCPMessage sent = captor.getValue();
    assertInstanceOf(UnknownNodeIdentifierMessage.class, sent);
    SimpleFieldSet sentFields = sent.getFieldSet();
    assertEquals("node-missing", sentFields.get("NodeIdentifier"));
    assertEquals("id-789", sentFields.get("Identifier"));
  }

  @Test
  void run_whenPeerPresent_removesPeerAndSendsPeerRemoved() throws Exception {
    when(handler.hasFullAccess()).thenReturn(true);
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.peer()).thenReturn(peerPort);
    when(peerPort.remove("node-123"))
        .thenReturn(new RemovedPeerSnapshot("identity-xyz", "node-123"));
    RemovePeer removePeer = new RemovePeer(buildFieldSet("node-123", "id-555"));

    removePeer.run(handler);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(captor.capture());

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
