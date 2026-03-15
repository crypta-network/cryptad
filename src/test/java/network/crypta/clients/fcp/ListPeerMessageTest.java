package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.runtime.spi.PeerPort;
import network.crypta.runtime.spi.PeerSnapshot;
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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ListPeerMessageTest {

  @Mock private FCPConnectionHandler handler;

  @Mock private Node node;

  @Mock private FCPServer server;

  @Mock private RuntimePorts runtimePorts;

  @Mock private PeerPort peerPort;

  @Test
  void constructor_whenIdentifierProvided_removesIdentifierFromFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-1");
    fs.putSingle("NodeIdentifier", "node-123");

    ListPeerMessage message = new ListPeerMessage(fs);

    assertEquals("req-1", message.requestIdentifier);
    assertNull(fs.get("Identifier"));
    assertEquals("node-123", fs.get("NodeIdentifier"));
  }

  @Test
  void run_whenHandlerLacksFullAccess_throwsAccessDenied() {
    when(handler.hasFullAccess()).thenReturn(false);
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-2");
    fs.putSingle("NodeIdentifier", "node-1");
    ListPeerMessage message = new ListPeerMessage(fs);

    MessageInvalidException thrown =
        assertThrows(MessageInvalidException.class, () -> message.run(handler, node));

    assertEquals(ProtocolErrorMessage.ACCESS_DENIED, thrown.protocolCode);
    assertEquals("ListPeer requires full access", thrown.getMessage());
    assertEquals("req-2", thrown.ident);
    assertFalse(thrown.global, "Expected non-global error");
    verify(handler, never()).send(any());
    verifyNoInteractions(server, runtimePorts, peerPort, node);
  }

  @Test
  void run_whenNodeIdentifierMissing_throwsMissingField() {
    when(handler.hasFullAccess()).thenReturn(true);
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-3");
    ListPeerMessage message = new ListPeerMessage(fs);

    MessageInvalidException thrown =
        assertThrows(MessageInvalidException.class, () -> message.run(handler, node));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, thrown.protocolCode);
    assertEquals("Error: NodeIdentifier field missing", thrown.getMessage());
    assertEquals("req-3", thrown.ident);
    assertFalse(thrown.global, "Expected non-global error");
    verify(handler, never()).send(any());
    verifyNoInteractions(server, runtimePorts, peerPort, node);
  }

  @Test
  void run_whenPeerUnknown_sendsUnknownNodeIdentifierMessage() throws Exception {
    when(handler.hasFullAccess()).thenReturn(true);
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.peer()).thenReturn(peerPort);
    when(peerPort.get("node-unknown", true, true))
        .thenThrow(new UnknownPeerException("node-unknown"));
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-4");
    fs.putSingle("NodeIdentifier", "node-unknown");
    ListPeerMessage message = new ListPeerMessage(fs);

    message.run(handler, node);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(captor.capture());
    FCPMessage sent = captor.getValue();
    UnknownNodeIdentifierMessage unknownMsg =
        assertInstanceOf(UnknownNodeIdentifierMessage.class, sent);
    assertEquals("node-unknown", unknownMsg.nodeIdentifier);
    assertEquals("req-4", unknownMsg.messageIdentifier);
  }

  @Test
  void run_whenPeerFound_sendsPeerMessageWithMetadataAndVolatile() throws Exception {
    when(handler.hasFullAccess()).thenReturn(true);
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.peer()).thenReturn(peerPort);
    PeerSnapshot snapshot =
        new PeerSnapshot(
            new network.crypta.runtime.spi.PeerFieldSet(
                java.util.Map.of("identity", "node-42"), java.util.Map.of()));
    when(peerPort.get("node-42", true, true)).thenReturn(snapshot);
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-5");
    fs.putSingle("NodeIdentifier", "node-42");
    ListPeerMessage message = new ListPeerMessage(fs);

    message.run(handler, node);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(captor.capture());
    PeerMessage peerMessage = assertInstanceOf(PeerMessage.class, captor.getValue());
    assertEquals(snapshot, peerMessage.snapshot);
    assertEquals("req-5", peerMessage.messageIdentifier);
  }

  @Test
  void getFieldSet_alwaysReturnsEmptyFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-6");
    ListPeerMessage message = new ListPeerMessage(fs);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertTrue(fieldSet.isEmpty());
  }
}
