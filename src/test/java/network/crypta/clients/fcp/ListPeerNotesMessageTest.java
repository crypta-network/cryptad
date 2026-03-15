package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.runtime.spi.DarknetPeerRequiredException;
import network.crypta.runtime.spi.PeerPort;
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
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ListPeerNotesMessageTest {

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

    ListPeerNotesMessage message = new ListPeerNotesMessage(fs);

    assertEquals("req-1", message.requestIdentifier);
    assertNull(fs.get("Identifier"));
    assertEquals("node-123", fs.get("NodeIdentifier"));
  }

  @Test
  void getFieldSet_alwaysReturnsEmptyFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-2");

    ListPeerNotesMessage message = new ListPeerNotesMessage(fs);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertTrue(fieldSet.isEmpty());
  }

  @Test
  void getName_returnsConstantName() {
    ListPeerNotesMessage message = new ListPeerNotesMessage(new SimpleFieldSet(true));

    assertEquals(ListPeerNotesMessage.NAME, message.getName());
  }

  @Test
  void run_whenHandlerLacksFullAccess_throwsAccessDenied() {
    when(handler.hasFullAccess()).thenReturn(false);
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-3");
    fs.putSingle("NodeIdentifier", "node-1");
    ListPeerNotesMessage message = new ListPeerNotesMessage(fs);

    MessageInvalidException thrown =
        assertThrows(MessageInvalidException.class, () -> message.run(handler));

    assertEquals(ProtocolErrorMessage.ACCESS_DENIED, thrown.protocolCode);
    assertEquals("ListPeerNotes requires full access", thrown.getMessage());
    assertEquals("req-3", thrown.ident);
    assertFalse(thrown.global, "Expected non-global error");
    verify(handler, never()).send(any());
    verifyNoInteractions(server, runtimePorts, peerPort, node);
  }

  @Test
  void run_whenNodeIdentifierMissing_throwsMissingField() {
    when(handler.hasFullAccess()).thenReturn(true);
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-4");
    ListPeerNotesMessage message = new ListPeerNotesMessage(fs);

    MessageInvalidException thrown =
        assertThrows(MessageInvalidException.class, () -> message.run(handler));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, thrown.protocolCode);
    assertEquals("Error: NodeIdentifier field missing", thrown.getMessage());
    assertEquals("req-4", thrown.ident);
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
    when(peerPort.readPrivateDarknetComment("node-unknown"))
        .thenThrow(new UnknownPeerException("node-unknown"));
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-5");
    fs.putSingle("NodeIdentifier", "node-unknown");
    ListPeerNotesMessage message = new ListPeerNotesMessage(fs);

    message.run(handler);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(captor.capture());
    UnknownNodeIdentifierMessage unknownMsg =
        assertInstanceOf(UnknownNodeIdentifierMessage.class, captor.getValue());
    assertEquals("node-unknown", unknownMsg.nodeIdentifier);
    assertEquals("req-5", unknownMsg.messageIdentifier);
    verifyNoMoreInteractions(handler);
  }

  @Test
  void run_whenPeerIsNotDarknet_throwsDarknetOnly() throws Exception {
    when(handler.hasFullAccess()).thenReturn(true);
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.peer()).thenReturn(peerPort);
    when(peerPort.readPrivateDarknetComment("node-2"))
        .thenThrow(new DarknetPeerRequiredException("node-2"));
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-6");
    fs.putSingle("NodeIdentifier", "node-2");
    ListPeerNotesMessage message = new ListPeerNotesMessage(fs);

    MessageInvalidException thrown =
        assertThrows(MessageInvalidException.class, () -> message.run(handler));

    assertEquals(ProtocolErrorMessage.DARKNET_ONLY, thrown.protocolCode);
    assertEquals("ModifyPeer only available for darknet peers", thrown.getMessage());
    assertEquals("req-6", thrown.ident);
    assertFalse(thrown.global, "Expected non-global error");
    verify(handler, never()).send(any());
  }

  @Test
  void run_whenPeerIsDarknet_sendsPeerNoteAndEndMessage() throws Exception {
    when(handler.hasFullAccess()).thenReturn(true);
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.peer()).thenReturn(peerPort);
    when(peerPort.readPrivateDarknetComment("node-3")).thenReturn("secret-note");
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-7");
    fs.putSingle("NodeIdentifier", "node-3");
    ListPeerNotesMessage message = new ListPeerNotesMessage(fs);

    message.run(handler);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler, times(2)).send(captor.capture());
    verifyNoMoreInteractions(handler);

    PeerNote peerNote = assertInstanceOf(PeerNote.class, captor.getAllValues().getFirst());
    assertEquals("node-3", peerNote.nodeIdentifier);
    assertEquals("secret-note", peerNote.noteText);
    assertEquals(Node.PEER_NOTE_TYPE_PRIVATE_DARKNET_COMMENT, peerNote.peerNoteType);
    assertEquals("req-7", peerNote.messageIdentifier);

    EndListPeerNotesMessage endMessage =
        assertInstanceOf(EndListPeerNotesMessage.class, captor.getAllValues().get(1));
    assertEquals("node-3", endMessage.nodeIdentifier);
  }
}
