package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.runtime.spi.DarknetPeerRequiredException;
import network.crypta.runtime.spi.PeerPort;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.runtime.spi.UnknownPeerException;
import network.crypta.support.Base64;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ModifyPeerNoteTest {

  private static final String IDENTIFIER = "req-1";
  private static final String NODE_IDENTIFIER = "peer-123";
  private static final String NOTE_TEXT = "Private darknet note";
  private static final String EXISTING_NOTE = "Existing note";
  private static final int UNKNOWN_PEER_NOTE_TYPE = 99;

  @Mock FCPConnectionHandler handler;

  @Mock Node node;

  @Mock FCPServer server;

  @Mock RuntimePorts runtimePorts;

  @Mock PeerPort peerPort;

  @Test
  void constructor_whenIdentifierPresent_removesIdentifierFromFieldSet() {
    SimpleFieldSet fs = baseFieldSet();

    new ModifyPeerNote(fs);

    assertNull(fs.get("Identifier"));
    assertEquals(NODE_IDENTIFIER, fs.get("NodeIdentifier"));
  }

  @Test
  void getName_returnsModifyPeerNoteLiteral() {
    SimpleFieldSet fs = baseFieldSet();
    ModifyPeerNote modifyPeerNote = new ModifyPeerNote(fs);

    assertEquals("ModifyPeerNote", modifyPeerNote.getName());
  }

  @Test
  void getFieldSet_returnsEmptyFieldSet() {
    SimpleFieldSet fs = baseFieldSet();
    ModifyPeerNote modifyPeerNote = new ModifyPeerNote(fs);

    assertTrue(modifyPeerNote.getFieldSet().isEmpty());
  }

  @Test
  void run_whenAccessDenied_throwsAccessDenied() {
    SimpleFieldSet fs = baseFieldSet();
    ModifyPeerNote modifyPeerNote = new ModifyPeerNote(fs);
    when(handler.hasFullAccess()).thenReturn(false);

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> modifyPeerNote.run(handler, node));

    assertEquals(ProtocolErrorMessage.ACCESS_DENIED, ex.protocolCode);
    assertEquals(IDENTIFIER, ex.ident);
    verifyNoInteractions(server, runtimePorts, peerPort, node);
    verify(handler, never()).send(any());
  }

  @Test
  void run_whenNodeIdentifierMissing_throwsMissingField() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    ModifyPeerNote modifyPeerNote = new ModifyPeerNote(fs);
    when(handler.hasFullAccess()).thenReturn(true);

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> modifyPeerNote.run(handler, node));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, ex.protocolCode);
    assertEquals(IDENTIFIER, ex.ident);
    verifyNoInteractions(server, runtimePorts, peerPort, node);
    verify(handler, never()).send(any());
  }

  @Test
  void run_whenPeerNotFound_sendsUnknownNodeIdentifierMessage() throws Exception {
    SimpleFieldSet fs = baseFieldSet();
    fs.put("PeerNoteType", Node.PEER_NOTE_TYPE_PRIVATE_DARKNET_COMMENT);
    fs.putSingle("NoteText", Base64.encodeUTF8(NOTE_TEXT, true));
    ModifyPeerNote modifyPeerNote = new ModifyPeerNote(fs);
    stubPeerPort();
    when(peerPort.readPrivateDarknetComment(NODE_IDENTIFIER))
        .thenThrow(new UnknownPeerException(NODE_IDENTIFIER));

    modifyPeerNote.run(handler, node);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler, times(1)).send(captor.capture());
    assertInstanceOf(UnknownNodeIdentifierMessage.class, captor.getValue());
    UnknownNodeIdentifierMessage sent = (UnknownNodeIdentifierMessage) captor.getValue();
    assertEquals(NODE_IDENTIFIER, sent.nodeIdentifier);
    assertEquals(IDENTIFIER, sent.messageIdentifier);
  }

  @Test
  void run_whenPeerIsNotDarknet_throwsDarknetOnly() throws Exception {
    SimpleFieldSet fs = baseFieldSet();
    fs.put("PeerNoteType", Node.PEER_NOTE_TYPE_PRIVATE_DARKNET_COMMENT);
    fs.putSingle("NoteText", Base64.encodeUTF8(NOTE_TEXT, true));
    ModifyPeerNote modifyPeerNote = new ModifyPeerNote(fs);
    stubPeerPort();
    when(peerPort.readPrivateDarknetComment(NODE_IDENTIFIER))
        .thenThrow(new DarknetPeerRequiredException(NODE_IDENTIFIER));

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> modifyPeerNote.run(handler, node));

    assertEquals(ProtocolErrorMessage.DARKNET_ONLY, ex.protocolCode);
    assertEquals(IDENTIFIER, ex.ident);
    verify(handler, never()).send(any());
  }

  @Test
  void run_whenPeerNoteTypeNotANumber_throwsInvalidField() throws Exception {
    SimpleFieldSet fs = baseFieldSet();
    fs.putSingle("PeerNoteType", "not-a-number");
    fs.putSingle("NoteText", Base64.encodeUTF8(NOTE_TEXT, true));
    ModifyPeerNote modifyPeerNote = new ModifyPeerNote(fs);
    stubPeerPort();

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> modifyPeerNote.run(handler, node));

    assertEquals(ProtocolErrorMessage.INVALID_FIELD, ex.protocolCode);
    assertEquals(IDENTIFIER, ex.ident);
    verify(handler, never()).send(any());
    verify(peerPort, never()).writePrivateDarknetComment(any(), any());
    verifyNoInteractions(node);
  }

  @Test
  void run_whenNoteTextMissing_throwsMissingField() throws Exception {
    SimpleFieldSet fs = baseFieldSet();
    fs.put("PeerNoteType", Node.PEER_NOTE_TYPE_PRIVATE_DARKNET_COMMENT);
    ModifyPeerNote modifyPeerNote = new ModifyPeerNote(fs);
    stubPeerPort();

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> modifyPeerNote.run(handler, node));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, ex.protocolCode);
    assertEquals(IDENTIFIER, ex.ident);
    verify(handler, never()).send(any());
    verify(peerPort, never()).writePrivateDarknetComment(any(), any());
    verifyNoInteractions(node);
  }

  @Test
  void run_whenNoteTextInvalidBase64_doesNotSendOrModifyPeer() throws Exception {
    SimpleFieldSet fs = baseFieldSet();
    fs.put("PeerNoteType", Node.PEER_NOTE_TYPE_PRIVATE_DARKNET_COMMENT);
    fs.putSingle("NoteText", "%%%"); // invalid Base64
    ModifyPeerNote modifyPeerNote = new ModifyPeerNote(fs);
    stubPeerPort();

    modifyPeerNote.run(handler, node);

    verify(handler, never()).send(any());
    verify(peerPort, never()).writePrivateDarknetComment(any(), any());
    verifyNoInteractions(node);
  }

  @Test
  void run_whenUnknownPeerNoteType_sendsUnknownPeerNoteTypeMessage() throws Exception {
    SimpleFieldSet fs = baseFieldSet();
    fs.put("PeerNoteType", UNKNOWN_PEER_NOTE_TYPE);
    fs.putSingle("NoteText", Base64.encodeUTF8(NOTE_TEXT, true));
    ModifyPeerNote modifyPeerNote = new ModifyPeerNote(fs);
    stubPeerPort();

    modifyPeerNote.run(handler, node);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler, times(1)).send(captor.capture());
    assertInstanceOf(UnknownPeerNoteTypeMessage.class, captor.getValue());
    UnknownPeerNoteTypeMessage sent = (UnknownPeerNoteTypeMessage) captor.getValue();
    assertEquals(UNKNOWN_PEER_NOTE_TYPE, sent.peerNoteType);
    assertEquals(IDENTIFIER, sent.messageIdentifier);
    verify(peerPort, never()).writePrivateDarknetComment(any(), any());
    verifyNoInteractions(node);
  }

  @Test
  void run_whenPeerMissingAndPeerNoteTypeUnsupported_sendsUnknownNodeIdentifierMessage()
      throws Exception {
    SimpleFieldSet fs = baseFieldSet();
    fs.put("PeerNoteType", UNKNOWN_PEER_NOTE_TYPE);
    fs.putSingle("NoteText", Base64.encodeUTF8(NOTE_TEXT, true));
    ModifyPeerNote modifyPeerNote = new ModifyPeerNote(fs);
    stubPeerPort();
    when(peerPort.readPrivateDarknetComment(NODE_IDENTIFIER))
        .thenThrow(new UnknownPeerException(NODE_IDENTIFIER));

    modifyPeerNote.run(handler, node);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler, times(1)).send(captor.capture());
    assertInstanceOf(UnknownNodeIdentifierMessage.class, captor.getValue());
    verify(peerPort, never()).writePrivateDarknetComment(any(), any());
    verifyNoInteractions(node);
  }

  @Test
  void run_whenPeerNotDarknetAndPeerNoteTypeUnsupported_throwsDarknetOnly() throws Exception {
    SimpleFieldSet fs = baseFieldSet();
    fs.put("PeerNoteType", UNKNOWN_PEER_NOTE_TYPE);
    fs.putSingle("NoteText", Base64.encodeUTF8(NOTE_TEXT, true));
    ModifyPeerNote modifyPeerNote = new ModifyPeerNote(fs);
    stubPeerPort();
    when(peerPort.readPrivateDarknetComment(NODE_IDENTIFIER))
        .thenThrow(new DarknetPeerRequiredException(NODE_IDENTIFIER));

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> modifyPeerNote.run(handler, node));

    assertEquals(ProtocolErrorMessage.DARKNET_ONLY, ex.protocolCode);
    assertEquals(IDENTIFIER, ex.ident);
    verify(handler, never()).send(any());
    verify(peerPort, never()).writePrivateDarknetComment(any(), any());
    verifyNoInteractions(node);
  }

  @Test
  void run_whenPrivateDarknetComment_updatesPeerAndSendsPeerNote() throws Exception {
    SimpleFieldSet fs = baseFieldSet();
    fs.put("PeerNoteType", Node.PEER_NOTE_TYPE_PRIVATE_DARKNET_COMMENT);
    fs.putSingle("NoteText", Base64.encodeUTF8(NOTE_TEXT, true));
    ModifyPeerNote modifyPeerNote = new ModifyPeerNote(fs);
    stubPeerPort();
    when(peerPort.writePrivateDarknetComment(NODE_IDENTIFIER, NOTE_TEXT)).thenReturn(NOTE_TEXT);

    modifyPeerNote.run(handler, node);

    verify(peerPort, times(1)).readPrivateDarknetComment(NODE_IDENTIFIER);
    verify(peerPort, times(1)).writePrivateDarknetComment(NODE_IDENTIFIER, NOTE_TEXT);
    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler, times(1)).send(captor.capture());
    assertInstanceOf(PeerNote.class, captor.getValue());
    PeerNote sent = (PeerNote) captor.getValue();
    assertEquals(NODE_IDENTIFIER, sent.nodeIdentifier);
    assertEquals(NOTE_TEXT, sent.noteText);
    assertEquals(Node.PEER_NOTE_TYPE_PRIVATE_DARKNET_COMMENT, sent.peerNoteType);
    assertEquals(IDENTIFIER, sent.messageIdentifier);
  }

  private static SimpleFieldSet baseFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    fs.putSingle("NodeIdentifier", NODE_IDENTIFIER);
    return fs;
  }

  private void stubPeerPort() throws Exception {
    when(handler.hasFullAccess()).thenReturn(true);
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.peer()).thenReturn(peerPort);
    when(peerPort.readPrivateDarknetComment(NODE_IDENTIFIER)).thenReturn(EXISTING_NOTE);
  }
}
