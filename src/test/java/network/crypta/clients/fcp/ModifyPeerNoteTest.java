package network.crypta.clients.fcp;

import network.crypta.node.DarknetPeerNode;
import network.crypta.node.Node;
import network.crypta.node.PeerNode;
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
import static org.mockito.ArgumentMatchers.anyString;
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
  private static final int UNKNOWN_PEER_NOTE_TYPE = 99;

  @Mock FCPConnectionHandler handler;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  Node node;

  @Mock DarknetPeerNode darknetPeerNode;
  @Mock PeerNode peerNode;

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
    verifyNoInteractions(node);
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
    verify(node.network(), never()).getPeerNode(anyString());
    verify(handler, never()).send(any());
  }

  @Test
  void run_whenPeerNotFound_sendsUnknownNodeIdentifierMessage() throws Exception {
    SimpleFieldSet fs = baseFieldSet();
    ModifyPeerNote modifyPeerNote = new ModifyPeerNote(fs);
    when(handler.hasFullAccess()).thenReturn(true);
    when(node.network().getPeerNode(NODE_IDENTIFIER)).thenReturn(null);

    modifyPeerNote.run(handler, node);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler, times(1)).send(captor.capture());
    assertInstanceOf(UnknownNodeIdentifierMessage.class, captor.getValue());
    UnknownNodeIdentifierMessage sent = (UnknownNodeIdentifierMessage) captor.getValue();
    assertEquals(NODE_IDENTIFIER, sent.nodeIdentifier);
    assertEquals(IDENTIFIER, sent.messageIdentifier);
  }

  @Test
  void run_whenPeerIsNotDarknet_throwsDarknetOnly() {
    SimpleFieldSet fs = baseFieldSet();
    ModifyPeerNote modifyPeerNote = new ModifyPeerNote(fs);
    when(handler.hasFullAccess()).thenReturn(true);
    when(node.network().getPeerNode(NODE_IDENTIFIER)).thenReturn(peerNode);

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> modifyPeerNote.run(handler, node));

    assertEquals(ProtocolErrorMessage.DARKNET_ONLY, ex.protocolCode);
    assertEquals(IDENTIFIER, ex.ident);
    verify(handler, never()).send(any());
  }

  @Test
  void run_whenPeerNoteTypeNotANumber_throwsInvalidField() {
    SimpleFieldSet fs = baseFieldSet();
    fs.putSingle("PeerNoteType", "not-a-number");
    fs.putSingle("NoteText", Base64.encodeUTF8(NOTE_TEXT, true));
    ModifyPeerNote modifyPeerNote = new ModifyPeerNote(fs);
    when(handler.hasFullAccess()).thenReturn(true);
    when(node.network().getPeerNode(NODE_IDENTIFIER)).thenReturn(darknetPeerNode);

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> modifyPeerNote.run(handler, node));

    assertEquals(ProtocolErrorMessage.INVALID_FIELD, ex.protocolCode);
    assertEquals(IDENTIFIER, ex.ident);
    verify(handler, never()).send(any());
    verify(darknetPeerNode, never()).setPrivateDarknetCommentNote(anyString());
  }

  @Test
  void run_whenNoteTextMissing_throwsMissingField() {
    SimpleFieldSet fs = baseFieldSet();
    fs.put("PeerNoteType", Node.PEER_NOTE_TYPE_PRIVATE_DARKNET_COMMENT);
    ModifyPeerNote modifyPeerNote = new ModifyPeerNote(fs);
    when(handler.hasFullAccess()).thenReturn(true);
    when(node.network().getPeerNode(NODE_IDENTIFIER)).thenReturn(darknetPeerNode);

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> modifyPeerNote.run(handler, node));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, ex.protocolCode);
    assertEquals(IDENTIFIER, ex.ident);
    verify(handler, never()).send(any());
    verify(darknetPeerNode, never()).setPrivateDarknetCommentNote(anyString());
  }

  @Test
  void run_whenNoteTextInvalidBase64_doesNotSendOrModifyPeer() throws Exception {
    SimpleFieldSet fs = baseFieldSet();
    fs.put("PeerNoteType", Node.PEER_NOTE_TYPE_PRIVATE_DARKNET_COMMENT);
    fs.putSingle("NoteText", "%%%"); // invalid Base64
    ModifyPeerNote modifyPeerNote = new ModifyPeerNote(fs);
    when(handler.hasFullAccess()).thenReturn(true);
    when(node.network().getPeerNode(NODE_IDENTIFIER)).thenReturn(darknetPeerNode);

    modifyPeerNote.run(handler, node);

    verify(darknetPeerNode, never()).setPrivateDarknetCommentNote(anyString());
    verify(handler, never()).send(any());
  }

  @Test
  void run_whenUnknownPeerNoteType_sendsUnknownPeerNoteTypeMessage() throws Exception {
    SimpleFieldSet fs = baseFieldSet();
    fs.put("PeerNoteType", UNKNOWN_PEER_NOTE_TYPE);
    fs.putSingle("NoteText", Base64.encodeUTF8(NOTE_TEXT, true));
    ModifyPeerNote modifyPeerNote = new ModifyPeerNote(fs);
    when(handler.hasFullAccess()).thenReturn(true);
    when(node.network().getPeerNode(NODE_IDENTIFIER)).thenReturn(darknetPeerNode);

    modifyPeerNote.run(handler, node);

    verify(darknetPeerNode, never()).setPrivateDarknetCommentNote(anyString());
    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler, times(1)).send(captor.capture());
    assertInstanceOf(UnknownPeerNoteTypeMessage.class, captor.getValue());
    UnknownPeerNoteTypeMessage sent = (UnknownPeerNoteTypeMessage) captor.getValue();
    assertEquals(UNKNOWN_PEER_NOTE_TYPE, sent.peerNoteType);
    assertEquals(IDENTIFIER, sent.messageIdentifier);
  }

  @Test
  void run_whenPrivateDarknetComment_updatesPeerAndSendsPeerNote() throws Exception {
    SimpleFieldSet fs = baseFieldSet();
    fs.put("PeerNoteType", Node.PEER_NOTE_TYPE_PRIVATE_DARKNET_COMMENT);
    fs.putSingle("NoteText", Base64.encodeUTF8(NOTE_TEXT, true));
    ModifyPeerNote modifyPeerNote = new ModifyPeerNote(fs);
    when(handler.hasFullAccess()).thenReturn(true);
    when(node.network().getPeerNode(NODE_IDENTIFIER)).thenReturn(darknetPeerNode);

    modifyPeerNote.run(handler, node);

    verify(darknetPeerNode, times(1)).setPrivateDarknetCommentNote(NOTE_TEXT);
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
}
