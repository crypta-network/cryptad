package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verifyNoInteractions;

import network.crypta.node.Node;
import network.crypta.support.Base64;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PeerNoteTest {

  private static final String NODE_IDENTIFIER = "peer-123";
  private static final String NOTE_TEXT = "A short note";
  private static final int PEER_NOTE_TYPE = 2;
  private static final String IDENTIFIER = "req-99";

  @Mock FCPConnectionHandler handler;
  @Mock Node node;

  @Test
  void getFieldSet_whenIdentifierProvided_containsEncodedFields() {
    PeerNote peerNote = new PeerNote(NODE_IDENTIFIER, NOTE_TEXT, PEER_NOTE_TYPE, IDENTIFIER);

    SimpleFieldSet fieldSet = peerNote.getFieldSet();

    assertEquals(NODE_IDENTIFIER, fieldSet.get("NodeIdentifier"));
    assertEquals(Integer.toString(PEER_NOTE_TYPE), fieldSet.get("PeerNoteType"));
    assertEquals(Base64.encodeUTF8(NOTE_TEXT, true), fieldSet.get("NoteText"));
    assertEquals(IDENTIFIER, fieldSet.get("Identifier"));
  }

  @Test
  void getFieldSet_whenIdentifierNull_omitsIdentifierField() {
    PeerNote peerNote = new PeerNote(NODE_IDENTIFIER, NOTE_TEXT, PEER_NOTE_TYPE, null);

    SimpleFieldSet fieldSet = peerNote.getFieldSet();

    assertEquals(NODE_IDENTIFIER, fieldSet.get("NodeIdentifier"));
    assertEquals(Integer.toString(PEER_NOTE_TYPE), fieldSet.get("PeerNoteType"));
    assertEquals(Base64.encodeUTF8(NOTE_TEXT, true), fieldSet.get("NoteText"));
    assertNull(fieldSet.get("Identifier"));
  }

  @Test
  void getName_returnsPeerNoteLiteral() {
    PeerNote peerNote = new PeerNote(NODE_IDENTIFIER, NOTE_TEXT, PEER_NOTE_TYPE, IDENTIFIER);

    assertEquals("PeerNote", peerNote.getName());
  }

  @Test
  void run_always_throwsInvalidMessageWithDetails() {
    PeerNote peerNote = new PeerNote(NODE_IDENTIFIER, NOTE_TEXT, PEER_NOTE_TYPE, IDENTIFIER);

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> peerNote.run(handler, node));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, ex.protocolCode);
    assertEquals("PeerNote goes from server to client not the other way around", ex.getMessage());
    assertEquals(IDENTIFIER, ex.ident);
    assertFalse(ex.global);
    verifyNoInteractions(handler, node);
  }

  @Test
  void run_whenIdentifierNull_throwsInvalidMessageWithNullIdent() {
    PeerNote peerNote = new PeerNote(NODE_IDENTIFIER, NOTE_TEXT, PEER_NOTE_TYPE, null);

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> peerNote.run(handler, node));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, ex.protocolCode);
    assertEquals("PeerNote goes from server to client not the other way around", ex.getMessage());
    assertNull(ex.ident);
    assertFalse(ex.global);
    verifyNoInteractions(handler, node);
  }
}
