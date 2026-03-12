package network.crypta.clients.fcp;

import java.util.stream.Stream;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verifyNoInteractions;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class UnknownPeerNoteTypeMessageTest {

  @Mock private FCPConnectionHandler handler;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Test
  void getFieldSet_whenIdentifierProvided_containsPeerNoteTypeAndIdentifier() {
    UnknownPeerNoteTypeMessage message = new UnknownPeerNoteTypeMessage(42, "peer-123");

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals(42, fieldSet.getInt("PeerNoteType", -1));
    assertEquals("peer-123", fieldSet.get("Identifier"));
  }

  @Test
  void getFieldSet_whenIdentifierNull_excludesIdentifierKey() {
    UnknownPeerNoteTypeMessage message = new UnknownPeerNoteTypeMessage(7, null);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals(7, fieldSet.getInt("PeerNoteType", -1));
    assertNull(fieldSet.get("Identifier"));
  }

  @Test
  void getName_whenCalled_returnsUnknownPeerNoteTypeLiteral() {
    UnknownPeerNoteTypeMessage message = new UnknownPeerNoteTypeMessage(1, "id");

    assertEquals("UnknownPeerNoteType", message.getName());
  }

  @ParameterizedTest
  @MethodSource("runArguments")
  void run_whenInvoked_throwsMessageInvalidExceptionWithProtocolDetails(String identifier) {
    UnknownPeerNoteTypeMessage message = new UnknownPeerNoteTypeMessage(5, identifier);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(handler, node));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(
        "UnknownPeerNoteType goes from server to client not the other way around",
        exception.getMessage());
    assertEquals(identifier, exception.ident);
    assertFalse(exception.global);
    verifyNoInteractions(handler, node);
  }

  private static Stream<Arguments> runArguments() {
    return Stream.of(Arguments.of("identifier"), Arguments.of((String) null));
  }
}
