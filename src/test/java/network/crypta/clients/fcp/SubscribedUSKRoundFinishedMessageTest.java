package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SubscribedUSKRoundFinishedMessageTest {

  @Mock private FCPConnectionHandler handler;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Test
  void getName_whenCalled_returnsSubscribedUSKRoundFinished() {
    SubscribedUSKRoundFinishedMessage message =
        new SubscribedUSKRoundFinishedMessage("identifier-value");

    String result = message.getName();

    assertEquals("SubscribedUSKRoundFinished", result);
  }

  @Test
  void getFieldSet_whenIdentifierProvided_containsIdentifierEntry() {
    String identifier = "test-id";
    SubscribedUSKRoundFinishedMessage message = new SubscribedUSKRoundFinishedMessage(identifier);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals(identifier, fieldSet.get("Identifier"));
  }

  @Test
  void getFieldSet_whenIdentifierIsNull_identifierEntryOmitted() {
    SubscribedUSKRoundFinishedMessage message = new SubscribedUSKRoundFinishedMessage(null);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertNull(fieldSet.get("Identifier"));
  }

  @Test
  void run_whenInvoked_throwsUnsupportedOperationException() {
    SubscribedUSKRoundFinishedMessage message =
        new SubscribedUSKRoundFinishedMessage("irrelevant-id");

    assertThrows(UnsupportedOperationException.class, () -> message.run(handler, node));
  }
}
