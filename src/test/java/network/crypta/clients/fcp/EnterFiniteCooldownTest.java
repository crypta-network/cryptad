package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import network.crypta.node.FSParseException;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class EnterFiniteCooldownTest {

  @ParameterizedTest
  @CsvSource({"req-123,true,1700000000000", "other,false,-42"})
  void getFieldSet_whenConstructed_containsExpectedValues(
      String identifier, boolean global, long wakeupTime) throws FSParseException {
    EnterFiniteCooldown message = new EnterFiniteCooldown(identifier, global, wakeupTime);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertNotNull(fieldSet);
    assertEquals(identifier, fieldSet.get("Identifier"));
    assertEquals(Boolean.toString(global), fieldSet.get("Global"));
    assertEquals(wakeupTime, fieldSet.getLong("WakeupTime"));
  }

  @Test
  void getName_whenCalled_returnsEnterFiniteCooldownLiteral() {
    EnterFiniteCooldown message = new EnterFiniteCooldown("id", true, 0L);

    String name = message.getName();

    assertEquals("EnterFiniteCooldown", name);
  }

  @Test
  void run_whenInvoked_doesNothingAndDoesNotTouchCollaborators() throws MessageInvalidException {
    EnterFiniteCooldown message = new EnterFiniteCooldown("id", false, 123L);
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);

    message.run(handler, node);

    verifyNoInteractions(handler, node);
  }
}
