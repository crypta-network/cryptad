package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class DisconnectMessageTest {

  @Mock private FCPConnectionHandler handler;

  @Test
  void getFieldSet_whenInvoked_returnsIndependentEmptyFieldSet() {
    SimpleFieldSet input = new SimpleFieldSet(true);
    DisconnectMessage message = new DisconnectMessage(input);

    SimpleFieldSet result = message.getFieldSet();

    assertNotNull(result);
    assertTrue(result.isEmpty());
    assertNotSame(input, result);
  }

  @Test
  void getName_whenInvoked_returnsDisconnectConstant() {
    DisconnectMessage message = new DisconnectMessage(new SimpleFieldSet(true));

    String name = message.getName();

    assertEquals(DisconnectMessage.NAME, name);
  }

  @Test
  void run_whenCalled_invokesHandlerClose() throws MessageInvalidException {
    DisconnectMessage message = new DisconnectMessage(new SimpleFieldSet(true));

    message.run(handler);

    verify(handler).close();
  }

  @Test
  void run_whenHandlerCloseThrows_propagatesException() {
    DisconnectMessage message = new DisconnectMessage(new SimpleFieldSet(true));
    RuntimeException failure = new RuntimeException("boom");
    doThrow(failure).when(handler).close();

    RuntimeException thrown = assertThrows(RuntimeException.class, () -> message.run(handler));

    assertSame(failure, thrown);
  }
}
