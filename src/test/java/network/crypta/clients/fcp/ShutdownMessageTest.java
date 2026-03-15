package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ShutdownMessageTest {

  @Mock private FCPConnectionHandler handler;
  @Mock private FCPServer server;
  @Mock private NodeClientCore core;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Test
  void getName_whenCalled_returnsShutdownConstant() {
    ShutdownMessage message = new ShutdownMessage();

    String result = message.getName();

    assertEquals(ShutdownMessage.NAME, result);
  }

  @Test
  void getFieldSet_whenCalled_returnsNull() {
    ShutdownMessage message = new ShutdownMessage();

    SimpleFieldSet result = message.getFieldSet();

    assertNull(result);
  }

  @Test
  void run_whenHandlerLacksFullAccess_throwsAccessDenied() {
    ShutdownMessage message = new ShutdownMessage();
    when(handler.hasFullAccess()).thenReturn(false);

    MessageInvalidException thrown =
        assertThrows(MessageInvalidException.class, () -> message.run(handler));

    assertEquals(ProtocolErrorMessage.ACCESS_DENIED, thrown.protocolCode);
    assertEquals("Shutdown requires full access", thrown.getMessage());
    assertNull(thrown.ident);
    assertFalse(thrown.global);
    verify(handler, never()).send(any());
    verify(node, never()).exit(any(String.class));
  }

  @Test
  void run_whenHandlerHasFullAccess_sendsShutdownProtocolErrorAndExits()
      throws MessageInvalidException {
    ShutdownMessage message = new ShutdownMessage();
    when(handler.hasFullAccess()).thenReturn(true);
    when(handler.getServer()).thenReturn(server);
    when(server.getCore()).thenReturn(core);
    when(core.getNode()).thenReturn(node);
    ArgumentCaptor<ProtocolErrorMessage> sentMessage =
        ArgumentCaptor.forClass(ProtocolErrorMessage.class);

    message.run(handler);

    verify(handler).send(sentMessage.capture());
    verify(node).exit("Received FCP shutdown message");

    ProtocolErrorMessage protocolError = sentMessage.getValue();
    assertEquals(ProtocolErrorMessage.SHUTTING_DOWN, protocolError.getCode());
    assertTrue(protocolError.fatal);
    assertEquals("The node is shutting down", protocolError.extra);
    assertEquals("Node", protocolError.ident);
    assertFalse(protocolError.global);
  }
}
