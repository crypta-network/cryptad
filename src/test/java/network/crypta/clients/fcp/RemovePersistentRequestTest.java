package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.runtime.spi.RequestQueuePort;
import network.crypta.runtime.spi.RequestQueuePriority;
import network.crypta.runtime.spi.RequestQueueTask;
import network.crypta.runtime.spi.RequestQueueUnavailableException;
import network.crypta.runtime.spi.RuntimePorts;
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
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class RemovePersistentRequestTest {

  private static final String IDENTIFIER = "req-id";

  @Mock private FCPConnectionHandler handler;
  @Mock private Node node;
  @Mock private FCPServer server;
  @Mock private RuntimePorts runtimePorts;
  @Mock private RequestQueuePort requestQueuePort;
  @Mock private ClientRequest clientRequest;

  @Test
  void constructor_whenIdentifierMissing_throwsMessageInvalidException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> new RemovePersistentRequest(fs));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, ex.protocolCode);
    assertEquals("Must have Identifier", ex.getMessage());
    assertNull(ex.ident);
    assertFalse(ex.global);
  }

  @Test
  void getFieldSet_whenCalled_emitsIdentifierOnly() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    RemovePersistentRequest message = new RemovePersistentRequest(fs);

    SimpleFieldSet result = message.getFieldSet();

    assertEquals(IDENTIFIER, result.get("Identifier"));
    assertNull(result.get("Global"));
  }

  @Test
  void getName_whenCalled_returnsConstantName() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    RemovePersistentRequest message = new RemovePersistentRequest(fs);

    assertEquals(RemovePersistentRequest.NAME, message.getName());
  }

  @Test
  void run_whenRebootRequestExists_stopsAfterInitialRemoval() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    RemovePersistentRequest message = new RemovePersistentRequest(fs);
    when(handler.removePersistentRebootRequest(false, IDENTIFIER)).thenReturn(clientRequest);

    message.run(handler, node);

    verify(handler).removePersistentRebootRequest(false, IDENTIFIER);
    verify(handler, never()).removeRequestByIdentifier(any(), anyBoolean());
    verifyNoInteractions(requestQueuePort);
  }

  @Test
  void run_whenNonPersistentRequestFound_skipsPersistentQueue() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    RemovePersistentRequest message = new RemovePersistentRequest(fs);
    when(handler.removePersistentRebootRequest(false, IDENTIFIER)).thenReturn(null);
    when(handler.removeRequestByIdentifier(IDENTIFIER, true)).thenReturn(clientRequest);

    message.run(handler, node);

    verify(handler).removePersistentRebootRequest(false, IDENTIFIER);
    verify(handler).removeRequestByIdentifier(IDENTIFIER, true);
    verify(handler, never()).removePersistentForeverRequest(anyBoolean(), any());
    verifyNoInteractions(requestQueuePort);
  }

  @Test
  void run_whenQueuedTaskRuns_removesForeverRequest() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    fs.put("Global", true);
    RemovePersistentRequest message = new RemovePersistentRequest(fs);

    stubRequestQueuePort();
    when(handler.removePersistentRebootRequest(true, IDENTIFIER)).thenReturn(null);
    when(handler.removePersistentForeverRequest(true, IDENTIFIER)).thenReturn(clientRequest);

    message.run(handler, node);

    ArgumentCaptor<RequestQueueTask> taskCaptor = ArgumentCaptor.forClass(RequestQueueTask.class);
    verify(requestQueuePort)
        .submitPersistentJob(taskCaptor.capture(), eq(RequestQueuePriority.HIGH));

    boolean result = taskCaptor.getValue().run();

    assertTrue(result);
    verify(handler).removePersistentForeverRequest(true, IDENTIFIER);
  }

  @Test
  void run_whenQueueUnavailable_sendsPersistenceDisabledProtocolError() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    RemovePersistentRequest message = new RemovePersistentRequest(fs);

    stubRequestQueuePort();
    when(handler.removePersistentRebootRequest(false, IDENTIFIER)).thenReturn(null);
    when(handler.removeRequestByIdentifier(IDENTIFIER, true)).thenReturn(null);
    doThrow(new RequestQueueUnavailableException("disabled"))
        .when(requestQueuePort)
        .submitPersistentJob(any(), eq(RequestQueuePriority.HIGH));

    message.run(handler, node);

    ArgumentCaptor<FCPMessage> messageCaptor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(messageCaptor.capture());
    ProtocolErrorMessage error = (ProtocolErrorMessage) messageCaptor.getValue();
    assertEquals(ProtocolErrorMessage.PERSISTENCE_DISABLED, error.getCode());
    assertEquals(IDENTIFIER, error.ident);
    assertEquals("Persistence disabled and non-persistent request not found", error.extra);
  }

  private void stubRequestQueuePort() {
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.requestQueue()).thenReturn(requestQueuePort);
  }
}
