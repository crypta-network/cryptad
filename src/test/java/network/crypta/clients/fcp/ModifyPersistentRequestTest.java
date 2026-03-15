package network.crypta.clients.fcp;

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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ModifyPersistentRequestTest {

  @Mock private FCPConnectionHandler handler;
  @Mock private FCPServer server;
  @Mock private RuntimePorts runtimePorts;
  @Mock private RequestQueuePort requestQueuePort;

  @Test
  void constructor_whenIdentifierMissing_throwsMessageInvalidException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.put("Global", true);

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> new ModifyPersistentRequest(fs));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, ex.protocolCode);
    assertEquals("Missing field: Identifier", ex.getMessage());
    assertNull(ex.ident);
    assertTrue(ex.global);
  }

  @Test
  void constructor_whenPriorityClassNotNumber_throwsMessageInvalidException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-1");
    fs.putSingle("PriorityClass", "not-a-number");

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> new ModifyPersistentRequest(fs));

    assertEquals(ProtocolErrorMessage.ERROR_PARSING_NUMBER, ex.protocolCode);
    assertEquals("req-1", ex.ident);
    assertTrue(ex.getMessage().startsWith("Could not parse PriorityClass:"));
    assertFalse(ex.global);
  }

  @Test
  void constructor_whenPriorityClassOutOfRange_throwsMessageInvalidException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-2");
    fs.putSingle("PriorityClass", "7");

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> new ModifyPersistentRequest(fs));

    assertEquals(ProtocolErrorMessage.INVALID_FIELD, ex.protocolCode);
    assertEquals("req-2", ex.ident);
    assertTrue(ex.getMessage().contains("Invalid priority class 7"));
    assertFalse(ex.global);
  }

  @Test
  void constructor_whenPriorityClassMissing_usesNegativeOneAndRespectsGlobal() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-3");
    fs.put("Global", true);

    ModifyPersistentRequest message = new ModifyPersistentRequest(fs);

    assertEquals("req-3", message.requestIdentifier);
    assertTrue(message.global);
    assertEquals(-1, message.priorityClass);
    assertNull(message.clientToken);
  }

  @Test
  void getFieldSet_whenClientTokenPresent_includesAllFields() throws Exception {
    SimpleFieldSet input = new SimpleFieldSet(true);
    input.putSingle("Identifier", "req-4");
    input.put("Global", false);
    input.putSingle("PriorityClass", "3");
    input.putSingle("ClientToken", "token-123");
    ModifyPersistentRequest message = new ModifyPersistentRequest(input);

    SimpleFieldSet result = message.getFieldSet();

    assertEquals("req-4", result.get("Identifier"));
    assertFalse(result.getBoolean("Global", true));
    assertEquals("3", result.get("PriorityClass"));
    assertEquals("token-123", result.get("ClientToken"));
  }

  @Test
  void getFieldSet_whenClientTokenMissing_doesNotEmitClientToken() throws Exception {
    SimpleFieldSet input = new SimpleFieldSet(true);
    input.putSingle("Identifier", "req-5");
    input.put("Global", false);
    input.putSingle("PriorityClass", "2");
    ModifyPersistentRequest message = new ModifyPersistentRequest(input);

    SimpleFieldSet result = message.getFieldSet();

    assertEquals("req-5", result.get("Identifier"));
    assertEquals("2", result.get("PriorityClass"));
    assertNull(result.get("ClientToken"));
  }

  @Test
  void getName_whenCalled_returnsConstantName() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-6");
    ModifyPersistentRequest message = new ModifyPersistentRequest(fs);

    assertEquals("ModifyPersistentRequest", message.getName());
  }

  @Test
  void run_whenRebootRequestExists_modifiesRequestViaHandlerServer() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-7");
    fs.put("Global", false);
    fs.putSingle("PriorityClass", "1");
    fs.putSingle("ClientToken", "tok");
    ModifyPersistentRequest message = new ModifyPersistentRequest(fs);

    ClientRequest rebootRequest = org.mockito.Mockito.mock(ClientRequest.class);
    when(handler.getRebootRequest(false, handler, "req-7")).thenReturn(rebootRequest);
    when(handler.getServer()).thenReturn(server);

    message.run(handler);

    verify(rebootRequest).modifyRequest("tok", (short) 1, server);
    verifyNoInteractions(requestQueuePort);
    verify(handler, never()).send(any(FCPMessage.class));
  }

  @Test
  void run_whenRebootRequestMissingAndForeverRequestExists_modifiesRequestViaHandlerServer()
      throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-8");
    fs.put("Global", false);
    fs.putSingle("PriorityClass", "4");
    fs.putSingle("ClientToken", "new-token");
    ModifyPersistentRequest message = new ModifyPersistentRequest(fs);

    ClientRequest foreverRequest = org.mockito.Mockito.mock(ClientRequest.class);
    stubRequestQueuePort();
    when(handler.getRebootRequest(false, handler, "req-8")).thenReturn(null);
    when(handler.getForeverRequest(false, handler, "req-8")).thenReturn(foreverRequest);

    message.run(handler);

    ArgumentCaptor<RequestQueueTask> taskCaptor = ArgumentCaptor.forClass(RequestQueueTask.class);
    verify(requestQueuePort)
        .submitPersistentJob(taskCaptor.capture(), eq(RequestQueuePriority.NORMAL));

    boolean checkpointRequested = taskCaptor.getValue().run();

    assertTrue(checkpointRequested);
    verify(foreverRequest).modifyRequest("new-token", (short) 4, server);
    verify(handler, never()).send(any(ProtocolErrorMessage.class));
  }

  @Test
  void run_whenRebootAndForeverRequestsMissing_sendsNoSuchIdentifierErrorFromQueuedTask()
      throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-9");
    fs.put("Global", false);
    ModifyPersistentRequest message = new ModifyPersistentRequest(fs);

    stubRequestQueuePort();
    when(handler.getRebootRequest(false, handler, "req-9")).thenReturn(null);
    when(handler.getForeverRequest(false, handler, "req-9")).thenReturn(null);

    message.run(handler);

    ArgumentCaptor<RequestQueueTask> taskCaptor = ArgumentCaptor.forClass(RequestQueueTask.class);
    verify(requestQueuePort)
        .submitPersistentJob(taskCaptor.capture(), eq(RequestQueuePriority.NORMAL));

    taskCaptor.getValue().run();

    ArgumentCaptor<ProtocolErrorMessage> errorCaptor =
        ArgumentCaptor.forClass(ProtocolErrorMessage.class);
    verify(handler).send(errorCaptor.capture());
    ProtocolErrorMessage error = errorCaptor.getValue();
    assertNotNull(error);
    assertEquals(ProtocolErrorMessage.NO_SUCH_IDENTIFIER, error.getCode());
    assertFalse(error.fatal);
    assertEquals("req-9", error.ident);
    assertFalse(error.global);
    assertNull(error.extra);
  }

  @Test
  void run_whenQueueUnavailable_sendsNoSuchIdentifierErrorImmediately() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-10");
    fs.put("Global", true);
    ModifyPersistentRequest message = new ModifyPersistentRequest(fs);

    stubRequestQueuePort();
    when(handler.getRebootRequest(true, handler, "req-10")).thenReturn(null);
    doThrow(new RequestQueueUnavailableException("disabled"))
        .when(requestQueuePort)
        .submitPersistentJob(any(), eq(RequestQueuePriority.NORMAL));

    ArgumentCaptor<ProtocolErrorMessage> errorCaptor =
        ArgumentCaptor.forClass(ProtocolErrorMessage.class);

    message.run(handler);

    verify(handler).send(errorCaptor.capture());
    verify(handler, never()).getForeverRequest(eq(true), eq(handler), eq("req-10"));
    ProtocolErrorMessage error = errorCaptor.getValue();
    assertEquals(ProtocolErrorMessage.NO_SUCH_IDENTIFIER, error.getCode());
    assertFalse(error.fatal);
    assertEquals("req-10", error.ident);
    assertTrue(error.global);
    assertNull(error.extra);
  }

  private void stubRequestQueuePort() {
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.requestQueue()).thenReturn(requestQueuePort);
  }
}
