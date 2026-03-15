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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class GetRequestStatusMessageTest {

  @Mock private FCPConnectionHandler handler;
  @Mock private FCPConnectionOutputHandler outputHandler;
  @Mock private Node node;
  @Mock private FCPServer server;
  @Mock private RuntimePorts runtimePorts;
  @Mock private RequestQueuePort requestQueuePort;

  @Test
  void constructor_whenFieldsPresent_setsFlagsAndIdentifier() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "abc");
    fs.putSingle("Global", "true");
    fs.putSingle("OnlyData", "true");

    GetRequestStatusMessage message = new GetRequestStatusMessage(fs);

    assertEquals("abc", message.requestIdentifier);
    assertTrue(message.global);
    assertTrue(message.onlyData);
  }

  @Test
  void getFieldSet_roundTripsIdentifier() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "roundTripId");
    GetRequestStatusMessage message = new GetRequestStatusMessage(fs);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals("roundTripId", fieldSet.get("Identifier"));
    assertNull(fieldSet.get("Global"));
    assertNull(fieldSet.get("OnlyData"));
  }

  @Test
  void getName_returnsConstantName() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "id");

    String result = new GetRequestStatusMessage(fs).getName();

    assertEquals(GetRequestStatusMessage.NAME, result);
  }

  @Test
  void run_whenRebootRequestExists_sendsPendingMessagesImmediately() throws Exception {
    String identifier = "existing";
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", identifier);
    fs.putSingle("OnlyData", "true");
    GetRequestStatusMessage message = new GetRequestStatusMessage(fs);

    ClientRequest request = org.mockito.Mockito.mock(ClientRequest.class);
    when(handler.getRebootRequest(false, handler, identifier)).thenReturn(request);
    when(handler.getOutputHandler()).thenReturn(outputHandler);

    message.run(handler, node);

    verify(request).sendPendingMessages(outputHandler, identifier, true, true);
    verify(handler, never()).send(any());
  }

  @Test
  void run_whenRequestMissingAndDatabaseKilled_returnsWithoutSending() throws Exception {
    String identifier = "missing";
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", identifier);
    GetRequestStatusMessage message = new GetRequestStatusMessage(fs);

    stubRequestQueuePort();
    when(handler.getRebootRequest(false, handler, identifier)).thenReturn(null);
    when(requestQueuePort.isPersistenceDatabaseKilled()).thenReturn(true);

    message.run(handler, node);

    verify(handler, never()).send(any());
    verify(requestQueuePort).isPersistenceDatabaseKilled();
    verify(requestQueuePort, never()).submitPersistentJob(any(), any());
    verifyNoMoreInteractions(requestQueuePort);
  }

  @Test
  void run_whenMissingQueuesForeverRequestFound_sendsPendingMessages() throws Exception {
    String identifier = "queued";
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", identifier);
    GetRequestStatusMessage message = new GetRequestStatusMessage(fs);

    ClientRequest queuedRequest = org.mockito.Mockito.mock(ClientRequest.class);
    stubRequestQueuePort();
    when(handler.getRebootRequest(false, handler, identifier)).thenReturn(null);
    when(handler.getForeverRequest(false, handler, identifier)).thenReturn(queuedRequest);
    when(handler.getOutputHandler()).thenReturn(outputHandler);
    when(requestQueuePort.isPersistenceDatabaseKilled()).thenReturn(false);

    message.run(handler, node);

    ArgumentCaptor<RequestQueueTask> taskCaptor = ArgumentCaptor.forClass(RequestQueueTask.class);
    verify(requestQueuePort)
        .submitPersistentJob(taskCaptor.capture(), eq(RequestQueuePriority.NORMAL));

    boolean checkpointRequested = taskCaptor.getValue().run();

    assertFalse(checkpointRequested);
    verify(handler).getForeverRequest(false, handler, identifier);
    verify(queuedRequest).sendPendingMessages(outputHandler, identifier, true, false);
    verify(handler, never()).send(any());
  }

  @Test
  void run_whenMissingQueuesForeverRequestMissing_sendsProtocolError() throws Exception {
    String identifier = "unknown";
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", identifier);
    GetRequestStatusMessage message = new GetRequestStatusMessage(fs);

    stubRequestQueuePort();
    when(handler.getRebootRequest(false, handler, identifier)).thenReturn(null);
    when(handler.getForeverRequest(false, handler, identifier)).thenReturn(null);
    when(requestQueuePort.isPersistenceDatabaseKilled()).thenReturn(false);

    message.run(handler, node);

    ArgumentCaptor<RequestQueueTask> taskCaptor = ArgumentCaptor.forClass(RequestQueueTask.class);
    verify(requestQueuePort)
        .submitPersistentJob(taskCaptor.capture(), eq(RequestQueuePriority.NORMAL));

    taskCaptor.getValue().run();

    ArgumentCaptor<ProtocolErrorMessage> errorCaptor =
        ArgumentCaptor.forClass(ProtocolErrorMessage.class);
    verify(handler).send(errorCaptor.capture());

    ProtocolErrorMessage sent = errorCaptor.getValue();
    assertNotNull(sent);
    assertEquals(ProtocolErrorMessage.NO_SUCH_IDENTIFIER, sent.getCode());
    assertEquals(identifier, sent.ident);
    assertFalse(sent.fatal);
  }

  @Test
  void run_whenQueueUnavailable_sendsProtocolErrorImmediately() throws Exception {
    String identifier = "noPersistence";
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", identifier);
    GetRequestStatusMessage message = new GetRequestStatusMessage(fs);

    stubRequestQueuePort();
    when(handler.getRebootRequest(false, handler, identifier)).thenReturn(null);
    when(requestQueuePort.isPersistenceDatabaseKilled()).thenReturn(false);
    doThrow(new RequestQueueUnavailableException("disabled"))
        .when(requestQueuePort)
        .submitPersistentJob(any(), eq(RequestQueuePriority.NORMAL));

    message.run(handler, node);

    ArgumentCaptor<ProtocolErrorMessage> errorCaptor =
        ArgumentCaptor.forClass(ProtocolErrorMessage.class);
    verify(handler).send(errorCaptor.capture());

    ProtocolErrorMessage error = errorCaptor.getValue();
    assertEquals(ProtocolErrorMessage.NO_SUCH_IDENTIFIER, error.getCode());
    assertEquals(identifier, error.ident);
    assertFalse(error.fatal);
  }

  private void stubRequestQueuePort() {
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.requestQueue()).thenReturn(requestQueuePort);
  }
}
