package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.PersistentJob;
import network.crypta.client.async.PersistentJobRunner;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.NativeThread;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class GetRequestStatusMessageTest {

  @Mock private FCPConnectionHandler handler;
  @Mock private FCPConnectionOutputHandler outputHandler;
  @Mock private Node node;
  @Mock private NodeClientCore nodeClientCore;

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
    // Ensure other flags are not unintentionally copied into the outgoing field set
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

    ClientRequest request = mock(ClientRequest.class);
    when(handler.getRebootRequest(false, handler, identifier)).thenReturn(request);
    when(handler.getOutputHandler()).thenReturn(outputHandler);

    message.run(handler, node);

    verify(request).sendPendingMessages(outputHandler, identifier, true, /* onlyData */ true);
    verify(handler, never()).send(any());
  }

  @Test
  void run_whenRequestMissingAndDatabaseKilled_returnsWithoutSending() throws Exception {
    String identifier = "missing";
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", identifier);
    GetRequestStatusMessage message = new GetRequestStatusMessage(fs);

    when(handler.getRebootRequest(false, handler, identifier)).thenReturn(null);
    when(node.getClientCore()).thenReturn(nodeClientCore);
    when(nodeClientCore.killedDatabase()).thenReturn(true);

    message.run(handler, node);

    verify(handler, never()).send(any());
    verify(nodeClientCore).killedDatabase();
    verifyNoMoreInteractions(nodeClientCore);
  }

  @Test
  void run_whenMissingQueuesForeverRequestFound_sendsPendingMessages() throws Exception {
    String identifier = "queued";
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", identifier);
    GetRequestStatusMessage message = new GetRequestStatusMessage(fs);

    ClientRequest queuedRequest = mock(ClientRequest.class);
    PersistentJobRunner jobRunner = mock(PersistentJobRunner.class);
    ClientContext context = contextWithJobRunner(jobRunner);

    when(handler.getRebootRequest(false, handler, identifier)).thenReturn(null);
    when(handler.getForeverRequest(false, handler, identifier)).thenReturn(queuedRequest);
    when(handler.getOutputHandler()).thenReturn(outputHandler);
    when(node.getClientCore()).thenReturn(nodeClientCore);
    when(nodeClientCore.killedDatabase()).thenReturn(false);
    when(nodeClientCore.getClientContext()).thenReturn(context);

    message.run(handler, node);

    ArgumentCaptor<PersistentJob> jobCaptor = ArgumentCaptor.forClass(PersistentJob.class);
    verify(jobRunner).queue(jobCaptor.capture(), eq(normPriority()));

    PersistentJob persistedJob = jobCaptor.getValue();
    boolean checkpointRequested = persistedJob.run(context);

    assertFalse(checkpointRequested);
    verify(handler).getForeverRequest(false, handler, identifier);
    verify(queuedRequest)
        .sendPendingMessages(outputHandler, identifier, true, /* onlyData */ false);
    verify(handler, never()).send(any());
  }

  @Test
  void run_whenMissingQueuesForeverRequestMissing_sendsProtocolError() throws Exception {
    String identifier = "unknown";
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", identifier);
    GetRequestStatusMessage message = new GetRequestStatusMessage(fs);

    PersistentJobRunner jobRunner = mock(PersistentJobRunner.class);
    ClientContext context = contextWithJobRunner(jobRunner);

    when(handler.getRebootRequest(false, handler, identifier)).thenReturn(null);
    when(handler.getForeverRequest(false, handler, identifier)).thenReturn(null);
    when(node.getClientCore()).thenReturn(nodeClientCore);
    when(nodeClientCore.killedDatabase()).thenReturn(false);
    when(nodeClientCore.getClientContext()).thenReturn(context);

    message.run(handler, node);

    ArgumentCaptor<PersistentJob> jobCaptor = ArgumentCaptor.forClass(PersistentJob.class);
    verify(jobRunner).queue(jobCaptor.capture(), eq(normPriority()));

    PersistentJob persistedJob = jobCaptor.getValue();
    persistedJob.run(context);

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
  void run_whenPersistenceDisabledOnQueue_sendsProtocolErrorImmediately() throws Exception {
    String identifier = "noPersistence";
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", identifier);
    GetRequestStatusMessage message = new GetRequestStatusMessage(fs);

    PersistentJobRunner jobRunner = mock(PersistentJobRunner.class);
    ClientContext context = contextWithJobRunner(jobRunner);

    when(handler.getRebootRequest(false, handler, identifier)).thenReturn(null);
    when(node.getClientCore()).thenReturn(nodeClientCore);
    when(nodeClientCore.killedDatabase()).thenReturn(false);
    when(nodeClientCore.getClientContext()).thenReturn(context);
    doThrow(new PersistenceDisabledException()).when(jobRunner).queue(any(), eq(normPriority()));

    message.run(handler, node);

    ArgumentCaptor<ProtocolErrorMessage> errorCaptor =
        ArgumentCaptor.forClass(ProtocolErrorMessage.class);
    verify(handler).send(errorCaptor.capture());

    ProtocolErrorMessage error = errorCaptor.getValue();
    assertEquals(ProtocolErrorMessage.NO_SUCH_IDENTIFIER, error.getCode());
    assertEquals(identifier, error.ident);
    assertFalse(error.fatal);
  }

  private ClientContext contextWithJobRunner(PersistentJobRunner jobRunner) {
    ClientContext context = mock(ClientContext.class);
    try {
      Field field = ClientContext.class.getDeclaredField("jobRunner");
      field.setAccessible(true);
      field.set(context, jobRunner);
    } catch (IllegalAccessException | NoSuchFieldException e) {
      throw new RuntimeException(e);
    }
    return context;
  }

  private int normPriority() {
    return NativeThread.PriorityLevel.NORM_PRIORITY.value;
  }
}
