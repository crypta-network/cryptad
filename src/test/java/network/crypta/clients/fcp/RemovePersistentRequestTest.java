package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.PersistentJob;
import network.crypta.client.async.PersistentJobRunner;
import network.crypta.node.NodeClientCore;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.NativeThread;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // method naming: method_whenCondition_expectOutcome
class RemovePersistentRequestTest {

  private static final String IDENTIFIER = "req-id";

  @Mock private FCPConnectionHandler handler;
  @Mock private FCPServer server;
  @Mock private NodeClientCore core;
  @Mock private ClientContext clientContext;
  @Mock private PersistentJobRunner jobRunner;
  @Mock private ClientRequest clientRequest;

  @BeforeEach
  void setUp() throws Exception {
    Field jobRunnerField = ClientContext.class.getField("jobRunner");
    jobRunnerField.setAccessible(true);
    jobRunnerField.set(clientContext, jobRunner);
  }

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

    message.run(handler, null);

    verify(handler).removePersistentRebootRequest(false, IDENTIFIER);
    verify(handler, never()).removeRequestByIdentifier(any(), anyBoolean());
    verifyNoInteractions(jobRunner);
  }

  @Test
  void run_whenNonPersistentRequestFound_skipsPersistenceJob() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    RemovePersistentRequest message = new RemovePersistentRequest(fs);
    when(handler.removePersistentRebootRequest(false, IDENTIFIER)).thenReturn(null);
    when(handler.removeRequestByIdentifier(IDENTIFIER, true)).thenReturn(clientRequest);

    message.run(handler, null);

    verify(handler).removePersistentRebootRequest(false, IDENTIFIER);
    verify(handler).removeRequestByIdentifier(IDENTIFIER, true);
    verify(handler, never()).removePersistentForeverRequest(anyBoolean(), any());
    verifyNoInteractions(jobRunner);
  }

  @Test
  void run_whenQueuedJobRuns_removesForeverRequest() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    fs.put("Global", true);
    RemovePersistentRequest message = new RemovePersistentRequest(fs);
    when(handler.removePersistentRebootRequest(true, IDENTIFIER)).thenReturn(null);
    when(handler.removePersistentForeverRequest(true, IDENTIFIER)).thenReturn(clientRequest);
    stubJobRunnerChain();
    ArgumentCaptor<PersistentJob> jobCaptor = ArgumentCaptor.forClass(PersistentJob.class);
    doAnswer(invocation -> null)
        .when(jobRunner)
        .queue(jobCaptor.capture(), eq(NativeThread.PriorityLevel.HIGH_PRIORITY.value));

    message.run(handler, null);

    verify(handler).removePersistentRebootRequest(true, IDENTIFIER);
    verify(handler, never()).removeRequestByIdentifier(any(), anyBoolean());
    verify(jobRunner)
        .queue(any(PersistentJob.class), eq(NativeThread.PriorityLevel.HIGH_PRIORITY.value));

    PersistentJob captured = jobCaptor.getValue();
    boolean result = captured.run(clientContext);

    assertTrue(result);
    verify(handler).removePersistentForeverRequest(true, IDENTIFIER);
  }

  @Test
  void run_whenPersistenceDisabled_sendsProtocolError() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    RemovePersistentRequest message = new RemovePersistentRequest(fs);
    when(handler.removePersistentRebootRequest(false, IDENTIFIER)).thenReturn(null);
    when(handler.removeRequestByIdentifier(IDENTIFIER, true)).thenReturn(null);
    stubJobRunnerChain();
    doThrow(new PersistenceDisabledException())
        .when(jobRunner)
        .queue(any(PersistentJob.class), anyInt());

    message.run(handler, null);

    ArgumentCaptor<FCPMessage> messageCaptor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(messageCaptor.capture());
    ProtocolErrorMessage error = (ProtocolErrorMessage) messageCaptor.getValue();
    assertEquals(ProtocolErrorMessage.PERSISTENCE_DISABLED, error.getCode());
    assertEquals(IDENTIFIER, error.ident);
    assertEquals("Persistence disabled and non-persistent request not found", error.extra);
  }

  private void stubJobRunnerChain() {
    when(handler.getServer()).thenReturn(server);
    when(server.getCore()).thenReturn(core);
    when(core.getClientContext()).thenReturn(clientContext);
  }
}
