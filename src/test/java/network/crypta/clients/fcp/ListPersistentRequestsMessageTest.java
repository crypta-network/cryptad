package network.crypta.clients.fcp;

import network.crypta.runtime.spi.RequestQueuePort;
import network.crypta.runtime.spi.RequestQueuePriority;
import network.crypta.runtime.spi.RequestQueueTask;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ListPersistentRequestsMessageTest {

  @Mock private FCPConnectionHandler handler;
  @Mock private FCPServer server;
  @Mock private RuntimePorts runtimePorts;
  @Mock private RequestQueuePort requestQueuePort;

  @Test
  void getName_whenCalled_returnsConstant() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    ListPersistentRequestsMessage message = new ListPersistentRequestsMessage(fs);

    assertEquals("ListPersistentRequests", message.getName());
  }

  @Test
  void getFieldSet_whenCalled_isEmptyFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    ListPersistentRequestsMessage message = new ListPersistentRequestsMessage(fs);

    String serialized = message.getFieldSet().toOrderedString();

    assertEquals("End\n", serialized);
  }

  @Test
  void run_whenWatchGlobalDisabled_sendsEndAfterLocalClients() throws Exception {
    String identifier = "req-1";
    ListPersistentRequestsMessage message = new ListPersistentRequestsMessage(fieldSet(identifier));

    FCPConnectionOutputHandler outputHandler = newOutputHandler();
    PersistentRequestClient rebootClient = mock(PersistentRequestClient.class);
    PersistentRequestClient foreverClient = mock(PersistentRequestClient.class);
    when(handler.getRebootClient()).thenReturn(rebootClient);
    when(handler.getForeverClient()).thenReturn(foreverClient);
    mockQueuesReturningEmpty(identifier, outputHandler, rebootClient, foreverClient);
    executePersistentTasksImmediately();

    message.run(handler, null);

    ArgumentCaptor<EndListPersistentRequestsMessage> captor =
        ArgumentCaptor.forClass(EndListPersistentRequestsMessage.class);
    verify(handler).send(captor.capture());
    assertEquals(identifier, captor.getValue().getFieldSet().get("Identifier"));
    verify(requestQueuePort).submitPersistentJob(any(), eq(RequestQueuePriority.LISTING));
    verify(rebootClient).queuePendingMessagesOnConnectionRestart(outputHandler, identifier, 0, 30);
    verify(rebootClient).queuePendingMessagesFromRunningRequests(outputHandler, identifier, 0, 30);
    verify(foreverClient).queuePendingMessagesOnConnectionRestart(outputHandler, identifier, 0, 30);
    verify(foreverClient).queuePendingMessagesFromRunningRequests(outputHandler, identifier, 0, 30);
  }

  @Test
  void run_whenWatchGlobalEnabled_includesGlobalQueuesThenEnds() throws Exception {
    String identifier = "req-global";
    ListPersistentRequestsMessage message = new ListPersistentRequestsMessage(fieldSet(identifier));

    FCPConnectionOutputHandler outputHandler = newOutputHandler();
    PersistentRequestClient rebootClient = mock(PersistentRequestClient.class);
    rebootClient.watchGlobal = true;
    PersistentRequestClient foreverClient = mock(PersistentRequestClient.class);
    PersistentRequestClient globalRebootClient = mock(PersistentRequestClient.class);
    PersistentRequestClient globalForeverClient = mock(PersistentRequestClient.class);

    when(handler.getRebootClient()).thenReturn(rebootClient);
    when(handler.getForeverClient()).thenReturn(foreverClient);
    when(server.getGlobalRebootClient()).thenReturn(globalRebootClient);
    when(server.getGlobalForeverClient()).thenReturn(globalForeverClient);
    mockQueuesReturningEmpty(identifier, outputHandler, rebootClient, foreverClient);
    mockQueuesReturningEmpty(identifier, outputHandler, globalRebootClient, globalForeverClient);
    executePersistentTasksImmediately();

    message.run(handler, null);

    verify(handler).send(any(EndListPersistentRequestsMessage.class));
    verify(requestQueuePort, times(1)).submitPersistentJob(any(), eq(RequestQueuePriority.LISTING));
    verify(globalRebootClient)
        .queuePendingMessagesOnConnectionRestart(outputHandler, identifier, 0, 30);
    verify(globalForeverClient)
        .queuePendingMessagesFromRunningRequests(outputHandler, identifier, 0, 30);
  }

  @Test
  void transientListJob_whenOutputQueueHalfFull_reschedulesViaRequestQueuePort() {
    FCPConnectionOutputHandler outputHandler = mock(FCPConnectionOutputHandler.class);
    when(outputHandler.isQueueHalfFull()).thenReturn(true);

    PersistentRequestClient client = mock(PersistentRequestClient.class);
    TrackingTransientListJob job =
        new TrackingTransientListJob(client, outputHandler, requestQueuePort, "id");

    job.run();

    verify(requestQueuePort).scheduleLater(job, 100L);
    verifyNoInteractions(client);
    assertFalse(job.completed);
  }

  @Test
  void persistentListJob_whenRun_submitsListingTaskViaRequestQueuePort() throws Exception {
    FCPConnectionOutputHandler outputHandler = mock(FCPConnectionOutputHandler.class);
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    TrackingPersistentListJob job =
        new TrackingPersistentListJob(client, outputHandler, requestQueuePort, "id");

    job.run();

    ArgumentCaptor<RequestQueueTask> taskCaptor = ArgumentCaptor.forClass(RequestQueueTask.class);
    verify(requestQueuePort)
        .submitPersistentJob(taskCaptor.capture(), eq(RequestQueuePriority.LISTING));
    assertFalse(job.completed);
    assertFalse(taskCaptor.getValue().run());
  }

  @Test
  void listJob_whenProgressAdvances_offsetsIncrementAndCompletes() {
    FCPConnectionOutputHandler outputHandler = mock(FCPConnectionOutputHandler.class);
    when(outputHandler.isQueueHalfFull()).thenReturn(false);

    PersistentRequestClient client = mock(PersistentRequestClient.class);
    when(client.queuePendingMessagesOnConnectionRestart(
            eq(outputHandler), eq("id"), anyInt(), anyInt()))
        .thenReturn(1, 1);
    when(client.queuePendingMessagesFromRunningRequests(
            eq(outputHandler), eq("id"), anyInt(), anyInt()))
        .thenReturn(0);

    TrackingListJob job = new TrackingListJob(client, outputHandler, "id", false);

    boolean result = job.execute();

    assertFalse(result);
    assertTrue(job.completed);

    ArgumentCaptor<Integer> restartOffsets = ArgumentCaptor.forClass(Integer.class);
    verify(client, times(2))
        .queuePendingMessagesOnConnectionRestart(
            eq(outputHandler), eq("id"), restartOffsets.capture(), eq(30));
    assertEquals(0, restartOffsets.getAllValues().get(0));
    assertEquals(1, restartOffsets.getAllValues().get(1));
  }

  private FCPConnectionOutputHandler newOutputHandler() {
    when(server.maxMessageQueueLength()).thenReturn(10);
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.requestQueue()).thenReturn(requestQueuePort);
    FCPConnectionOutputHandler outputHandler = new FCPConnectionOutputHandler(handler);
    when(handler.getOutputHandler()).thenReturn(outputHandler);
    return outputHandler;
  }

  private void executePersistentTasksImmediately() throws Exception {
    doAnswer(
            invocation -> {
              RequestQueueTask task = invocation.getArgument(0);
              task.run();
              return null;
            })
        .when(requestQueuePort)
        .submitPersistentJob(any(), eq(RequestQueuePriority.LISTING));
  }

  private static void mockQueuesReturningEmpty(
      String identifier,
      FCPConnectionOutputHandler outputHandler,
      PersistentRequestClient rebootClient,
      PersistentRequestClient foreverClient) {
    when(rebootClient.queuePendingMessagesOnConnectionRestart(
            eq(outputHandler), eq(identifier), anyInt(), anyInt()))
        .thenReturn(0);
    when(rebootClient.queuePendingMessagesFromRunningRequests(
            eq(outputHandler), eq(identifier), anyInt(), anyInt()))
        .thenReturn(0);
    when(foreverClient.queuePendingMessagesOnConnectionRestart(
            eq(outputHandler), eq(identifier), anyInt(), anyInt()))
        .thenReturn(0);
    when(foreverClient.queuePendingMessagesFromRunningRequests(
            eq(outputHandler), eq(identifier), anyInt(), anyInt()))
        .thenReturn(0);
  }

  private static SimpleFieldSet fieldSet(String identifier) {
    SimpleFieldSet input = new SimpleFieldSet(true);
    input.putSingle("Identifier", identifier);
    return input;
  }

  private static class TrackingListJob extends ListPersistentRequestsMessage.ListJob {
    boolean completed;
    private final boolean noRunning;

    TrackingListJob(
        PersistentRequestClient client,
        FCPConnectionOutputHandler outputHandler,
        String listRequestIdentifier,
        boolean noRunning) {
      super(client, outputHandler, listRequestIdentifier);
      this.noRunning = noRunning;
    }

    @Override
    void reschedule() {
      // No-op for this focused progress test.
    }

    @Override
    void complete() {
      completed = true;
    }

    @Override
    protected boolean noRunning() {
      return noRunning;
    }
  }

  private static final class TrackingTransientListJob
      extends ListPersistentRequestsMessage.TransientListJob {
    boolean completed;

    TrackingTransientListJob(
        PersistentRequestClient client,
        FCPConnectionOutputHandler outputHandler,
        RequestQueuePort requestQueuePort,
        String listRequestIdentifier) {
      super(client, outputHandler, requestQueuePort, listRequestIdentifier);
    }

    @Override
    void complete() {
      completed = true;
    }
  }

  private static final class TrackingPersistentListJob
      extends ListPersistentRequestsMessage.PersistentListJob {
    boolean completed;

    TrackingPersistentListJob(
        PersistentRequestClient client,
        FCPConnectionOutputHandler outputHandler,
        RequestQueuePort requestQueuePort,
        String listRequestIdentifier) {
      super(client, outputHandler, requestQueuePort, listRequestIdentifier, () -> {});
    }

    @Override
    void complete() {
      completed = true;
    }
  }
}
