package network.crypta.clients.fcp;

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

import java.util.Random;
import network.crypta.client.ArchiveManager;
import network.crypta.client.FetchContext;
import network.crypta.client.InsertContext;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientContextDefaults;
import network.crypta.client.async.ClientContextRafFactories;
import network.crypta.client.async.ClientContextRuntime;
import network.crypta.client.async.ClientContextServices;
import network.crypta.client.async.ClientContextStorageFactories;
import network.crypta.client.async.ClientLayerPersister;
import network.crypta.client.async.DatastoreChecker;
import network.crypta.client.async.HealingQueue;
import network.crypta.client.async.PersistentJob;
import network.crypta.client.async.USKManager;
import network.crypta.client.filter.LinkFilterExceptionProvider;
import network.crypta.config.Config;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.node.ClientContextResources;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.Ticker;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.compress.RealCompressor;
import network.crypta.support.io.FileRandomAccessBufferFactory;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.PersistentFileTracker;
import network.crypta.support.io.PersistentTempBucketFactory;
import network.crypta.support.io.TempBucketFactory;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ListPersistentRequestsMessageTest {

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
    SimpleFieldSet input = new SimpleFieldSet(true);
    input.putSingle("Identifier", identifier);
    ListPersistentRequestsMessage message = new ListPersistentRequestsMessage(input);

    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    FCPServer server = mock(FCPServer.class);
    when(server.maxMessageQueueLength()).thenReturn(10);
    when(handler.getServer()).thenReturn(server);

    FCPConnectionOutputHandler outputHandler = new FCPConnectionOutputHandler(handler);
    when(handler.getOutputHandler()).thenReturn(outputHandler);

    PersistentRequestClient rebootClient = mock(PersistentRequestClient.class);
    PersistentRequestClient foreverClient = mock(PersistentRequestClient.class);
    when(handler.getRebootClient()).thenReturn(rebootClient);
    when(handler.getForeverClient()).thenReturn(foreverClient);

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

    ClientLayerPersister jobRunner = mock(ClientLayerPersister.class);
    Ticker ticker = mock(Ticker.class);
    ClientContext context = newClientContext(jobRunner, ticker);
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    when(node.getClientCore()).thenReturn(core);
    when(core.getClientContext()).thenReturn(context);

    doAnswer(
            invocation -> {
              PersistentJob job = invocation.getArgument(0);
              return job.run(context);
            })
        .when(jobRunner)
        .queue(any(PersistentJob.class), anyInt());

    message.run(handler, node);

    ArgumentCaptor<EndListPersistentRequestsMessage> captor =
        ArgumentCaptor.forClass(EndListPersistentRequestsMessage.class);
    verify(handler).send(captor.capture());
    assertEquals(identifier, captor.getValue().getFieldSet().get("Identifier"));

    verify(rebootClient).queuePendingMessagesOnConnectionRestart(outputHandler, identifier, 0, 30);
    verify(rebootClient).queuePendingMessagesFromRunningRequests(outputHandler, identifier, 0, 30);
    verify(foreverClient).queuePendingMessagesOnConnectionRestart(outputHandler, identifier, 0, 30);
    verify(foreverClient).queuePendingMessagesFromRunningRequests(outputHandler, identifier, 0, 30);
  }

  @Test
  void run_whenWatchGlobalEnabled_includesGlobalQueuesThenEnds() throws Exception {
    String identifier = "req-global";
    SimpleFieldSet input = new SimpleFieldSet(true);
    input.putSingle("Identifier", identifier);
    ListPersistentRequestsMessage message = new ListPersistentRequestsMessage(input);

    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    FCPServer server = mock(FCPServer.class);
    when(server.maxMessageQueueLength()).thenReturn(10);
    when(handler.getServer()).thenReturn(server);

    FCPConnectionOutputHandler outputHandler = new FCPConnectionOutputHandler(handler);
    when(handler.getOutputHandler()).thenReturn(outputHandler);

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

    ClientLayerPersister jobRunner = mock(ClientLayerPersister.class);
    Ticker ticker = mock(Ticker.class);
    ClientContext context = newClientContext(jobRunner, ticker);
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    when(node.getClientCore()).thenReturn(core);
    when(core.getClientContext()).thenReturn(context);

    doAnswer(
            invocation -> {
              PersistentJob job = invocation.getArgument(0);
              return job.run(context);
            })
        .when(jobRunner)
        .queue(any(PersistentJob.class), anyInt());

    message.run(handler, node);

    verify(handler).send(any(EndListPersistentRequestsMessage.class));
    verify(globalRebootClient)
        .queuePendingMessagesOnConnectionRestart(outputHandler, identifier, 0, 30);
    verify(globalForeverClient)
        .queuePendingMessagesFromRunningRequests(outputHandler, identifier, 0, 30);
  }

  @Test
  void listJob_whenOutputQueueHalfFull_reschedulesAndStops() {
    FCPConnectionOutputHandler outputHandler = mock(FCPConnectionOutputHandler.class);
    when(outputHandler.isQueueHalfFull()).thenReturn(true);

    PersistentRequestClient client = mock(PersistentRequestClient.class);
    TrackingListJob job = new TrackingListJob(client, outputHandler, "id", true);

    boolean result = job.run(null);

    assertFalse(result, "run should stop when rescheduled");
    assertTrue(job.rescheduled, "reschedule should be invoked");
    verifyNoInteractions(client);
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

    boolean result = job.run(null);

    assertFalse(result);
    assertTrue(job.completed);

    ArgumentCaptor<Integer> restartOffsets = ArgumentCaptor.forClass(Integer.class);
    verify(client, times(2))
        .queuePendingMessagesOnConnectionRestart(
            eq(outputHandler), eq("id"), restartOffsets.capture(), eq(30));
    assertEquals(0, restartOffsets.getAllValues().get(0));
    assertEquals(1, restartOffsets.getAllValues().get(1));
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

  private static ClientContext newClientContext(ClientLayerPersister jobRunner, Ticker ticker) {
    PriorityAwareExecutor executor =
        new PriorityAwareExecutor() {

          @Override
          public void execute(@NotNull Runnable job) {
            job.run();
          }

          @Override
          public void execute(@NotNull Runnable job, String jobName) {
            job.run();
          }

          @Override
          public void execute(@NotNull Runnable job, String jobName, boolean fromTicker) {
            job.run();
          }

          @Override
          public int[] waitingThreads() {
            return new int[0];
          }

          @Override
          public int[] runningThreads() {
            return new int[0];
          }

          @Override
          public int getWaitingThreadsCount() {
            return 0;
          }
        };

    return new ClientContext(
        1L,
        new ClientContextRuntime(
            jobRunner,
            executor,
            mock(MemoryLimitedJobRunner.class),
            ticker,
            mock(RandomSource.class),
            new Random(0),
            mock(MasterSecret.class)),
        new ClientContextStorageFactories(
            mock(PersistentTempBucketFactory.class),
            mock(TempBucketFactory.class),
            mock(PersistentFileTracker.class),
            mock(FilenameGenerator.class),
            mock(FilenameGenerator.class),
            mock(FileRandomAccessBufferFactory.class),
            mock(FileRandomAccessBufferFactory.class)),
        new ClientContextRafFactories(
            mock(LockableRandomAccessBufferFactory.class),
            mock(LockableRandomAccessBufferFactory.class)),
        new ClientContextServices(
            new ClientContextResources(mock(ArchiveManager.class), mock(HealingQueue.class)),
            mock(USKManager.class),
            mock(RealCompressor.class),
            mock(DatastoreChecker.class),
            mock(PersistentRequestRoot.class),
            mock(LinkFilterExceptionProvider.class)),
        new ClientContextDefaults(
            mock(FetchContext.class), mock(InsertContext.class), mock(Config.class)));
  }

  private static class TrackingListJob extends ListPersistentRequestsMessage.ListJob {
    boolean rescheduled;
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
    void reschedule(ClientContext context) {
      rescheduled = true;
    }

    @Override
    void complete(ClientContext context) {
      completed = true;
    }

    @Override
    protected boolean noRunning() {
      return noRunning;
    }
  }
}
