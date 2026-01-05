package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.PersistentJob;
import network.crypta.client.async.USKManager;
import network.crypta.client.filter.LinkFilterExceptionProvider;
import network.crypta.config.Config;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.node.ClientContextResources;
import network.crypta.node.ClientEndpoints;
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
import network.crypta.support.io.NativeThread;
import network.crypta.support.io.PersistentFileTracker;
import network.crypta.support.io.PersistentTempBucketFactory;
import network.crypta.support.io.TempBucketFactory;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // test method naming: method_whenCondition_expectOutcome
class ModifyPersistentRequestTest {

  // ---------- Constructor validation ----------

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
    // RequestStarter.PAUSED_PRIORITY_CLASS == 6, MAXIMUM_PRIORITY_CLASS == 0
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

  // ---------- getFieldSet / getName ----------

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

  // ---------- run(): reboot request path ----------

  @Test
  void run_whenRebootRequestExists_modifiesRequestViaNodeFcpServer() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-7");
    fs.put("Global", false);
    fs.putSingle("PriorityClass", "1");
    fs.putSingle("ClientToken", "tok");
    ModifyPersistentRequest message = new ModifyPersistentRequest(fs);

    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    ClientRequest rebootRequest = mock(ClientRequest.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeClientCore core = mock(NodeClientCore.class);
    FCPServer server = mock(FCPServer.class);

    when(handler.getRebootRequest(false, handler, "req-7")).thenReturn(rebootRequest);
    network.crypta.node.subsystem.NodeServicesSubsystem services =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    when(services.clientCore()).thenReturn(core);
    ClientEndpoints endpoints = mock(ClientEndpoints.class);
    when(core.getEndpoints()).thenReturn(endpoints);
    when(endpoints.getFCPServer()).thenReturn(server);

    message.run(handler, node);

    verify(handler, times(1)).getRebootRequest(false, handler, "req-7");
    verify(rebootRequest, times(1)).modifyRequest("tok", (short) 1, server);
    verify(handler, never()).send(any(FCPMessage.class));
  }

  // ---------- run(): forever request path via job runner ----------

  @Test
  void run_whenRebootRequestMissingAndForeverRequestExists_modifiesRequestViaHandlerServer()
      throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-8");
    fs.put("Global", false);
    fs.putSingle("PriorityClass", "4");
    fs.putSingle("ClientToken", "new-token");
    ModifyPersistentRequest message = new ModifyPersistentRequest(fs);

    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    ClientRequest foreverRequest = mock(ClientRequest.class);
    FCPServer server = mock(FCPServer.class);
    when(handler.getRebootRequest(false, handler, "req-8")).thenReturn(null);
    when(handler.getForeverRequest(false, handler, "req-8")).thenReturn(foreverRequest);
    when(handler.getServer()).thenReturn(server);

    ClientLayerPersister jobRunner = mock(ClientLayerPersister.class);
    Ticker ticker = mock(Ticker.class);
    ClientContext context = newClientContext(jobRunner, ticker);
    NodeClientCore core = mock(NodeClientCore.class);
    when(core.getClientContext()).thenReturn(context);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    network.crypta.node.subsystem.NodeServicesSubsystem services =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    when(services.clientCore()).thenReturn(core);

    doAnswer(
            invocation -> {
              PersistentJob job = invocation.getArgument(0);
              job.run(context);
              return null;
            })
        .when(jobRunner)
        .queue(any(PersistentJob.class), anyInt());

    message.run(handler, node);

    verify(jobRunner, times(1))
        .queue(any(PersistentJob.class), eq(NativeThread.PriorityLevel.NORM_PRIORITY.value));
    verify(handler, times(1)).getForeverRequest(false, handler, "req-8");
    verify(foreverRequest, times(1)).modifyRequest("new-token", (short) 4, server);
    verify(handler, never()).send(any(ProtocolErrorMessage.class));
  }

  @Test
  void run_whenRebootAndForeverRequestsMissing_sendsNoSuchIdentifierErrorFromJob()
      throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-9");
    fs.put("Global", false);
    ModifyPersistentRequest message = new ModifyPersistentRequest(fs);

    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    when(handler.getRebootRequest(false, handler, "req-9")).thenReturn(null);
    when(handler.getForeverRequest(false, handler, "req-9")).thenReturn(null);

    ClientLayerPersister jobRunner = mock(ClientLayerPersister.class);
    Ticker ticker = mock(Ticker.class);
    ClientContext context = newClientContext(jobRunner, ticker);
    NodeClientCore core = mock(NodeClientCore.class);
    when(core.getClientContext()).thenReturn(context);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    network.crypta.node.subsystem.NodeServicesSubsystem services =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    when(services.clientCore()).thenReturn(core);

    ArgumentCaptor<ProtocolErrorMessage> errorCaptor =
        ArgumentCaptor.forClass(ProtocolErrorMessage.class);

    doAnswer(
            invocation -> {
              PersistentJob job = invocation.getArgument(0);
              job.run(context);
              return null;
            })
        .when(jobRunner)
        .queue(any(PersistentJob.class), anyInt());

    message.run(handler, node);

    verify(handler, times(1)).send(errorCaptor.capture());
    ProtocolErrorMessage error = errorCaptor.getValue();
    assertNotNull(error);
    assertEquals(ProtocolErrorMessage.NO_SUCH_IDENTIFIER, error.getCode());
    assertFalse(error.fatal);
    assertEquals("req-9", error.ident);
    assertFalse(error.global);
    assertNull(error.extra);
  }

  // ---------- run(): persistence disabled path ----------

  @Test
  void run_whenPersistenceDisabled_sendsNoSuchIdentifierErrorImmediately() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-10");
    fs.put("Global", true);
    ModifyPersistentRequest message = new ModifyPersistentRequest(fs);

    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    when(handler.getRebootRequest(true, handler, "req-10")).thenReturn(null);

    ClientLayerPersister jobRunner = mock(ClientLayerPersister.class);
    Ticker ticker = mock(Ticker.class);
    ClientContext context = newClientContext(jobRunner, ticker);
    NodeClientCore core = mock(NodeClientCore.class);
    when(core.getClientContext()).thenReturn(context);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    network.crypta.node.subsystem.NodeServicesSubsystem services =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    when(services.clientCore()).thenReturn(core);

    doThrow(new PersistenceDisabledException())
        .when(jobRunner)
        .queue(any(PersistentJob.class), anyInt());

    ArgumentCaptor<ProtocolErrorMessage> errorCaptor =
        ArgumentCaptor.forClass(ProtocolErrorMessage.class);

    message.run(handler, node);

    verify(handler, times(1)).send(errorCaptor.capture());
    verify(handler, never())
        .getForeverRequest(anyBoolean(), any(FCPConnectionHandler.class), anyString());
    ProtocolErrorMessage error = errorCaptor.getValue();
    assertEquals(ProtocolErrorMessage.NO_SUCH_IDENTIFIER, error.getCode());
    assertFalse(error.fatal);
    assertEquals("req-10", error.ident);
    assertTrue(error.global);
    assertNull(error.extra);
  }

  @Test
  void run_whenRebootRequestExists_doesNotInteractWithJobRunner() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-11");
    fs.put("Global", false);
    ModifyPersistentRequest message = new ModifyPersistentRequest(fs);

    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    ClientRequest rebootRequest = mock(ClientRequest.class);
    when(handler.getRebootRequest(false, handler, "req-11")).thenReturn(rebootRequest);

    ClientLayerPersister jobRunner = mock(ClientLayerPersister.class);
    NodeClientCore core = mock(NodeClientCore.class);
    ClientEndpoints endpoints = mock(ClientEndpoints.class);
    when(core.getEndpoints()).thenReturn(endpoints);
    when(endpoints.getFCPServer()).thenReturn(mock(FCPServer.class));
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    network.crypta.node.subsystem.NodeServicesSubsystem services =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    when(services.clientCore()).thenReturn(core);

    message.run(handler, node);

    verifyNoInteractions(jobRunner);
  }

  // ---------- Test helpers ----------

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
}
