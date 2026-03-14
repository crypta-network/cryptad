package network.crypta.clients.fcp;

import java.lang.reflect.Field;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientRequester;
import network.crypta.client.async.PersistentJob;
import network.crypta.client.async.PersistentJobRunner;
import network.crypta.node.NodeClientCore;
import network.crypta.node.PrioRunnable;
import network.crypta.runtime.spi.ExecutionPort;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.io.NativeThread;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class ClientRequestRestartAsyncTest {

  @Test
  void restartAsync_whenPersistenceNotForever_submitsPrioRunnableThroughRuntimeExecution()
      throws Exception {
    // Arrange
    ExecutionPort executionPort = mock(ExecutionPort.class);
    RuntimePorts runtimePorts = mock(RuntimePorts.class);
    when(runtimePorts.execution()).thenReturn(executionPort);
    PersistentJobRunner jobRunner = mock(PersistentJobRunner.class);
    ClientContext context = newContextWithJobRunner(jobRunner);
    NodeClientCore core = mock(NodeClientCore.class);
    when(core.getClientContext()).thenReturn(context);
    FCPServer server = mock(FCPServer.class);
    when(server.runtime()).thenReturn(runtimePorts);
    when(server.getCore()).thenReturn(core);
    TestClientRequest request = TestClientRequest.connection();
    request.markStarted();

    // Act
    request.restartAsync(server, true);

    // Assert
    assertFalse(request.isStarted());
    ArgumentCaptor<Runnable> taskCaptor = ArgumentCaptor.forClass(Runnable.class);
    verify(executionPort).execute(taskCaptor.capture(), eq("Restart request"));
    verify(jobRunner, never()).queue(any(PersistentJob.class), anyInt());
    Runnable submittedTask = taskCaptor.getValue();
    PrioRunnable prioRunnable = assertInstanceOf(PrioRunnable.class, submittedTask);
    assertEquals(NativeThread.PriorityLevel.NORM_PRIORITY.value, prioRunnable.getPriority());

    submittedTask.run();

    assertEquals(1, request.restartCalls);
    assertSame(context, request.lastRestartContext);
    assertTrue(request.lastDisableFilterData);
  }

  @Test
  void restartAsync_whenPersistenceForever_queuesPersistentJobRunnerAndLeavesExecutionPortUnused()
      throws Exception {
    // Arrange
    ExecutionPort executionPort = mock(ExecutionPort.class);
    RuntimePorts runtimePorts = mock(RuntimePorts.class);
    when(runtimePorts.execution()).thenReturn(executionPort);
    PersistentJobRunner jobRunner = mock(PersistentJobRunner.class);
    ClientContext context = newContextWithJobRunner(jobRunner);
    NodeClientCore core = mock(NodeClientCore.class);
    when(core.getClientContext()).thenReturn(context);
    FCPServer server = mock(FCPServer.class);
    when(server.runtime()).thenReturn(runtimePorts);
    when(server.getCore()).thenReturn(core);
    TestClientRequest request = TestClientRequest.forever();
    request.markStarted();

    // Act
    request.restartAsync(server, false);

    // Assert
    assertFalse(request.isStarted());
    ArgumentCaptor<PersistentJob> jobCaptor = ArgumentCaptor.forClass(PersistentJob.class);
    verify(jobRunner)
        .queue(jobCaptor.capture(), eq(NativeThread.PriorityLevel.HIGH_PRIORITY.value));
    verify(executionPort, never()).execute(any(), anyString());

    boolean checkpointRequested = jobCaptor.getValue().run(context);

    assertTrue(checkpointRequested);
    assertEquals(1, request.restartCalls);
    assertSame(context, request.lastRestartContext);
    assertFalse(request.lastDisableFilterData);
  }

  @SuppressWarnings("java:S3011")
  private static ClientContext newContextWithJobRunner(PersistentJobRunner jobRunner) {
    ClientContext context =
        Mockito.mock(
            ClientContext.class, Mockito.withSettings().defaultAnswer(Mockito.CALLS_REAL_METHODS));
    try {
      Field field = ClientContext.class.getDeclaredField("jobRunner");
      field.setAccessible(true);
      field.set(context, jobRunner);
      return context;
    } catch (ReflectiveOperationException e) {
      throw new LinkageError("Failed to set ClientContext.jobRunner", e);
    }
  }

  private static final class TestClientRequest extends ClientRequest {
    private ClientContext lastRestartContext;
    private boolean lastDisableFilterData;
    private int restartCalls;

    private TestClientRequest(ConstructorInit init) {
      super(init);
    }

    static TestClientRequest connection() {
      return new TestClientRequest(
          prepareConstructorInit(
              new ClientRequestParams(
                  null,
                  "connection-request",
                  0,
                  (short) 1,
                  Persistence.CONNECTION,
                  false,
                  null,
                  false),
              null));
    }

    static TestClientRequest forever() {
      PersistentRequestRoot root = new PersistentRequestRoot();
      PersistentRequestClient client = root.registerForeverClient("restart-client", null);
      return new TestClientRequest(
          prepareConstructorInit(
              new ClientRequestParams(
                  null, "forever-request", 0, (short) 1, Persistence.FOREVER, false, null, false),
              null,
              client));
    }

    void markStarted() {
      started = true;
    }

    @Override
    public void onLostConnection(ClientContext context) {
      // This test double only exercises restart scheduling and does not simulate connection loss.
    }

    @Override
    public void sendPendingMessages(
        FCPConnectionOutputHandler handler,
        String listRequestIdentifier,
        boolean includeData,
        boolean onlyData) {
      // Restart scheduling does not emit pending FCP messages in this focused test.
    }

    @Override
    void register(boolean noTags) {
      // The test invokes restartAsync() directly and does not participate in normal registration.
    }

    @Override
    protected ClientRequester getClientRequest() {
      return null;
    }

    @Override
    protected void freeData() {
      // The test request never allocates external data that needs explicit cleanup.
    }

    @Override
    public double getSuccessFraction() {
      return 0;
    }

    @Override
    public double getTotalBlocks() {
      return 0;
    }

    @Override
    public double getMinBlocks() {
      return 0;
    }

    @Override
    public double getFetchedBlocks() {
      return 0;
    }

    @Override
    public double getFailedBlocks() {
      return 0;
    }

    @Override
    public double getFatalyFailedBlocks() {
      return 0;
    }

    @Override
    public String getFailureReason(boolean longDescription) {
      return "failure";
    }

    @Override
    public boolean isTotalFinalized() {
      return true;
    }

    @Override
    public void start(ClientContext context) {
      // Starting the request is outside this test's scope; only restart dispatch is validated.
    }

    @Override
    public boolean hasSucceeded() {
      return false;
    }

    @Override
    public boolean canRestart() {
      return true;
    }

    @Override
    public boolean restart(ClientContext context, boolean disableFilterData) {
      restartCalls++;
      lastRestartContext = context;
      lastDisableFilterData = disableFilterData;
      return true;
    }

    @Override
    RequestStatus getStatus() {
      return null;
    }

    @Override
    protected void innerResume(ClientContext context) {
      // This focused test covers restartAsync() only and does not model resume behavior.
    }

    @Override
    RequestIdentifier.RequestType getType() {
      return RequestIdentifier.RequestType.GET;
    }

    @Override
    public boolean fullyResumed() {
      return true;
    }
  }
}
