package network.crypta.client.async;

import java.io.Serial;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.node.ClientContextResources;
import network.crypta.node.Node;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestStarter;
import network.crypta.node.SendableGet;
import network.crypta.node.SendableRequestItem;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.io.NativeThread;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class DatastoreCheckerTest {
  private static final String THREAD_NAME = "ds-check";

  private static class TestExecutor implements PriorityAwareExecutor {
    final List<Runnable> submitted = new ArrayList<>();
    boolean runInline = true;

    @Override
    public void execute(@NotNull Runnable job) {
      if (runInline) job.run();
      else submitted.add(job);
    }

    @Override
    public void execute(Runnable job, String jobName) {
      execute(job);
    }

    @Override
    public void execute(Runnable job, String jobName, boolean fromTicker) {
      execute(job);
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

    void runCaptured() {
      for (Runnable r : submitted) {
        r.run();
      }
      submitted.clear();
    }
  }

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private ClientRequestScheduler scheduler;

  private TestExecutor executor;

  @BeforeEach
  void setup() {
    executor = new TestExecutor();
  }

  // --- Minimal concrete request types for deterministic tests ---

  private record TestRequestClient(boolean persistent, boolean rt) implements RequestClient {

    @Override
    public boolean realTimeFlag() {
      return rt;
    }
  }

  private static class TestRequester extends ClientRequester {
    TestRequester(short prio, RequestClient client) {
      super(prio, client);
    }

    @Override
    public void onTransition(
        ClientGetState oldState, ClientGetState newState, ClientContext context) {
      // Intentionally blank: no-op test stub
    }

    @Override
    public void cancel(ClientContext context) {
      // Intentionally blank: no-op test stub
    }

    @Override
    public network.crypta.keys.FreenetURI getURI() {
      return null;
    }

    @Override
    public boolean isFinished() {
      return false;
    }

    @Override
    protected void innerNotifyClients(ClientContext context) {
      // Intentionally blank: no-op test stub
    }

    @Override
    protected void innerToNetwork(ClientContext context) {
      // Intentionally blank: no-op test stub
    }

    @Override
    protected ClientBaseCallback getCallback() {
      return new ClientBaseCallback() {
        @Override
        public void onResume(ClientContext context) {
          // Intentionally blank: no-op test stub
        }

        @Override
        public RequestClient getRequestClient() {
          return getClient();
        }
      };
    }
  }

  private static class TestSendableGet extends SendableGet {
    @Serial private static final long serialVersionUID = 1L;

    private final short prio;
    private final transient Key[] keys;
    private final transient ClientRequestScheduler sched;
    private final boolean isSSK;

    TestSendableGet(
        ClientRequester parent,
        boolean realTime,
        short prio,
        Key[] keys,
        ClientRequestScheduler sched,
        boolean isSSK) {
      super(parent, realTime);
      this.prio = prio;
      this.keys = keys;
      this.sched = sched;
      this.isSSK = isSSK;
    }

    @Override
    public network.crypta.keys.ClientKey getKey(SendableRequestItem token) {
      return null;
    }

    @Override
    public Key[] listKeys() {
      return keys;
    }

    @Override
    public network.crypta.client.FetchContext getContext() {
      return null;
    }

    @Override
    public void onFailure(
        network.crypta.node.LowLevelGetException e,
        SendableRequestItem token,
        ClientContext context) {
      // Intentionally blank: failure handling is not exercised in these tests
    }

    @Override
    public long getCooldownWakeup(SendableRequestItem token, ClientContext context) {
      return 0;
    }

    @Override
    public boolean preRegister(ClientContext context, boolean toNetwork) {
      return false;
    }

    @Override
    public SendableRequestItem chooseKey(
        network.crypta.node.KeysFetchingLocally keys, ClientContext context) {
      return null;
    }

    @Override
    public long countAllKeys(ClientContext context) {
      return keys == null ? 0 : keys.length;
    }

    @Override
    public long countSendableKeys(ClientContext context) {
      return keys == null ? 0 : keys.length;
    }

    @Override
    public network.crypta.node.SendableRequestSender getSender(ClientContext context) {
      return null;
    }

    @Override
    public boolean isCancelled() {
      return false;
    }

    @Override
    public RequestClient getClient() {
      return parent == null ? null : parent.client;
    }

    @Override
    public ClientRequester getClientRequest() {
      return parent;
    }

    @Override
    public short getPriorityClass() {
      return prio;
    }

    @Override
    public ClientRequestScheduler getScheduler(ClientContext context) {
      return sched;
    }

    @Override
    public boolean isSSK() {
      return isSSK;
    }

    @Override
    protected ClientGetState getClientGetState() {
      return null;
    }

    @Override
    public long getWakeupTime(ClientContext context, long now) {
      return 0; // ready now
    }
  }

  @Test
  void getPriority_returnsNormPriorityValue() {
    DatastoreChecker checker = new DatastoreChecker(node, true, executor, THREAD_NAME);
    assertEquals(NativeThread.PriorityLevel.NORM_PRIORITY.value, checker.getPriority());
  }

  @Test
  void queueRequest_nonPersistent_allBlocksFound_tripsKeysAndFinishesWithAnyValidFalse() {
    DatastoreChecker checker = new DatastoreChecker(node, true, executor, THREAD_NAME);

    ClientContext ctx = mock(ClientContext.class);
    checker.setContext(ctx);

    Key k1 = mock(Key.class);
    Key k2 = mock(Key.class);
    TestRequester parent =
        new TestRequester(
            RequestStarter.MAXIMUM_PRIORITY_CLASS, new TestRequestClient(false, false));
    SendableGet getter =
        new TestSendableGet(
            parent,
            false,
            RequestStarter.MAXIMUM_PRIORITY_CLASS,
            new Key[] {k1, k2},
            scheduler,
            false);

    BlockSet blocks = mock(BlockSet.class);
    KeyBlock b1 = mock(KeyBlock.class);
    KeyBlock b2 = mock(KeyBlock.class);
    when(blocks.get(k1)).thenReturn(b1);
    when(blocks.get(k2)).thenReturn(b2);

    checker.queueRequest(getter, blocks);

    // Executor runs inline; DatastoreChecker should process immediately and then terminate lazily.
    verify(scheduler, times(2)).tripPendingKey(any(KeyBlock.class));
    verify(scheduler, times(1))
        .finishRegister(
            argThat(arr -> arr.length == 1 && getter.equals(arr[0])), eq(false), eq(false));
  }

  @Test
  void queueRequest_nonPersistent_someBlocksMissing_tripsFoundAndFinishesWithAnyValidTrue() {
    DatastoreChecker checker = new DatastoreChecker(node, true, executor, THREAD_NAME);

    ClientContext ctx = mock(ClientContext.class);
    checker.setContext(ctx);

    Key k1 = mock(Key.class);
    Key k2 = mock(Key.class);
    TestRequester parent =
        new TestRequester(
            RequestStarter.INTERACTIVE_PRIORITY_CLASS, new TestRequestClient(false, false));
    SendableGet getter =
        new TestSendableGet(
            parent,
            false,
            RequestStarter.INTERACTIVE_PRIORITY_CLASS,
            new Key[] {k1, k2},
            scheduler,
            false);

    BlockSet blocks = mock(BlockSet.class);
    KeyBlock b1 = mock(KeyBlock.class);
    when(blocks.get(k1)).thenReturn(b1);
    when(blocks.get(k2)).thenReturn(null);

    checker.queueRequest(getter, blocks);

    verify(scheduler, times(1)).tripPendingKey(b1);
    verify(scheduler, times(1))
        .finishRegister(
            argThat(arr -> arr.length == 1 && getter.equals(arr[0])), eq(false), eq(true));
  }

  @Test
  void queueRequest_persistent_queuesPersistentJobAndFinishesPersistent() throws Exception {
    // Prepare a ClientContext with a jobRunner that runs jobs inline.
    TestExecutor mainExec = new TestExecutor();
    ClientLayerPersister jobRunner = mock(ClientLayerPersister.class);

    // Build a minimal ClientContext; most collaborators are not exercised here.
    ClientContext context =
        new ClientContext(
            1L,
            new ClientContextRuntime(
                jobRunner,
                mainExec,
                null,
                null,
                null,
                new SecureRandom(), // fastWeakRandom (secure for Sonar rule)
                null),
            new ClientContextStorageFactories(null, null, null, null, null, null, null),
            new ClientContextRafFactories(null, null),
            new ClientContextServices(
                new ClientContextResources(null, null), null, null, null, null, null),
            new ClientContextDefaults(null, null, null));

    DatastoreChecker checker = new DatastoreChecker(node, true, executor, THREAD_NAME);
    checker.setContext(context);

    // Arrange the jobRunner to execute the queued PersistentJob immediately.
    doAnswer(
            inv -> {
              PersistentJob job = inv.getArgument(0);
              job.run(context);
              return null;
            })
        .when(jobRunner)
        .queue(any(PersistentJob.class), anyInt());

    Key k1 = mock(Key.class);
    Key k2 = mock(Key.class);
    TestRequester parent =
        new TestRequester(RequestStarter.UPDATE_PRIORITY_CLASS, new TestRequestClient(true, false));
    SendableGet getter =
        new TestSendableGet(
            parent,
            false,
            RequestStarter.UPDATE_PRIORITY_CLASS,
            new Key[] {k1, k2},
            scheduler,
            false);

    // Make both missing so anyValid=true
    BlockSet blocks = mock(BlockSet.class);
    when(blocks.get(any(Key.class))).thenReturn(null);

    checker.queueRequest(getter, blocks);

    // Finish is invoked from inside the PersistentJob with persistent=true and anyValid=true
    verify(scheduler, times(1))
        .finishRegister(
            argThat(arr -> arr.length == 1 && getter.equals(arr[0])), eq(true), eq(true));
    // No transient finish
    verify(scheduler, never())
        .finishRegister(
            argThat(arr -> arr.length == 1 && getter.equals(arr[0])), eq(false), anyBoolean());
  }

  @Test
  void removeRequest_whenQueued_removesAndNoWorkDone() {
    // Capture execution; do not run automatically so we can remove before processing.
    executor.runInline = false;
    DatastoreChecker checker = new DatastoreChecker(node, true, executor, THREAD_NAME);

    ClientContext ctx = mock(ClientContext.class);
    checker.setContext(ctx);

    short prio = RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS;
    Key k = mock(Key.class);
    TestRequester parent = new TestRequester(prio, new TestRequestClient(false, false));
    SendableGet getter = new TestSendableGet(parent, false, prio, new Key[] {k}, scheduler, false);

    BlockSet blocks = mock(BlockSet.class);

    checker.queueRequest(getter, blocks);

    checker.removeRequest(getter, false, ctx, prio);

    // Now run whatever was captured; since the item was removed, no scheduler interaction happens.
    executor.runCaptured();

    verify(scheduler, never()).finishRegister(any(), anyBoolean(), anyBoolean());
    verify(scheduler, never()).tripPendingKey(any());
  }

  @Test
  void queueRequest_withNullBlockSet_usesNodeFetchPath() {
    DatastoreChecker checker = new DatastoreChecker(node, true, executor, THREAD_NAME);
    ClientContext ctx = mock(ClientContext.class);
    checker.setContext(ctx);

    Key k1 = mock(Key.class);
    Key k2 = mock(Key.class);
    TestRequester parent =
        new TestRequester(
            RequestStarter.MAXIMUM_PRIORITY_CLASS, new TestRequestClient(false, false));
    SendableGet getter =
        new TestSendableGet(
            parent,
            false,
            RequestStarter.MAXIMUM_PRIORITY_CLASS,
            new Key[] {k1, k2},
            scheduler,
            false);

    KeyBlock block = mock(KeyBlock.class);
    when(node.storage()
            .fetch(any(Key.class), anyBoolean(), anyBoolean(), anyBoolean(), anyBoolean(), any()))
        .thenReturn(block);

    checker.queueRequest(getter, null);

    verify(node.storage(), times(2))
        .fetch(any(Key.class), anyBoolean(), anyBoolean(), anyBoolean(), anyBoolean(), any());
    verify(scheduler, times(2)).tripPendingKey(block);
    verify(scheduler, times(1))
        .finishRegister(
            argThat(arr -> arr.length == 1 && getter.equals(arr[0])), eq(false), eq(false));
  }
}
