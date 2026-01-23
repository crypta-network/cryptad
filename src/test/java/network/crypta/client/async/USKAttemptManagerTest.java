package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.stream.Collectors;
import network.crypta.client.ArchiveManager;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchContextOptions;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContextOptions;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.client.filter.LinkFilterExceptionProvider;
import network.crypta.clients.fcp.PersistentRequestRoot;
import network.crypta.config.Config;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.USK;
import network.crypta.node.ClientContextResources;
import network.crypta.node.RequestClient;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.io.FileRandomAccessBufferFactory;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.PersistentFileTracker;
import network.crypta.support.io.PersistentTempBucketFactory;
import network.crypta.support.io.TempBucketFactory;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class USKAttemptManagerTest {

  private static final RequestClient TRANSIENT_CLIENT =
      new RequestClient() {
        @Override
        public boolean persistent() {
          return false;
        }

        @Override
        public boolean realTimeFlag() {
          return false;
        }
      };

  private static final class DirectExecutor implements PriorityAwareExecutor {
    @Override
    public void execute(@NonNull Runnable job) {
      job.run();
    }

    @Override
    public void execute(Runnable job, String jobName) {
      job.run();
    }

    @Override
    public void execute(Runnable job, String jobName, boolean fromTicker) {
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
  }

  private static final class DirectTicker implements Ticker {
    private final PriorityAwareExecutor executor = new DirectExecutor();

    @Override
    public void queueTimedJob(Runnable job, long offset) {
      job.run();
    }

    @Override
    public void queueTimedJob(
        Runnable job, String name, long offset, boolean runOnTickerAnyway, boolean noDupes) {
      job.run();
    }

    @Override
    public PriorityAwareExecutor getExecutor() {
      return executor;
    }

    @Override
    public void removeQueuedJob(Runnable job) {
      // no-op
    }

    @Override
    public void queueTimedJobAbsolute(
        Runnable runner, String name, long time, boolean runOnTickerAnyway, boolean noDupes) {
      runner.run();
    }
  }

  private static final class TestRequester extends ClientRequester {
    private final ClientBaseCallback callback;
    private final network.crypta.keys.FreenetURI uri;
    private int toNetworkCalls;
    private boolean cancelled;

    private TestRequester(network.crypta.keys.FreenetURI uri, RequestClient client) {
      super((short) 1, client);
      this.uri = uri;
      this.callback =
          new ClientBaseCallback() {
            @Override
            public void onResume(ClientContext context) {
              // no-op
            }

            @Override
            public RequestClient getRequestClient() {
              return client;
            }
          };
    }

    @Override
    public void onTransition(
        ClientGetState oldState, ClientGetState newState, ClientContext context) {
      // no-op
    }

    @Override
    public void cancel(ClientContext context) {
      cancelled = true;
    }

    @Override
    public network.crypta.keys.FreenetURI getURI() {
      return uri;
    }

    @Override
    public boolean isFinished() {
      return cancelled;
    }

    @Override
    protected void innerNotifyClients(ClientContext context) {
      // no-op
    }

    @Override
    protected void innerToNetwork(ClientContext context) {
      toNetworkCalls++;
    }

    @Override
    protected ClientBaseCallback getCallback() {
      return callback;
    }

    int toNetworkCalls() {
      return toNetworkCalls;
    }
  }

  private static FetchContext newFetchContext() {
    return new FetchContext(
        FetchContextOptions.builder()
            .limits(16 * 1024L, 16 * 1024L, 4096)
            .archiveLimits(1, 0, 0, true)
            .retryLimits(0, 0, 2)
            .splitfileLimits(true, 0, 0)
            .behavior(false, false, false)
            .clientOptions(new SimpleEventProducer(), true, false)
            .filterOverrides(null, null, null)
            .build());
  }

  private static InsertContext newInsertContext() {
    return new InsertContext(
        InsertContextOptions.builder()
            .retryLimits(0, 0)
            .splitfileSegmentLimits(0, 0)
            .clientOptions(new SimpleEventProducer(), true, false, false)
            .compressorDescriptor(null)
            .redundancy(0, 0)
            .compatibility(InsertContext.CompatibilityMode.COMPAT_CURRENT)
            .build());
  }

  private static ClientContext minimalContext(USKManager uskManager, RandomSource randomSource) {
    return new ClientContext(
        1L,
        new ClientContextRuntime(
            mock(ClientLayerPersister.class),
            new DirectExecutor(),
            mock(MemoryLimitedJobRunner.class),
            new DirectTicker(),
            randomSource,
            new Random(123),
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
            uskManager,
            mock(network.crypta.support.compress.RealCompressor.class),
            mock(DatastoreChecker.class),
            mock(PersistentRequestRoot.class),
            mock(LinkFilterExceptionProvider.class)),
        new ClientContextDefaults(newFetchContext(), newInsertContext(), mock(Config.class)));
  }

  private static USK newUSK() throws MalformedURLException {
    byte[] pubKeyHash = new byte[NodeSSK.PUBKEY_HASH_SIZE];
    byte[] cryptoKey = new byte[ClientSSK.CRYPTO_KEY_LENGTH];
    byte[] extras =
        new byte[] {
          NodeSSK.SSK_VERSION, 0, Key.ALGO_AES_PCFB_256_SHA256, 0, (byte) KeyBlock.HASH_SHA256
        };
    return new USK(pubKeyHash, cryptoKey, extras, "site", 0L);
  }

  private static USKKeyWatchSet.Lookup lookup(USK usk, long edition, boolean ignoreStore) {
    USKKeyWatchSet.Lookup lookup = new USKKeyWatchSet.Lookup();
    lookup.val = edition;
    lookup.key = usk.getSSK(edition);
    lookup.ignoreStore = ignoreStore;
    lookup.label = "test";
    return lookup;
  }

  private static USKAttemptManager newManager(
      USKAttemptCallbacks callbacks,
      USKManager uskManager,
      USKKeyWatchSet watchingKeys,
      boolean checkStoreOnly,
      boolean keepLastData,
      USK usk,
      ClientRequester parent) {
    USKAttemptContext attemptContext =
        new USKAttemptContext(callbacks, usk, newFetchContext(), newFetchContext(), parent, false);
    return new USKAttemptManager(
        attemptContext, uskManager, watchingKeys, checkStoreOnly, keepLastData);
  }

  @Test
  void cancelBefore_whenRunningAndPollingBeforeCutoff_removesAndReturns() throws Exception {
    USKManager uskManager = mock(USKManager.class);
    USKKeyWatchSet watchingKeys = mock(USKKeyWatchSet.class);
    USKAttemptCallbacks callbacks = mock(USKAttemptCallbacks.class);
    USK usk = newUSK();
    TestRequester parent = new TestRequester(usk.getURI(), TRANSIENT_CLIENT);
    ClientContext context = minimalContext(uskManager, mock(RandomSource.class));

    USKKeyWatchSet.Lookup runningOld = lookup(usk, 1L, false);
    USKKeyWatchSet.Lookup runningNew = lookup(usk, 4L, false);
    USKKeyWatchSet.Lookup pollingOld = lookup(usk, 2L, true);
    USKKeyWatchSet.Lookup pollingNew = lookup(usk, 5L, true);
    USKKeyWatchSet.ToFetch plan =
        new USKKeyWatchSet.ToFetch(
            Arrays.asList(runningOld, runningNew), Arrays.asList(pollingOld, pollingNew));

    when(callbacks.shouldAddRandomEditions(any(Random.class), anyBoolean())).thenReturn(false);
    when(watchingKeys.getEditionsToFetch(
            anyLong(), any(Random.class), anyList(), anyBoolean(), anyBoolean()))
        .thenReturn(plan);

    USKAttemptManager manager =
        newManager(callbacks, uskManager, watchingKeys, false, false, usk, parent);

    manager.addNewAttempts(0L, context, true);
    manager.clearAttemptsToStart();

    List<USKAttempt> toCancel = manager.cancelBefore(3L);

    assertEquals(2, toCancel.size());
    Set<Long> cancelledNumbers =
        toCancel.stream().map(attempt -> attempt.number).collect(Collectors.toSet());
    assertEquals(Set.of(1L, 2L), cancelledNumbers);
    assertEquals(1, manager.runningAttemptCount());
    assertEquals(1, manager.pollingAttemptCount());
  }

  @Test
  void finishCancelBefore_whenAttemptsProvided_invokesCancel() throws Exception {
    USKManager uskManager = mock(USKManager.class);
    USKKeyWatchSet watchingKeys = mock(USKKeyWatchSet.class);
    USKAttemptCallbacks callbacks = mock(USKAttemptCallbacks.class);
    USK usk = newUSK();
    TestRequester parent = new TestRequester(usk.getURI(), TRANSIENT_CLIENT);
    USKAttemptManager manager =
        newManager(callbacks, uskManager, watchingKeys, false, false, usk, parent);
    ClientContext context = mock(ClientContext.class);
    USKAttempt attempt = mock(USKAttempt.class);

    manager.finishCancelBefore(List.of(attempt), context);

    verify(attempt).cancel(context);
  }

  @Test
  void shouldAddRandomEditions_delegatesToCallbacks() throws Exception {
    USKManager uskManager = mock(USKManager.class);
    USKKeyWatchSet watchingKeys = mock(USKKeyWatchSet.class);
    USKAttemptCallbacks callbacks = mock(USKAttemptCallbacks.class);
    RandomSource randomSource = mock(RandomSource.class);
    USK usk = newUSK();
    TestRequester parent = new TestRequester(usk.getURI(), TRANSIENT_CLIENT);
    ClientContext context = minimalContext(uskManager, randomSource);

    when(callbacks.shouldAddRandomEditions(randomSource, true)).thenReturn(true);

    USKAttemptManager manager =
        newManager(callbacks, uskManager, watchingKeys, false, false, usk, parent);

    assertTrue(manager.shouldAddRandomEditions(context, true));
    verify(callbacks).shouldAddRandomEditions(randomSource, true);
  }

  @Test
  void addNewAttempts_whenStoreOnly_doesNotStage() throws Exception {
    USKManager uskManager = mock(USKManager.class);
    USKKeyWatchSet watchingKeys = mock(USKKeyWatchSet.class);
    USKAttemptCallbacks callbacks = mock(USKAttemptCallbacks.class);
    USK usk = newUSK();
    TestRequester parent = new TestRequester(usk.getURI(), TRANSIENT_CLIENT);
    ClientContext context = minimalContext(uskManager, mock(RandomSource.class));

    USKKeyWatchSet.ToFetch plan =
        new USKKeyWatchSet.ToFetch(List.of(lookup(usk, 1L, false)), List.of(lookup(usk, 2L, true)));
    when(callbacks.shouldAddRandomEditions(any(Random.class), anyBoolean())).thenReturn(false);
    when(watchingKeys.getEditionsToFetch(
            anyLong(), any(Random.class), anyList(), anyBoolean(), anyBoolean()))
        .thenReturn(plan);

    USKAttemptManager manager =
        newManager(callbacks, uskManager, watchingKeys, true, false, usk, parent);

    manager.addNewAttempts(0L, context, true);

    assertFalse(manager.hasPendingAttempts());
    assertEquals(0, manager.runningAttemptCount());
    assertEquals(0, manager.pollingAttemptCount());
  }

  @Test
  void addNewAttempts_whenDuplicateEditions_skipsDuplicate() throws Exception {
    USKManager uskManager = mock(USKManager.class);
    USKKeyWatchSet watchingKeys = mock(USKKeyWatchSet.class);
    USKAttemptCallbacks callbacks = mock(USKAttemptCallbacks.class);
    USK usk = newUSK();
    TestRequester parent = new TestRequester(usk.getURI(), TRANSIENT_CLIENT);
    ClientContext context = minimalContext(uskManager, mock(RandomSource.class));

    USKKeyWatchSet.ToFetch plan =
        new USKKeyWatchSet.ToFetch(List.of(lookup(usk, 3L, false)), List.of(lookup(usk, 4L, true)));
    when(callbacks.shouldAddRandomEditions(any(Random.class), anyBoolean())).thenReturn(false);
    when(watchingKeys.getEditionsToFetch(
            anyLong(), any(Random.class), anyList(), anyBoolean(), anyBoolean()))
        .thenReturn(plan);

    USKAttemptManager manager =
        newManager(callbacks, uskManager, watchingKeys, false, false, usk, parent);

    manager.addNewAttempts(0L, context, true);
    assertEquals(2, manager.snapshotAttemptsToStart().length);
    manager.clearAttemptsToStart();

    manager.addNewAttempts(0L, context, true);

    assertFalse(manager.hasPendingAttempts());
    assertEquals(1, manager.runningAttemptCount());
    assertEquals(1, manager.pollingAttemptCount());
  }

  @Test
  void addNewAttempts_whenNegativeEdition_throwsIllegalArgumentException() throws Exception {
    USKManager uskManager = mock(USKManager.class);
    USKKeyWatchSet watchingKeys = mock(USKKeyWatchSet.class);
    USKAttemptCallbacks callbacks = mock(USKAttemptCallbacks.class);
    USK usk = newUSK();
    TestRequester parent = new TestRequester(usk.getURI(), TRANSIENT_CLIENT);
    ClientContext context = minimalContext(uskManager, mock(RandomSource.class));

    USKKeyWatchSet.Lookup negative = new USKKeyWatchSet.Lookup();
    negative.val = -1L;
    negative.key = usk.getSSK(0L);
    negative.ignoreStore = false;
    negative.label = "negative";
    USKKeyWatchSet.ToFetch plan = new USKKeyWatchSet.ToFetch(List.of(negative), List.of());

    when(callbacks.shouldAddRandomEditions(any(Random.class), anyBoolean())).thenReturn(false);
    when(watchingKeys.getEditionsToFetch(
            anyLong(), any(Random.class), anyList(), anyBoolean(), anyBoolean()))
        .thenReturn(plan);

    USKAttemptManager manager =
        newManager(callbacks, uskManager, watchingKeys, false, false, usk, parent);

    assertThrows(IllegalArgumentException.class, () -> manager.addNewAttempts(0L, context, true));
  }

  @Test
  void registerAttempts_whenNewerSchedulesAndNotifiesNetwork() throws Exception {
    USKManager uskManager = mock(USKManager.class);
    USKKeyWatchSet watchingKeys = mock(USKKeyWatchSet.class);
    USKAttemptCallbacks callbacks = mock(USKAttemptCallbacks.class);
    USK usk = newUSK();
    TestRequester parent = new TestRequester(usk.getURI(), TRANSIENT_CLIENT);
    ClientContext addContext = minimalContext(uskManager, mock(RandomSource.class));
    ClientContext scheduleContext = mock(ClientContext.class);

    USKKeyWatchSet.ToFetch plan =
        new USKKeyWatchSet.ToFetch(
            List.of(lookup(usk, 10L, false)), List.of(lookup(usk, 11L, true)));
    when(callbacks.shouldAddRandomEditions(any(Random.class), anyBoolean())).thenReturn(false);
    when(watchingKeys.getEditionsToFetch(
            anyLong(), any(Random.class), anyList(), anyBoolean(), anyBoolean()))
        .thenReturn(plan);

    USKAttemptManager manager =
        newManager(callbacks, uskManager, watchingKeys, false, false, usk, parent);
    manager.addNewAttempts(0L, addContext, true);

    USKAttempt[] attempts = manager.snapshotAttemptsToStart();
    List<USKChecker> checkers = new ArrayList<>();
    for (USKAttempt attempt : attempts) {
      USKChecker checker = mock(USKChecker.class);
      attempt.checker = checker;
      checkers.add(checker);
    }

    when(uskManager.lookupLatestSlot(usk)).thenReturn(9L);

    manager.registerAttempts(
        new USKAttemptManager.USKAttemptRegistrationParams(scheduleContext, true, 15L));

    assertEquals(1, parent.toNetworkCalls());
    assertFalse(manager.hasPendingAttempts());
    for (USKChecker checker : checkers) {
      verify(checker).schedule(scheduleContext);
    }
  }

  @Test
  void registerAttempts_whenObsolete_removesFromMaps() throws Exception {
    USKManager uskManager = mock(USKManager.class);
    USKKeyWatchSet watchingKeys = mock(USKKeyWatchSet.class);
    USKAttemptCallbacks callbacks = mock(USKAttemptCallbacks.class);
    USK usk = newUSK();
    TestRequester parent = new TestRequester(usk.getURI(), TRANSIENT_CLIENT);
    ClientContext addContext = minimalContext(uskManager, mock(RandomSource.class));
    ClientContext scheduleContext = mock(ClientContext.class);

    USKKeyWatchSet.ToFetch plan =
        new USKKeyWatchSet.ToFetch(List.of(lookup(usk, 5L, false)), List.of());
    when(callbacks.shouldAddRandomEditions(any(Random.class), anyBoolean())).thenReturn(false);
    when(watchingKeys.getEditionsToFetch(
            anyLong(), any(Random.class), anyList(), anyBoolean(), anyBoolean()))
        .thenReturn(plan);

    USKAttemptManager manager =
        newManager(callbacks, uskManager, watchingKeys, false, false, usk, parent);
    manager.addNewAttempts(0L, addContext, true);

    USKAttempt attempt = manager.snapshotAttemptsToStart()[0];
    USKChecker checker = mock(USKChecker.class);
    attempt.checker = checker;

    when(uskManager.lookupLatestSlot(usk)).thenReturn(5L);

    manager.registerAttempts(
        new USKAttemptManager.USKAttemptRegistrationParams(scheduleContext, true, 5L));

    assertEquals(1, parent.toNetworkCalls());
    assertEquals(0, manager.runningAttemptCount());
    verify(checker, never()).schedule(scheduleContext);
  }

  @Test
  void registerAttempts_whenKeepLastDataAndNoLastRequestData_schedulesSuggestedEdition()
      throws Exception {
    USKManager uskManager = mock(USKManager.class);
    USKKeyWatchSet watchingKeys = mock(USKKeyWatchSet.class);
    USKAttemptCallbacks callbacks = mock(USKAttemptCallbacks.class);
    USK usk = newUSK();
    TestRequester parent = new TestRequester(usk.getURI(), TRANSIENT_CLIENT);
    ClientContext addContext = minimalContext(uskManager, mock(RandomSource.class));
    ClientContext scheduleContext = mock(ClientContext.class);

    USKKeyWatchSet.ToFetch plan =
        new USKKeyWatchSet.ToFetch(List.of(lookup(usk, 12L, false)), List.of());
    when(callbacks.shouldAddRandomEditions(any(Random.class), anyBoolean())).thenReturn(false);
    when(watchingKeys.getEditionsToFetch(
            anyLong(), any(Random.class), anyList(), anyBoolean(), anyBoolean()))
        .thenReturn(plan);

    USKAttemptManager manager =
        newManager(callbacks, uskManager, watchingKeys, false, true, usk, parent);
    manager.addNewAttempts(0L, addContext, true);

    USKAttempt attempt = manager.snapshotAttemptsToStart()[0];
    USKChecker checker = mock(USKChecker.class);
    attempt.checker = checker;

    when(uskManager.lookupLatestSlot(usk)).thenReturn(12L);

    manager.registerAttempts(
        new USKAttemptManager.USKAttemptRegistrationParams(scheduleContext, false, 12L));

    verify(checker).schedule(scheduleContext);
  }

  @Test
  void reloadPollParameters_whenPollingAttemptsPresent_refreshesChecker() throws Exception {
    USKManager uskManager = mock(USKManager.class);
    USKKeyWatchSet watchingKeys = mock(USKKeyWatchSet.class);
    USKAttemptCallbacks callbacks = mock(USKAttemptCallbacks.class);
    USK usk = newUSK();
    TestRequester parent = new TestRequester(usk.getURI(), TRANSIENT_CLIENT);
    ClientContext context = minimalContext(uskManager, mock(RandomSource.class));

    USKKeyWatchSet.ToFetch plan =
        new USKKeyWatchSet.ToFetch(List.of(), List.of(lookup(usk, 7L, true)));
    when(callbacks.shouldAddRandomEditions(any(Random.class), anyBoolean())).thenReturn(false);
    when(watchingKeys.getEditionsToFetch(
            anyLong(), any(Random.class), anyList(), anyBoolean(), anyBoolean()))
        .thenReturn(plan);

    USKAttemptManager manager =
        newManager(callbacks, uskManager, watchingKeys, false, false, usk, parent);
    manager.addNewAttempts(0L, context, true);
    manager.clearAttemptsToStart();

    USKAttempt pollingAttempt = manager.snapshotPollingAttempts()[0];
    USKChecker checker = mock(USKChecker.class);
    pollingAttempt.checker = checker;

    manager.reloadPollParameters();

    verify(checker).onChangedFetchContext();
  }

  @Test
  void runningAttemptsDescription_includesCancelledAndSucceededFlags() throws Exception {
    USKManager uskManager = mock(USKManager.class);
    USKKeyWatchSet watchingKeys = mock(USKKeyWatchSet.class);
    USKAttemptCallbacks callbacks = mock(USKAttemptCallbacks.class);
    USK usk = newUSK();
    TestRequester parent = new TestRequester(usk.getURI(), TRANSIENT_CLIENT);
    ClientContext context = minimalContext(uskManager, mock(RandomSource.class));

    USKKeyWatchSet.ToFetch plan =
        new USKKeyWatchSet.ToFetch(List.of(lookup(usk, 2L, false)), List.of());
    when(callbacks.shouldAddRandomEditions(any(Random.class), anyBoolean())).thenReturn(false);
    when(watchingKeys.getEditionsToFetch(
            anyLong(), any(Random.class), anyList(), anyBoolean(), anyBoolean()))
        .thenReturn(plan);

    USKAttemptManager manager =
        newManager(callbacks, uskManager, watchingKeys, false, false, usk, parent);
    manager.addNewAttempts(0L, context, true);
    manager.clearAttemptsToStart();

    USKAttempt attempt = manager.snapshotRunningAttempts()[0];
    attempt.cancelled = true;
    attempt.succeeded = true;

    String description = manager.runningAttemptsDescription();

    assertTrue(description.contains("2"));
    assertTrue(description.contains("(cancelled)"));
    assertTrue(description.contains("(succeeded)"));
  }
}
