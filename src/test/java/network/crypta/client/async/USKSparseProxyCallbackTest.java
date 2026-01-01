package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.MalformedURLException;
import java.util.Random;
import network.crypta.client.ArchiveManager;
import network.crypta.client.FetchContext;
import network.crypta.client.InsertContext;
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
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.compress.RealCompressor;
import network.crypta.support.io.FileRandomAccessBufferFactory;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.PersistentFileTracker;
import network.crypta.support.io.PersistentTempBucketFactory;
import network.crypta.support.io.TempBucketFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class USKSparseProxyCallbackTest {

  // ---------------- Minimal helpers to construct deterministic inputs ----------------

  private static byte[] bytes(int len, int start) {
    byte[] b = new byte[len];
    for (int i = 0; i < len; i++) b[i] = (byte) (start + i);
    return b;
  }

  private static USK newUsk() throws MalformedURLException {
    byte[] pubKeyHash = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0);
    byte[] cryptoKey = bytes(ClientSSK.CRYPTO_KEY_LENGTH, 32);
    byte[] extras =
        new byte[] {
          NodeSSK.SSK_VERSION, 0, Key.ALGO_AES_PCFB_256_SHA256, 0, (byte) KeyBlock.HASH_SHA256
        };
    return new USK(pubKeyHash, cryptoKey, extras, "site", 0L);
  }

  private static final class DirectExecutor implements PriorityAwareExecutor {
    @Override
    public void execute(Runnable job) {
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

  private static FetchContext newFetchContext() {
    // Copied pattern from existing tests to match constructor signature
    return new FetchContext(
        64 * 1024,
        64 * 1024,
        1024,
        1,
        0,
        0,
        true,
        0,
        0,
        3,
        true,
        false,
        false,
        false,
        0,
        0,
        new SimpleEventProducer(),
        true,
        false,
        null,
        null,
        null);
  }

  private static InsertContext newInsertContext() {
    return new InsertContext(
        0, // maxRetries
        0, // rnfsToSuccess
        0, // splitfileSegmentDataBlocks
        0, // splitfileSegmentCheckBlocks
        new SimpleEventProducer(),
        true, // canWriteClientCache
        false, // forkOnCacheable
        false, // localRequestOnly
        null, // compressorDescriptor
        0, // extraInsertsSingleBlock
        0, // extraInsertsSplitfileHeaderBlock
        InsertContext.CompatibilityMode.COMPAT_CURRENT);
  }

  private static ClientContext minimalContext(
      ClientLayerPersister jobRunner,
      LinkFilterExceptionProvider linkFilterExceptionProvider,
      FetchContext defaultPF,
      InsertContext defaultPI,
      USKManager uskManager,
      PersistentTempBucketFactory ptbf,
      TempBucketFactory tbf) {
    return new ClientContext(
        1L,
        jobRunner,
        new DirectExecutor(),
        Mockito.mock(ArchiveManager.class),
        ptbf,
        tbf,
        Mockito.mock(PersistentFileTracker.class),
        Mockito.mock(HealingQueue.class),
        uskManager,
        Mockito.mock(RandomSource.class),
        new Random(123),
        new DirectTicker(),
        Mockito.mock(MemoryLimitedJobRunner.class),
        Mockito.mock(FilenameGenerator.class),
        Mockito.mock(FilenameGenerator.class),
        Mockito.mock(LockableRandomAccessBufferFactory.class),
        Mockito.mock(LockableRandomAccessBufferFactory.class),
        Mockito.mock(FileRandomAccessBufferFactory.class),
        Mockito.mock(FileRandomAccessBufferFactory.class),
        Mockito.mock(RealCompressor.class),
        Mockito.mock(DatastoreChecker.class),
        Mockito.mock(PersistentRequestRoot.class),
        Mockito.mock(MasterSecret.class),
        linkFilterExceptionProvider,
        defaultPF,
        defaultPI,
        Mockito.mock(Config.class));
  }

  // ---------------- Mocks and test fixture ----------------

  @Mock private USKCallback target;
  @Mock private USKManager uskManager;
  @Mock private ClientLayerPersister persister;
  @Mock private LinkFilterExceptionProvider linkFilterExceptionProvider;
  @Mock private PersistentTempBucketFactory ptbf;
  @Mock private TempBucketFactory tbf;

  private ClientContext context;
  private USK usk;

  @BeforeEach
  void setUp() throws MalformedURLException {
    context =
        minimalContext(
            persister,
            linkFilterExceptionProvider,
            newFetchContext(),
            newInsertContext(),
            uskManager,
            ptbf,
            tbf);
    usk = newUsk();
  }

  @Test
  @DisplayName("onFoundEdition_beforeRoundFinished_defers_untilRoundFinishedFlush")
  void onFoundEdition_beforeRoundFinished_defers_untilRoundFinishedFlush() {
    // Arrange
    USKSparseProxyCallback proxy = new USKSparseProxyCallback(target, usk);

    // Act: two updates before the round finishes; should not pass through yet
    byte[] data12 = new byte[] {1, 2};
    byte[] data345 = new byte[] {3, 4, 5};
    proxy.onFoundEdition(1L, usk, context, true, (short) 7, data12, false, false);
    proxy.onFoundEdition(2L, usk, context, false, (short) 9, data345, true, true);

    // Assert: no call yet
    verify(target, never())
        .onFoundEdition(
            any(Long.class),
            eq(usk),
            eq(context),
            any(Boolean.class),
            any(Short.class),
            any(),
            any(Boolean.class),
            any(Boolean.class));

    // Act: finish the round; should flush a single latest notification (edition 2)
    proxy.onRoundFinished(context);

    // Assert: exactly once with latest values and knownGood propagated
    verify(target, times(1))
        .onFoundEdition(2L, usk, context, false, (short) 9, data345, true, true);

    // Act: finishing again without new updates should not duplicate
    proxy.onRoundFinished(context);
    verify(target, times(1))
        .onFoundEdition(2L, usk, context, false, (short) 9, data345, true, true);
  }

  @Test
  @DisplayName("onSendingToNetwork_flushesWithoutSettingRound_and_noDuplicates")
  void onSendingToNetwork_flushesWithoutSettingRound_and_noDuplicates() {
    // Arrange
    USKSparseProxyCallback proxy = new USKSparseProxyCallback(target, usk);

    // Act: update then flush via sending-to-network
    byte[] data8 = new byte[] {8};
    proxy.onFoundEdition(5L, usk, context, false, (short) 1, data8, false, false);
    proxy.onSendingToNetwork(context);

    // Assert: flushed once with wasKnownGood=false → both flags false
    verify(target, times(1))
        .onFoundEdition(5L, usk, context, false, (short) 1, data8, false, false);

    // Act: call again without new updates — should not duplicate
    proxy.onSendingToNetwork(context);
    verify(target, times(1))
        .onFoundEdition(5L, usk, context, false, (short) 1, data8, false, false);
  }

  @Test
  @DisplayName("onRoundFinished_whenNoEdition_noPassThrough_evenIfLookupHasValue")
  void onRoundFinished_whenNoEdition_noPassThrough_evenIfLookupHasValue() {
    // Arrange
    USKSparseProxyCallback proxy = new USKSparseProxyCallback(target, usk);

    // Case 1: with no prior editions seen, guard returns early and nothing is forwarded
    proxy.onRoundFinished(context);
    verify(target, never())
        .onFoundEdition(
            any(Long.class),
            eq(usk),
            eq(context),
            any(Boolean.class),
            any(Short.class),
            any(),
            any(Boolean.class),
            any(Boolean.class));

    // Case 2: calling again without any prior edition still results in no call
    proxy.onRoundFinished(context);
    verify(target, never())
        .onFoundEdition(
            any(Long.class),
            eq(usk),
            eq(context),
            any(Boolean.class),
            any(Short.class),
            any(),
            any(Boolean.class),
            any(Boolean.class));
  }

  @Test
  @DisplayName(
      "onFoundEdition_whenOlderAndRoundFinishedAndNewKnownGoodTrue_callsThroughImmediately")
  void onFoundEdition_whenOlderAndRoundFinishedAndNewKnownGoodTrue_callsThroughImmediately() {
    // Arrange
    USKSparseProxyCallback proxy = new USKSparseProxyCallback(target, usk);
    byte[] data1 = new byte[] {1};
    proxy.onFoundEdition(5L, usk, context, false, (short) 0, data1, false, false);
    proxy.onRoundFinished(context); // finish the round so subsequent older edition may pass through

    // Act: older edition but newKnownGood=true should call through immediately
    byte[] data9 = new byte[] {9};
    proxy.onFoundEdition(4L, usk, context, true, (short) 2, data9, true, false);

    // Assert: called with the older edition's parameters
    verify(target, times(1))
        .onFoundEdition(5L, usk, context, false, (short) 0, data1, false, false);
    verify(target, times(1)).onFoundEdition(4L, usk, context, true, (short) 2, data9, true, false);
  }

  @Test
  @DisplayName("onFoundEdition_sameEditionThenKnownGood_setsFlag_forFlush")
  void onFoundEdition_sameEditionThenKnownGood_setsFlag_forFlush() {
    // Arrange
    USKSparseProxyCallback proxy = new USKSparseProxyCallback(target, usk);

    // Act: first store the edition (knownGood=false), then mark same edition as knownGood
    byte[] data23 = new byte[] {2, 3};
    proxy.onFoundEdition(7L, usk, context, true, (short) 11, data23, false, false);
    proxy.onFoundEdition(7L, usk, context, true, (short) 11, data23, true, false);
    proxy.onRoundFinished(context);

    // Assert: the flush uses wasKnownGood=true for both flags
    verify(target, times(1)).onFoundEdition(7L, usk, context, true, (short) 11, data23, true, true);
  }

  @Test
  @DisplayName("priority_methods_delegate_to_target")
  void priority_methods_delegate_to_target() {
    when(target.getPollingPriorityNormal()).thenReturn((short) 12);
    when(target.getPollingPriorityProgress()).thenReturn((short) 34);

    USKSparseProxyCallback proxy = new USKSparseProxyCallback(target, usk);

    assertEquals(12, proxy.getPollingPriorityNormal());
    assertEquals(34, proxy.getPollingPriorityProgress());
  }
}
