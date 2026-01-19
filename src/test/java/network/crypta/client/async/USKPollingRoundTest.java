package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.Serial;
import java.net.MalformedURLException;
import java.util.Random;
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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class USKPollingRoundTest {

  private static final class FixedRandomSource extends RandomSource {
    @Serial private static final long serialVersionUID = 1L;

    @Override
    public int nextInt(int bound) {
      return 0;
    }

    @Override
    public int acceptEntropy(
        network.crypta.crypt.EntropySource source, long data, int entropyGuess) {
      return 0;
    }

    @Override
    public int acceptTimerEntropy(network.crypta.crypt.EntropySource timer) {
      return 0;
    }

    @Override
    public int acceptTimerEntropy(network.crypta.crypt.EntropySource fnpTimingSource, double bias) {
      return 0;
    }

    @Override
    public int acceptEntropyBytes(
        network.crypta.crypt.EntropySource myPacketDataSource,
        byte[] buf,
        int offset,
        int length,
        double bias) {
      return 0;
    }

    @Override
    public void close() {
      // No-op for deterministic tests.
    }
  }

  private static ClientContext minimalContext(RandomSource randomSource) {
    return new ClientContext(
        1L,
        new ClientContextRuntime(
            mock(ClientLayerPersister.class),
            mock(PriorityAwareExecutor.class),
            mock(MemoryLimitedJobRunner.class),
            mock(Ticker.class),
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
            mock(USKManager.class),
            mock(RealCompressor.class),
            mock(DatastoreChecker.class),
            mock(PersistentRequestRoot.class),
            mock(LinkFilterExceptionProvider.class)),
        new ClientContextDefaults(newFetchContext(), newInsertContext(), mock(Config.class)));
  }

  private static FetchContext newFetchContext() {
    return new FetchContext(
        FetchContextOptions.builder()
            .limits(0, 0, 0)
            .archiveLimits(1, 0, 0, true)
            .retryLimits(0, 0, 0)
            .splitfileLimits(false, 0, 0)
            .behavior(false, false, false)
            .clientOptions(new SimpleEventProducer(), false, false)
            .filterOverrides(null, null, null)
            .build());
  }

  private static InsertContext newInsertContext() {
    return new InsertContext(
        InsertContextOptions.builder()
            .retryLimits(0, 0)
            .splitfileSegmentLimits(0, 0)
            .clientOptions(new SimpleEventProducer(), false, false, false)
            .compressorDescriptor(null)
            .redundancy(0, 0)
            .compatibility(InsertContext.CompatibilityMode.COMPAT_CURRENT)
            .build());
  }

  private static USK newUSK(long suggestedEdition) throws MalformedURLException {
    byte[] pubKeyHash = new byte[NodeSSK.PUBKEY_HASH_SIZE];
    byte[] cryptoKey = new byte[ClientSSK.CRYPTO_KEY_LENGTH];
    byte[] extras =
        new byte[] {
          NodeSSK.SSK_VERSION, 0, Key.ALGO_AES_PCFB_256_SHA256, 0, (byte) KeyBlock.HASH_SHA256
        };
    return new USK(pubKeyHash, cryptoKey, extras, "site", suggestedEdition);
  }

  private static USKPollingRound newRound(
      USKAttemptManager attempts,
      USKStoreCheckCoordinator storeChecks,
      USKDateHintFetches dbrHintFetches,
      USKSubscriberRegistry subscribers,
      USKManager uskManager,
      USK usk,
      long sleepTime,
      boolean firstLoop,
      long origSleepTime,
      long maxSleepTime) {
    USKPollingRoundContext context =
        new USKPollingRoundContext(
            attempts, storeChecks, dbrHintFetches, subscribers, uskManager, usk, false);
    return new USKPollingRound(context, sleepTime, firstLoop, origSleepTime, maxSleepTime);
  }

  @ParameterizedTest
  @CsvSource({"true,false", "false,true"})
  void resolvePollingAttemptsIfAllChecksDone_whenCancelledOrCompleted_returnsNotReady(
      boolean cancelled, boolean completed) throws Exception {
    USKPollingRound round =
        newRound(
            mock(USKAttemptManager.class),
            mock(USKStoreCheckCoordinator.class),
            mock(USKDateHintFetches.class),
            mock(USKSubscriberRegistry.class),
            mock(USKManager.class),
            newUSK(0L),
            100L,
            true,
            50L,
            500L);

    USKPollingRound.PollingResolution res =
        round.resolvePollingAttemptsIfAllChecksDone(cancelled, completed);

    assertFalse(res.ready);
    assertEquals(0, res.attempts.length);
  }

  @Test
  void resolvePollingAttemptsIfAllChecksDone_whenStoreCheckRunning_returnsNotReady()
      throws Exception {
    USKStoreCheckCoordinator storeChecks = mock(USKStoreCheckCoordinator.class);
    when(storeChecks.isStoreCheckRunning()).thenReturn(true);
    USKPollingRound round =
        newRound(
            mock(USKAttemptManager.class),
            storeChecks,
            mock(USKDateHintFetches.class),
            mock(USKSubscriberRegistry.class),
            mock(USKManager.class),
            newUSK(0L),
            100L,
            false,
            50L,
            500L);

    USKPollingRound.PollingResolution res =
        round.resolvePollingAttemptsIfAllChecksDone(false, false);

    assertFalse(res.ready);
    assertEquals(0, res.attempts.length);
  }

  @Test
  void resolvePollingAttemptsIfAllChecksDone_whenRunningAttempts_returnsNotReady()
      throws Exception {
    USKAttemptManager attempts = mock(USKAttemptManager.class);
    when(attempts.hasRunningAttempts()).thenReturn(true);
    USKPollingRound round =
        newRound(
            attempts,
            mock(USKStoreCheckCoordinator.class),
            mock(USKDateHintFetches.class),
            mock(USKSubscriberRegistry.class),
            mock(USKManager.class),
            newUSK(0L),
            100L,
            true,
            50L,
            500L);

    USKPollingRound.PollingResolution res =
        round.resolvePollingAttemptsIfAllChecksDone(false, false);

    assertFalse(res.ready);
    assertEquals(0, res.attempts.length);
  }

  @Test
  void resolvePollingAttemptsIfAllChecksDone_whenNoPollingAttempts_returnsNotReady()
      throws Exception {
    USKAttemptManager attempts = mock(USKAttemptManager.class);
    when(attempts.hasNoPollingAttempts()).thenReturn(true);
    USKPollingRound round =
        newRound(
            attempts,
            mock(USKStoreCheckCoordinator.class),
            mock(USKDateHintFetches.class),
            mock(USKSubscriberRegistry.class),
            mock(USKManager.class),
            newUSK(0L),
            100L,
            true,
            50L,
            500L);

    USKPollingRound.PollingResolution res =
        round.resolvePollingAttemptsIfAllChecksDone(false, false);

    assertFalse(res.ready);
    assertEquals(0, res.attempts.length);
  }

  @Test
  void resolvePollingAttemptsIfAllChecksDone_whenHintsOutstanding_returnsNotReady()
      throws Exception {
    USKDateHintFetches dbrHintFetches = mock(USKDateHintFetches.class);
    when(dbrHintFetches.hasOutstanding()).thenReturn(true);
    USKPollingRound round =
        newRound(
            mock(USKAttemptManager.class),
            mock(USKStoreCheckCoordinator.class),
            dbrHintFetches,
            mock(USKSubscriberRegistry.class),
            mock(USKManager.class),
            newUSK(0L),
            100L,
            true,
            50L,
            500L);

    USKPollingRound.PollingResolution res =
        round.resolvePollingAttemptsIfAllChecksDone(false, false);

    assertFalse(res.ready);
    assertEquals(0, res.attempts.length);
  }

  @Test
  void resolvePollingAttemptsIfAllChecksDone_whenReady_returnsSnapshot() throws Exception {
    USKAttemptManager attempts = mock(USKAttemptManager.class);
    USKAttempt[] snapshot = new USKAttempt[] {mock(USKAttempt.class)};
    when(attempts.snapshotPollingAttempts()).thenReturn(snapshot);
    USKPollingRound round =
        newRound(
            attempts,
            mock(USKStoreCheckCoordinator.class),
            mock(USKDateHintFetches.class),
            mock(USKSubscriberRegistry.class),
            mock(USKManager.class),
            newUSK(0L),
            100L,
            true,
            50L,
            500L);

    USKPollingRound.PollingResolution res =
        round.resolvePollingAttemptsIfAllChecksDone(false, false);

    assertTrue(res.ready);
    assertSame(snapshot, res.attempts);
  }

  @Test
  void checkFinishedForNow_whenAttemptNeverCooled_doesNotNotify() throws Exception {
    USKAttemptManager attempts = mock(USKAttemptManager.class);
    USKAttempt attempt = mock(USKAttempt.class);
    when(attempts.snapshotPollingAttempts()).thenReturn(new USKAttempt[] {attempt});
    USKSubscriberRegistry subscribers = mock(USKSubscriberRegistry.class);
    when(attempt.everInCooldown()).thenReturn(false);
    USKPollingRound round =
        newRound(
            attempts,
            mock(USKStoreCheckCoordinator.class),
            mock(USKDateHintFetches.class),
            subscribers,
            mock(USKManager.class),
            newUSK(0L),
            100L,
            true,
            50L,
            500L);
    ClientContext context = mock(ClientContext.class);

    round.checkFinishedForNow(context, false, false);

    verifyNoInteractions(subscribers);
  }

  @Test
  void checkFinishedForNow_whenAllAttemptsCooled_notifiesSubscribers() throws Exception {
    USKAttemptManager attempts = mock(USKAttemptManager.class);
    USKAttempt attempt = mock(USKAttempt.class);
    when(attempt.everInCooldown()).thenReturn(true);
    when(attempts.snapshotPollingAttempts()).thenReturn(new USKAttempt[] {attempt});
    USKSubscriberRegistry subscribers = mock(USKSubscriberRegistry.class);
    USKProgressCallback callback = mock(USKProgressCallback.class);
    USKCallback otherCallback = mock(USKCallback.class);
    when(subscribers.snapshotSubscribers()).thenReturn(new USKCallback[] {callback, otherCallback});
    USKPollingRound round =
        newRound(
            attempts,
            mock(USKStoreCheckCoordinator.class),
            mock(USKDateHintFetches.class),
            subscribers,
            mock(USKManager.class),
            newUSK(0L),
            100L,
            true,
            50L,
            500L);
    ClientContext context = mock(ClientContext.class);

    round.checkFinishedForNow(context, false, false);

    verify(callback).onRoundFinished(context);
    verifyNoInteractions(otherCallback);
  }

  @ParameterizedTest
  @CsvSource({"true,false", "false,true"})
  void notifyFinishedForNow_whenCancelledOrCompleted_skipsCallbacks(
      boolean cancelled, boolean completed) throws Exception {
    USKSubscriberRegistry subscribers = mock(USKSubscriberRegistry.class);
    USKPollingRound round =
        newRound(
            mock(USKAttemptManager.class),
            mock(USKStoreCheckCoordinator.class),
            mock(USKDateHintFetches.class),
            subscribers,
            mock(USKManager.class),
            newUSK(0L),
            100L,
            true,
            50L,
            500L);
    ClientContext context = mock(ClientContext.class);

    round.notifyFinishedForNow(context, cancelled, completed);

    verifyNoInteractions(subscribers);
  }

  @Test
  void rescheduleBackgroundPoll_whenNoProgress_doublesAndCapsSleepTime() throws Exception {
    USKManager manager = mock(USKManager.class);
    USK usk = newUSK(10L);
    when(manager.lookupLatestSlot(usk)).thenReturn(10L);
    USKPollingRound round =
        newRound(
            mock(USKAttemptManager.class),
            mock(USKStoreCheckCoordinator.class),
            mock(USKDateHintFetches.class),
            mock(USKSubscriberRegistry.class),
            manager,
            usk,
            60L,
            true,
            30L,
            100L);
    ClientContext context = minimalContext(new FixedRandomSource());

    long delay = round.rescheduleBackgroundPoll(context, 10L);

    assertEquals(0L, delay);
    assertEquals(100L, round.sleepTime());
    assertTrue(round.firstLoop());
  }

  @Test
  void rescheduleBackgroundPoll_whenNoProgress_keepsBackoffUnderMax() throws Exception {
    USKManager manager = mock(USKManager.class);
    USK usk = newUSK(10L);
    when(manager.lookupLatestSlot(usk)).thenReturn(10L);
    USKPollingRound round =
        newRound(
            mock(USKAttemptManager.class),
            mock(USKStoreCheckCoordinator.class),
            mock(USKDateHintFetches.class),
            mock(USKSubscriberRegistry.class),
            manager,
            usk,
            40L,
            true,
            30L,
            200L);
    ClientContext context = minimalContext(new FixedRandomSource());

    long delay = round.rescheduleBackgroundPoll(context, 10L);

    assertEquals(0L, delay);
    assertEquals(80L, round.sleepTime());
    assertTrue(round.firstLoop());
  }

  @Test
  void rescheduleBackgroundPoll_whenProgressDetected_resetsSleepTimeAndFirstLoop()
      throws Exception {
    USKManager manager = mock(USKManager.class);
    USK usk = newUSK(10L);
    when(manager.lookupLatestSlot(usk)).thenReturn(15L);
    USKPollingRound round =
        newRound(
            mock(USKAttemptManager.class),
            mock(USKStoreCheckCoordinator.class),
            mock(USKDateHintFetches.class),
            mock(USKSubscriberRegistry.class),
            manager,
            usk,
            40L,
            true,
            20L,
            200L);
    ClientContext context = minimalContext(new FixedRandomSource());

    long delay = round.rescheduleBackgroundPoll(context, 12L);

    assertEquals(0L, delay);
    assertEquals(20L, round.sleepTime());
    assertFalse(round.firstLoop());
  }

  @Test
  void setFirstLoop_whenInvoked_updatesState() throws Exception {
    USKPollingRound round =
        newRound(
            mock(USKAttemptManager.class),
            mock(USKStoreCheckCoordinator.class),
            mock(USKDateHintFetches.class),
            mock(USKSubscriberRegistry.class),
            mock(USKManager.class),
            newUSK(0L),
            100L,
            true,
            50L,
            500L);

    round.setFirstLoop(false);

    //noinspection ConstantValue
    assertFalse(round.firstLoop());
  }
}
