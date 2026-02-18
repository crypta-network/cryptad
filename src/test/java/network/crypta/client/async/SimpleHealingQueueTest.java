package network.crypta.client.async;

import java.io.IOException;
import java.util.Random;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.InsertContextOptions;
import network.crypta.client.InsertException;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.Key;
import network.crypta.node.ClientContextResources;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SimpleHealingQueueTest {

  private InsertContext insertCtx;
  private ClientContext clientCtx;

  @BeforeEach
  void setUp() {
    insertCtx =
        new InsertContext(
            InsertContextOptions.builder()
                .retryLimits(0, 1)
                .splitfileSegmentLimits(1, 1)
                .clientOptions(new SimpleEventProducer(), false, false, false)
                .compressorDescriptor(null)
                .redundancy(0, 0)
                .compatibility(CompatibilityMode.COMPAT_CURRENT)
                .build());
    insertCtx.setGetCHKOnly(true); // make SingleBlockInserter.schedule() complete synchronously

    // Minimal, deterministic ClientContext
    PriorityAwareExecutor directExec = new DirectExecutor();
    MemoryLimitedJobRunner mlr = new MemoryLimitedJobRunner(1, 1, directExec, 1);
    clientCtx =
        new ClientContext(
            /*bootID*/ 1L,
            new ClientContextRuntime(
                null,
                directExec,
                mlr,
                new NoopTicker(directExec),
                new DummyRandomSource(123L),
                new Random(42L),
                null),
            new ClientContextStorageFactories(null, null, null, null, null, null, null),
            new ClientContextRafFactories(null, null),
            new ClientContextServices(
                new ClientContextResources(null, null), null, null, null, null, null),
            new ClientContextDefaults(null, insertCtx, null));
  }

  @Test
  void innerQueue_whenMaxRunningExceeded_expectFalse() {
    // Arrange: queue with maxRunning = 0 and pre-filled running map
    HealingDecisionSupplier alwaysTrue = new HealingDecisionSupplier(() -> 0.0, () -> false);
    SimpleHealingQueue queue = new SimpleHealingQueue(insertCtx, (short) 0, 0, alwaysTrue);
    Bucket prefillBucket = new ArrayBucket();
    queue.runningInserters.put(prefillBucket, mock(SingleBlockInserter.class));

    Bucket data = new ArrayBucket();

    // Act
    boolean enqueued =
        queue.innerQueue(
            data, /*cryptoKey*/ null, /*cryptoAlgorithm*/ Key.ALGO_AES_CTR_256_SHA256, clientCtx);

    // Assert
    assertFalse(enqueued, "Queue should refuse when maxRunning is exceeded");
  }

  @Test
  void queue_whenInnerQueueReturnsFalse_expectBucketFreed() {
    // Arrange: use maxRunning = 0 so innerQueue returns false; queue() should free the bucket
    HealingDecisionSupplier alwaysTrue = new HealingDecisionSupplier(() -> 0.0, () -> false);
    SimpleHealingQueue queue = new SimpleHealingQueue(insertCtx, (short) 0, 0, alwaysTrue);
    queue.runningInserters.put(new ArrayBucket(), mock(SingleBlockInserter.class));
    ArrayBucket data = new ArrayBucket();

    // Act
    queue.queue(data, /*cryptoKey*/ null, Key.ALGO_AES_CTR_256_SHA256, clientCtx);

    // Assert: bucket should be freed
    assertThrows(IOException.class, data::getInputStream);
  }

  @Test
  void innerQueue_whenHealingDecisionFalse_expectNotAddedAndFreed() {
    // Arrange: opennet enabled, random=0 → shouldHeal() always false regardless of key location
    HealingDecisionSupplier neverHeal =
        new HealingDecisionSupplier(() -> 0.0, () -> true, () -> 0.0);
    SimpleHealingQueue queue = new SimpleHealingQueue(insertCtx, (short) 0, 10, neverHeal);
    ArrayBucket data = new ArrayBucket();

    // Act
    boolean enqueued =
        queue.innerQueue(data, /*cryptoKey*/ null, Key.ALGO_AES_CTR_256_SHA256, clientCtx);

    // Assert: innerQueue returns true (scheduled), but running map never records it; bucket freed
    assertTrue(enqueued, "Insert should be scheduled even if not tracked");
    assertEquals(0, queue.runningInserters.size(), "Healing-disabled inserts must not be tracked");
    assertThrows(
        IOException.class, data::getInputStream, "Data bucket must be freed on completion");
    assertEquals(FreenetURI.EMPTY_CHK_URI, queue.getURI());
  }

  @Test
  void innerQueue_whenHealingDecisionTrue_expectTrackedThenRemovedAndFreed() {
    // Arrange: darknet (opennet disabled) → shouldHeal() always true
    HealingDecisionSupplier alwaysHeal = new HealingDecisionSupplier(() -> 0.5, () -> false);
    SimpleHealingQueue queue = new SimpleHealingQueue(insertCtx, (short) 0, 10, alwaysHeal);
    ArrayBucket data = new ArrayBucket();

    // Act
    boolean enqueued =
        queue.innerQueue(data, /*cryptoKey*/ null, Key.ALGO_AES_CTR_256_SHA256, clientCtx);

    // Assert: scheduled successfully; running map is empty after synchronous success; bucket freed
    assertTrue(enqueued, "Insert should be scheduled successfully");
    assertEquals(0, queue.runningInserters.size(), "Entry should be removed after success");
    assertThrows(IOException.class, data::getInputStream, "Data bucket must be freed on success");
  }

  @Test
  void onFailure_whenCalled_removesFromRunningAndFreesBucket() {
    // Arrange: build a real SingleBlockInserter so getToken() returns our bucket
    HealingDecisionSupplier alwaysHeal = new HealingDecisionSupplier(() -> 0.0, () -> false);
    SimpleHealingQueue queue = new SimpleHealingQueue(insertCtx, (short) 0, 10, alwaysHeal);
    ArrayBucket data = new ArrayBucket();

    SingleBlockInserter sbi =
        new SingleBlockInserter(
            new BlockInsertPayload(
                data,
                FreenetURI.EMPTY_CHK_URI,
                (short) -1,
                /*isMetadata*/ false,
                /*sourceLength*/ 0,
                /*cryptoAlgorithm*/ Key.ALGO_AES_CTR_256_SHA256,
                /*cryptoKey*/ null),
            new BlockInsertParams(queue, insertCtx, queue, 123, data, false, clientCtx),
            new BlockInsertOptions(false, false, false, 0),
            /*dontSendEncoded*/ true);

    // Put into the running map as SimpleHealingQueue does when healing is accepted
    queue.runningInserters.put(data, sbi);

    // Act: simulate failure callback
    queue.onFailure(
        new InsertException(InsertException.InsertExceptionMode.INTERNAL_ERROR), sbi, clientCtx);

    // Assert: removed and freed
    assertEquals(0, queue.runningInserters.size(), "Entry must be removed on failure");
    assertThrows(IOException.class, data::getInputStream, "Data bucket must be freed on failure");
  }

  @Test
  void trivial_methods_returnExpectedDefaults() {
    HealingDecisionSupplier alwaysTrue = new HealingDecisionSupplier(() -> 0.0, () -> false);
    SimpleHealingQueue queue = new SimpleHealingQueue(insertCtx, (short) 1, 1, alwaysTrue);

    assertEquals(FreenetURI.EMPTY_CHK_URI, queue.getURI());
    assertFalse(queue.isFinished());
    assertEquals(0, queue.getMinSuccessFetchBlocks());
    assertNull(queue.getCallback());
    assertDoesNotThrow(() -> queue.cancel(clientCtx));
    assertDoesNotThrow(() -> queue.innerOnResume(clientCtx));
  }

  // --- Test helpers ---

  /** Executes tasks inline; returns zeros for stats. */
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
      return new int[] {0};
    }

    @Override
    public int[] runningThreads() {
      return new int[] {0};
    }

    @Override
    public int getWaitingThreadsCount() {
      return 0;
    }
  }

  /** No-op ticker used to satisfy ClientContext construction. */
  private static final class NoopTicker implements Ticker {
    private final PriorityAwareExecutor exec;

    NoopTicker(PriorityAwareExecutor exec) {
      this.exec = exec;
    }

    @Override
    public void queueTimedJob(Runnable job, long offset) {
      exec.execute(job);
    }

    @Override
    public void queueTimedJob(
        Runnable job, String name, long offset, boolean runOnTickerAnyway, boolean noDupes) {
      exec.execute(job);
    }

    @Override
    public PriorityAwareExecutor getExecutor() {
      return exec;
    }

    @Override
    public void removeQueuedJob(Runnable job) {
      // no-op
    }

    @Override
    public void queueTimedJobAbsolute(
        Runnable runner, String name, long time, boolean runOnTickerAnyway, boolean noDupes) {
      exec.execute(runner);
    }
  }
}
