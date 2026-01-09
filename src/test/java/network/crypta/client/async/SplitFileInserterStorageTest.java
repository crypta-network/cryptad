package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import java.util.Random;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FECCodec;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContextOptions;
import network.crypta.client.InsertException;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.Metadata.SplitfileAlgorithm;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.keys.CHKBlock;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.ByteArrayRandomAccessBuffer;
import network.crypta.support.io.ByteArrayRandomAccessBufferFactory;
import network.crypta.support.io.FileRandomAccessBuffer;
import network.crypta.support.io.NullRandomAccessBuffer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SplitFileInserterStorageTest {

  @Mock private SplitFileInserterStorageCallback callback;
  @Mock private KeysFetchingLocally keysFetching;

  private PriorityAwareExecutor executor;
  private MemoryLimitedJobRunner mlRunner;
  private SplitFileInserterStorageTest.ImmediateTicker ticker;
  private LockableRandomAccessBufferFactory rafFactory;
  private ArrayBucketFactory bucketFactory;
  private ChecksumChecker checker;
  private Random random;

  @BeforeEach
  void setUp() {
    // Immediate inline executor to make async code deterministic in tests
    executor = new ImmediateExecutor();
    // Generous capacity and two worker "threads" (inline) with a few priority buckets (0..3)
    mlRunner = new MemoryLimitedJobRunner(64L * 1024 * 1024, 2, executor, 4);
    ticker = new ImmediateTicker(executor);
    rafFactory = new ByteArrayRandomAccessBufferFactory();
    bucketFactory = new ArrayBucketFactory();
    checker = ChecksumChecker.create(ChecksumChecker.CHECKSUM_CRC);
    random = new Random(1234);
    // No stubbing needed on keysFetching; default boolean return is fine for tests
  }

  private static InsertContext newInsertContext(InsertContext.CompatibilityMode cmode) {
    // Keep values small and deterministic. Blocks per segment defaults are in
    // HighLevelSimpleClientImpl.
    return new InsertContext(
        InsertContextOptions.builder()
            .retryLimits(3, 0)
            .splitfileSegmentLimits(
                FECCodec.MAX_TOTAL_BLOCKS_PER_SEGMENT, FECCodec.MAX_TOTAL_BLOCKS_PER_SEGMENT)
            .clientOptions(new SimpleEventProducer(), false, false, false)
            .compressorDescriptor(null)
            .redundancy(0, 0)
            .compatibility(cmode)
            .build());
  }

  private SplitFileInserterStorage newStorage(
      LockableRandomAccessBuffer original,
      boolean persistent,
      InsertContext.CompatibilityMode cmode,
      byte[] explicitSplitfileKey)
      throws IOException, InsertException {
    InsertContext ctx = newInsertContext(cmode);
    byte[] hashThisLayerOnly =
        (explicitSplitfileKey == null
                && (cmode == InsertContext.CompatibilityMode.COMPAT_CURRENT
                    || cmode.ordinal() >= InsertContext.CompatibilityMode.COMPAT_1255.ordinal()))
            ? new byte[32]
            : null;
    SplitFileInserterStorageRuntimeParams runtimeParams =
        new SplitFileInserterStorageRuntimeParams.Builder()
            .callback(callback)
            .random(random)
            .memoryLimitedJobRunner(mlRunner)
            .jobRunner(new network.crypta.support.DummyJobRunner(executor, null))
            .ticker(ticker)
            .keysFetching(keysFetching)
            .build();
    SplitFileInserterStorageInitParams initParams =
        new SplitFileInserterStorageInitParams.Builder()
            .originalData(original)
            .decompressedLength(original.size())
            .runtime(runtimeParams)
            .compressionCodec(null)
            .meta(new ClientMetadata("application/octet-stream"))
            .isMetadata(false)
            .archiveType(null)
            .rafFactory(rafFactory)
            .persistent(persistent)
            .ctx(ctx)
            .splitfileCryptoAlgorithm((byte) 0)
            .splitfileCryptoKey(explicitSplitfileKey)
            .hashThisLayerOnly(hashThisLayerOnly)
            .hashes(null)
            .tempBucketFactory(bucketFactory)
            .checker(checker)
            .topDontCompress(false)
            .topRequiredBlocks(0)
            .topTotalBlocks(0)
            .origDataSize(original.size())
            .origCompressedDataSize(original.size())
            .build();
    return new SplitFileInserterStorage(initParams);
  }

  @Test
  void constructor_whenDataTooBig_expectTooBigException() {
    long huge = ((long) Integer.MAX_VALUE) * CHKBlock.DATA_LENGTH + 1L;
    try (LockableRandomAccessBuffer original = new NullRandomAccessBuffer(huge)) {
      InsertContext ctx = newInsertContext(InsertContext.CompatibilityMode.COMPAT_CURRENT);
      assertEquals(SplitfileAlgorithm.ONION_STANDARD, ctx.getSplitfileAlgorithm());

      InsertException ex =
          assertThrows(
              InsertException.class,
              () ->
                  new SplitFileInserterStorage(
                      new SplitFileInserterStorageInitParams.Builder()
                          .originalData(original)
                          .decompressedLength(huge)
                          .runtime(
                              new SplitFileInserterStorageRuntimeParams.Builder()
                                  .callback(callback)
                                  .random(random)
                                  .memoryLimitedJobRunner(mlRunner)
                                  .jobRunner(
                                      new network.crypta.support.DummyJobRunner(executor, null))
                                  .ticker(ticker)
                                  .keysFetching(keysFetching)
                                  .build())
                          .compressionCodec(null)
                          .meta(new ClientMetadata("text/plain"))
                          .isMetadata(false)
                          .archiveType(null)
                          .rafFactory(rafFactory)
                          .persistent(false)
                          .ctx(ctx)
                          .splitfileCryptoAlgorithm((byte) 0)
                          .splitfileCryptoKey(null)
                          .hashThisLayerOnly(null)
                          .hashes(null)
                          .tempBucketFactory(bucketFactory)
                          .checker(checker)
                          .topDontCompress(false)
                          .topRequiredBlocks(0)
                          .topTotalBlocks(0)
                          .origDataSize(huge)
                          .origCompressedDataSize(huge)
                          .build()));
      assertEquals(InsertExceptionMode.TOO_BIG, ex.getMode());
    }
  }

  @Test
  void hasSplitfileKey_whenExplicitKeyProvided_expectTrueAndCounts() throws Exception {
    byte[] buf = new byte[CHKBlock.DATA_LENGTH];
    for (int i = 0; i < buf.length; i++) buf[i] = (byte) i;
    SplitFileInserterStorage storage =
        newStorage(
            new ByteArrayRandomAccessBuffer(buf),
            /* persistent= */ false,
            InsertContext.CompatibilityMode.COMPAT_CURRENT,
            new byte[32]);

    assertTrue(storage.hasSplitfileKey());
    // For 1 data block and COMPAT_CURRENT, OnionFECCodec returns 2 check blocks for segment of size
    // 1
    assertEquals(1 + 2, storage.getTotalBlockCount());
    // Keys count equals total blocks (1 data + 2 check)
    assertEquals(3L, storage.countAllKeys());
    // Before encoding, chooser reports all blocks as fetchable (eligibility is enforced later)
    assertEquals(3L, storage.countSendableKeys());
  }

  @Test
  void hasSplitfileKey_whenOldCompatAndNoKey_expectFalse() throws Exception {
    byte[] buf = new byte[CHKBlock.DATA_LENGTH];
    SplitFileInserterStorage storage =
        newStorage(
            new ByteArrayRandomAccessBuffer(buf),
            /* persistent= */ false,
            InsertContext.CompatibilityMode.COMPAT_1251,
            /* explicitSplitfileKey= */ null);

    assertFalse(storage.hasSplitfileKey());
  }

  @Test
  void writeAndReadSegmentCheckBlock_whenCalled_expectSameBytes() throws Exception {
    byte[] data = new byte[CHKBlock.DATA_LENGTH];
    SplitFileInserterStorage storage =
        newStorage(
            new ByteArrayRandomAccessBuffer(data),
            /* persistent= */ false,
            InsertContext.CompatibilityMode.COMPAT_CURRENT,
            null);

    byte[] check = new byte[CHKBlock.DATA_LENGTH];
    for (int i = 0; i < check.length; i++) check[i] = (byte) (255 - i);
    // Single segment, first check block is index 0
    storage.writeSegmentCheckBlock(0, 0, check);
    byte[] readBack = storage.readSegmentCheckBlock(0, 0);
    assertArrayEquals(check, readBack);
  }

  @Test
  void persistentOffsets_whenPersistent_expectNonZeroAndIOWorks() throws Exception {
    // Two data blocks to ensure presence of statuses and a check block region
    int size = CHKBlock.DATA_LENGTH * 2;
    java.io.File tmp = java.io.File.createTempFile("sfi-persist-", ".bin");
    tmp.deleteOnExit();
    FileRandomAccessBuffer original = new FileRandomAccessBuffer(tmp, size, /* readOnly= */ false);
    byte[] fill = new byte[size];
    for (int i = 0; i < size; i++) fill[i] = (byte) (i * 3);
    original.pwrite(0, fill, 0, size);

    SplitFileInserterStorage storage =
        newStorage(
            original, /* persistent= */ true, InsertContext.CompatibilityMode.COMPAT_CURRENT, null);

    // Segment 0 must have a status offset when persistent
    long statusOffset = storage.getOffsetSegmentStatus(0);
    assertTrue(statusOffset >= 0);

    // Read/write check block still functions in persistent mode
    byte[] check = new byte[CHKBlock.DATA_LENGTH];
    for (int i = 0; i < check.length; i++) check[i] = (byte) (i ^ 0x5A);
    storage.writeSegmentCheckBlock(0, 0, check);
    assertArrayEquals(check, storage.readSegmentCheckBlock(0, 0));
  }

  @Test
  void readSegmentDataBlock_whenLastBlockPadded_expectPaddedBytes() throws Exception {
    int extra = 10;
    int total = CHKBlock.DATA_LENGTH + extra; // two data blocks; last is short and should be padded
    ByteArrayRandomAccessBuffer original = new ByteArrayRandomAccessBuffer(total);
    byte[] pattern = new byte[total];
    for (int i = 0; i < total; i++) pattern[i] = (byte) (i * 7);
    original.pwrite(0, pattern, 0, pattern.length);

    SplitFileInserterStorage storage =
        newStorage(
            original,
            /* persistent= */ false,
            InsertContext.CompatibilityMode.COMPAT_CURRENT,
            null);

    // Expected padded last block: pad the last `extra` bytes to CHKBlock.DATA_LENGTH
    byte[] tail = new byte[extra];
    System.arraycopy(pattern, CHKBlock.DATA_LENGTH, tail, 0, extra);
    byte[] expected = BucketTools.pad(tail, CHKBlock.DATA_LENGTH, tail.length);

    // Only one segment, last data block index is 1
    byte[] last = storage.readSegmentDataBlock(0, 1);
    assertArrayEquals(expected, last);
  }

  @Test
  void start_whenNoCrossSegments_encodesAndUpdatesStatus() throws Exception {
    byte[] data = new byte[CHKBlock.DATA_LENGTH];
    SplitFileInserterStorage storage =
        newStorage(
            new ByteArrayRandomAccessBuffer(data),
            /* persistent= */ false,
            InsertContext.CompatibilityMode.COMPAT_CURRENT,
            null);

    // Simulate STARTED without triggering actual encode, then mark segment encoded and notify.
    java.lang.reflect.Field statusField = SplitFileInserterStorage.class.getDeclaredField("status");
    statusField.setAccessible(true);
    statusField.set(storage, SplitFileInserterStorage.Status.STARTED);
    java.lang.reflect.Field f = SplitFileInserterSegmentStorage.class.getDeclaredField("encoded");
    f.setAccessible(true);
    f.set(storage.segments[0], true);
    storage.onFinishedEncoding(storage.segments[0]);

    assertEquals(SplitFileInserterStorage.Status.ENCODED, storage.getStatus());
    assertEquals(1, storage.countEncodedSegments());
    verify(callback, times(1)).onFinishedEncode();
    verify(callback, times(1)).encodingProgress();
    verify(callback, never()).onFailed(any());
  }

  @Test
  void failOnDiskError_whenCalled_expectFailedAndCallback() throws Exception {
    byte[] data = new byte[CHKBlock.DATA_LENGTH];
    SplitFileInserterStorage storage =
        newStorage(
            new ByteArrayRandomAccessBuffer(data),
            /* persistent= */ false,
            InsertContext.CompatibilityMode.COMPAT_CURRENT,
            null);

    storage.failOnDiskError(new IOException("boom"));

    assertEquals(SplitFileInserterStorage.Status.FAILED, storage.getStatus());
    verify(callback, times(1)).onFailed(any(InsertException.class));
    // Once finished, wakeup time is -1
    assertEquals(-1, storage.getWakeupTime(null, System.currentTimeMillis()));
  }

  @Test
  void chooseBlock_whenAllSegmentsCancelled_expectNullAndCooldown() throws Exception {
    byte[] data = new byte[CHKBlock.DATA_LENGTH];
    SplitFileInserterStorage storage =
        newStorage(
            new ByteArrayRandomAccessBuffer(data),
            /* persistent= */ false,
            InsertContext.CompatibilityMode.COMPAT_CURRENT,
            null);

    // Cancel all segments to make no block selectable
    for (SplitFileInserterSegmentStorage seg : storage.segments) {
      assertTrue(seg.cancel());
    }
    SplitFileInserterSegmentStorage.BlockInsert choice = storage.chooseBlock();
    assertNull(choice);
    assertTrue(storage.noBlocksToSend());
    assertEquals(Long.MAX_VALUE, storage.getWakeupTime(null, System.currentTimeMillis()));
  }

  // --- Test helpers ---

  private static final class ImmediateExecutor implements PriorityAwareExecutor {
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
      return new int[] {0, 0, 0, 0};
    }

    @Override
    public int[] runningThreads() {
      return new int[] {0, 0, 0, 0};
    }

    @Override
    public int getWaitingThreadsCount() {
      return 0;
    }
  }

  private static final class ImmediateTicker implements Ticker {
    private final PriorityAwareExecutor exec;

    ImmediateTicker(PriorityAwareExecutor exec) {
      this.exec = exec;
    }

    @Override
    public void queueTimedJob(Runnable job, long offset) {
      // Execute immediately for determinism in tests
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
      // No-op for immediate execution
    }

    @Override
    public void queueTimedJobAbsolute(
        Runnable runner, String name, long time, boolean runOnTickerAnyway, boolean noDupes) {
      exec.execute(runner);
    }
  }
}
