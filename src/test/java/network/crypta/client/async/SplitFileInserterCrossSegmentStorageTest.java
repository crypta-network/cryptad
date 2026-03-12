package network.crypta.client.async;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import network.crypta.client.ClientMetadata;
import network.crypta.client.HighLevelSimpleClientImpl;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertException;
import network.crypta.client.Metadata;
import network.crypta.crypt.CRCChecksumChecker;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.Key;
import network.crypta.node.BaseSendableGet;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.node.SendableRequestItemKey;
import network.crypta.support.CheatingTicker;
import network.crypta.support.DummyJobRunner;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PooledExecutor;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.WaitableExecutor;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.ByteArrayRandomAccessBufferFactory;
import network.crypta.support.io.NativeThread;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.spy;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SplitFileInserterCrossSegmentStorageTest {

  // Shared, lightweight test infrastructure
  private WaitableExecutor executor;
  private CheatingTicker ticker;
  private MemoryLimitedJobRunner mlr; // configured per-test
  private final ChecksumChecker checker = new CRCChecksumChecker();
  private final LockableRandomAccessBufferFactory rafFactory =
      new ByteArrayRandomAccessBufferFactory();
  private final InsertContext baseContext =
      HighLevelSimpleClientImpl.makeDefaultInsertContext(new ArrayBucketFactory(), null);

  @BeforeEach
  void setUp() {
    executor = new WaitableExecutor(new PooledExecutor());
    ticker = new CheatingTicker(executor);
  }

  @Test
  void startEncode_whenNotEncoded_encodesAndSetsFlags() throws Exception {
    // Arrange: minimal real parent storage with 2 data blocks, transient (no persistence)
    final long size = CHKBlock.DATA_LENGTH * 2L;
    LockableRandomAccessBuffer data = rafFactory.makeRAF(size);
    byte[] key = new byte[32];
    mlr =
        new MemoryLimitedJobRunner(
            16 * 1024 * 1024L, 4, executor, NativeThread.JAVA_PRIORITY_RANGE);
    SplitFileInserterStorage parent =
        new SplitFileInserterStorage(
            new SplitFileInserterStorageInitParams.Builder()
                .originalData(data)
                .decompressedLength(size)
                .runtime(
                    new SplitFileInserterStorageRuntimeParams.Builder()
                        .callback(new NoopCallback())
                        .random(new SecureRandom())
                        .memoryLimitedJobRunner(mlr)
                        .jobRunner(new DummyJobRunner(executor, null))
                        .ticker(ticker)
                        .keysFetching(new NoopKeysFetchingLocally())
                        .build())
                .compressionCodec(null)
                .meta(new ClientMetadata())
                .isMetadata(false)
                .archiveType(null)
                .rafFactory(rafFactory)
                .persistent(false)
                .ctx(baseContext)
                .splitfileCryptoAlgorithm(Key.ALGO_AES_CTR_256_SHA256)
                .splitfileCryptoKey(key)
                .hashThisLayerOnly(null)
                .hashes(null)
                .tempBucketFactory(new ArrayBucketFactory())
                .checker(checker)
                .topDontCompress(false)
                .topRequiredBlocks(0)
                .topTotalBlocks(0)
                .origDataSize(0)
                .origCompressedDataSize(0)
                .build());
    // Spy to neutralize the callback invoked after encoding so we don't depend on crossSegments.
    SplitFileInserterStorage spyParent = spy(parent);
    doNothing().when(spyParent).onFinishedEncoding(any(SplitFileInserterCrossSegmentStorage.class));

    // Build a tiny cross-segment: 2 data blocks, 0 cross-check blocks
    SplitFileInserterCrossSegmentStorage xs =
        new SplitFileInserterCrossSegmentStorage(spyParent, 0, false, 2, 0);
    xs.addDataBlock(spyParent.segments[0], 0);
    xs.addDataBlock(spyParent.segments[0], 1);

    // Act: run the cross-segment encode
    assertFalse(xs.isFinishedEncoding());
    xs.startEncode((short) 0);
    executor.waitForIdle();

    // Assert: encoding completed and flags updated
    assertTrue(xs.isFinishedEncoding());
    assertFalse(xs.isEncoding());
    assertTrue(xs.hasCompletedOrFailed());
  }

  @Test
  void cancel_whenNotStarted_expectImmediateCancel() {
    // Arrange: parent only needed for checksum setup; use small, transient configuration
    SplitFileInserterStorage parent = minimalParent();
    SplitFileInserterCrossSegmentStorage xs =
        new SplitFileInserterCrossSegmentStorage(parent, 1, false, 1, 0);
    xs.addDataBlock(parent.segments[0], 0);

    // Act
    boolean cancelledNow = xs.cancel();

    // Assert
    assertTrue(cancelledNow);
    assertTrue(xs.hasCompletedOrFailed());
    assertFalse(xs.isEncoding());
    assertFalse(xs.hasEncodedSuccessfully());
  }

  @Test
  void cancel_whenEncoding_expectDeferredCancel() {
    // Arrange: prevent jobs from starting by using a no-op executor
    PriorityAwareExecutor noopExecutor =
        new PriorityAwareExecutor() {
          @Override
          public void execute(@NotNull Runnable job) {
            // drop tasks
          }

          @Override
          public void execute(Runnable job, String jobName) {
            // drop tasks
          }

          @Override
          public void execute(Runnable job, String jobName, boolean fromTicker) {
            // drop tasks
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
    mlr =
        new MemoryLimitedJobRunner(
            16 * 1024 * 1024L, 1, noopExecutor, NativeThread.JAVA_PRIORITY_RANGE);
    SplitFileInserterStorage parent = minimalParent(mlr);
    SplitFileInserterCrossSegmentStorage xs =
        new SplitFileInserterCrossSegmentStorage(parent, 2, false, 2, 0);
    xs.addDataBlock(parent.segments[0], 0);
    xs.addDataBlock(parent.segments[0], 1);

    // Act: begin encoding (won't actually run), then cancel
    xs.startEncode((short) 0);
    assertTrue(xs.isEncoding());
    boolean cancelledNow = xs.cancel();

    // Assert: still considered in-progress until the job thread finishes
    assertFalse(cancelledNow);
    assertFalse(xs.hasCompletedOrFailed());
    assertTrue(xs.isEncoding());
  }

  @Test
  void storedStatusLength_whenConstructed_matchesFormat() {
    // Arrange
    SplitFileInserterStorage parent = minimalParent();
    SplitFileInserterCrossSegmentStorage xs =
        new SplitFileInserterCrossSegmentStorage(parent, 3, false, 2, 0);
    xs.addDataBlock(parent.segments[0], 0);
    xs.addDataBlock(parent.segments[0], 1);

    // Act
    long len = xs.storedStatusLength();

    // Assert: int segNo (4) + boolean encoded (1) + checksum (4)
    assertEquals(4 + 1 + parent.checker.checksumLength(), len);
  }

  @Test
  void writeFixedSettings_whenReadBack_containsExpectedMapping() throws Exception {
    // Arrange
    SplitFileInserterStorage parent = minimalParent();
    SplitFileInserterCrossSegmentStorage xs =
        new SplitFileInserterCrossSegmentStorage(parent, 4, false, 2, 0);
    xs.addDataBlock(parent.segments[0], 0);
    xs.addDataBlock(parent.segments[0], 1);

    // Act: serialize settings
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      xs.writeFixedSettings(dos);
    }
    byte[] raw = baos.toByteArray();

    // Assert: parse and verify fields
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(raw))) {
      int dataBlocks = dis.readInt();
      int crossBlocks = dis.readInt();
      int seg0 = dis.readInt();
      int block0 = dis.readInt();
      int seg1 = dis.readInt();
      int block1 = dis.readInt();
      int statusLength = dis.readInt();

      assertEquals(2, dataBlocks);
      assertEquals(0, crossBlocks);
      assertEquals(parent.segments[0].segNo, seg0);
      assertEquals(0, block0);
      assertEquals(parent.segments[0].segNo, seg1);
      assertEquals(1, block1);
      assertEquals(xs.storedStatusLength(), statusLength);
    }
  }

  // Helpers

  private SplitFileInserterStorage minimalParent() {
    return minimalParent(
        new MemoryLimitedJobRunner(
            16 * 1024 * 1024L, 2, executor, NativeThread.JAVA_PRIORITY_RANGE));
  }

  private SplitFileInserterStorage minimalParent(MemoryLimitedJobRunner runner) {
    final long size = CHKBlock.DATA_LENGTH * 2L;
    try {
      LockableRandomAccessBuffer data = rafFactory.makeRAF(size);
      byte[] key = new byte[32];
      return new SplitFileInserterStorage(
          new SplitFileInserterStorageInitParams.Builder()
              .originalData(data)
              .decompressedLength(size)
              .runtime(
                  new SplitFileInserterStorageRuntimeParams.Builder()
                      .callback(new NoopCallback())
                      .random(new SecureRandom())
                      .memoryLimitedJobRunner(runner)
                      .jobRunner(new DummyJobRunner(executor, null))
                      .ticker(ticker)
                      .keysFetching(new NoopKeysFetchingLocally())
                      .build())
              .compressionCodec(null)
              .meta(new ClientMetadata())
              .isMetadata(false)
              .archiveType(null)
              .rafFactory(rafFactory)
              .persistent(false)
              .ctx(baseContext)
              .splitfileCryptoAlgorithm(Key.ALGO_AES_CTR_256_SHA256)
              .splitfileCryptoKey(key)
              .hashThisLayerOnly(null)
              .hashes(null)
              .tempBucketFactory(new ArrayBucketFactory())
              .checker(checker)
              .topDontCompress(false)
              .topRequiredBlocks(0)
              .topTotalBlocks(0)
              .origDataSize(0)
              .origCompressedDataSize(0)
              .build());
    } catch (IOException | InsertException e) {
      throw new AssertionError("Failed to create minimal parent storage", e);
    }
  }

  // Minimal callback and KeysFetching stubs for isolated tests
  private static final class NoopCallback implements SplitFileInserterStorageCallback {
    @Override
    public void onFinishedEncode() {
      // Intentionally empty: test stub callback does not need to react
    }

    @Override
    public void encodingProgress() {
      // Intentionally empty: progress callbacks are irrelevant in these tests
    }

    @Override
    public void onHasKeys() {
      // Intentionally empty: tests drive flow explicitly
    }

    @Override
    public void onSucceeded(Metadata metadata) {
      // Intentionally empty: success handling not required for these tests
    }

    @Override
    public void onFailed(InsertException e) {
      // Intentionally empty: failure handling not required for these tests
    }

    @Override
    public void onInsertedBlock() {
      // Intentionally empty: not observing per-block inserts here
    }

    @Override
    public void clearCooldown() {
      // Intentionally empty: no cooldown behavior in these tests
    }

    @Override
    public short getPriorityClass() {
      return 0;
    }
  }

  private static final class NoopKeysFetchingLocally implements KeysFetchingLocally {
    @Override
    public long checkRecentlyFailed(Key key, boolean realTime) {
      return 0;
    }

    @Override
    public boolean hasKey(Key key, BaseSendableGet getterWaiting) {
      return false;
    }

    @Override
    public boolean hasInsert(SendableRequestItemKey token) {
      return false;
    }
  }
}
