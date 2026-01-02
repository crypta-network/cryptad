package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import network.crypta.client.FECCodec;
import network.crypta.client.async.PersistentJobRunner.CheckpointLock;
import network.crypta.keys.CHKBlock;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PriorityAwareExecutor;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SplitFileFetcherCrossSegmentStorageTest {

  @Mock private FECCodec codec;

  private static SplitFileFetcherStorage newParentWithRunners(
      MemoryLimitedJobRunner mlr, PersistentJobRunner pjr) {
    // Use a Mockito mock and inject the required (package-private final) fields via reflection.
    SplitFileFetcherStorage parent = mock(SplitFileFetcherStorage.class);
    setFinal(parent, "memoryLimitedJobRunner", mlr);
    setFinal(parent, "jobRunner", pjr);
    return parent;
  }

  private static void setFinal(Object target, String fieldName, Object value) {
    try {
      Field f = SplitFileFetcherStorage.class.getDeclaredField(fieldName);
      f.setAccessible(true);
      f.set(target, value);
    } catch (NoSuchFieldException | IllegalAccessException e) {
      throw new AssertionError("Failed to set field '" + fieldName + "'", e);
    }
  }

  private static MemoryLimitedJobRunner newInlineRunner(long capacity) {
    return new MemoryLimitedJobRunner(capacity, 4, new InlineExecutor(), /* priorities= */ 4);
  }

  private static class InlineExecutor implements PriorityAwareExecutor {
    @Override
    public void execute(@NotNull Runnable job) {
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

  private static SplitFileFetcherSegmentStorage newSegmentMock(int segNo) {
    SplitFileFetcherSegmentStorage seg = mock(SplitFileFetcherSegmentStorage.class);
    try {
      Field f = SplitFileFetcherSegmentStorage.class.getDeclaredField("segNo");
      f.setAccessible(true);
      f.set(seg, segNo);
    } catch (NoSuchFieldException | IllegalAccessException e) {
      throw new AssertionError(e);
    }
    return seg;
  }

  // Helper to build a DataInputStream for cross-segment fixed metadata.
  // Derives dataBlocks from array sizes to avoid constant parameters.
  private static DataInputStream newCrossMetaStream(int checkBlocks, int[] segIdx, int[] blockNos) {
    int total = segIdx.length;
    if (blockNos.length != total) {
      throw new IllegalArgumentException("Mismatched array sizes for metadata");
    }
    int dataBlocks = total - checkBlocks;
    if (dataBlocks < 0) {
      throw new IllegalArgumentException("checkBlocks exceeds total blocks");
    }
    try {
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      DataOutputStream dos = new DataOutputStream(bos);
      dos.writeInt(dataBlocks);
      dos.writeInt(checkBlocks);
      for (int i = 0; i < total; i++) {
        dos.writeInt(segIdx[i]);
        dos.writeInt(blockNos[i]);
      }
      dos.flush();
      return new DataInputStream(new ByteArrayInputStream(bos.toByteArray()));
    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }

  @BeforeEach
  void setupCodecDefaults() {
    // Keep memory usage small and do-nothing FEC ops for predictable tests.
    org.mockito.Mockito.lenient()
        .doReturn(0L)
        .when(codec)
        .maxMemoryOverheadDecode(any(Integer.class), any(Integer.class));
    org.mockito.Mockito.lenient()
        .doReturn(0L)
        .when(codec)
        .maxMemoryOverheadEncode(any(Integer.class), any(Integer.class));
    org.mockito.Mockito.lenient()
        .doAnswer(_ -> null)
        .when(codec)
        .decode(
            any(byte[][].class),
            any(byte[][].class),
            any(boolean[].class),
            any(boolean[].class),
            eq(CHKBlock.DATA_LENGTH));
    org.mockito.Mockito.lenient()
        .doAnswer(_ -> null)
        .when(codec)
        .encode(
            any(byte[][].class),
            any(byte[][].class),
            any(boolean[].class),
            eq(CHKBlock.DATA_LENGTH));
  }

  @Test
  @DisplayName("writeFixedMetadata_whenBlocksAdded_writesExpectedInts")
  void writeFixedMetadata_whenBlocksAdded_writesExpectedInts() throws Exception {
    // Arrange
    PersistentJobRunner pjr = mock(PersistentJobRunner.class);
    MemoryLimitedJobRunner mlr = newInlineRunner(1024L * 1024L * 1024L);
    SplitFileFetcherStorage parent = newParentWithRunners(mlr, pjr);
    setFinal(parent, "fecCodec", codec);

    SplitFileFetcherCrossSegmentStorage cross =
        new SplitFileFetcherCrossSegmentStorage(
            0, /* dataBlocks= */ 2, /* checkBlocks= */ 1, parent, codec);

    SplitFileFetcherSegmentStorage s1 = newSegmentMock(7);
    SplitFileFetcherSegmentStorage s2 = newSegmentMock(9);
    SplitFileFetcherSegmentStorage s3 = newSegmentMock(11);

    cross.addDataBlock(s1, 100);
    cross.addDataBlock(s2, 200);
    cross.addDataBlock(s3, 300);

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(bos);

    // Act
    cross.writeFixedMetadata(dos);
    dos.flush();

    // Assert
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()))) {
      assertEquals(2, dis.readInt());
      assertEquals(1, dis.readInt());
      // (segNo, blockNo) triplets
      assertEquals(7, dis.readInt());
      assertEquals(100, dis.readInt());
      assertEquals(9, dis.readInt());
      assertEquals(200, dis.readInt());
      assertEquals(11, dis.readInt());
      assertEquals(300, dis.readInt());
    }
  }

  @Test
  @DisplayName("streamCtor_whenInvalidSegment_throwsStorageFormatException")
  void streamCtor_whenInvalidSegment_throwsStorageFormatException() {
    // Arrange
    PersistentJobRunner pjr = mock(PersistentJobRunner.class);
    MemoryLimitedJobRunner mlr = newInlineRunner(1024L * 1024L);
    SplitFileFetcherStorage parent = newParentWithRunners(mlr, pjr);
    setFinal(parent, "fecCodec", codec);

    SplitFileFetcherSegmentStorage seg0 = newSegmentMock(1);
    // segments length = 2 (valid indices: 0,1)
    setFinal(parent, "segments", new SplitFileFetcherSegmentStorage[] {seg0, newSegmentMock(2)});

    // Act + Assert
    try (DataInputStream dis = newCrossMetaStream(1, new int[] {1, 2}, new int[] {0, 0})) {
      assertThrows(
          network.crypta.support.io.StorageFormatException.class,
          () -> new SplitFileFetcherCrossSegmentStorage(parent, 0, dis));
    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  @DisplayName("streamCtor_whenInvalidBlockNumber_throwsStorageFormatException")
  void streamCtor_whenInvalidBlockNumber_throwsStorageFormatException() {
    // Arrange
    PersistentJobRunner pjr = mock(PersistentJobRunner.class);
    MemoryLimitedJobRunner mlr = newInlineRunner(1024L * 1024L);
    SplitFileFetcherStorage parent = newParentWithRunners(mlr, pjr);
    setFinal(parent, "fecCodec", codec);

    SplitFileFetcherSegmentStorage seg0 = newSegmentMock(4);
    doReturn(1).when(seg0).totalBlocks();
    setFinal(parent, "segments", new SplitFileFetcherSegmentStorage[] {seg0});

    // Act + Assert
    try (DataInputStream dis = newCrossMetaStream(0, new int[] {0}, new int[] {1})) {
      assertThrows(
          network.crypta.support.io.StorageFormatException.class,
          () -> new SplitFileFetcherCrossSegmentStorage(parent, 0, dis));
    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  @DisplayName("restart_whenAllBlocksPresent_runsJobAndFinishes")
  void restart_whenAllBlocksPresent_runsJobAndFinishes() throws Exception {
    // Arrange
    PersistentJobRunner pjr = mock(PersistentJobRunner.class);
    doAnswer(_ -> (CheckpointLock) (_, _) -> {}).when(pjr).lock();

    // Run jobs inline with plenty of capacity so the decode job starts immediately.
    MemoryLimitedJobRunner mlr = newInlineRunner(10L * CHKBlock.DATA_LENGTH);
    SplitFileFetcherStorage parent = newParentWithRunners(mlr, pjr);
    setFinal(parent, "fecCodec", codec);
    doReturn((short) 0).when(parent).getPriorityClass();

    SplitFileFetcherCrossSegmentStorage cross =
        new SplitFileFetcherCrossSegmentStorage(
            0, /* dataBlocks= */ 2, /* checkBlocks= */ 1, parent, codec);

    // Attach segments and make their blocks present.
    SplitFileFetcherSegmentStorage s0 = newSegmentMock(0);
    SplitFileFetcherSegmentStorage s1 = newSegmentMock(1);
    SplitFileFetcherSegmentStorage s2 = newSegmentMock(2);

    cross.addDataBlock(s0, 10);
    cross.addDataBlock(s1, 20);
    cross.addDataBlock(s2, 30);

    doReturn(new byte[CHKBlock.DATA_LENGTH]).when(s0).checkAndGetBlockData(10);
    doReturn(new byte[CHKBlock.DATA_LENGTH]).when(s1).checkAndGetBlockData(20);
    doReturn(new byte[CHKBlock.DATA_LENGTH]).when(s2).checkAndGetBlockData(30);

    // Trigger: mark two data blocks as found to meet threshold and start decoding.
    cross.onFetchedRelevantBlock(s0, 10);
    cross.onFetchedRelevantBlock(s1, 20);

    // Assert: the decode job should have run and invoked the completion callback.
    verify(parent, times(1)).finishedEncoding(cross);
  }

  @Test
  @DisplayName("cancel_whileDecoding_doesNotFinishImmediately")
  void cancel_whileDecoding_doesNotFinishImmediately() {
    // Arrange
    // Use a mocked runner that accepts the job but never starts it.
    MemoryLimitedJobRunner mockedRunner = mock(MemoryLimitedJobRunner.class);
    PersistentJobRunner pjr = mock(PersistentJobRunner.class);
    SplitFileFetcherStorage parent = newParentWithRunners(mockedRunner, pjr);
    setFinal(parent, "fecCodec", codec);
    doReturn((short) 0).when(parent).getPriorityClass();

    SplitFileFetcherCrossSegmentStorage cross =
        new SplitFileFetcherCrossSegmentStorage(
            0, /* dataBlocks= */ 1, /* checkBlocks= */ 0, parent, codec);

    SplitFileFetcherSegmentStorage s0 = newSegmentMock(0);
    cross.addDataBlock(s0, 1);

    // Act: onFetchedRelevantBlock queues the job and sets tryDecode=true (isDecoding())
    cross.onFetchedRelevantBlock(s0, 1);
    // Cancel while decoding is pending/running -> should not call finishedEncoding immediately.
    cross.cancel();

    // Assert
    verify(parent, times(0)).finishedEncoding(cross);
  }

  @Test
  @DisplayName("innerDecode_whenDiskError_callsFailOnDiskError")
  void innerDecode_whenDiskError_callsFailOnDiskError() throws Exception {
    // Arrange
    PersistentJobRunner pjr = mock(PersistentJobRunner.class);
    doAnswer(_ -> (CheckpointLock) (_, _) -> {}).when(pjr).lock();
    // Run queued jobs (failOffThread/failDiskOffThread) immediately
    doAnswer(
            inv -> {
              PersistentJob job = inv.getArgument(0, PersistentJob.class);
              // Run immediately and return
              job.run(null);
              return null;
            })
        .when(pjr)
        .queueNormalOrDrop(any(PersistentJob.class));

    MemoryLimitedJobRunner mlr = newInlineRunner(10L * CHKBlock.DATA_LENGTH);
    SplitFileFetcherStorage parent = newParentWithRunners(mlr, pjr);
    setFinal(parent, "fecCodec", codec);
    doReturn((short) 0).when(parent).getPriorityClass();

    SplitFileFetcherCrossSegmentStorage cross =
        new SplitFileFetcherCrossSegmentStorage(
            0, /* dataBlocks= */ 1, /* checkBlocks= */ 0, parent, codec);

    SplitFileFetcherSegmentStorage s0 = newSegmentMock(0);
    cross.addDataBlock(s0, 1);

    // Simulate disk I/O failure when reading the block
    doAnswer(
            _ -> {
              throw new IOException("disk error");
            })
        .when(s0)
        .checkAndGetBlockData(1);

    // Act: trigger decode
    cross.onFetchedRelevantBlock(s0, 1);

    // Assert
    verify(parent, times(1)).finishedEncoding(cross);
    // The failDiskOffThread path enqueues a job that calls parent.failOnDiskError
    verify(parent, times(1)).failOnDiskError(any(IOException.class));
  }

  @Test
  @DisplayName("innerDecode_whenCheckBlockDiskError_exitsEarlyAndFailsGracefully")
  void innerDecode_whenCheckBlockDiskError_exitsEarlyAndFailsGracefully() throws Exception {
    // Arrange
    PersistentJobRunner pjr = mock(PersistentJobRunner.class);
    doAnswer(_ -> (CheckpointLock) (_, _) -> {}).when(pjr).lock();
    // Run queued jobs (failOffThread/failDiskOffThread) immediately
    doAnswer(
            inv -> {
              PersistentJob job = inv.getArgument(0, PersistentJob.class);
              job.run(null);
              return null;
            })
        .when(pjr)
        .queueNormalOrDrop(any(PersistentJob.class));

    MemoryLimitedJobRunner mlr = newInlineRunner(10L * CHKBlock.DATA_LENGTH);
    SplitFileFetcherStorage parent = newParentWithRunners(mlr, pjr);
    setFinal(parent, "fecCodec", codec);
    doReturn((short) 0).when(parent).getPriorityClass();

    // Two data blocks, one cross-check block
    SplitFileFetcherCrossSegmentStorage cross =
        new SplitFileFetcherCrossSegmentStorage(
            0, /* dataBlocks= */ 2, /* checkBlocks= */ 1, parent, codec);

    // Attach segments and make data present; check block will throw on read.
    SplitFileFetcherSegmentStorage s0 = newSegmentMock(0);
    SplitFileFetcherSegmentStorage s1 = newSegmentMock(1);
    SplitFileFetcherSegmentStorage s2 = newSegmentMock(2);

    cross.addDataBlock(s0, 10);
    cross.addDataBlock(s1, 20);
    cross.addDataBlock(s2, 30); // check block

    doReturn(new byte[CHKBlock.DATA_LENGTH]).when(s0).checkAndGetBlockData(10);
    doReturn(new byte[CHKBlock.DATA_LENGTH]).when(s1).checkAndGetBlockData(20);
    doAnswer(
            _ -> {
              throw new IOException("disk error check block");
            })
        .when(s2)
        .checkAndGetBlockData(30);

    // Act: trigger decode by marking both data blocks found.
    cross.onFetchedRelevantBlock(s0, 10);
    cross.onFetchedRelevantBlock(s1, 20);

    // Assert: the decode job should complete without crashing and enqueue disk failure handling.
    verify(parent, times(1)).finishedEncoding(cross);
    verify(parent, times(1)).failOnDiskError(any(IOException.class));
  }

  @Test
  @DisplayName("getBlockNumbers_returnsClone")
  void getBlockNumbers_returnsClone() {
    // Arrange
    MemoryLimitedJobRunner mlr = newInlineRunner(1);
    PersistentJobRunner pjr = mock(PersistentJobRunner.class);
    SplitFileFetcherStorage parent = newParentWithRunners(mlr, pjr);

    SplitFileFetcherCrossSegmentStorage cross =
        new SplitFileFetcherCrossSegmentStorage(
            0, /* dataBlocks= */ 2, /* checkBlocks= */ 1, parent, codec);
    cross.addDataBlock(newSegmentMock(0), 10);
    cross.addDataBlock(newSegmentMock(1), 20);
    cross.addDataBlock(newSegmentMock(2), 30);

    // Act
    int[] nums = cross.getBlockNumbers();
    // Mutate returned array and ensure internal state doesn't change
    nums[0] = 999;

    // Assert
    assertArrayEquals(new int[] {10, 20, 30}, cross.getBlockNumbers());
  }
}
