package network.crypta.client.async;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;
import network.crypta.client.FECCodec;
import network.crypta.client.Metadata;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SplitFileFetcherCrossSegmentAllocatorTest {

  private static Metadata metadataWithHash(byte[] hash, int deductBlocks) {
    Metadata metadata = mock(Metadata.class);
    when(metadata.getHashThisLayerOnly()).thenReturn(hash);
    when(metadata.getHashes()).thenReturn(null);
    when(metadata.getDeductBlocksFromSegments()).thenReturn(deductBlocks);
    return metadata;
  }

  private static Metadata metadataWithoutHash() {
    Metadata metadata = mock(Metadata.class);
    when(metadata.getHashThisLayerOnly()).thenReturn(null);
    when(metadata.getHashes()).thenReturn(null);
    return metadata;
  }

  private static int[] readBlockNumbers(SplitFileFetcherCrossSegmentStorage cross) {
    try {
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      DataOutputStream dos = new DataOutputStream(bos);
      cross.writeFixedMetadata(dos);
      dos.flush();
      try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()))) {
        int dataBlocks = dis.readInt();
        int checkBlocks = dis.readInt();
        int total = dataBlocks + checkBlocks;
        int[] blockNumbers = new int[total];
        for (int i = 0; i < total; i++) {
          dis.readInt(); // segNo
          blockNumbers[i] = dis.readInt();
        }
        return blockNumbers;
      }
    } catch (IOException e) {
      throw new AssertionError("Failed to read fixed metadata", e);
    }
  }

  @Test
  void createCrossSegments_whenCrossCheckBlocksZero_returnsEmptyArrayAndSkipsAllocation() {
    // Arrange
    SplitFileFetcherStorage owner = mock(SplitFileFetcherStorage.class);
    Metadata metadata = mock(Metadata.class);
    SplitFileFetcherSegmentStorage seg1 = mock(SplitFileFetcherSegmentStorage.class);
    SplitFileFetcherSegmentStorage seg2 = mock(SplitFileFetcherSegmentStorage.class);
    FECCodec codec = mock(FECCodec.class);

    // Act
    SplitFileFetcherCrossSegmentStorage[] result =
        SplitFileFetcherCrossSegmentAllocator.createCrossSegments(
            owner,
            metadata,
            /* crossCheckBlocks= */ 0,
            /* blocksPerSegment= */ 3,
            new SplitFileFetcherSegmentStorage[] {seg1, seg2},
            codec);

    // Assert
    assertEquals(0, result.length);
    verifyNoInteractions(owner, metadata, seg1, seg2, codec);
  }

  @Test
  void createCrossSegments_whenMetadataMissingHashes_throwsIllegalArgumentException() {
    // Arrange
    Metadata metadata = metadataWithoutHash();
    SplitFileFetcherStorage owner = mock(SplitFileFetcherStorage.class);
    FECCodec codec = mock(FECCodec.class);
    SplitFileFetcherSegmentStorage seg1 = mock(SplitFileFetcherSegmentStorage.class);
    SplitFileFetcherSegmentStorage seg2 = mock(SplitFileFetcherSegmentStorage.class);

    // Act + Assert
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SplitFileFetcherCrossSegmentAllocator.createCrossSegments(
                owner,
                metadata,
                /* crossCheckBlocks= */ 1,
                /* blocksPerSegment= */ 1,
                new SplitFileFetcherSegmentStorage[] {seg1, seg2},
                codec));
    verifyNoInteractions(seg1, seg2);
  }

  @Test
  void createCrossSegments_whenDeductBlocksFromSegments_adjustsDataBlockCountForTrailingSegments() {
    // Arrange
    Metadata metadata = metadataWithHash(new byte[] {1, 2, 3}, /* deductBlocks= */ 2);
    SplitFileFetcherStorage owner = mock(SplitFileFetcherStorage.class);
    FECCodec codec = mock(FECCodec.class);
    SplitFileFetcherSegmentStorage[] segments =
        new SplitFileFetcherSegmentStorage[] {
          mock(SplitFileFetcherSegmentStorage.class),
          mock(SplitFileFetcherSegmentStorage.class),
          mock(SplitFileFetcherSegmentStorage.class)
        };

    AtomicInteger dataCalls = new AtomicInteger();
    AtomicInteger checkCalls = new AtomicInteger();
    for (SplitFileFetcherSegmentStorage segment : segments) {
      doAnswer(
              _ -> {
                dataCalls.incrementAndGet();
                return 0;
              })
          .when(segment)
          .allocateCrossDataBlock(
              any(SplitFileFetcherCrossSegmentStorage.class), any(Random.class));
      doAnswer(
              _ -> {
                checkCalls.incrementAndGet();
                return 0;
              })
          .when(segment)
          .allocateCrossCheckBlock(
              any(SplitFileFetcherCrossSegmentStorage.class), any(Random.class));
    }

    // Act
    SplitFileFetcherCrossSegmentStorage[] result =
        SplitFileFetcherCrossSegmentAllocator.createCrossSegments(
            owner, metadata, /* crossCheckBlocks= */ 2, /* blocksPerSegment= */ 4, segments, codec);

    // Assert
    assertEquals(3, result.length);
    assertEquals(4, result[0].dataBlockCount);
    assertEquals(3, result[1].dataBlockCount);
    assertEquals(3, result[2].dataBlockCount);
    for (SplitFileFetcherCrossSegmentStorage cross : result) {
      assertEquals(2, cross.crossCheckBlockCount);
      assertEquals(cross.dataBlockCount + 2, cross.totalBlocks);
    }
    assertEquals(10, dataCalls.get());
    assertEquals(6, checkCalls.get());
  }

  @Test
  void createCrossSegments_whenDataAllocationFailsForAllSegments_throwsIllegalStateException() {
    // Arrange
    Metadata metadata = metadataWithHash(new byte[] {9}, /* deductBlocks= */ 0);
    SplitFileFetcherStorage owner = mock(SplitFileFetcherStorage.class);
    FECCodec codec = mock(FECCodec.class);
    SplitFileFetcherSegmentStorage seg1 = mock(SplitFileFetcherSegmentStorage.class);
    SplitFileFetcherSegmentStorage seg2 = mock(SplitFileFetcherSegmentStorage.class);

    when(seg1.allocateCrossDataBlock(
            any(SplitFileFetcherCrossSegmentStorage.class), any(Random.class)))
        .thenReturn(-1);
    when(seg2.allocateCrossDataBlock(
            any(SplitFileFetcherCrossSegmentStorage.class), any(Random.class)))
        .thenReturn(-1);

    // Act + Assert
    assertThrows(
        IllegalStateException.class,
        () ->
            SplitFileFetcherCrossSegmentAllocator.createCrossSegments(
                owner,
                metadata,
                /* crossCheckBlocks= */ 1,
                /* blocksPerSegment= */ 1,
                new SplitFileFetcherSegmentStorage[] {seg1, seg2},
                codec));
    verify(seg1, never())
        .allocateCrossCheckBlock(any(SplitFileFetcherCrossSegmentStorage.class), any(Random.class));
    verify(seg2, never())
        .allocateCrossCheckBlock(any(SplitFileFetcherCrossSegmentStorage.class), any(Random.class));
  }

  @Test
  void createCrossSegments_whenCheckAllocationFailsForAllSegments_throwsIllegalStateException() {
    // Arrange
    Metadata metadata = metadataWithHash(new byte[] {4, 2}, /* deductBlocks= */ 0);
    SplitFileFetcherStorage owner = mock(SplitFileFetcherStorage.class);
    FECCodec codec = mock(FECCodec.class);
    SplitFileFetcherSegmentStorage seg1 = mock(SplitFileFetcherSegmentStorage.class);
    SplitFileFetcherSegmentStorage seg2 = mock(SplitFileFetcherSegmentStorage.class);

    when(seg1.allocateCrossCheckBlock(
            any(SplitFileFetcherCrossSegmentStorage.class), any(Random.class)))
        .thenReturn(-1);
    when(seg2.allocateCrossCheckBlock(
            any(SplitFileFetcherCrossSegmentStorage.class), any(Random.class)))
        .thenReturn(-1);

    // Act + Assert
    assertThrows(
        IllegalStateException.class,
        () ->
            SplitFileFetcherCrossSegmentAllocator.createCrossSegments(
                owner,
                metadata,
                /* crossCheckBlocks= */ 1,
                /* blocksPerSegment= */ 1,
                new SplitFileFetcherSegmentStorage[] {seg1, seg2},
                codec));
  }

  @Test
  void createCrossSegments_whenRandomAttemptsFail_fallsBackToSequentialAllocationForDataBlock() {
    // Arrange
    Metadata metadata = metadataWithHash(new byte[] {7, 7, 7}, /* deductBlocks= */ 0);
    SplitFileFetcherStorage owner = mock(SplitFileFetcherStorage.class);
    FECCodec codec = mock(FECCodec.class);
    SplitFileFetcherSegmentStorage segment = mock(SplitFileFetcherSegmentStorage.class);
    SplitFileFetcherSegmentStorage[] segments = new SplitFileFetcherSegmentStorage[] {segment};

    AtomicInteger dataCalls = new AtomicInteger();
    doAnswer(
            _ -> {
              int call = dataCalls.incrementAndGet();
              return call <= 10 ? -1 : 42;
            })
        .when(segment)
        .allocateCrossDataBlock(any(SplitFileFetcherCrossSegmentStorage.class), any(Random.class));
    when(segment.allocateCrossCheckBlock(
            any(SplitFileFetcherCrossSegmentStorage.class), any(Random.class)))
        .thenReturn(7);

    // Act
    SplitFileFetcherCrossSegmentStorage[] result =
        SplitFileFetcherCrossSegmentAllocator.createCrossSegments(
            owner, metadata, /* crossCheckBlocks= */ 1, /* blocksPerSegment= */ 1, segments, codec);

    // Assert
    assertEquals(1, result.length);
    assertEquals(11, dataCalls.get());
    int[] blockNumbers = readBlockNumbers(result[0]);
    assertEquals(42, blockNumbers[0]);
    assertEquals(7, blockNumbers[1]);
  }

  @Test
  void createCrossSegments_whenCheckRandomAttemptsFail_fallsBackToSequentialAllocation() {
    // Arrange
    Metadata metadata = metadataWithHash(new byte[] {8, 8}, /* deductBlocks= */ 0);
    SplitFileFetcherStorage owner = mock(SplitFileFetcherStorage.class);
    FECCodec codec = mock(FECCodec.class);
    SplitFileFetcherSegmentStorage segment = mock(SplitFileFetcherSegmentStorage.class);
    SplitFileFetcherSegmentStorage[] segments = new SplitFileFetcherSegmentStorage[] {segment};

    when(segment.allocateCrossDataBlock(
            any(SplitFileFetcherCrossSegmentStorage.class), any(Random.class)))
        .thenReturn(3);

    AtomicInteger checkCalls = new AtomicInteger();
    doAnswer(
            _ -> {
              int call = checkCalls.incrementAndGet();
              return call <= 10 ? -1 : 9;
            })
        .when(segment)
        .allocateCrossCheckBlock(any(SplitFileFetcherCrossSegmentStorage.class), any(Random.class));

    // Act
    SplitFileFetcherCrossSegmentStorage[] result =
        SplitFileFetcherCrossSegmentAllocator.createCrossSegments(
            owner, metadata, /* crossCheckBlocks= */ 1, /* blocksPerSegment= */ 1, segments, codec);

    // Assert
    assertEquals(1, result.length);
    assertEquals(11, checkCalls.get());
    int[] blockNumbers = readBlockNumbers(result[0]);
    assertEquals(3, blockNumbers[0]);
    assertEquals(9, blockNumbers[1]);
  }
}
